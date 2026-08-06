//
// Scalpel3 is Copyright(C) 2021 - 2025 by Golden G. Richard III and
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

// Debug-only block-placement trace. When defined, every block placed into a
// candidate is logged to stdout with the call site that placed it, so a
// mis-assembled candidate can be attributed to a specific reassembly path.
// Comment out to disable; there is zero cost when undefined.
//#define PDF_TRACE_PLACEMENT

// Diagnostic: log pdf_file_validate accept/reject decisions (low volume).
//#define PDF_TRACE_VALIDATE

// Diagnostic: log per-candidate reassembly outcome (Strategy 2 scan/score).
//#define PDF_TRACE_REASM

// Diagnostic: log stream reconstruction stalls.
//#define PDF_TRACE_STALL

// Diagnostic: log zlib/stream INNEXTBLOCK contiguity of block selection.
//#define PDF_TRACE_ZSTALL

// Diagnostic: log each xref-bearing block scan_blocks_for_xref surfaces.
//#define PDF_TRACE_SCANXREF

// Define stream conditions
#define LENGTHNOTFOUND -1
#define INBLOCK 1
#define INNEXTBLOCK 2
#define MULTIBLOCK 3

// Define stream filters
#define NOFILTER 0
#define ZLIB 1
#define XML 2
#define JPEG 3

// Maximum number of digits parsed for an integer / byte offset. A 64-bit value
// is at most 20 decimal digits; a longer run is never a legitimate number.
// Parsers cap the copy length to this so a long attacker-controlled digit run
// cannot size an unbounded stack VLA (char temp[digit_run + 1]).
#define PDF_MAX_INT_DIGITS 20

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
    // Linearization parameters, read once from the candidate's header block.
    // A linearized file places its entry-point xref at the FRONT, so its final
    // startxref does NOT locate the main table; lin_T does. See
    // pdf_detect_linearization().
    bool    linearized;      // /Linearized dict present as the first object
    int64_t lin_L;           // /L: declared total length of that revision, -1 if absent
    int64_t lin_T;           // /T: offset of that revision's main xref, -1 if absent
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

typedef struct ZlibStreamReassembler {
    z_stream strm;           // current decompression state
    z_stream checkpoint;     // last known-good state
    size_t total_verified;   // total bytes successfully decompressed
    unsigned char *output;   // accumulated decompressed output
    size_t output_len;
    size_t output_capacity;
    // Declared /Length and bytes consumed: needed to reach Z_STREAM_END, where
    // zlib verifies the Adler-32 over the whole output -- DEFLATE's only integrity
    // check, since a wrong block otherwise decodes to plausible garbage.
    size_t stream_length;    // 0 = unknown, no completion gate
    size_t fed;              // compressed bytes consumed so far
    int    ended;            // Z_STREAM_END reached
} ZlibStreamReassembler;

/*
 * Reassembler for uncompressed XML/XMP metadata streams. With no checksum to
 * validate blocks, acceptance is driven by the exact /Length, a per-byte
 * printable-text/UTF-8 gate, and an incremental XML structural state machine.
 * Scalar fields are snapshotted/restored by value on reject, so no checkpoint
 * clone is needed.
 */
typedef struct XmlStreamReassembler {
    unsigned char *output;       // accumulated stream bytes
    size_t output_len;           // bytes appended so far
    size_t output_capacity;
    size_t stream_length;        // exact expected /Length of the stream
    size_t fed;                  // stream bytes consumed by the state machine
    int    state;                // XmlScanState (see reconstruct path)
    int    just_opened;          // next byte is the first char after '<'
    int    prev_slash;           // previous in-tag char was '/' (for "/>")
    int    prev_q;               // previous in-PI char was '?' (for "?>")
    int    quote;                // inside a quoted attribute value: 0, '"' or '\''
    int    marker_run;           // trailing '-' (comment) or ']' (CDATA) run, capped at 2
    int    tag_depth;            // running element nesting depth
    int    malformed;            // structural/text violation seen
} XmlStreamReassembler;

/*
 * Reassembler for DCTDecode (JPEG) streams. Driven by the exact /Length and an
 * incremental state machine rather than a checksum, validating two regions: the
 * header/marker grammar (SOI -> APPn/DQT/DHT/SOF/DRI/SOS, with explicit segment
 * lengths) and the entropy-coded scan (the 0xFF byte-stuffing rule, plus the RSTn
 * cadence when a DRI restart interval is present). init() preallocates the full
 * output capacity, so a rejected block rolls back with a by-value struct copy.
 */
typedef struct JpegStreamReassembler {
    unsigned char *output;       // accumulated stream bytes
    size_t output_len;           // bytes appended so far
    size_t output_capacity;
    size_t stream_length;        // exact expected /Length of the stream
    size_t fed;                  // stream bytes consumed by the state machine

    int state;                   // JpegScanState (see reconstruct path)
    int marker;                  // marker code of the segment being parsed
    int seg_len;                 // declared segment length (incl. 2 length bytes)
    int seg_remaining;           // payload bytes still to consume
    int prev_ff;                 // previous byte was 0xFF (marker/stuffing lead-in)

    int restart_interval;        // MCUs between RSTn (from DRI); 0 = none
    int expected_rst;            // next expected RSTn number (0..7), cycling
    int have_seen_rst;           // at least one RSTn cadence validated
    int dri_capture;             // currently reading the 2-byte DRI interval

    int saw_sos;                 // entered entropy scan at least once
    int saw_eoi;                 // EOI (FF D9) seen
    int malformed;               // grammar/stuffing/cadence violation seen

    // --- frame/table structure, used to validate segments against the spec ---
    size_t pos;                  // stream bytes fed so far; bounds segment lengths
    int saw_sof;                 // a frame header has been seen (exactly one is legal)
    int sof_marker;              // which SOFn defined the frame
    int precision;               // sample precision from SOF
    int frame_w, frame_h;        // image dimensions from SOF
    int ncomp;                   // component count from SOF
    unsigned dht_defined;        // Huffman tables defined, bit (class<<2)|id
    unsigned dqt_defined;        // quantisation tables defined, bit id
    int tbl_phase;               // DHT/DQT sub-parser: 0=header 1=counts 2=payload
    int tbl_id;                  // Tc/Th or Pq/Tq byte of the table being read
    int tbl_count;               // count bytes consumed (DHT)
    int tbl_total;               // sum of DHT counts = number of symbols
    int tbl_sym;                 // payload bytes still to consume for this table
    int scan_ncomp;              // component count of the current scan (SOS)
    int scan_count;              // scans seen
} JpegStreamReassembler;

/* Incremental XML scan states for the metadata-stream reassembler. */
enum XmlScanState {
    X_TEXT,     // character data between tags
    X_OPEN,     // inside an opening/empty element tag "<name ...>"
    X_CLOSE,    // inside a closing tag "</name>"
    X_PI,       // inside a processing instruction "<? ... ?>"
    X_DECL,     // inside a declaration ending on '>' (e.g. "<!DOCTYPE ...>")
    X_BANG,     // just consumed "<!", deciding comment / CDATA / declaration
    X_BANG2,    // consumed "<!-", a comment needs a second '-'
    X_COMMENT,  // inside "<!-- ... -->" (content, incl. '<'/'>', is ignored)
    X_CDATA     // inside "<![CDATA[ ... ]]>" (content is character data)
};

/* Incremental marker/scan states for the JPEG (DCTDecode) reassembler. */
enum JpegScanState {
    J_START,    // expecting SOI (FF D8)
    J_MARKER,   // between segments: expecting FF then a marker code
    J_LEN1,     // reading high byte of a segment length
    J_LEN2,     // reading low byte of a segment length
    J_PAYLOAD,  // consuming a segment payload
    J_SCAN,     // entropy-coded scan data
    J_DONE      // EOI seen; stream complete
};

/*******************************************************/
/* HELPER FUNCTION PROTOTYPES                         */
/*******************************************************/

int extract_int(char* data, int64_t offset, int64_t length, int64_t *end_offset);

int extract_obj_num(char *data, size_t offset, uint64_t length);

int detect_xref_type(const char *data, int64_t offset, int64_t length, int64_t *out_offset);

int64_t find_xref_stream_start(char *data, int64_t offset);

static inline const char *min_xref_start(const char *a, const char *b, const char *c, int *out_type);

int64_t find_prev_entry(char *data, int64_t length, int64_t offset, int xref_type);

int64_t find_stm_entry(char *data, int64_t length, int64_t offset, int xref_type);

int extract_w_array(const char *data, int64_t offset, int *w_out, int64_t length);

char *extract_stream_data(char *data, int64_t offset, size_t *out_length, int64_t length, uint64_t *xref_end_offset);

Object* store_xref_table(char *data, int64_t offset, int *num_entries, int64_t length, uint64_t *xref_end_offset);

static inline ObjectHashTable* hash_table_create(int bucket_count);

static inline int hash_function(int obj_num, int bucket_count);

static inline void hash_table_insert(ObjectHashTable *table, int obj_num, int entry_idx);

static inline bool hash_table_lookup(ObjectHashTable *table, int obj_num, int *out_entry_idx);

static inline void hash_table_free(ObjectHashTable *table);

int validate_at_offset(char *data, int64_t offset, int obj_num1, int64_t length);

uint32_t read_be(const unsigned char *data, size_t len, size_t max_len);

Object* store_xref_stream(const char *decoded_data, size_t decoded_len, const size_t *index_array, size_t index_count, const int *w_array, size_t size_value, int *num_type1);

Object* analyze_xref(char* data, int64_t offset, int64_t length, int *entry_count, uint64_t *xref_end_offset);

int extract_index_array(const char *data, int64_t offset, size_t **index_array_out, size_t *index_count_out, int64_t length);

char *decompress_with_uncompress(const char *input, size_t input_length, size_t *out_length);

char *apply_png_predictor_up(const char *input, size_t input_length, size_t columns, size_t *out_length);

static int compare_objects(const void *a, const void *b);

void sort_xref_data_by_offset(XrefTables *data);

bool add_xref_table(PDFCarveState *state, XrefTables *xref_table, int table_idx);

int check_startxref(char *data, uint64_t validation_cutoff);

int *list_candidate_objects(char *data, uint64_t length, int *obj_count);

bool is_indirect_object(char *data, uint64_t length, uint64_t offset, int *out_obj_num);

uint64_t search_tables_for_object(XrefTables *test_tables, int num_tables, int obj_num);

int64_t scan_blocks_for_object(int obj_num, uint64_t obj_offset);

int check_last_object_length(char *data, uint64_t length, uint64_t *out_offset, XrefTables *test_tables, int num_tables, const char *dict, int dict_len, uint64_t obj_offset);

int check_last_object_filter(const char *dict, int dict_len);

int calculate_stream_offsets(char *data, uint64_t object_length, uint64_t length, uint64_t offset, int32_t *out_startstream_local_offset, int32_t *out_endstream_local_offset, int *out_blocks_to_extend);

int zlib_stream_reassembler_init(ZlibStreamReassembler *r, const unsigned char *first_block, size_t block_size, size_t stream_offset, size_t stream_length);

int zlib_stream_reassembler_try_block(ZlibStreamReassembler *r, const unsigned char *block, size_t block_size);

void zlib_stream_reassembler_free(ZlibStreamReassembler *r);

int64_t find_last_object(const char *data, uint64_t length);

char *extract_dict(ThreadWork *work, CarveInfo *candidate, const char *data, uint64_t length, uint64_t obj_offset, int *out_len);

bool reconstruct_zlib_stream(ThreadWork *work, CarveInfo *candidate, const char *first_stream_block_data, int32_t startstream_local_offset, int32_t endstream_local_offset, int blocks_to_extend, uint64_t stream_length, int mode);

bool reconstruct_raw_stream(ThreadWork *work, CarveInfo *candidate, int32_t endstream_local_offset, int blocks_to_extend, int mode);

static inline void xml_feed_byte(XmlStreamReassembler *r, unsigned char c);

static inline bool xml_has_signature(const unsigned char *buf, size_t len);

int xml_stream_reassembler_init(XmlStreamReassembler *r, const unsigned char *first_block, size_t block_size, size_t stream_offset, size_t stream_length);

int xml_stream_reassembler_try_block(XmlStreamReassembler *r, const unsigned char *block, size_t block_size);

void xml_stream_reassembler_free(XmlStreamReassembler *r);

bool reconstruct_xml_stream(ThreadWork *work, CarveInfo *candidate, const char *first_stream_block_data, int32_t startstream_local_offset, int32_t endstream_local_offset, int blocks_to_extend, uint64_t stream_length, int mode);

static inline bool jpeg_marker_standalone(int m);

static inline bool jpeg_marker_is_sof(int m);

static inline bool jpeg_marker_legal_after_scan(int m);

static inline bool jpeg_marker_legal_in_header(int m);

static inline void jpeg_feed_dht(JpegStreamReassembler *r, unsigned char c);

static inline void jpeg_feed_dqt(JpegStreamReassembler *r, unsigned char c);

static inline void jpeg_feed_sof(JpegStreamReassembler *r, unsigned char c, int idx);

static inline void jpeg_feed_sos(JpegStreamReassembler *r, unsigned char c, int idx);

static inline void jpeg_feed_byte(JpegStreamReassembler *r, unsigned char c);

int jpeg_stream_reassembler_init(JpegStreamReassembler *r, const unsigned char *first_block, size_t block_size, size_t stream_offset, size_t stream_length);

int jpeg_stream_reassembler_try_block(JpegStreamReassembler *r, const unsigned char *block, size_t block_size);

void jpeg_stream_reassembler_free(JpegStreamReassembler *r);

bool reconstruct_jpeg_stream(ThreadWork *work, CarveInfo *candidate, const char *first_stream_block_data, int32_t startstream_local_offset, int32_t endstream_local_offset, int blocks_to_extend, uint64_t stream_length, int mode);

Object* scan_blocks_for_xref_at_offset(CarveInfo *candidate, BlockVector *scan_bv, int *entry_count, int64_t **out_xref_blocks, int *out_xref_block_count, int32_t expected_offset);

Object* scan_blocks_for_xref(CarveInfo *candidate, BlockVector **scan_bv, int *entry_count, int64_t **out_xref_blocks, int *out_xref_block_count, int32_t *out_xref_local);

const char *scan_buf_for_xref(char *data, uint64_t length, uint64_t search_pos, int *xref_type);

static int64_t pdf_lin_param(const char *dict, int dict_len, const char *key, int key_len);

static void pdf_detect_linearization(PDFCarveState *s, const char *data, uint64_t length);

static bool pdf_place_blocks_at_slot(CarveInfo *candidate, const int64_t *actual_blocks, int count, uint64_t first_slot, const char *site);

static int pdf_collect_xref_anchors(const char *data, uint64_t length, int64_t *out, int max_out);

static int64_t pdf_resolve_xref_slot(CarveInfo *candidate, const int64_t *xref_blocks, int xref_block_count, int32_t xref_local);

static int pdf_xref_slot_object_count(CarveInfo *candidate, uint64_t slot);

static bool pdf_block_matches_xref_slot(CarveInfo *candidate, int64_t apparent_block, uint64_t slot);

static bool pdf_candidate_has_holes(CarveInfo *candidate);

static bool pdf_complete_trailer(ThreadWork *work, CarveInfo *candidate);

#ifdef PDF_TRACE_PLACEMENT
static void pdf_trace_table_adopt(CarveInfo *candidate, const char *how, Object *ents, int count, int score);
#endif

#ifdef PDF_TRACE_PLACEMENT
static void pdf_reassembly_extension_successful_traced(int id, CarveInfo *candidate, uint64_t logical_slot_index, int line, const char *site, int64_t ctx1, int64_t ctx2);
#endif

static bool pdf_claim_body_blocks_or_duplicate(CarveInfo *candidate);

static int pdf_xref_confirms_header(CarveInfo *candidate, Object *entries, int entry_count);

static bool pdf_flate_body_ok(const unsigned char *buf, size_t len);

static bool pdf_jpeg_body_ok(const unsigned char *buf, size_t len);

static bool pdf_streams_decode_ok(char *data, uint64_t length, XrefTables *tables, int num_tables);

/*
 * PDF_PLACE() -- the single funnel through which every block placement passes.
 * It tags each call to pdf_reassembly_extension_successful() with a site label
 * and two site-specific context values so a mis-assembled candidate can be
 * attributed to a specific decision in a trace. With PDF_TRACE_PLACEMENT
 * undefined it compiles to the original call, discarding the context arguments.
 */
#ifdef PDF_TRACE_PLACEMENT
#define PDF_PLACE(id, cand, slot, site, c1, c2)                               \
    pdf_reassembly_extension_successful_traced((id), (cand),                  \
        (uint64_t)(slot), __LINE__, (site), (int64_t)(c1), (int64_t)(c2))
#else
#define PDF_PLACE(id, cand, slot, site, c1, c2)                               \
    do {                                                                      \
        (void)(site); (void)(c1); (void)(c2);                                 \
        pdf_reassembly_extension_successful((id), (cand), (uint64_t)(slot));  \
    } while (0)
#endif

/*******************************************************/
/* BLOCK STATE FUNCTION PROTOTYPES                    */
/*******************************************************/

static inline bool pdf_serialize_block_state(void **state, FILE *fp, StateSerialization mode);

static inline void *pdf_clone_block_state(const void *srcstate);

static inline void pdf_free_block_state(void **state);

static inline void pdf_print_block_state(const void *state);

static inline PDFBlockState *pdf_get_blockstate_from_apparent(CarveInfo *candidate, int64_t apparent, int64_t *out_actual);

/*******************************************************/
/* CARVE STATE FUNCTION PROTOTYPES                    */
/*******************************************************/

static inline bool pdf_serialize_carve_state(void **state, FILE *fp, StateSerialization mode);

static inline void *pdf_clone_carve_state(const void *srcstate);

static inline void pdf_free_carve_state(void **state);

static inline void pdf_print_carve_state(const void *state);

/*******************************************************/
/* REASSEMBLY FUNCTION PROTOTYPES                     */
/*******************************************************/

static void pdf_reassembly_init_candidate(int id, CarveInfo *candidate, uuid_string_t uuidp, uuid_string_t uuidc);

static void pdf_reassembly_prepare_for_extension( int id, CarveInfo *candidate, int num_blocks, int mode);

int64_t pdf_reassembly_get_block_choice(CarveInfo *candidate, int obj_num, int32_t endstream_local_offset, uint64_t streamstart_block_app, uint64_t endstream_block_app, int32_t stream_blocks_extended, int mode, int64_t target_slot);

static void pdf_reassembly_did_not_validate(int id,
					   CarveInfo *candidate,
					   uint64_t validates_to,
					   int64_t block_choice);

static void pdf_reassembly_extension_successful(int id, CarveInfo *candidate, uint64_t logical_slot_index);

static int64_t pdf_reassembly_backtrack(int id,
				       CarveInfo *candidate,
				       uuid_string_t uuidp,
				       uuid_string_t uuidc);

void pdf_reassembly(ThreadWork *work, CarveInfo **c, uuid_string_t uuidp, uuid_string_t uuidc);

static void pdf_reassembly_extension(ThreadWork *work, CarveInfo **c, Object *new_entries, int new_entry_count, int64_t *xref_blocks, int xref_block_count, int64_t xref_slot, bool save_new_table);

/*******************************************************/
/* VALIDATION FUNCTION PROTOTYPES                     */
/*******************************************************/

static inline uint32_t pdf_block_validate(char *data, uint64_t length, BlockValidationDecision *decision, uint64_t *validates_to, uint32_t needleidx, uint32_t blocksize, void *blockhashkey);

static inline void pdf_file_validate(char *data, uint64_t length, bool *validates, uint64_t *validates_to, bool *promising, uint32_t needleidx, uint32_t blocksize, void *carvehashkey);

/*******************************************************/
/* FILE-SCOPE REASSEMBLY STATE                        */
/*******************************************************/

/*
 * Xref tables the current extension pass is working from, published so the
 * cross-check can see the table just scanned before it is committed to
 * PDFCarveState. Thread-local because reassembly is multithreaded; the pointer
 * refers to a stack array, so it is cleared on every exit path from that function.
 */
static __thread const XrefTables *pdf_inflight_tables = NULL;
static __thread int pdf_inflight_table_count = 0;

/*
 * Duplicate-validation guard for the parallel reassembly phase. Several header
 * candidates can converge on the same self-complete body (PDF validation
 * authenticates the body's trailer/xref chain regardless of the %PDF header
 * block). The filemirror coverage that would exclude an already-claimed body is
 * not swapped in until too late to guard a within-phase race, so the blocks
 * claimed by VALIDATED pdfs are tracked here and claimed atomically, validating
 * only the first candidate to claim a given body.
 */
static pthread_mutex_t pdf_validated_blocks_lock = PTHREAD_MUTEX_INITIALIZER;
static bool           *pdf_validated_blocks = NULL;
static uint64_t        pdf_validated_blocks_count = 0;

/*******************************************************/
/* HELPER FUNCTION DEFINITIONS                        */
/*******************************************************/

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

    // Cap the copy to a fixed-size buffer so an overlong digit run can't size an
    // unbounded stack VLA. A value beyond PDF_MAX_INT_DIGITS digits is not a
    // legitimate integer/offset anyway.
    int64_t copy_length = int_length > PDF_MAX_INT_DIGITS ? PDF_MAX_INT_DIGITS : int_length;
    char temp[PDF_MAX_INT_DIGITS + 1];
    memcpy(temp, &data[start], copy_length);
    temp[copy_length] = '\0';

    return atoi(temp);
}

/**
 * @description         Extracts the object number of an object by parsing the
 *                      format "int int obj" where the first int is the object num.
 * @param data          The buffer containing the candidate.
 * @param offset        The offset of the "o" in "obj".
 * @param length        The length of the candidate.
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

    while(offset + 6 <= length && memcmp(&data[offset], "stream", 6))offset++;
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

    if ((offset + 4 <= length) && !memcmp(&data[offset], "xref", 4)) offset += 4;
    while (offset < length && isspace(data[offset])) offset++;

    // First pass count how many 'n' entries exist
    int count = 0;
    int64_t scan = offset;
    while ((scan + 7 <= length) && memcmp(&data[scan], "trailer", 7)) {
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
    // Report only the entries actually parsed. The pass-1 'n'-count is just an
    // allocation bound; on a non-xref block the second pass breaks early, and
    // keeping the 'n'-count would expose the uninitialized malloc tail as phantom
    // 0@0 entries that win xref attribution by count.
#ifndef PDF_NO_XREF_COUNT_FIX
    *num_entries = entry_index;
#endif
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
 * @description         Maps an object number to a bucket index by modulo hashing.
 * @param obj_num       The object number (key).
 * @param bucket_count  The number of buckets in the table.
 * @return              The bucket index in [0, bucket_count).
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

    // Need another block to parse or there is no object number at the offset
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
    // Cap the copy to a fixed-size buffer so an overlong digit run can't size an
    // unbounded stack VLA. A value beyond PDF_MAX_INT_DIGITS digits is not a
    // legitimate object number anyway.
    int64_t copy_length = obj2_length > PDF_MAX_INT_DIGITS ? PDF_MAX_INT_DIGITS : obj2_length;
    char temp[PDF_MAX_INT_DIGITS + 1];
    memcpy(temp, &data[start], copy_length);
    temp[copy_length] = '\0';

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
    // A zero-width entry (/W [0 0 0]) makes every entry occupy 0 bytes, so the
    // "offset + entry_len > decoded_len" bound below never trips and the loops
    // would spin the attacker-controlled /Size (or /Index count) times. Reject
    // it: the per-entry stride must be positive and bounded by the decoded data.
    if (entry_len == 0 || entry_len > decoded_len) {
        return NULL;
    }
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

        while (nested_level > 0 && offset < dict_scan_limit && offset + 2 <= length) {
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

/**
 * @description  qsort comparator ordering two Objects by ascending obj_offset.
 * @param a      Pointer to the first Object.
 * @param b      Pointer to the second Object.
 * @return       -1, 0, or 1 as a's offset is less than, equal to, or greater than b's.
 */
static int compare_objects(const void *a, const void *b) {
    const Object *obj_a = (const Object *)a;
    const Object *obj_b = (const Object *)b;
    return (obj_a->obj_offset > obj_b->obj_offset) - (obj_a->obj_offset < obj_b->obj_offset);
}

/**
 * @description  Sorts a table's object entries in place by ascending obj_offset.
 * @param data   The xref table whose entries are sorted.
 * @return       Void.
 */
void sort_xref_data_by_offset(XrefTables *data) {
    if (!data || !data->entries || data->count == 0) return;
    
    qsort(data->entries, data->count, sizeof(Object), compare_objects);
}

/**
 * @description  Appends one table from an array to the carve state's xref_tables,
 *               growing the array by one.
 * @param state       The carve state receiving the table.
 * @param xref_table  The array of candidate tables.
 * @param table_idx   Index of the table within that array to append.
 * @return       true on success, false if state/table is null or the realloc fails.
 */
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

/**
 * @description  Verifies that every startxref before the cutoff points at a valid
 *               xref: each startxref value must be in range and detect_xref_type()
 *               must recognise an xref there.
 * @param data              The candidate buffer.
 * @param validation_cutoff The byte offset to stop scanning at.
 * @return       1 if all startxrefs resolve to a valid xref, 0 if one does not,
 *               -1 if a startxref value points past the cutoff.
 */
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

/**
 * @description  Scans the candidate for every "N G obj" indirect-object header,
 *               validating the bytes around each "obj" keyword, and returns the
 *               list of object numbers found.
 * @param data       The candidate buffer.
 * @param length     Length of the buffer.
 * @param obj_count  Out: the number of objects found (caller must init to 0).
 * @return       A malloc'd array of object numbers (caller frees), or NULL.
 */
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

/**
 * @description  Whether the tokens starting at offset form an indirect reference
 *               "N G R", and if so reports the referenced object number.
 * @param data         The buffer to parse.
 * @param length       Length of the buffer.
 * @param offset       The offset to begin parsing at.
 * @param out_obj_num  Out: the referenced object number when true is returned.
 * @return       true if an "N G R" reference is present at offset.
 */
bool is_indirect_object(char *data, uint64_t length, uint64_t offset, int *out_obj_num){
    while(offset < length && isspace((unsigned char)data[offset])) offset++;
    if(offset >= length || !isdigit((unsigned char)data[offset])) return false;
    int64_t end = 0;
    *out_obj_num = extract_int(data, (int64_t)offset, (int64_t)length, &end);
    if(*out_obj_num < 0) return false;
    offset = (uint64_t)end;
    if(offset >= length || !isspace((unsigned char)data[offset])) return false;
    while(offset < length && isspace((unsigned char)data[offset])) offset++;
    if(offset >= length || !isdigit((unsigned char)data[offset])) return false;
    while(offset < length && isdigit((unsigned char)data[offset])) offset++;
    if(offset >= length || !isspace((unsigned char)data[offset])) return false;
    while(offset < length && isspace((unsigned char)data[offset])) offset++;
    return offset < length && data[offset] == 'R';
}

/**
 * @description  Looks up an object number across the given xref tables and returns
 *               the offset the first matching entry records for it.
 * @param test_tables  The xref tables to search.
 * @param num_tables   Count of those tables.
 * @param obj_num      The object number to find.
 * @return       The object's recorded offset, or 0 if not found.
 */
uint64_t search_tables_for_object(XrefTables *test_tables, int num_tables, int obj_num){
    for(int i = 0; i < num_tables; i++){
        for(int j = 0; j < test_tables[i].count; j++){
            if(test_tables[i].entries[j].obj_num == obj_num) {
                return test_tables[i].entries[j].obj_offset;
            }
        }
    }
    return 0;
}

/**
 * @description  Searches every image block for the one carrying object obj_num at
 *               obj_offset's local offset, validating the header at that position.
 * @param obj_num     The object number to locate.
 * @param obj_offset  The object's file offset (its local offset gives the position
 *                    within a block).
 * @return       The apparent block number holding the object, or -1 if none does.
 */
int64_t scan_blocks_for_object(int obj_num, uint64_t obj_offset){
    BlockVector *scan_bv = NULL;
    uint64_t slot = 0;
    int64_t start = 0;
    uint64_t evaluated;
    int64_t block_choice;
    int64_t result = -1;
    init_blockvector(scalpel_state.filemirror, &scan_bv, 1, false);
    inflate_blockvector(scan_bv);
    uint64_t local_offset = obj_offset % scalpel_state.blocksize;

    while ((block_choice = blockvector_get_choice(scan_bv, slot, start, -1, &evaluated)) != -1) {
        blockvector_remove_choice(scan_bv, slot, block_choice);
        start = block_choice + 1;
        char *blk = (char*)get_apparent_block_data(scalpel_state.filemirror, block_choice);
        int check = validate_at_offset(blk, local_offset, obj_num, scalpel_state.blocksize);
        free(blk);
        if (check == 1) {
            result = block_choice;
            break;
        }
    }
    free_blockvector(&scan_bv);
    return result;
}

/**
 * @description  Resolves the /Length of a stream object from its dict, following an
 *               indirect "/Length N G R" reference through the xref tables and the
 *               image blocks when the value is not inline.
 * @param data         The candidate buffer (unused fallback context).
 * @param length       Length of the buffer.
 * @param out_offset   Out: set to obj_offset once a /Length is located.
 * @param test_tables  The xref tables used to resolve an indirect length.
 * @param num_tables   Count of those tables.
 * @param dict         The object's dictionary bytes.
 * @param dict_len     Length of the dictionary.
 * @param obj_offset   File offset of the object owning the dictionary.
 * @return       The stream length, or LENGTHNOTFOUND if none could be resolved.
 */
int check_last_object_length(char *data, uint64_t length, uint64_t *out_offset,
                              XrefTables *test_tables, int num_tables,
                              const char *dict, int dict_len, uint64_t obj_offset) {
    int64_t object_length = 0;
    int obj_num = -1;
    for(int64_t i = 0; i + 7 <= dict_len; i++){
        if(!memcmp(&dict[i], "/Length", 7) && !isdigit((unsigned char)dict[i + 7])){
            bool is_indirect = is_indirect_object((char*)dict, (uint64_t)dict_len, i + 7, &obj_num);
            if(!is_indirect){
                object_length = extract_int((char*)dict, i + 7, (int64_t)dict_len, NULL);
                *out_offset = obj_offset;
                break;
            }
            uint64_t ref_offset = search_tables_for_object(test_tables, num_tables, obj_num);
            if(ref_offset != 0){
                // Prefer the candidate's OWN assembled data: if the length object is
                // already present (e.g. its block was placed during xref adoption),
                // read it directly. The image-wide scan below is ambiguous -- object
                // numbers repeat across files, so it can match, and read a bogus
                // length from, a FOREIGN object of the same number.
                if(ref_offset < length &&
                   validate_at_offset(data, (int64_t)ref_offset, obj_num, (int64_t)length) == 1){
                    int64_t pos = (int64_t)ref_offset, lim = pos + 40;
                    if(lim > (int64_t)length) lim = (int64_t)length;
                    while(pos + 4 < lim && memcmp(&data[pos], " obj", 4)) pos++;
                    if(pos + 4 < lim)
                        object_length = extract_int(data, pos + 4, (int64_t)length, NULL);
                }
                // Fallback: image-wide scan for the length object.
                if(object_length <= 0){
                    object_length = 0;
                    int64_t obj_block = scan_blocks_for_object(obj_num, ref_offset);
                    if(obj_block != -1){
                        unsigned char *blk_data = (unsigned char*)get_apparent_block_data(scalpel_state.filemirror, obj_block);
                        if(blk_data){
                            uint64_t local_offset = ref_offset % scalpel_state.blocksize;
                            uint64_t pos = local_offset;
                            while(pos + 4 < (uint64_t)scalpel_state.blocksize){
                                if(!memcmp(&blk_data[pos], " obj", 4)){ pos += 4; break; }
                                pos++;
                            }
                            object_length = extract_int((char*)blk_data, (int64_t)pos,
                                                        (int64_t)scalpel_state.blocksize, NULL);
                            free(blk_data);
                        }
                    }
                    // A length must be a positive integer; a foreign or non-length
                    // object yields garbage, so refuse it rather than feeding a bogus
                    // /Length to the stream reconstructor.
                    if(object_length <= 0) object_length = 0;
                }
            }
            *out_offset = obj_offset;
            break;
        }
    }
    if(object_length == 0) return LENGTHNOTFOUND;
    return (int)object_length;
}

/**
 * @description  Identifies a stream object's encoding from its dictionary by
 *               reading /Filter (including the single-element array form) or a
 *               /Subtype of XML.
 * @param dict      The object's dictionary bytes.
 * @param dict_len  Length of the dictionary.
 * @return       ZLIB, JPEG, or XML for a recognised filter, else NOFILTER.
 */
int check_last_object_filter(const char *dict, int dict_len) {
    int offset = 0;
    while (offset < dict_len) {
        if (offset + 7 <= dict_len && !memcmp(&dict[offset], "/Filter", 7)) {
            offset += 7;
            while (offset < dict_len && isspace((unsigned char)dict[offset])) offset++;
            // handle array form: /Filter [/FlateDecode]
            if (offset < dict_len && dict[offset] == '[') {
                offset++;
                while (offset < dict_len && isspace((unsigned char)dict[offset])) offset++;
            }
            if (offset < dict_len && dict[offset] == '/') {
                offset++;
                if (offset + 11 <= dict_len && !memcmp(&dict[offset], "FlateDecode", 11)) return ZLIB;
                if (offset + 9  <= dict_len && !memcmp(&dict[offset], "DCTDecode",   9))  return JPEG;
            }
        } else if (offset + 8 <= dict_len && !memcmp(&dict[offset], "/Subtype", 8)) {
            offset += 8;
            while (offset < dict_len && isspace((unsigned char)dict[offset])) offset++;
            if (offset < dict_len && dict[offset] == '/') {
                offset++;
                if (offset + 3 <= dict_len && !memcmp(&dict[offset], "XML", 3)) return XML;
            }
        } else {
            offset++;
        }
    }
    return NOFILTER;
}

/**
 * @description  Locates the "stream" keyword after an object and, from the stream
 *               length, computes the block-local offsets of the stream start and
 *               endstream and how many blocks past the candidate the stream reaches,
 *               classifying the stream's extent.
 * @param data                          The candidate buffer.
 * @param object_length                 The stream's data length.
 * @param length                        Length of the candidate so far.
 * @param offset                        Offset to begin the "stream" search from.
 * @param out_startstream_local_offset  Out: block-local offset of the stream start.
 * @param out_endstream_local_offset    Out: block-local offset of endstream.
 * @param out_blocks_to_extend          Out: blocks past the candidate the stream spans.
 * @return       INBLOCK, INNEXTBLOCK, or MULTIBLOCK by extent, or LENGTHNOTFOUND
 *               if no stream keyword is found.
 */
int calculate_stream_offsets(char *data, uint64_t object_length,
                            uint64_t length,
                            uint64_t offset,
                            int32_t *out_startstream_local_offset,
                            int32_t *out_endstream_local_offset,
                            int *out_blocks_to_extend){
    // Find the stream keyword to get its file-relative offset
    uint64_t stream_file_offset = 0;
    for(; offset + 6 < length; offset++){
        if(!memcmp(&data[offset], "stream", 6)){
            // Make sure this isn't "endstream"
            if(offset >= 3 && !memcmp(&data[offset-3], "end", 3)) continue;
            stream_file_offset = offset + 6;
            if(data[stream_file_offset] == '\r') stream_file_offset++;
            if(data[stream_file_offset] == '\n') stream_file_offset++;
            break;
        }
    }
    if(stream_file_offset == 0) return LENGTHNOTFOUND;

    // Compute endstream file-relative offset using the stream data length
    uint64_t endstream_file_offset = stream_file_offset + object_length;

    // Compute block-relative offset of endstream
    *out_endstream_local_offset = endstream_file_offset % scalpel_state.blocksize;

    // Compute block-relative offset of stream start (for reassembler init)
    *out_startstream_local_offset = stream_file_offset % scalpel_state.blocksize;

    uint32_t last_candidate_block = (uint32_t)((length - 1) / scalpel_state.blocksize);
    uint32_t endstream_block = endstream_file_offset / scalpel_state.blocksize;
    *out_blocks_to_extend = endstream_block - last_candidate_block;

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
    if((int64_t)object_length < length_in_candidate) return INBLOCK;

    // This stream only extends into the next block
    else if((int64_t)object_length < length_in_candidate + (int64_t)scalpel_state.blocksize) return INNEXTBLOCK;

    // This stream extends into the next 2 blocks at the least
    return MULTIBLOCK;
}

/**
 * @description  Initialises a zlib stream reassembler and inflates the stream's
 *               first block from stream_offset (capped at /Length), recording an
 *               inflate checkpoint that later blocks are tried against.
 * @param r             The reassembler to initialise.
 * @param first_block   The block holding the stream start.
 * @param block_size    Size of a block.
 * @param stream_offset Block-local offset where the stream data begins.
 * @param stream_length The declared /Length, or 0 if unknown.
 * @return       0 on success, -1 on allocation or inflate-init failure.
 */
int zlib_stream_reassembler_init(ZlibStreamReassembler *r, const unsigned char *first_block,
                     size_t block_size, size_t stream_offset, size_t stream_length) {
    memset(r, 0, sizeof(*r));
    r->stream_length = stream_length;

    r->output_capacity = 1024 * 1024;
    r->output = malloc(r->output_capacity);
    if (!r->output) return -1;

    if (inflateInit2(&r->strm, 15) != Z_OK) {
        free(r->output);
        r->output = NULL;
        return -1;
    }

    // Start decompression from where the actual stream data begins
    unsigned char tmp[scalpel_state.blocksize];
    size_t avail = (stream_offset < block_size) ? (block_size - stream_offset) : 0;
    if (stream_length && avail > stream_length) avail = stream_length;   // stop at /Length
    r->strm.next_in  = (Bytef *)(first_block + stream_offset);
    r->strm.avail_in = avail;
    r->fed = avail;

        do {
        r->strm.next_out  = tmp;
        r->strm.avail_out = sizeof(tmp);
        int ret = inflate(&r->strm, Z_NO_FLUSH);
        if (ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
            inflateEnd(&r->strm);
            free(r->output);
            r->output = NULL;
            return -1;
        }

        size_t produced = sizeof(tmp) - r->strm.avail_out;
        if (r->output_len + produced > r->output_capacity) {
            r->output_capacity *= 2;
            unsigned char *t = realloc(r->output, r->output_capacity);
            if (!t) { inflateEnd(&r->strm); free(r->output); r->output = NULL; return -1; }
            r->output = t;
        }
        memcpy(r->output + r->output_len, tmp, produced);
        r->output_len += produced;

    } while (r->strm.avail_out == 0);

    // Snapshot this as our first checkpoint
    if (inflateCopy(&r->checkpoint, &r->strm) != Z_OK) {
        inflateEnd(&r->strm);
        free(r->output);
        r->output = NULL;
        return -1;
    }

    r->total_verified = r->output_len;
    return 0;
}

/**
 * @description  Tries one block as the next in a zlib stream: inflates it (never
 *               past /Length) and, on success, advances the checkpoint. A block
 *               that fails to inflate, or that exhausts /Length without reaching
 *               Z_STREAM_END (where the Adler-32 checksum is verified), is rolled
 *               back to the last checkpoint.
 * @param r           The reassembler.
 * @param block       The candidate next block.
 * @param block_size  Size of the block.
 * @return       2 if the stream is now complete, 1 if the block was accepted,
 *               0 if rejected (rolled back), -1 on allocation error.
 */
int zlib_stream_reassembler_try_block(ZlibStreamReassembler *r, const unsigned char *block, size_t block_size) {
    unsigned char tmp[scalpel_state.blocksize];

    // Save state so a rejected block can be rolled back
    size_t saved_output_len = r->output_len;
    size_t saved_fed        = r->fed;

    if (r->ended) return 2;                     // already complete

    // Never consume past the declared /Length: the compressed data ends there
    // and everything after belongs to the next object. This alone rejects a
    // final block that would overrun.
    size_t take = block_size;
    if (r->stream_length) {
        size_t remaining = (r->fed < r->stream_length) ? (r->stream_length - r->fed) : 0;
        if (remaining == 0) return 0;
        if (take > remaining) take = remaining;
    }

    // Work on the live state (which equals checkpoint at this point)
    r->strm.next_in  = (Bytef *)block;
    r->strm.avail_in = take;

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
            r->fed        = saved_fed;
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

    r->fed += take - r->strm.avail_in;          // bytes actually consumed

    /*
     * Completion gate. Once the declared /Length has been consumed the stream
     * MUST have terminated: Z_STREAM_END is where zlib verifies the Adler-32
     * checksum over the entire decompressed output, and that checksum is the
     * only redundancy DEFLATE retains. Reaching the end of the data without it
     * proves the assembled block sequence is wrong, even though every
     * individual block decoded without error.
     */
    if (r->stream_length && r->fed >= r->stream_length && !stream_ended) {
        inflateEnd(&r->strm);
        inflateCopy(&r->strm, &r->checkpoint);
        r->output_len = saved_output_len;
        r->fed        = saved_fed;
        return 0;
    }

    // ACCEPT: update checkpoint to include this block
    inflateEnd(&r->checkpoint);
    if (inflateCopy(&r->checkpoint, &r->strm) != Z_OK) return -1;
    r->total_verified = r->output_len;
    r->ended = stream_ended;

    return stream_ended ? 2 : 1;  // 2 means stream is complete
}

/**
 * @description  Releases a zlib reassembler's inflate state, checkpoint, and
 *               output buffer.
 * @param r  The reassembler to free.
 * @return       Void.
 */
void zlib_stream_reassembler_free(ZlibStreamReassembler *r) {
    inflateEnd(&r->strm);
    inflateEnd(&r->checkpoint);
    free(r->output);
}

/**
 * @description  Scans backward from the end of the buffer for the last "obj"
 *               keyword that stands as a whitespace-delimited token.
 * @param data    The buffer to scan.
 * @param length  Length of the buffer.
 * @return       The offset of the 'o' in "obj", or -1 if none is found.
 */
int64_t find_last_object(const char *data, uint64_t length) {
    if (length < 3) return -1;
    ptrdiff_t scan = (ptrdiff_t)length - 1;
    while (scan >= 2) {
        if (data[scan-2] == 'o' && data[scan-1] == 'b' && data[scan] == 'j') {
            bool pre_ok  = (scan < 3) || isspace((unsigned char)data[scan-3]);
            bool post_ok = ((uint64_t)(scan+1) >= length) || isspace((unsigned char)data[scan+1]);
            if (pre_ok && post_ok) return (int64_t)(scan - 2);
        }
        scan--;
    }
    return -1;
}

/**
 * @description  Extracts a complete object dictionary starting from the '<<' after
 *               obj_offset, balancing nested dicts, hex strings, string literals,
 *               and comments. If the dict crosses the current block boundary, pulls
 *               the next apparent block and, when that closes the dict, adds it to
 *               the candidate before returning the combined bytes.
 * @param work        The thread work context.
 * @param candidate   The candidate (extended if a trailing block completes the dict).
 * @param data        The candidate buffer.
 * @param length      Length of the buffer.
 * @param obj_offset  Offset of the object whose dictionary is extracted.
 * @param out_len     Out: length of the returned dictionary.
 * @return       A malloc'd null-terminated dictionary buffer (caller frees), or NULL.
 */
char *extract_dict(ThreadWork *work, CarveInfo *candidate,
                   const char *data, uint64_t length,
                   uint64_t obj_offset, int *out_len) {
    // Scan forward from obj_offset to the opening '<<'
    uint64_t i = obj_offset;
    while (i + 1 < length && !(data[i] == '<' && data[i+1] == '<')) i++;
    if (i + 1 >= length) return NULL;

    uint64_t dict_start = i;
    int depth = 0;

    while (i < length) {
        char c = data[i];
        if (c == '<' && i + 1 < length && data[i+1] == '<') {
            depth++; i += 2;
        } else if (c == '>' && i + 1 < length && data[i+1] == '>') {
            depth--; i += 2;
            if (depth == 0) {
                uint64_t dict_len = i - dict_start;
                char *result = malloc(dict_len + 1);
                if (!result) return NULL;
                memcpy(result, data + dict_start, dict_len);
                result[dict_len] = '\0';
                *out_len = (int)dict_len;
                return result;
            }
        } else if (c == '<') {
            i++;
            while (i < length && data[i] != '>') i++;
            if (i < length) i++;
        } else if (c == '(') {
            i++;
            int paren_depth = 1;
            while (i < length && paren_depth > 0) {
                if (data[i] == '\\')       i += 2;
                else if (data[i] == '(') { paren_depth++; i++; }
                else if (data[i] == ')') { paren_depth--; i++; }
                else i++;
            }
        } else if (c == '%') {
            while (i < length && data[i] != '\n' && data[i] != '\r') i++;
        } else {
            i++;
        }
    }

    // Dict not closed within current data — try the next apparent block
    if (!work || !candidate) return NULL;
    uint64_t last_apparent = blockvector_get_apparent_blocknumber(candidate->b,
        blockvector_get_num_blocks(candidate->b) - 1);
    const char *next_block = (const char*)get_apparent_block_data(
        scalpel_state.filemirror, last_apparent + 1);
    if (!next_block) return NULL;

    uint64_t j = 0;
    while (j < (uint64_t)scalpel_state.blocksize) {
        char c = next_block[j];
        if (c == '<' && j + 1 < (uint64_t)scalpel_state.blocksize && next_block[j+1] == '<') {
            depth++; j += 2;
        } else if (c == '>' && j + 1 < (uint64_t)scalpel_state.blocksize && next_block[j+1] == '>') {
            depth--; j += 2;
            if (depth == 0) {
                if (!pdf_block_matches_xref_slot(candidate, (int64_t)(last_apparent + 1),
                                                 blockvector_get_num_blocks(candidate->b))) {
                    free((void*)next_block);
                    return NULL;
                }
                candidate->newblock = filemirror_actual_blocknumber(
                    scalpel_state.filemirror, last_apparent + 1);
                pdf_reassembly_prepare_for_extension(work->id, candidate, 1, OBJECTEXTNSION);
                PDF_PLACE(work->id, candidate, blockvector_get_num_blocks(candidate->b) - 1, "DICT_CROSS", (int64_t)(last_apparent + 1), (int64_t)j);

                uint64_t part1 = length - dict_start;
                uint64_t dict_len = part1 + j;
                char *result = malloc(dict_len + 1);
                if (result) {
                    memcpy(result, data + dict_start, part1);
                    memcpy(result + part1, next_block, j);
                    result[dict_len] = '\0';
                    *out_len = (int)dict_len;
                }
                free((void*)next_block);
                return result;
            }
        } else if (c == '<') {
            j++;
            while (j < (uint64_t)scalpel_state.blocksize && next_block[j] != '>') j++;
            if (j < (uint64_t)scalpel_state.blocksize) j++;
        } else if (c == '(') {
            j++;
            int paren_depth = 1;
            while (j < (uint64_t)scalpel_state.blocksize && paren_depth > 0) {
                if (next_block[j] == '\\')       j += 2;
                else if (next_block[j] == '(') { paren_depth++; j++; }
                else if (next_block[j] == ')') { paren_depth--; j++; }
                else j++;
            }
        } else if (c == '%') {
            while (j < (uint64_t)scalpel_state.blocksize && next_block[j] != '\n' && next_block[j] != '\r') j++;
        } else {
            j++;
        }
    }

    free((void*)next_block);
    return NULL;
}

/**
 * @description  Reassembles a FlateDecode stream onto the candidate. Dispatches on
 *               mode: INBLOCK needs no extension; INNEXTBLOCK tries a contiguous
 *               fast-path then a search; MULTIBLOCK runs a deferred-commit split
 *               search that tries block sequences and commits only when inflate
 *               reaches Z_STREAM_END, so the Adler-32 checksum validates the whole
 *               stream before any block is kept.
 * @param work                     The thread work context.
 * @param candidate                The candidate being extended.
 * @param first_stream_block_data  The block holding the stream start.
 * @param startstream_local_offset Block-local offset where the stream data begins.
 * @param endstream_local_offset   Block-local offset expected for endstream.
 * @param blocks_to_extend         Blocks past the candidate the stream spans.
 * @param stream_length            The declared /Length.
 * @param mode                     INBLOCK, INNEXTBLOCK, or MULTIBLOCK.
 * @return       true if the stream was fully reassembled and committed, else false.
 */
bool reconstruct_zlib_stream(ThreadWork *work, CarveInfo *candidate,
    const char *first_stream_block_data,
    int32_t startstream_local_offset,
    int32_t endstream_local_offset,
    int blocks_to_extend,
    uint64_t stream_length,
    int mode)
{
    uint64_t streamstart_block_app = blockvector_get_apparent_blocknumber(candidate->b,
        blockvector_get_num_blocks(candidate->b) - 1);


    if (mode == INNEXTBLOCK) {
        // Fast path: the next block is usually the apparent-contiguous one. Read it
        // directly, bypassing the coverage-limited blockvector_get_choice, and accept
        // only on completion (stream_check == 2) where zlib verifies the Adler-32, so
        // a wrong block cannot pass. A fragmented stream fails here and the coverage-
        // aware search below still runs.
        int64_t contig = (int64_t)streamstart_block_app + 1;
        if (contig < (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror)) {
            ZlibStreamReassembler rc;
            if (zlib_stream_reassembler_init(&rc, (const unsigned char*)first_stream_block_data,
                    scalpel_state.blocksize, startstream_local_offset, (size_t)stream_length) != -1) {
                const unsigned char *cb =
                    (const unsigned char*)get_apparent_block_data(scalpel_state.filemirror, contig);
                int chk = cb ? zlib_stream_reassembler_try_block(&rc, cb, scalpel_state.blocksize) : 0;
                free((void*)cb);
                zlib_stream_reassembler_free(&rc);
                if (chk == 2) {
                    candidate->newblock = filemirror_actual_blocknumber(scalpel_state.filemirror, contig);
                    pdf_reassembly_prepare_for_extension(work->id, candidate, 1, OBJECTEXTNSION);
                    PDF_PLACE(work->id, candidate, blockvector_get_num_blocks(candidate->b) - 1, "ZLIB_NEXT_CONTIG", contig, chk);
                    return true;
                }
            }
        }

        BlockVector *scan_bv = NULL;
        uint64_t evaluated;
        init_blockvector(scalpel_state.filemirror, &scan_bv, 1, false);
        inflate_blockvector(scan_bv);
        int64_t block_choice = blockvector_get_choice(scan_bv, 0, streamstart_block_app + 1, -1, &evaluated);
        free_blockvector(&scan_bv);
        if (block_choice == -1) return false;

        ZlibStreamReassembler r;
        if (zlib_stream_reassembler_init(&r, (const unsigned char*)first_stream_block_data,
                scalpel_state.blocksize, startstream_local_offset, (size_t)stream_length) == -1)
            return false;

        const unsigned char *stream_block =
            (const unsigned char*)get_apparent_block_data(scalpel_state.filemirror, block_choice);
        int stream_check = zlib_stream_reassembler_try_block(&r, stream_block, scalpel_state.blocksize);
        // Accept a block that validly continues (1) OR completes (2) the stream.
        // A small object stream that ends in this next block returns 2
        // (Z_STREAM_END); rejecting it (accepting only 1) discarded the
        // header-anchored reconstruction, defeating header discrimination.
        if (stream_check == 1 || stream_check == 2) {
            candidate->newblock = filemirror_actual_blocknumber(scalpel_state.filemirror, block_choice);
            pdf_reassembly_prepare_for_extension(work->id, candidate, 1, OBJECTEXTNSION);
            PDF_PLACE(work->id, candidate, blockvector_get_num_blocks(candidate->b) - 1, "ZLIB_NEXT", block_choice, stream_check);
        } else {
            free((void*)stream_block);
            block_choice = pdf_reassembly_get_block_choice(candidate, -1, endstream_local_offset, 0, 0, -1, FINDENDSTREAM, \
            (int64_t)blockvector_get_num_blocks(candidate->b));
            if (block_choice == -1) {
                zlib_stream_reassembler_free(&r);
                return false;
            }
            stream_block = (const unsigned char*)get_apparent_block_data(scalpel_state.filemirror, block_choice);
            stream_check = zlib_stream_reassembler_try_block(&r, stream_block, scalpel_state.blocksize);
            if (stream_check == 1 || stream_check == 2) {
                candidate->newblock = filemirror_actual_blocknumber(scalpel_state.filemirror, block_choice);
                pdf_reassembly_prepare_for_extension(work->id, candidate, 1, OBJECTEXTNSION);
                PDF_PLACE(work->id, candidate, blockvector_get_num_blocks(candidate->b) - 1, "ZLIB_NEXT_ES", block_choice, stream_check);
            }
        }
        zlib_stream_reassembler_free(&r);
        free((void*)stream_block);
        return true;
    }

    if (mode == MULTIBLOCK) {
        /*
         * Reconstruct the interior of a multi-block zlib stream by searching for
         * the fragment-switch point, using stream completion (the Adler-32 at
         * Z_STREAM_END) as the oracle and committing nothing until it verifies.
         * DEFLATE has no local check to test a single block against, so the only
         * sound question is the global one -- does this whole assignment complete?
         * -- asked once per candidate split. The stream is assumed to occupy at
         * most two fragments.
         */
        if (blocks_to_extend <= 0) return false;
        const int64_t tot_app = (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror);

        // Endstream-block candidates, tried in order: the contiguous position
        // first (streams are usually contiguous, and content-only FINDENDSTREAM
        // often matches "endstream" coincidentally in a foreign block), then
        // FINDENDSTREAM as the fallback for tails in another fragment.
        int64_t es_cands[2];
        int n_es = 0;
        int64_t contig_es = (int64_t)streamstart_block_app + blocks_to_extend;
        if (contig_es >= 0 && contig_es < tot_app) es_cands[n_es++] = contig_es;
        int64_t findes = pdf_reassembly_get_block_choice(candidate, -1, endstream_local_offset, 0, 0, -1, FINDENDSTREAM,
            (int64_t)blockvector_get_num_blocks(candidate->b) + (int64_t)blocks_to_extend - 1);
        if (findes >= 0 && findes < tot_app && findes != contig_es) es_cands[n_es++] = findes;
        if (n_es == 0) return false;

        const uint64_t nb_before   = blockvector_get_num_blocks(candidate->b);
        const int      n_interior  = blocks_to_extend - 1;   // last slot is the endstream block
        const int      MAX_SPLITS  = 64;                     // bound the search cost

        int64_t *chosen = (int64_t*)malloc(sizeof(int64_t) * (size_t)blocks_to_extend);
        if (!chosen) return false;

        bool solved = false;
        uint64_t endstream_block_apparent = (uint64_t)es_cands[0];
        for (int ei = 0; ei < n_es && !solved; ei++) {
            endstream_block_apparent = (uint64_t)es_cands[ei];
            int tried = 0;
            for (int m = n_interior; m >= 0 && !solved && tried < MAX_SPLITS; m--, tried++) {
                ZlibStreamReassembler r;
                if (zlib_stream_reassembler_init(&r, (const unsigned char*)first_stream_block_data,
                        scalpel_state.blocksize, startstream_local_offset, (size_t)stream_length) == -1)
                    break;                                    // stream start itself is unusable

                bool ok = true;
                for (int i = 1; i <= n_interior && ok; i++) {
                    // interior block i comes from the forward run while i <= m,
                    // and from the run ending at the endstream anchor thereafter
                    int64_t app = (i <= m) ? (int64_t)streamstart_block_app + i
                                           : (int64_t)endstream_block_apparent - (blocks_to_extend - i);
                    if (app < 0 || app >= tot_app) { ok = false; break; }
                    const unsigned char *blk =
                        (const unsigned char*)get_apparent_block_data(scalpel_state.filemirror, app);
                    if (!blk) { ok = false; break; }
                    int chk = zlib_stream_reassembler_try_block(&r, blk, scalpel_state.blocksize);
                    free((void*)blk);
                    if (chk != 1 && chk != 2) { ok = false; break; }
                    chosen[i-1] = app;
                }

                // The endstream block carries the stream's tail; feed it unless
                // the declared length already ran out on a block boundary.
                if (ok && !r.ended) {
                    const unsigned char *blk =
                        (const unsigned char*)get_apparent_block_data(scalpel_state.filemirror, endstream_block_apparent);
                    if (!blk) ok = false;
                    else {
                        int chk = zlib_stream_reassembler_try_block(&r, blk, scalpel_state.blocksize);
                        free((void*)blk);
                        if (chk != 2) ok = false;             // must COMPLETE here
                    }
                }
                chosen[blocks_to_extend-1] = (int64_t)endstream_block_apparent;

                // Accept only on Z_STREAM_END: that is where Adler-32 is verified
                // over the entire decompressed output.
                solved = ok && r.ended;
                zlib_stream_reassembler_free(&r);
            }
        }

        if (!solved) {
#ifdef PDF_TRACE_STALL
            lock_fprintf(stdout, "[PDFZMB] split-search UNSOLVED streamstart=%" PRIu64 " contig_es=%" PRId64 " findes=%" PRId64 " bte=%d\n", streamstart_block_app, contig_es, findes, blocks_to_extend);
#endif
            free(chosen); return false;
        }

        // Split verified: grow the candidate and place the whole run.
        pdf_reassembly_prepare_for_extension(work->id, candidate, blocks_to_extend, ENDSTREAMEXTENSION);
        for (int i = 0; i < blocks_to_extend; i++) {
            uint64_t slot = nb_before + (uint64_t)i;
            if (!pdf_block_matches_xref_slot(candidate, chosen[i], slot)) continue;
            candidate->newblock = filemirror_actual_blocknumber(scalpel_state.filemirror, chosen[i]);
            PDF_PLACE(work->id, candidate, slot,
                      (i == blocks_to_extend-1) ? "ZLIB_MB_ANCHOR" : "ZLIB_MB_START",
                      chosen[i], i);
        }
        free(chosen);
        return true;
    }

    return true;
}

/**
 * @description             Reconstruct an unfiltered stream (/Length, no /Filter).
 *                          Such streams have no decoder to validate blocks, so
 *                          this tests one verifiable hypothesis -- the stream is
 *                          disk-contiguous -- confirmed by its two endpoints (the
 *                          "endstream" keyword at the /Length-predicted offset and
 *                          a non-vacuous xref cross-check on the end block). On
 *                          failure the interior is left as holes (PROMISING).
 *                          Weaker than the decoder paths by nature; leans on those
 *                          two endpoints plus the whole-file validator.
 *
 * @param work              The reassembly thread work item.
 * @param candidate         The candidate being extended.
 * @param endstream_local_offset  Expected block-local offset of "endstream".
 * @param blocks_to_extend  Number of blocks the stream spans past the frontier.
 * @param mode              Only MULTIBLOCK is handled here.
 *
 * @return                  true on success or nothing-to-do; false to abandon.
 */
bool reconstruct_raw_stream(ThreadWork *work, CarveInfo *candidate,
    int32_t endstream_local_offset,
    int blocks_to_extend,
    int mode)
{
    if (mode != MULTIBLOCK || blocks_to_extend <= 0) return true;

    uint64_t streamstart_block_app = blockvector_get_apparent_blocknumber(candidate->b,
        blockvector_get_num_blocks(candidate->b) - 1);
#ifdef PDF_TRACE_PLACEMENT
    {
        // The stream extent here is derived from the CANDIDATE's bytes. If the
        // candidate is already wrong, this describes a stream that does not
        // exist -- log it so that can be checked against ground truth.
        uuid_string_t uu; uuid_unparse_lower(candidate->binuuid, uu);
        lock_fprintf(stdout,
            "[PDFRAW] uuid=%.8s first_slot=%" PRIu64 " bte=%d endstream_local=%d\n",
            uu, blockvector_get_num_blocks(candidate->b), blocks_to_extend, endstream_local_offset);
    }
#endif

    // Hypothesis: the stream is disk-contiguous, so its blocks are streamstart+1
    // .. streamstart+blocks_to_extend. Confirmed by the two endpoints below; if
    // either fails the stream is fragmented (unverifiable without a checksum) and
    // the interior is left as holes.
    const uint64_t nb0   = blockvector_get_num_blocks(candidate->b);
    const int64_t  total = (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror);

    // The contiguous hypothesis: interior + end blocks are streamstart+1 ..
    // streamstart+blocks_to_extend.
    uint64_t endstream_app = streamstart_block_app + (uint64_t)blocks_to_extend;
    if ((int64_t)endstream_app >= total) return false;   // runs off the image

    // (1) Confirm "endstream" sits at its predicted offset in the contiguous
    // end block (handling the case where the keyword straddles the boundary
    // into the next contiguous block).
    bool endstream_ok = false;
    char *eblk = (char*)get_apparent_block_data(scalpel_state.filemirror, endstream_app);
    if (eblk) {
        int32_t off = endstream_local_offset;
        while (off < (int32_t)scalpel_state.blocksize && isspace((unsigned char)eblk[off])) off++;
        if (off >= 0 && off + 9 <= (int32_t)scalpel_state.blocksize) {
            endstream_ok = !memcmp(&eblk[off], "endstream", 9);
        } else if (off >= 0 && (int64_t)endstream_app + 1 < total) {
            char *nblk = (char*)get_apparent_block_data(scalpel_state.filemirror, endstream_app + 1);
            if (nblk) {
                char win[9]; int j = 0;
                for (int i = off; i < (int)scalpel_state.blocksize && j < 9; i++, j++) win[j] = eblk[i];
                for (int i = 0; j < 9; i++, j++) win[j] = nblk[i];
                endstream_ok = !memcmp(win, "endstream", 9);
                free(nblk);
            }
        }
        free(eblk);
    }
    if (!endstream_ok) return false;             // not contiguous -- leave holes

    // (2) Confirm the next object anchors in that end block. A raw stream has no
    // checksum, so this cross-check is the only defence against a foreign run that
    // carries "endstream" at the predicted offset -- and it must be non-vacuous: if
    // the xref places no object in the endstream slot, endpoint (1) alone
    // (~1/blocksize) is not enough to trust an unchecksummed fill, so leave holes.
    uint64_t es_slot = nb0 + (uint64_t)blocks_to_extend - 1;
    if (pdf_xref_slot_object_count(candidate, es_slot) == 0)
        return false;                            // no object anchors the tail -- cannot verify a raw fill
    if (!pdf_block_matches_xref_slot(candidate, (int64_t)endstream_app, es_slot))
        return false;                            // end block's objects don't match -- leave holes

    // Both endpoints verified: fill the contiguous run.
    pdf_reassembly_prepare_for_extension(work->id, candidate, blocks_to_extend, ENDSTREAMEXTENSION);
    for (int k = 1; k <= blocks_to_extend; k++) {
        uint64_t app  = streamstart_block_app + (uint64_t)k;
        uint64_t slot = nb0 + (uint64_t)k - 1;
        candidate->newblock = filemirror_actual_blocknumber(scalpel_state.filemirror, app);
        PDF_PLACE(work->id, candidate, slot, "RAW_MB_CONTIG", (int64_t)app, blocks_to_extend);
    }
    return true;
}

/**
 * @description  Feeds one stream byte through the XML structural state machine,
 *               setting r->malformed on a text-gate or structural violation. Tracks
 *               element nesting depth and self-closing tags, and treats quoted
 *               attribute values, processing instructions, comments, CDATA, and
 *               declarations as opaque so '<'/'>' inside them are not read as tag
 *               delimiters.
 * @param r  The XML reassembler state.
 * @param c  The next stream byte.
 * @return       Void.
 */
static inline void xml_feed_byte(XmlStreamReassembler *r, unsigned char c) {
    if (r->malformed) return;

    // Text gate: XMP is printable UTF-8 text. Reject NUL, C0 controls (except
    // TAB/CR/LF) and DEL. Bytes >= 0x80 are allowed as UTF-8 continuation/lead.
    if (c == 0x00 || c == 0x7f || (c < 0x20 && c != '\t' && c != '\n' && c != '\r')) {
        r->malformed = 1;
        return;
    }

    switch (r->state) {
        case X_TEXT:
            if (c == '<') { r->state = X_OPEN; r->just_opened = 1; r->prev_slash = 0; }
            else if (c == '>') { r->malformed = 1; }   // stray '>' outside a tag
            break;

        case X_OPEN:
            if (r->just_opened) {
                r->just_opened = 0;
                if (c == '/') { r->state = X_CLOSE; break; }   // </name>
                if (c == '?') { r->state = X_PI;    break; }   // <? ... ?>
                if (c == '!') { r->state = X_BANG;  break; }   // <!-- / <![CDATA[ / <!DOCTYPE
                // otherwise an opening element name; fall through
            }
            if (r->quote) {
                // Inside a quoted attribute value: only the matching quote ends
                // it, so '<' and '>' here are data, not tag delimiters.
                if (c == r->quote) r->quote = 0;
                r->prev_slash = 0;                             // nothing in a quote is a trailing '/'
            } else if (c == '"' || c == '\'') {
                r->quote = c;                                  // start of an attribute value
                r->prev_slash = 0;
            } else if (c == '>') {
                if (!r->prev_slash) r->tag_depth++;            // <name ...> (not "/>")
                r->state = X_TEXT;
                r->prev_slash = 0;
            } else if (c == '<') {
                r->malformed = 1;                              // '<' inside a tag
            } else {
                r->prev_slash = (c == '/');
            }
            break;

        case X_CLOSE:
            if (c == '>') {
                r->tag_depth--;
                if (r->tag_depth < 0) r->malformed = 1;        // closed more than opened
                r->state = X_TEXT;
            } else if (c == '<') {
                r->malformed = 1;
            }
            break;

        case X_PI:
            if (c == '>' && r->prev_q) { r->state = X_TEXT; r->prev_q = 0; }
            else r->prev_q = (c == '?');
            break;

        case X_DECL:
            if (c == '>') r->state = X_TEXT;
            break;

        case X_BANG:
            // Just consumed "<!". Distinguish a comment, a CDATA section, or a
            // generic declaration (e.g. DOCTYPE) that simply ends on '>'.
            if (c == '-')      { r->state = X_BANG2; }                   // maybe "<!--"
            else if (c == '[') { r->state = X_CDATA; r->marker_run = 0; } // "<![CDATA[ ..."
            else               { r->state = X_DECL; }                    // "<!DOCTYPE ...>"
            break;

        case X_BANG2:
            // Consumed "<!-"; a comment requires a second '-'.
            if (c == '-') { r->state = X_COMMENT; r->marker_run = 0; }
            else          { r->state = X_DECL; }                         // not a comment
            break;

        case X_COMMENT:
            // Scan to "-->". Content (including '<' and '>') is not markup.
            if (c == '-') { if (r->marker_run < 2) r->marker_run++; }
            else if (c == '>' && r->marker_run >= 2) { r->state = X_TEXT; r->marker_run = 0; }
            else { r->marker_run = 0; }
            break;

        case X_CDATA:
            // Scan to "]]>". Content is character data, not markup.
            if (c == ']') { if (r->marker_run < 2) r->marker_run++; }
            else if (c == '>' && r->marker_run >= 2) { r->state = X_TEXT; r->marker_run = 0; }
            else { r->marker_run = 0; }
            break;
    }
}

/**
 * @description  Whether the assembled stream carries an XMP/XML metadata signature
 *               ("<?xpacket", "<x:xmpmeta", "<rdf:RDF", or a generic "<?xml"). Gates
 *               completion so balanced-but-non-XML garbage is rejected.
 * @param buf   The assembled stream bytes.
 * @param len   Length of the buffer.
 * @return       true if any recognised signature is present.
 */
static inline bool xml_has_signature(const unsigned char *buf, size_t len) {
    static const char *sigs[] = { "<?xpacket", "<x:xmpmeta", "<rdf:RDF", "<?xml" };
    for (size_t s = 0; s < sizeof(sigs) / sizeof(sigs[0]); s++) {
        size_t sl = strlen(sigs[s]);
        if (sl > len) continue;
        for (size_t i = 0; i + sl <= len; i++) {
            if (!memcmp(buf + i, sigs[s], sl)) return true;
        }
    }
    return false;
}

/**
 * @description  Initialises an XML stream reassembler and feeds the stream data in
 *               the first block (capped at /Length) through the state machine,
 *               failing if that header portion is already non-text or malformed.
 * @param r             The reassembler to initialise.
 * @param first_block   The block holding the stream start.
 * @param block_size    Size of a block.
 * @param stream_offset Block-local offset where the stream data begins.
 * @param stream_length The declared /Length.
 * @return       0 on success, -1 on allocation failure or malformed header.
 */
int xml_stream_reassembler_init(XmlStreamReassembler *r, const unsigned char *first_block,
                     size_t block_size, size_t stream_offset, size_t stream_length) {
    memset(r, 0, sizeof(*r));
    r->stream_length = stream_length;
    r->state = X_TEXT;

    r->output_capacity = stream_length + block_size + 1;
    r->output = malloc(r->output_capacity);
    if (!r->output) return -1;

    // Consume the portion of the first block that is actual stream data,
    // capped at the exact stream length.
    size_t avail = (stream_offset < block_size) ? (block_size - stream_offset) : 0;
    size_t take  = (avail < stream_length) ? avail : stream_length;
    for (size_t i = 0; i < take; i++) {
        unsigned char c = first_block[stream_offset + i];
        xml_feed_byte(r, c);
        r->output[r->output_len++] = c;
    }
    r->fed = take;

    // The first block holds the xpacket header; if it is already non-text or
    // structurally broken this is not a valid metadata stream.
    if (r->malformed) { free(r->output); r->output = NULL; return -1; }
    return 0;
}

/**
 * @description  Tries one block as the next in an XML stream: feeds its bytes
 *               (never past /Length) through the state machine, rolling back on any
 *               malformation. On reaching /Length, requires balanced tags and an
 *               XMP/XML signature to accept completion.
 * @param r           The reassembler.
 * @param block       The candidate next block.
 * @param block_size  Size of the block.
 * @return       2 if the stream is now complete, 1 if the block was accepted with
 *               more needed, 0 if rejected (rolled back).
 */
int xml_stream_reassembler_try_block(XmlStreamReassembler *r, const unsigned char *block, size_t block_size) {
    // Snapshot for rollback. A by-value struct copy is safe because init()
    // preallocated the whole output, so r->output never reallocs mid-feed; only
    // output_len advances, and every scan-state field is rolled back with it.
    XmlStreamReassembler snap = *r;

    size_t remaining = (r->fed < r->stream_length) ? (r->stream_length - r->fed) : 0;
    size_t take = (block_size < remaining) ? block_size : remaining;

    for (size_t i = 0; i < take; i++) {
        xml_feed_byte(r, block[i]);
        if (r->malformed) { *r = snap; return 0; }   // REJECT: roll back
        r->output[r->output_len++] = block[i];
    }
    r->fed += take;

    if (r->fed >= r->stream_length) {
        // Completion: the full /Length is accounted for. Require balanced tags,
        // not mid-tag, and a recognizable XMP/XML signature.
        if (r->state == X_TEXT && r->tag_depth == 0 &&
            xml_has_signature(r->output, r->output_len)) {
            return 2;
        }
        *r = snap;
        return 0;
    }
    return 1;   // accepted; more blocks needed
}

/**
 * @description  Releases an XML reassembler's output buffer.
 * @param r  The reassembler to free.
 * @return       Void.
 */
void xml_stream_reassembler_free(XmlStreamReassembler *r) {
    free(r->output);
    r->output = NULL;
}

/**
 * @description  Reassembles an uncompressed XML/XMP metadata stream. Mirrors
 *               reconstruct_zlib_stream's block-selection control flow but swaps the
 *               inflate validator for the text/structure validator, driven by the
 *               exact stream_length; completion requires balanced tags and an
 *               XMP/XML signature.
 * @param work                     The thread work context.
 * @param candidate                The candidate being extended.
 * @param first_stream_block_data  The block holding the stream start.
 * @param startstream_local_offset Block-local offset where the stream data begins.
 * @param endstream_local_offset   Block-local offset expected for endstream.
 * @param blocks_to_extend         Blocks past the candidate the stream spans.
 * @param stream_length            The declared /Length.
 * @param mode                     INBLOCK, INNEXTBLOCK, or MULTIBLOCK.
 * @return       true if the stream was fully reassembled and committed, else false.
 */
bool reconstruct_xml_stream(ThreadWork *work, CarveInfo *candidate,
    const char *first_stream_block_data,
    int32_t startstream_local_offset,
    int32_t endstream_local_offset,
    int blocks_to_extend,
    uint64_t stream_length,
    int mode)
{
    uint64_t streamstart_block_app = blockvector_get_apparent_blocknumber(candidate->b,
        blockvector_get_num_blocks(candidate->b) - 1);

    if (mode == INNEXTBLOCK) {
        BlockVector *scan_bv = NULL;
        uint64_t evaluated;
        init_blockvector(scalpel_state.filemirror, &scan_bv, 1, false);
        inflate_blockvector(scan_bv);
        int64_t block_choice = blockvector_get_choice(scan_bv, 0, streamstart_block_app + 1, -1, &evaluated);
        free_blockvector(&scan_bv);
#ifdef PDF_TRACE_ZSTALL
        lock_fprintf(stdout, "[PDFZ] INNEXTBLOCK streamstart=%" PRIu64 " contig=%" PRIu64
            " get_choice=%" PRId64 " %s\n", streamstart_block_app, streamstart_block_app+1,
            block_choice, (block_choice==(int64_t)streamstart_block_app+1)?"CONTIG":"NOT-CONTIG");
#endif
        if (block_choice == -1) return false;

        XmlStreamReassembler r;
        if (xml_stream_reassembler_init(&r, (const unsigned char*)first_stream_block_data,
                scalpel_state.blocksize, startstream_local_offset, (size_t)stream_length) == -1)
            return false;

        const unsigned char *stream_block =
            (const unsigned char*)get_apparent_block_data(scalpel_state.filemirror, block_choice);
        int stream_check = xml_stream_reassembler_try_block(&r, stream_block, scalpel_state.blocksize);
        if (stream_check == 2) {   // INNEXTBLOCK: the stream must complete in this one block (2), never 1
            candidate->newblock = filemirror_actual_blocknumber(scalpel_state.filemirror, block_choice);
            pdf_reassembly_prepare_for_extension(work->id, candidate, 1, OBJECTEXTNSION);
            PDF_PLACE(work->id, candidate, blockvector_get_num_blocks(candidate->b) - 1, "XML_NEXT", block_choice, stream_check);
        } else {
            free((void*)stream_block);
            block_choice = pdf_reassembly_get_block_choice(candidate, -1, endstream_local_offset, 0, 0, -1, FINDENDSTREAM, \
            (int64_t)blockvector_get_num_blocks(candidate->b));
            if (block_choice == -1) {
                xml_stream_reassembler_free(&r);
                return false;
            }
            stream_block = (const unsigned char*)get_apparent_block_data(scalpel_state.filemirror, block_choice);
            stream_check = xml_stream_reassembler_try_block(&r, stream_block, scalpel_state.blocksize);
            if (stream_check == 2) {   // INNEXTBLOCK: the stream must complete in this one block (2), never 1
                candidate->newblock = filemirror_actual_blocknumber(scalpel_state.filemirror, block_choice);
                pdf_reassembly_prepare_for_extension(work->id, candidate, 1, OBJECTEXTNSION);
                PDF_PLACE(work->id, candidate, blockvector_get_num_blocks(candidate->b) - 1, "XML_NEXT_ES", block_choice, stream_check);
            }
        }
        xml_stream_reassembler_free(&r);
        free((void*)stream_block);
        return true;
    }

    if (mode == MULTIBLOCK) {
        int64_t block_choice = pdf_reassembly_get_block_choice(candidate, -1, endstream_local_offset, 0, 0, -1, FINDENDSTREAM, \
            (int64_t)blockvector_get_num_blocks(candidate->b) + (int64_t)blocks_to_extend - 1);
        uint64_t endstream_block_apparent = (uint64_t)block_choice;
        if (block_choice == -1) return false;

        candidate->newblock = filemirror_actual_blocknumber(scalpel_state.filemirror, block_choice);
        pdf_reassembly_prepare_for_extension(work->id, candidate, blocks_to_extend, ENDSTREAMEXTENSION);
        PDF_PLACE(work->id, candidate, blockvector_get_num_blocks(candidate->b) - 1, "XML_MB_ANCHOR", block_choice, blocks_to_extend);

        XmlStreamReassembler r;
        int k = 1;
        if (xml_stream_reassembler_init(&r, (const unsigned char*)first_stream_block_data,
                scalpel_state.blocksize, startstream_local_offset, (size_t)stream_length) == -1) {
            k = blocks_to_extend + 1;
        }
        bool extend_from_start = true;
        const unsigned char *stream_block;
        int stream_check;
        while (k <= blocks_to_extend) {
            if (extend_from_start) {
                block_choice = pdf_reassembly_get_block_choice(candidate, -1, -1,
                    streamstart_block_app, 0, k, EXTENDSTREAMFROMSTART, -1);
                if (block_choice == -1) { extend_from_start = false; k++; continue; }
                if (!pdf_block_matches_xref_slot(candidate, block_choice,
                        blockvector_get_num_blocks(candidate->b) - (uint64_t)blocks_to_extend + (uint64_t)k - 1)) {
                    extend_from_start = false; k++; continue;
                }
                stream_block = (const unsigned char*)get_apparent_block_data(scalpel_state.filemirror, block_choice);
                stream_check = xml_stream_reassembler_try_block(&r, stream_block, scalpel_state.blocksize);
                free((void*)stream_block);
                if (stream_check == 1 || stream_check == 2) {
                    candidate->newblock = filemirror_actual_blocknumber(scalpel_state.filemirror, block_choice);
                    PDF_PLACE(work->id, candidate, (blockvector_get_num_blocks(candidate->b) - blocks_to_extend + k - 1), "XML_MB_START", block_choice, k);
                } else if (stream_check == 0 || stream_check == -1) extend_from_start = false;
            } else {
                block_choice = pdf_reassembly_get_block_choice(candidate, -1, -1,
                    streamstart_block_app, endstream_block_apparent, (blocks_to_extend - k) + 1, EXTENDSTREAMFROMEND, -1);
                if (block_choice == -1) { k++; continue; }
                if (!pdf_block_matches_xref_slot(candidate, block_choice,
                        blockvector_get_num_blocks(candidate->b) - (uint64_t)blocks_to_extend + (uint64_t)k - 2)) {
                    k++; continue;
                }
                stream_block = (const unsigned char*)get_apparent_block_data(scalpel_state.filemirror, block_choice);
                stream_check = xml_stream_reassembler_try_block(&r, stream_block, scalpel_state.blocksize);
                free((void*)stream_block);
                if (stream_check == 1 || stream_check == 2) {
                    candidate->newblock = filemirror_actual_blocknumber(scalpel_state.filemirror, block_choice);
                    PDF_PLACE(work->id, candidate, (blockvector_get_num_blocks(candidate->b) - blocks_to_extend + k - 2), "XML_MB_END", block_choice, k);
                }
            }
            k++;
        }
        xml_stream_reassembler_free(&r);
        return true;
    }

    return true;
}

/* JPEG marker classification (ITU-T T.81). A marker is 0xFF then a code; the
 * groups below must not be conflated, or a foreign block escapes validation by
 * being read as a length-bearing segment whose payload is then skipped. */

/**
 * @description  Whether a marker code is standalone (carries no length/payload).
 * @param m      The marker code (byte after 0xFF).
 * @return       true for TEM, RSTn, SOI, EOI.
 */
static inline bool jpeg_marker_standalone(int m) {
    return m == 0x01 ||                     /* TEM  */
           (m >= 0xD0 && m <= 0xD7) ||      /* RST0..RST7 */
           m == 0xD8 ||                     /* SOI  */
           m == 0xD9;                       /* EOI  */
}

/**
 * @description  Whether a marker code is a start-of-frame (SOFn) header. 0xC4
 *               (DHT), 0xC8 (reserved) and 0xCC (DAC) are excluded from the range.
 * @param m      The marker code.
 * @return       true if a frame header.
 */
static inline bool jpeg_marker_is_sof(int m) {
    if (m == 0xC4 || m == 0xC8 || m == 0xCC) return false;
    return (m >= 0xC0 && m <= 0xCF);
}

/**
 * @description  Whether a marker may legally follow entropy-coded scan data
 *               (RSTn, tables/misc segments, a further SOS, EOI). Excludes a
 *               second SOF, reserved JPGn, and hierarchical-mode markers.
 * @param m      The marker code.
 * @return       true if legal after a scan.
 */
static inline bool jpeg_marker_legal_after_scan(int m) {
    if (m >= 0xD0 && m <= 0xD7) return true;   /* RSTn */
    if (m >= 0xE0 && m <= 0xEF) return true;   /* APPn */
    switch (m) {
        case 0xC4:   /* DHT */
        case 0xCC:   /* DAC */
        case 0xDB:   /* DQT */
        case 0xDC:   /* DNL */
        case 0xDD:   /* DRI */
        case 0xDA:   /* SOS -- next scan of a progressive image */
        case 0xD9:   /* EOI */
        case 0xFE:   /* COM */
            return true;
        default:
            return false;
    }
}

/**
 * @description  Whether a marker is legal in the tables/misc region before or
 *               between frames (APPn, the SOFn header, DHT/DQT/DRI/SOS/etc.).
 * @param m      The marker code.
 * @return       true if legal in the header region.
 */
static inline bool jpeg_marker_legal_in_header(int m) {
    if (m >= 0xE0 && m <= 0xEF) return true;   /* APPn */
    if (jpeg_marker_is_sof(m))   return true;  /* the frame header itself */
    switch (m) {
        case 0xC4: case 0xCC: case 0xDB: case 0xDD:
        case 0xDA: case 0xD9: case 0xFE: case 0xDC:
            return true;
        default:
            return false;
    }
}

/**
 * @description  Feed one byte of a DHT payload (tables of Tc/Th + 16 counts +
 *               sum(counts) symbols). Sets r->malformed on a bad table; the
 *               segment must end exactly on a table boundary.
 * @param r      The reassembler state.
 * @param c      The payload byte.
 * @return       Void.
 */
static inline void jpeg_feed_dht(JpegStreamReassembler *r, unsigned char c) {
    switch (r->tbl_phase) {
        case 0:
            if ((c >> 4) > 1 || (c & 0x0F) > 3) { r->malformed = 1; return; }
            r->tbl_id = c; r->tbl_phase = 1; r->tbl_count = 0; r->tbl_total = 0;
            break;
        case 1:
            r->tbl_total += c;
            if (++r->tbl_count == 16) {
                if (r->tbl_total > 256) { r->malformed = 1; return; }
                r->tbl_sym = r->tbl_total;
                if (r->tbl_sym == 0) {
                    r->dht_defined |= 1u << ((((unsigned)r->tbl_id >> 4) << 2) | ((unsigned)r->tbl_id & 3));
                    r->tbl_phase = 0;
                } else {
                    r->tbl_phase = 2;
                }
            }
            break;
        default:
            if (--r->tbl_sym == 0) {
                r->dht_defined |= 1u << ((((unsigned)r->tbl_id >> 4) << 2) | ((unsigned)r->tbl_id & 3));
                r->tbl_phase = 0;
            }
            break;
    }
}

/**
 * @description  Feed one byte of a DQT payload (tables of Pq/Tq + 64 or 128
 *               values). Sets r->malformed on a bad table; must end on a table
 *               boundary.
 * @param r      The reassembler state.
 * @param c      The payload byte.
 * @return       Void.
 */
static inline void jpeg_feed_dqt(JpegStreamReassembler *r, unsigned char c) {
    if (r->tbl_phase == 0) {
        if ((c >> 4) > 1 || (c & 0x0F) > 3) { r->malformed = 1; return; }
        r->tbl_id = c;
        r->tbl_sym = ((c >> 4) == 0) ? 64 : 128;
        r->tbl_phase = 2;
    } else {
        if (--r->tbl_sym == 0) {
            r->dqt_defined |= 1u << ((unsigned)r->tbl_id & 3);
            r->tbl_phase = 0;
        }
    }
}

/**
 * @description  Feed one byte of an SOF payload (precision, height, width, Nf,
 *               3 bytes/component). Sets r->malformed unless the length equals
 *               8 + 3*Nf and the fields are in range.
 * @param r      The reassembler state.
 * @param c      The payload byte.
 * @param idx    0-based index of this byte within the payload.
 * @return       Void.
 */
static inline void jpeg_feed_sof(JpegStreamReassembler *r, unsigned char c, int idx) {
    switch (idx) {
        case 0:
            r->precision = c;
            if (c != 8 && c != 12 && c != 16) r->malformed = 1;
            break;
        case 1: r->frame_h  = (int)c << 8; break;
        case 2: r->frame_h |= (int)c;      break;
        case 3: r->frame_w  = (int)c << 8; break;
        case 4: r->frame_w |= (int)c;      break;
        case 5:
            r->ncomp = c;
            if (c < 1 || c > 4)            { r->malformed = 1; return; }
            if (r->seg_len != 8 + 3 * (int)c) { r->malformed = 1; return; }
            if (r->frame_w == 0)           { r->malformed = 1; return; }
            break;
        default: break;
    }
}

/**
 * @description  Feed one byte of an SOS payload (Ns, 2 bytes/component, Ss/Se/
 *               Ah|Al). Sets r->malformed unless the length equals 6 + 2*Ns and
 *               the table selectors are in range.
 * @param r      The reassembler state.
 * @param c      The payload byte.
 * @param idx    0-based index of this byte within the payload.
 * @return       Void.
 */
static inline void jpeg_feed_sos(JpegStreamReassembler *r, unsigned char c, int idx) {
    if (idx == 0) {
        r->scan_ncomp = c;
        if (c < 1 || c > 4)              { r->malformed = 1; return; }
        if (r->seg_len != 6 + 2 * (int)c) { r->malformed = 1; return; }
        return;
    }
    if (idx >= 2 && idx <= 2 * r->scan_ncomp && (idx % 2) == 0) {
        if ((c >> 4) > 3 || (c & 0x0F) > 3) r->malformed = 1;   /* Td/Ta selectors */
    }
}

/**
 * @description  Feeds one stream byte through the JPEG marker/scan state machine,
 *               setting r->malformed on any grammar, byte-stuffing, or restart-
 *               cadence violation. Captures the restart interval from a DRI segment
 *               and checks that RSTn markers in the scan follow the 0..7 cadence.
 * @param r  The JPEG reassembler state.
 * @param c  The next stream byte.
 * @return       Void.
 */
static inline void jpeg_feed_byte(JpegStreamReassembler *r, unsigned char c) {
    if (r->malformed || r->state == J_DONE) return;
    r->pos++;   // stream position, used to bound declared segment lengths

    switch (r->state) {
        case J_START:
            // SOI must be exactly FF D8.
            if (!r->prev_ff) { if (c == 0xFF) r->prev_ff = 1; else r->malformed = 1; }
            else { if (c == 0xD8) { r->prev_ff = 0; r->state = J_MARKER; } else r->malformed = 1; }
            break;

        case J_MARKER:
            if (!r->prev_ff) {
                if (c == 0xFF) r->prev_ff = 1;
                else r->malformed = 1;            // marker region must begin with FF
                break;
            }
            if (c == 0xFF) break;                 // fill byte: stay, prev_ff still set
            r->prev_ff = 0;
            if (c == 0x00) { r->malformed = 1; break; }               // FF00 is not a marker here
            if (c == 0xD9) { r->saw_eoi = 1; r->state = J_DONE; break; }
            if (c == 0xD8) { r->malformed = 1; break; }               // duplicate SOI
            if (c >= 0xD0 && c <= 0xD7) { r->malformed = 1; break; }  // RSTn only inside a scan
            if (c == 0x01) { r->state = J_MARKER; break; }            // TEM: standalone

            // Reject codes that cannot appear in the tables/misc region, and a
            // second frame header -- one JPEG describes exactly one frame.
            if (!jpeg_marker_legal_in_header(c)) { r->malformed = 1; break; }
            if (jpeg_marker_is_sof(c)) {
                if (r->saw_sof) { r->malformed = 1; break; }
                r->saw_sof = 1;
                r->sof_marker = c;
            }
            // A scan cannot start before the frame it belongs to is described.
            if (c == 0xDA && !r->saw_sof) { r->malformed = 1; break; }

            r->marker = c;
            r->state = J_LEN1;
            break;

        case J_LEN1:
            r->seg_len = (int)c << 8;
            r->state = J_LEN2;
            break;

        case J_LEN2:
            r->seg_len |= (int)c;
            if (r->seg_len < 2) { r->malformed = 1; break; }   // length counts its own 2 bytes
            r->seg_remaining = r->seg_len - 2;

            // A segment cannot extend past the end of the declared stream. This
            // is what stops a fabricated length from swallowing the rest of a
            // block unchecked.
            if (r->stream_length && (size_t)r->seg_remaining > r->stream_length - r->pos) {
                r->malformed = 1; break;
            }

            r->tbl_phase = 0;                     // start each table segment cleanly
            if (r->marker == 0xDD) {              // DRI: exactly 2 payload bytes
                if (r->seg_remaining != 2) { r->malformed = 1; break; }
                r->dri_capture = 1;
                r->restart_interval = 0;
            }
            r->state = (r->seg_remaining == 0) ? J_MARKER : J_PAYLOAD;
            break;

        case J_PAYLOAD: {
            int idx = r->seg_len - 2 - r->seg_remaining;   // 0-based index into the payload

            if (r->marker == 0xDD && r->dri_capture) {
                if (r->seg_remaining == 2)      r->restart_interval  = (int)c << 8;
                else if (r->seg_remaining == 1) r->restart_interval |= (int)c;
            } else if (r->marker == 0xC4) {
                jpeg_feed_dht(r, c);
            } else if (r->marker == 0xDB) {
                jpeg_feed_dqt(r, c);
            } else if (r->marker == 0xDA) {
                jpeg_feed_sos(r, c, idx);
            } else if (jpeg_marker_is_sof(r->marker)) {
                jpeg_feed_sof(r, c, idx);
            }
            if (r->malformed) break;

            r->seg_remaining--;
            if (r->seg_remaining == 0) {
                // A table segment must end exactly on a table boundary; a partly
                // consumed table means the declared length did not match the
                // contents, which arbitrary data essentially never satisfies.
                if ((r->marker == 0xC4 || r->marker == 0xDB) && r->tbl_phase != 0) {
                    r->malformed = 1; break;
                }
                if (r->marker == 0xDA) {          // SOS consumed; entropy data follows
                    r->saw_sos = 1;
                    r->scan_count++;
                    r->expected_rst = 0;
                    r->prev_ff = 0;
                    r->state = J_SCAN;
                } else {
                    r->dri_capture = 0;
                    r->state = J_MARKER;
                }
            }
            break;
        }

        case J_SCAN:
            if (!r->prev_ff) {
                if (c == 0xFF) r->prev_ff = 1;    // potential marker/stuffing lead-in
                break;                            // otherwise an ordinary entropy byte
            }
            r->prev_ff = 0;
            if (c == 0x00) {
                // Stuffed byte: a literal 0xFF in the entropy stream. Valid.
            } else if (c == 0xFF) {
                r->prev_ff = 1;                   // fill byte run; still pending
            } else if (c >= 0xD0 && c <= 0xD7) {
                if (r->restart_interval > 0) {
                    if ((c - 0xD0) != r->expected_rst) { r->malformed = 1; break; }
                    r->expected_rst = (r->expected_rst + 1) & 7;
                    r->have_seen_rst = 1;
                } else {
                    r->malformed = 1;             // RSTn without a declared DRI
                }
            } else if (c == 0xD9) {
                r->saw_eoi = 1;
                r->state = J_DONE;
            } else if (jpeg_marker_legal_after_scan(c)) {
                // A tables/misc segment or the next scan of a progressive image.
                // Only codes that can legally follow entropy data reach here; a
                // second SOF, a reserved JPGn code or a hierarchical-mode marker
                // is a foreign block, not a continuation of this stream.
                r->marker = c;
                r->state = J_LEN1;
            } else {
                r->malformed = 1;                 // FF followed by an illegal code
            }
            break;
    }
}

/**
 * @description  Initialises a JPEG stream reassembler and feeds the stream data in
 *               the first block (capped at /Length) through the marker/scan state
 *               machine, failing if that header portion is already malformed.
 * @param r             The reassembler to initialise.
 * @param first_block   The block holding the stream start.
 * @param block_size    Size of a block.
 * @param stream_offset Block-local offset where the stream data begins.
 * @param stream_length The declared /Length.
 * @return       0 on success, -1 on allocation failure or malformed header.
 */
int jpeg_stream_reassembler_init(JpegStreamReassembler *r, const unsigned char *first_block,
                     size_t block_size, size_t stream_offset, size_t stream_length) {
    memset(r, 0, sizeof(*r));
    r->stream_length = stream_length;
    r->state = J_START;

    r->output_capacity = stream_length + block_size + 1;
    r->output = malloc(r->output_capacity);
    if (!r->output) return -1;

    size_t avail = (stream_offset < block_size) ? (block_size - stream_offset) : 0;
    size_t take  = (avail < stream_length) ? avail : stream_length;
    for (size_t i = 0; i < take; i++) {
        unsigned char c = first_block[stream_offset + i];
        jpeg_feed_byte(r, c);
        r->output[r->output_len++] = c;
    }
    r->fed = take;

    // The first block must start with a valid SOI/marker sequence; if it is
    // already broken this is not a recoverable DCTDecode stream.
    if (r->malformed) { free(r->output); r->output = NULL; return -1; }
    return 0;
}

/**
 * @description  Tries one block as the next in a JPEG stream: feeds its bytes
 *               (never past /Length) through the marker/scan machine, rolling back
 *               on any malformation. On reaching /Length, requires a scan that
 *               terminated at EOI to accept completion.
 * @param r           The reassembler.
 * @param block       The candidate next block.
 * @param block_size  Size of the block.
 * @return       2 if the stream is now complete, 1 if the block was accepted with
 *               more needed, 0 if rejected (rolled back).
 */
int jpeg_stream_reassembler_try_block(JpegStreamReassembler *r, const unsigned char *block, size_t block_size) {
    // Snapshot for rollback. Safe as a shallow copy: capacity was preallocated
    // for the whole stream, so no realloc happens mid-feed and r->output is
    // never reallocated; only output_len advances.
    JpegStreamReassembler snap = *r;

    size_t remaining = (r->fed < r->stream_length) ? (r->stream_length - r->fed) : 0;
    size_t take = (block_size < remaining) ? block_size : remaining;

    for (size_t i = 0; i < take; i++) {
        jpeg_feed_byte(r, block[i]);
        if (r->malformed) { *r = snap; return 0; }   // REJECT: roll back
        r->output[r->output_len++] = block[i];
    }
    r->fed += take;

    if (r->fed >= r->stream_length) {
        // Completion: full /Length accounted for. Require a real scan that
        // terminated at EOI. (Restart-interval JPEGs additionally have their
        // RSTn cadence validated above; non-DRI JPEGs are accepted best-effort.)
        if (r->saw_sos && r->saw_eoi) return 2;   // saw_eoi is set iff state==J_DONE
        *r = snap;
        return 0;
    }
    return 1;   // accepted; more blocks needed
}

/**
 * @description  Releases a JPEG reassembler's output buffer.
 * @param r  The reassembler to free.
 * @return       Void.
 */
void jpeg_stream_reassembler_free(JpegStreamReassembler *r) {
    free(r->output);
    r->output = NULL;
}

/**
 * @description  Reassembles a DCTDecode (JPEG) stream. Mirrors reconstruct_xml_stream's
 *               block-selection control flow, swapping in the JPEG marker/scan
 *               validator; MULTIBLOCK uses the deferred-commit split search and
 *               accepts only when the scan reaches EOI.
 * @param work                     The thread work context.
 * @param candidate                The candidate being extended.
 * @param first_stream_block_data  The block holding the stream start.
 * @param startstream_local_offset Block-local offset where the stream data begins.
 * @param endstream_local_offset   Block-local offset expected for endstream.
 * @param blocks_to_extend         Blocks past the candidate the stream spans.
 * @param stream_length            The declared /Length.
 * @param mode                     INBLOCK, INNEXTBLOCK, or MULTIBLOCK.
 * @return       true if the stream was fully reassembled and committed, else false.
 */
bool reconstruct_jpeg_stream(ThreadWork *work, CarveInfo *candidate,
    const char *first_stream_block_data,
    int32_t startstream_local_offset,
    int32_t endstream_local_offset,
    int blocks_to_extend,
    uint64_t stream_length,
    int mode)
{
    uint64_t streamstart_block_app = blockvector_get_apparent_blocknumber(candidate->b,
        blockvector_get_num_blocks(candidate->b) - 1);

    if (mode == INNEXTBLOCK) {
        BlockVector *scan_bv = NULL;
        uint64_t evaluated;
        init_blockvector(scalpel_state.filemirror, &scan_bv, 1, false);
        inflate_blockvector(scan_bv);
        int64_t block_choice = blockvector_get_choice(scan_bv, 0, streamstart_block_app + 1, -1, &evaluated);
        free_blockvector(&scan_bv);
#ifdef PDF_TRACE_ZSTALL
        lock_fprintf(stdout, "[PDFZ] INNEXTBLOCK streamstart=%" PRIu64 " contig=%" PRIu64
            " get_choice=%" PRId64 " %s\n", streamstart_block_app, streamstart_block_app+1,
            block_choice, (block_choice==(int64_t)streamstart_block_app+1)?"CONTIG":"NOT-CONTIG");
#endif
        if (block_choice == -1) return false;

        JpegStreamReassembler r;
        if (jpeg_stream_reassembler_init(&r, (const unsigned char*)first_stream_block_data,
                scalpel_state.blocksize, startstream_local_offset, (size_t)stream_length) == -1)
            return false;

        const unsigned char *stream_block =
            (const unsigned char*)get_apparent_block_data(scalpel_state.filemirror, block_choice);
        int stream_check = jpeg_stream_reassembler_try_block(&r, stream_block, scalpel_state.blocksize);
        if (stream_check == 2) {   // INNEXTBLOCK: the stream must complete in this one block (2), never 1
            candidate->newblock = filemirror_actual_blocknumber(scalpel_state.filemirror, block_choice);
            pdf_reassembly_prepare_for_extension(work->id, candidate, 1, OBJECTEXTNSION);
            PDF_PLACE(work->id, candidate, blockvector_get_num_blocks(candidate->b) - 1, "JPG_NEXT", block_choice, stream_check);
        } else {
            free((void*)stream_block);
            block_choice = pdf_reassembly_get_block_choice(candidate, -1, endstream_local_offset, 0, 0, -1, FINDENDSTREAM, \
            (int64_t)blockvector_get_num_blocks(candidate->b));
            if (block_choice == -1) {
                jpeg_stream_reassembler_free(&r);
                return false;
            }
            stream_block = (const unsigned char*)get_apparent_block_data(scalpel_state.filemirror, block_choice);
            stream_check = jpeg_stream_reassembler_try_block(&r, stream_block, scalpel_state.blocksize);
            if (stream_check == 2) {   // INNEXTBLOCK: the stream must complete in this one block (2), never 1
                candidate->newblock = filemirror_actual_blocknumber(scalpel_state.filemirror, block_choice);
                pdf_reassembly_prepare_for_extension(work->id, candidate, 1, OBJECTEXTNSION);
                PDF_PLACE(work->id, candidate, blockvector_get_num_blocks(candidate->b) - 1, "JPG_NEXT_ES", block_choice, stream_check);
            }
        }
        jpeg_stream_reassembler_free(&r);
        free((void*)stream_block);
        return true;
    }

    if (mode == MULTIBLOCK) {
        /*
         * Deferred-commit split-search, identical in shape to the zlib MULTIBLOCK
         * path. JPEG entropy-scan data has no checksum, so nothing is committed
         * until a whole block assignment reaches EOI having consumed exactly
         * /Length -- a foreign block carries no EOI at the declared position, so
         * such an assignment never completes. The endstream block is tried at its
         * contiguous position first (content-only FINDENDSTREAM often matches
         * coincidentally in a foreign block), then via FINDENDSTREAM as a fallback.
         */
        if (blocks_to_extend <= 0) return false;
        const int64_t tot_app = (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror);

        int64_t es_cands[2];
        int n_es = 0;
        int64_t contig_es = (int64_t)streamstart_block_app + blocks_to_extend;
        if (contig_es >= 0 && contig_es < tot_app) es_cands[n_es++] = contig_es;
        int64_t findes = pdf_reassembly_get_block_choice(candidate, -1, endstream_local_offset, 0, 0, -1, FINDENDSTREAM,
            (int64_t)blockvector_get_num_blocks(candidate->b) + (int64_t)blocks_to_extend - 1);
        if (findes >= 0 && findes < tot_app && findes != contig_es) es_cands[n_es++] = findes;
        if (n_es == 0) return false;

        const uint64_t nb_before  = blockvector_get_num_blocks(candidate->b);
        const int      n_interior = blocks_to_extend - 1;
        const int      MAX_SPLITS = 64;

        int64_t *chosen = (int64_t*)malloc(sizeof(int64_t) * (size_t)blocks_to_extend);
        if (!chosen) return false;

        bool solved = false;
        uint64_t endstream_block_apparent = (uint64_t)es_cands[0];
        for (int ei = 0; ei < n_es && !solved; ei++) {
            endstream_block_apparent = (uint64_t)es_cands[ei];
            int tried = 0;
            for (int m = n_interior; m >= 0 && !solved && tried < MAX_SPLITS; m--, tried++) {
                JpegStreamReassembler r;
                if (jpeg_stream_reassembler_init(&r, (const unsigned char*)first_stream_block_data,
                        scalpel_state.blocksize, startstream_local_offset, (size_t)stream_length) == -1)
                    break;

                bool ok = true;
                for (int i = 1; i <= n_interior && ok; i++) {
                    int64_t app = (i <= m) ? (int64_t)streamstart_block_app + i
                                           : (int64_t)endstream_block_apparent - (blocks_to_extend - i);
                    if (app < 0 || app >= tot_app) { ok = false; break; }
                    const unsigned char *blk =
                        (const unsigned char*)get_apparent_block_data(scalpel_state.filemirror, app);
                    if (!blk) { ok = false; break; }
                    int chk = jpeg_stream_reassembler_try_block(&r, blk, scalpel_state.blocksize);
                    free((void*)blk);
                    if (chk != 1 && chk != 2) { ok = false; break; }
                    chosen[i-1] = app;
                }

                if (ok && !r.saw_eoi) {
                    const unsigned char *blk =
                        (const unsigned char*)get_apparent_block_data(scalpel_state.filemirror, endstream_block_apparent);
                    if (!blk) ok = false;
                    else {
                        int chk = jpeg_stream_reassembler_try_block(&r, blk, scalpel_state.blocksize);
                        free((void*)blk);
                        if (chk != 2) ok = false;             // must COMPLETE (EOI) here
                    }
                }
                chosen[blocks_to_extend-1] = (int64_t)endstream_block_apparent;

                // Accept only on completion: EOI reached having consumed /Length.
                solved = ok && r.saw_eoi;
                jpeg_stream_reassembler_free(&r);
            }
        }

        if (!solved) { free(chosen); return false; }           // commit nothing

        pdf_reassembly_prepare_for_extension(work->id, candidate, blocks_to_extend, ENDSTREAMEXTENSION);
        for (int i = 0; i < blocks_to_extend; i++) {
            uint64_t slot = nb_before + (uint64_t)i;
            if (!pdf_block_matches_xref_slot(candidate, chosen[i], slot)) continue;
            candidate->newblock = filemirror_actual_blocknumber(scalpel_state.filemirror, chosen[i]);
            PDF_PLACE(work->id, candidate, slot,
                      (i == blocks_to_extend-1) ? "JPG_MB_ANCHOR" : "JPG_MB_START",
                      chosen[i], i);
        }
        free(chosen);
        return true;
    }

    return true;
}

/**
 * @description  Scans image blocks for an xref located at expected_offset (its
 *               block-local offset), handling xrefs that span into following blocks,
 *               and analyses it into an Object entry array. Reports which actual
 *               blocks hold the xref so the caller can place them at their true slot.
 * @param candidate             The candidate whose block states are consulted.
 * @param scan_bv               A block vector for the scan (reinitialised here).
 * @param entry_count           Out: number of Object entries returned.
 * @param out_xref_blocks       Out: malloc'd array of the actual blocks holding the xref.
 * @param out_xref_block_count  Out: count of those blocks.
 * @param expected_offset       The block-local offset the xref must start at.
 * @return       A malloc'd Object array for the xref (caller frees), or NULL if no
 *               xref matches at expected_offset.
 */
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
    while ((block_choice = blockvector_get_choice(scan_bv, slot, start, -1, &evaluated)) != -1) {
        blockvector_remove_choice(scan_bv, slot, block_choice);
        start = block_choice + 1;

        PDFBlockState *blk_state = pdf_get_blockstate_from_apparent(candidate, block_choice, NULL);
#ifdef PDF_TRACE_SCANXREF
        {
            uuid_string_t uu; uuid_unparse_lower(candidate->binuuid, uu);
            int64_t act = filemirror_actual_blocknumber(scalpel_state.filemirror, block_choice);
            // reached=1 always here; state=0 means classified INVALID (NULL);
            // xrefs = num_xrefs (0 = reached, valid, but no xref marker)
            lock_fprintf(stdout, "[PDFSCANX] uuid=%.8s reached=%" PRId64 " state=%d xrefs=%d\n",
                         uu, act, blk_state?1:0, blk_state?blk_state->num_xrefs:-1);
        }
#endif
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
                    goto cleanup;
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
                            goto cleanup;
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
            // An xref stream whose dict spans blocks has no in-block end marker;
            // try to find its tail in the next apparent block.
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
                    goto cleanup;
                }
            }
        }
        pdf_free_block_state((void**)&blk_state);
    }
cleanup:
    free_blockvector(&scan_bv);
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
                      BlockVector **scan_bv,
                      int *entry_count,
                      int64_t **out_xref_blocks,
                      int *out_xref_block_count,
                      int32_t *out_xref_local){
    if(out_xref_local) *out_xref_local = -1;
    if(*scan_bv == NULL){
        init_blockvector(scalpel_state.filemirror, scan_bv, 1, false);
        inflate_blockvector(*scan_bv);
    }
    BlockVector *bv = *scan_bv;

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
    while ((block_choice = blockvector_get_choice(bv, slot, start, -1, &evaluated)) != -1) {
        blockvector_remove_choice(bv, slot, block_choice);
        start = block_choice + 1;

        PDFBlockState *blk_state = pdf_get_blockstate_from_apparent(candidate, block_choice, NULL);
#ifdef PDF_TRACE_SCANXREF
        {
            uuid_string_t uu; uuid_unparse_lower(candidate->binuuid, uu);
            int64_t act = filemirror_actual_blocknumber(scalpel_state.filemirror, block_choice);
            // reached=1 always here; state=0 means classified INVALID (NULL);
            // xrefs = num_xrefs (0 = reached, valid, but no xref marker)
            lock_fprintf(stdout, "[PDFSCANX] uuid=%.8s reached=%" PRId64 " state=%d xrefs=%d\n",
                         uu, act, blk_state?1:0, blk_state?blk_state->num_xrefs:-1);
        }
#endif
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
                if(entries && *entry_count > 0){
                    int start_ap = (blk_state->xref_block_data[i].conditional_flag == INCOMPLETESTREAMDICT)
                                   ? block_choice - 1 : block_choice;
                    int num_blocks = block_choice - start_ap + 1;
                    *out_xref_blocks = malloc(num_blocks * sizeof(int64_t));
                    *out_xref_block_count = num_blocks;
                    for(int b = 0; b < num_blocks; b++)
                        (*out_xref_blocks)[b] = filemirror_actual_blocknumber(scalpel_state.filemirror, start_ap + b);
                    // Offset of the xref within the first returned block. For the
                    // INCOMPLETESTREAMDICT case xref_start was recomputed against a
                    // 2-block buffer starting at start_ap, so it is already relative
                    // to the first returned block in both branches.
                    if(out_xref_local) *out_xref_local = (int32_t)blk_state->xref_block_data[i].xref_start;
                    pdf_free_block_state((void**)&blk_state);
                    return entries;
                }
                // analyze_xref can fail on a corrupt/unparseable xref (e.g. a mangled
                // xref stream), returning entries==NULL with a garbage entry_count.
                // Discard it and keep scanning: returning NULL here would break the
                // caller's scan loop and starve every candidate whose own xref sits
                // past this block.
                free(entries); entries = NULL; *entry_count = 0;
            }

            // This xref starts in this block and continues in another
            // try to find the tail in the proceeding blocks
            if(blk_state->xref_block_data[i].xref_start != -1 && 
               blk_state->xref_block_data[i].xref_end == -1 &&
               blk_state->xref_block_data[i].xref_type == 1){
                int64_t tail = start;
                int64_t tail_choice = -1;

                // Probe forward for the xref's continuation on a PRIVATE clone of the
                // scan blockvector. Removing walked-past blocks from the shared bv
                // would consume blocks that are not part of this xref -- including
                // another file's own xref block -- and permanently exclude them from
                // the main sweep. The clone carries the same exclusion state, so the
                // walk is unchanged, but removals stay local and are discarded here.
                BlockVector *tail_bv = NULL;
                clone_blockvector(bv, &tail_bv, true);

                while ((tail_choice = blockvector_get_choice(tail_bv, slot, tail, -1, &evaluated)) != -1){
                    blockvector_remove_choice(tail_bv, slot, tail_choice);
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
                            if(out_xref_local) *out_xref_local = (int32_t)blk_state->xref_block_data[i].xref_start;
                            pdf_free_block_state((void**)&tail_state);
                            pdf_free_block_state((void**)&blk_state);
                            free_blockvector(&tail_bv);
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
                free_blockvector(&tail_bv);
            }
            // An xref stream whose dict spans blocks has no in-block end marker;
            // try to find its tail in the next apparent block.
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
                    if(out_xref_local) *out_xref_local = (int32_t)blk_state->xref_block_data[i].xref_start;
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
 * @description  Finds the earliest xref in the buffer from search_pos, considering
 *               both a classic "xref" keyword (validated as a standalone token) and
 *               an xref stream ("/Type/XRef"), and reports which kind was found.
 * @param data       The buffer to scan.
 * @param length     Length of the buffer.
 * @param search_pos Offset to begin scanning from.
 * @param xref_type  Out: the kind of xref found (classic table vs stream).
 * @return       Pointer to the earliest xref start, or NULL if none is found.
 */
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

/**
 * @description  Read one integer parameter out of the linearization dictionary.
 *               The key must be followed by whitespace or a digit, so "/L" does
 *               not match inside "/Linearized" (nor "/T" inside "/Type").
 * @param dict   The dictionary bytes.
 * @param dict_len  Their length.
 * @param key    The key to find (e.g. "/L").
 * @param key_len   Its length.
 * @return       The value, or -1 if the key is absent.
 */
static int64_t pdf_lin_param(const char *dict, int dict_len,
                             const char *key, int key_len) {
    for (int i = 0; i + key_len < dict_len; i++) {
        if (memcmp(&dict[i], key, (size_t)key_len)) continue;
        char c = dict[i + key_len];
        if (!isspace((unsigned char)c) && !isdigit((unsigned char)c)) continue;
        return extract_int((char *)dict, i + key_len, dict_len, NULL);
    }
    return -1;
}

/**
 * @description  Detect the linearization dictionary in the candidate's header
 *               block and cache /L and /T. A linearized PDF puts its entry-point
 *               xref at the FRONT, so its final startxref does NOT locate the
 *               main table -- /T does, and it lives in the header block. The
 *               search is scoped to the FIRST object (spec Annex F) so a later
 *               incremental "/Linearized" string cannot supply stale parameters.
 *               /L and /T describe that revision, not necessarily the whole file:
 *               treat them as anchors, not terminators.
 * @param s      Carve state; s->linearized/lin_L/lin_T are written.
 * @param data   The candidate buffer (header block).
 * @param length Its length.
 * @return       Void.
 */
static void pdf_detect_linearization(PDFCarveState *s, const char *data, uint64_t length) {
    s->linearized = false;
    s->lin_L = -1;
    s->lin_T = -1;
    if (!s || !data || length == 0) return;

    // Only the header block can hold the first object.
    uint64_t scan = (length < (uint64_t)scalpel_state.blocksize)
                    ? length : (uint64_t)scalpel_state.blocksize;

    const char *first_obj = memmem(data, scan, " obj", 4);
    if (!first_obj) return;

    uint64_t obj_off = (uint64_t)(first_obj - data);
    uint64_t win = scan - obj_off;
    if (win > 512) win = 512;              // the dictionary is short and follows "obj"

    if (!memmem(first_obj, win, "/Linearized", 11)) return;

    s->linearized = true;
    s->lin_L = pdf_lin_param(first_obj, (int)win, "/L", 2);
    s->lin_T = pdf_lin_param(first_obj, (int)win, "/T", 2);

#ifdef PDF_TRACE_PLACEMENT
    lock_fprintf(stdout,
        "[PDFLIN] linearized=1 L=%" PRId64 " T=%" PRId64 " T_slot=%" PRId64
        " T_local=%" PRId64 "\n",
        s->lin_L, s->lin_T,
        s->lin_T >= 0 ? s->lin_T / (int64_t)scalpel_state.blocksize : -1,
        s->lin_T >= 0 ? s->lin_T % (int64_t)scalpel_state.blocksize : -1);
#endif
}

/**
 * @description        Place a run of consecutive blocks at their TRUE file slot,
 *                     derived from an absolute file offset. Unlike the append
 *                     path (prepare_for_extension + extension_successful), this
 *                     can place far past the frontier, leaving the intervening
 *                     slots as holes (a supported BlockVector state that
 *                     read_vector() zero-fills; such a candidate must not be
 *                     reported VALIDATED -- see pdf_candidate_has_holes). Length
 *                     grows to cover the highest slot written and never shrinks.
 *                     Refuses to displace a slot already holding a DIFFERENT
 *                     block (first confirmed placement wins), and checks the
 *                     whole run before any write so a partial run cannot leave a
 *                     mixed state.
 * @param candidate    The candidate being extended.
 * @param actual_blocks  Actual (on-disk) block numbers to place, in order.
 * @param count        How many blocks.
 * @param first_slot   Slot for actual_blocks[0].
 * @param site         Trace label (unused when tracing is off).
 * @return             true if placed; false if the range is implausible or a
 *                     slot is already occupied by a different block.
 */
static bool pdf_place_blocks_at_slot(CarveInfo *candidate,
                                     const int64_t *actual_blocks,
                                     int count,
                                     uint64_t first_slot,
                                     const char *site) {
    (void)site;
    if (!candidate || !actual_blocks || count <= 0) return false;

    uint64_t last_slot = first_slot + (uint64_t)count - 1;
    // A file cannot span more blocks than the image holds; this bounds a bogus
    // offset without needing to know the true file length.
    if (last_slot >= (uint64_t)filemirror_apparent_blocks(scalpel_state.filemirror))
        return false;

    // First confirmed placement wins: a later pass may resolve a foreign xref to
    // a slot already filled correctly, and the cross-check cannot catch it (the
    // foreign table validates itself). Refuse to overwrite a different block.
    for (int b = 0; b < count; b++) {
        uint64_t slot = first_slot + (uint64_t)b;
        if (slot >= blockvector_get_num_blocks(candidate->b)) continue;
        int64_t cur = blockvector_get_apparent_blocknumber(candidate->b, slot);
        if (cur < 0) continue;                       // hole: free to fill
        int64_t want = filemirror_apparent_blocknumber(scalpel_state.filemirror, actual_blocks[b]);
        if (cur != want) return false;               // occupied by a different block
    }

    candidate->fastpath = false;

    if (last_slot + 1 > blockvector_get_num_blocks(candidate->b))
        resize_blockvector(candidate->b, last_slot + 1);

    for (int b = 0; b < count; b++) {
        uint64_t slot = first_slot + (uint64_t)b;
        candidate->newblock = actual_blocks[b];
        blockvector_set_apparent_blocknumber(candidate->b, slot,
            filemirror_apparent_blocknumber(scalpel_state.filemirror, candidate->newblock));
        inflate_blockvector_single_block(candidate->b, slot);
#ifdef PDF_TRACE_PLACEMENT
        {
            uuid_string_t uuidp;
            uuid_unparse_lower(candidate->binuuid, uuidp);
            lock_fprintf(stdout,
                "[PDFPLACE] uuid=%.8s slot=%" PRIu64 " apparent=%" PRId64 " actual=%" PRId64
                " slots=%" PRIu64 " len=%" PRIu64 " site=%-14s line=%d c1=%d c2=%d\n",
                uuidp, slot,
                filemirror_apparent_blocknumber(scalpel_state.filemirror, candidate->newblock),
                candidate->newblock,
                blockvector_get_num_blocks(candidate->b),
                blockvector_get_data_length(candidate->b),
                site, __LINE__, b, count);
        }
#endif
    }

    uint64_t want = (last_slot + 1) * (uint64_t)scalpel_state.blocksize;
    if (want > blockvector_get_data_length(candidate->b)) {
        candidate->best_validates_to = want - 1;
        blockvector_set_data_length(candidate->b, want);
    }
    return true;
}

/**
 * @description  Collects absolute file offsets at which an xref might live, from
 *               every startxref and /Prev in the data. None is trustworthy on its
 *               own -- the final startxref of a linearized file points at the
 *               front table, not the main one -- so the caller must confirm each
 *               against block content. This only gathers; pdf_resolve_xref_slot()
 *               decides.
 * @param data    The buffer to scan.
 * @param length  Length of the buffer.
 * @param out     Output array of candidate offsets.
 * @param max_out Capacity of out[].
 * @return       The number of anchors written to out[].
 */
static int pdf_collect_xref_anchors(const char *data, uint64_t length,
                                    int64_t *out, int max_out) {
    int n = 0;
    if (!data || length == 0) return 0;

    uint64_t pos = 0;
    while (n < max_out && pos + 9 <= length) {
        const char *hit = memmem(&data[pos], (size_t)(length - pos), "startxref", 9);
        if (!hit) break;
        uint64_t off = (uint64_t)(hit - data);
        int64_t v = extract_int((char *)data, (int64_t)off + 9, (int64_t)length, NULL);
        if (v > 0) out[n++] = v;
        pos = off + 9;
    }

    pos = 0;
    while (n < max_out && pos + 5 <= length) {
        const char *hit = memmem(&data[pos], (size_t)(length - pos), "/Prev", 5);
        if (!hit) break;
        uint64_t off = (uint64_t)(hit - data);
        int64_t v = extract_int((char *)data, (int64_t)off + 5, (int64_t)length, NULL);
        if (v > 0) out[n++] = v;
        pos = off + 5;
    }

    return n;
}

/**
 * @description  Resolves the true file slot of a scanned xref from the document's
 *               own metadata, since the scan knows which blocks hold the xref but
 *               not where they belong. The discriminator is the xref's offset
 *               within its block: for a true anchor A, A % blocksize must equal
 *               that local offset, which rejects the wrong (front vs main) table.
 *               Anchors come from the xref's own blocks (a "startxref N" trailer),
 *               then the candidate's data, then /T for linearized files. /T gets a
 *               range test, not an exact one, since it points past the subsection
 *               header at the first entry.
 * @param candidate         The candidate.
 * @param xref_blocks       The blocks holding the scanned xref.
 * @param xref_block_count  Count of those blocks.
 * @param xref_local        The xref's byte offset within its first block.
 * @return       The resolved slot, or -1 if nothing confirms.
 */
static int64_t pdf_resolve_xref_slot(CarveInfo *candidate,
                                     const int64_t *xref_blocks, int xref_block_count,
                                     int32_t xref_local) {
    if (!xref_blocks || xref_block_count <= 0 || xref_local < 0) return -1;

    const uint64_t bsz = (uint64_t)scalpel_state.blocksize;  // not "BS": png.h defines that
    const int64_t  total_blocks = (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror);

    enum { MAX_ANCHORS = 64 };
    int64_t anchors[MAX_ANCHORS];
    int n = 0;

    // (1) The xref's own blocks: a trailer's "startxref N" names this xref.
    {
        uint64_t buflen = (uint64_t)xref_block_count * bsz;
        char *buf = (char *)malloc((size_t)buflen);
        if (buf) {
            bool ok = true;
            for (int b = 0; b < xref_block_count; b++) {
                uint64_t app = filemirror_apparent_blocknumber(scalpel_state.filemirror, xref_blocks[b]);
                char *blk = (char *)get_apparent_block_data(scalpel_state.filemirror, app);
                if (!blk) { ok = false; break; }
                memcpy(buf + (uint64_t)b * bsz, blk, bsz);
                free(blk);
            }
            if (ok) n = pdf_collect_xref_anchors(buf, buflen, anchors, MAX_ANCHORS);
            free(buf);
        }
    }

    // (2) The candidate's assembled data (header block always included).
    if (n < MAX_ANCHORS) {
        n += pdf_collect_xref_anchors(blockvector_get_data_pointer(candidate->b),
                                      blockvector_get_data_length(candidate->b),
                                      anchors + n, MAX_ANCHORS - n);
    }

    // Exact confirmation: the anchor must agree with where the xref sits in its block.
    for (int i = 0; i < n; i++) {
        int64_t A = anchors[i];
        if (A < 0 || A / (int64_t)bsz >= total_blocks) continue;   // out of range
        if ((uint64_t)(A % (int64_t)bsz) == (uint64_t)xref_local)
            return A / (int64_t)bsz;
    }

    // (3) /T for linearized files, range-matched (see comment above).
    PDFCarveState *cs = (PDFCarveState *)carve_get_state(candidate->carvehashkey);
    int64_t slot = -1;
    if (cs && cs->linearized && cs->lin_T >= 0 && cs->lin_T / (int64_t)bsz < total_blocks) {
        int64_t delta = (cs->lin_T % (int64_t)bsz) - (int64_t)xref_local;
        // /T lands just past the xref keyword, within the subsection header line.
        if (delta >= 0 && delta <= 64) slot = cs->lin_T / (int64_t)bsz;
    }
    if (cs) pdf_free_carve_state((void **)&cs);
    return slot;
}

/**
 * @description  Counts how many objects the xref (committed + in-flight) places
 *               inside a slot. Distinguishes a real confirmation from a vacuous
 *               pass of pdf_block_matches_xref_slot(): a raw (unchecksummed) stream
 *               ending in an unconstrained slot cannot be trusted on the endstream
 *               offset match alone, since that match is only ~1/blocksize.
 * @param candidate  The candidate.
 * @param slot       The slot to inspect.
 * @return       The number of objects the xref places in the slot.
 */
static int pdf_xref_slot_object_count(CarveInfo *candidate, uint64_t slot) {
    if (!candidate) return 0;
    PDFCarveState *cs = (PDFCarveState *)carve_get_state(candidate->carvehashkey);
    if (!cs) return 0;
    const uint64_t bsz = (uint64_t)scalpel_state.blocksize;
    const uint64_t lo = slot * bsz, hi = lo + bsz;
    int n = 0;
    for (int src = 0; src < 2; src++) {
        const XrefTables *tabs = (src == 0) ? cs->xref_tables : pdf_inflight_tables;
        int ntab = (src == 0) ? (int)cs->num_tables : pdf_inflight_table_count;
        if (!tabs) continue;
        for (int t = 0; t < ntab; t++) {
            if (!tabs[t].entries) continue;
            for (int e = 0; e < tabs[t].count; e++) {
                uint64_t off = tabs[t].entries[e].obj_offset;
                if (off >= lo && off < hi) n++;
            }
        }
    }
    pdf_free_carve_state((void **)&cs);
    return n;
}

/**
 * @description  Verifies a candidate block against what the xref says must live at
 *               a slot: for every object the xref places inside the slot, that
 *               object's header must appear at its expected offset in the block.
 *               The stream reassemblers judge only whether bytes decode, not whether
 *               they belong to THIS file; this supplies the missing constraint.
 *               Passes vacuously when no object constrains the slot (roughly half
 *               are stream interior), and when there is no carve state or the block
 *               is unreadable: this is a veto on positive evidence, not a proof.
 * @param candidate       The candidate.
 * @param apparent_block  The apparent block number to check.
 * @param slot            The slot the block would occupy.
 * @return       true unless an xref-placed object is absent where it should be.
 */
static bool pdf_block_matches_xref_slot(CarveInfo *candidate,
                                        int64_t apparent_block,
                                        uint64_t slot) {
    if (!candidate || apparent_block < 0) return true;

    PDFCarveState *cs = (PDFCarveState *)carve_get_state(candidate->carvehashkey);
    if (!cs) return true;

    const uint64_t bsz = (uint64_t)scalpel_state.blocksize;
    const uint64_t lo  = slot * bsz;
    const uint64_t hi  = lo + bsz;

    char *blk = NULL;
    bool  ok  = true;
    int   objs_seen = 0;

    // Two sources: the tables already committed to carve state, and the tables
    // the in-progress extension is working from. The second matters -- without
    // it the check runs blind through most of a pass.
    for (int src = 0; src < 2 && ok; src++) {
        const XrefTables *tabs = (src == 0) ? cs->xref_tables : pdf_inflight_tables;
        int ntab = (src == 0) ? (int)cs->num_tables : pdf_inflight_table_count;
        if (!tabs) continue;

        for (int t = 0; t < ntab && ok; t++) {
            if (!tabs[t].entries) continue;
            for (int e = 0; e < tabs[t].count && ok; e++) {
                uint64_t off = tabs[t].entries[e].obj_offset;
                if (off < lo || off >= hi) continue;   // object is not in this slot

                if (!blk) {
                    blk = (char *)get_apparent_block_data(scalpel_state.filemirror, apparent_block);
                    if (!blk) goto done;               // unreadable: do not veto
                }
                objs_seen++;
                if (validate_at_offset(blk, (int64_t)(off - lo),
                                       tabs[t].entries[e].obj_num,
                                       (int64_t)bsz) != 1) {
                    ok = false;                        // object absent where the xref puts it
                }
            }
        }
    }
done:
    free(blk);
#ifdef PDF_TRACE_PLACEMENT
    lock_fprintf(stdout,
        "[PDFXCHK] slot=%" PRIu64 " block=%" PRId64 " tables=%d(+%d) objs_in_slot=%d verdict=%s\n",
        slot, apparent_block, (int)cs->num_tables, pdf_inflight_table_count,
        objs_seen, ok ? "pass" : "VETO");
#endif
    pdf_free_carve_state((void **)&cs);
    return ok;
}

/**
 * @description  Whether any slot in the candidate is still unfilled. Positional
 *               placement can leave gaps that read back as zeroes, which the file
 *               validator would parse as real content, so a holed candidate must
 *               never be promoted to VALIDATED.
 * @param candidate  The candidate.
 * @return       true if a hole exists.
 */
static bool pdf_candidate_has_holes(CarveInfo *candidate) {
    uint64_t n = blockvector_get_num_blocks(candidate->b);
    for (uint64_t i = 0; i < n; i++) {
        if (blockvector_get_apparent_blocknumber(candidate->b, i) < 0) return true;
    }
    return false;
}

#ifdef PDF_TRACE_PLACEMENT
/**
 * @description  Logs a fingerprint (object numbers + offsets) of every xref table
 *               admitted to carve state, tagged with the path that admitted it, so
 *               foreign xref adoption can be observed directly rather than inferred
 *               from downstream block placement. Trace builds only.
 * @param candidate  The candidate adopting the table.
 * @param how        Short label for the admitting path (e.g. "INIT", "PREV").
 * @param ents       The table's object entries.
 * @param count      Count of those entries.
 * @param score      The attribution score that admitted the table.
 * @return       Void.
 */
static void pdf_trace_table_adopt(CarveInfo *candidate, const char *how,
                                  Object *ents, int count, int score) {
    if (!candidate || !ents || count <= 0) return;
    uuid_string_t uu; uuid_unparse_lower(candidate->binuuid, uu);
    char buf[256]; int n = 0;
    for (int i = 0; i < count && i < 6; i++)
        n += snprintf(buf+n, sizeof(buf)-n, "%s%d@%" PRIu64,
                      i?",":"", ents[i].obj_num, (uint64_t)ents[i].obj_offset);
    lock_fprintf(stdout, "[PDFADOPT] uuid=%.8s how=%s count=%d score=%d ents=%s\n",
                 uu, how, count, score, buf);
}
#endif

#ifdef PDF_TRACE_PLACEMENT
/**
 * @description  Debug wrapper behind PDF_PLACE() (trace builds only): emits one
 *               "[PDFPLACE]" line per placement, then performs the placement.
 *               Fields describing the incoming decision are logged before the call
 *               and those describing the resulting candidate after it, so one line
 *               captures both.
 * @param id                  The reassembly id passed through to the placement.
 * @param candidate           The candidate receiving the block.
 * @param logical_slot_index  The slot the block is written to.
 * @param line                Source line of the call site (__LINE__).
 * @param site                Short label for the reassembly path that decided this.
 * @param ctx1                Site-specific context value (see call site).
 * @param ctx2                Site-specific context value (see call site).
 * @return       Void.
 */
static void pdf_reassembly_extension_successful_traced(int id,
                            CarveInfo *candidate,
                            uint64_t logical_slot_index,
                            int line, const char *site,
                            int64_t ctx1, int64_t ctx2) {
    uuid_string_t uuidp;
    uuid_unparse_lower(candidate->binuuid, uuidp);

    int64_t actual   = candidate->newblock;
    int64_t apparent = filemirror_apparent_blocknumber(scalpel_state.filemirror, actual);
    uint64_t slots_before = blockvector_get_num_blocks(candidate->b);

    pdf_reassembly_extension_successful(id, candidate, logical_slot_index);

    lock_fprintf(stdout,
        "[PDFPLACE] uuid=%.8s slot=%" PRIu64 " apparent=%" PRId64 " actual=%" PRId64
        " slots=%" PRIu64 " len=%" PRIu64 " site=%-14s line=%d c1=%" PRId64 " c2=%" PRId64 "\n",
        uuidp, logical_slot_index, apparent, actual,
        slots_before,
        blockvector_get_data_length(candidate->b),
        site, line, ctx1, ctx2);
}
#endif

/**
 * @description  Atomically claims a candidate's body blocks (indices 1..n-1) unless
 *               a previously-validated pdf already claimed any of them. Block 0, the
 *               candidate's own %PDF header, is excluded because it is what differs
 *               between duplicate copies of the same body.
 * @param candidate  The assembled candidate to claim.
 * @return       true if the body was already claimed (a duplicate), false if this
 *               call successfully claimed it.
 */
static bool pdf_claim_body_blocks_or_duplicate(CarveInfo *candidate) {
    uint64_t num_blocks = blockvector_get_num_blocks(candidate->b);
    bool duplicate = false;

    pthread_mutex_lock(&pdf_validated_blocks_lock);

    if (!pdf_validated_blocks) {
        pdf_validated_blocks_count =
            filemirror_filesize(scalpel_state.filemirror) / scalpel_state.blocksize + 1;
        pdf_validated_blocks = (bool *)calloc(pdf_validated_blocks_count, sizeof(bool));
    }

    if (pdf_validated_blocks) {
        for (uint64_t i = 1; i < num_blocks && !duplicate; i++) {
            int64_t actual = blockvector_get_actual_blocknumber(candidate->b, i);
            if (actual >= 0 && (uint64_t)actual < pdf_validated_blocks_count
                && pdf_validated_blocks[actual]) {
                duplicate = true;
            }
        }
        if (!duplicate) {
            for (uint64_t i = 1; i < num_blocks; i++) {
                int64_t actual = blockvector_get_actual_blocknumber(candidate->b, i);
                if (actual >= 0 && (uint64_t)actual < pdf_validated_blocks_count) {
                    pdf_validated_blocks[actual] = true;
                }
            }
        }
    }

    pthread_mutex_unlock(&pdf_validated_blocks_lock);
    return duplicate;
}

/**
 * @description  Attribution check (read-only): scores how strongly a scanned xref
 *               belongs to this candidate's header. Since many PDFs share an
 *               identical first object, a single match proves nothing, so a second
 *               xref object must validate -- either one the xref places in the
 *               header block (tier 1), or, if the header holds only the one stream
 *               object, the next object one block past the header (tier 2). Returns
 *               a score rather than yes/no so the caller can argmax over all xrefs:
 *               a file's own xref confirms 2-68 objects here while foreign xrefs
 *               never exceeded 4, which a threshold alone cannot separate. Never
 *               mutates the candidate (probes a scratch copy).
 * @param candidate     The candidate whose header is tested.
 * @param entries       The scanned xref's object entries.
 * @param entry_count   Count of those entries.
 * @return       The number of the xref's objects confirmed against the header.
 */
static int pdf_xref_confirms_header(CarveInfo *candidate, Object *entries, int entry_count) {
    if (!entries || entry_count < 1) return 0;

    char *data = blockvector_get_data_pointer(candidate->b);
    int64_t len = (int64_t)blockvector_get_data_length(candidate->b);

    // Tier 1: count EVERY object that validates within the current (header)
    // blocks. The old code stopped at 2, which was enough for a yes/no answer
    // but throws away exactly the signal that distinguishes a genuine xref
    // (long tail of confirmations) from a foreign one (never more than a few).
    int in_header = 0;
    for (int i = 0; i < entry_count; i++) {
        if (entries[i].obj_offset >= (uint64_t)len) continue;
        if (validate_at_offset(data, entries[i].obj_offset, entries[i].obj_num, len) == 1)
            in_header++;
    }
    if (in_header >= 2) return in_header;
    if (in_header == 0) return 0;       // not even the first object -- not our xref

    // Tier 2: exactly one object here (a stream). The next xref object lies past
    // that stream, which may span several blocks, so extend contiguously from the
    // header far enough to cover its offset and require it to validate there -- a
    // foreign xref will not place its object at the matching offset.
    uint64_t streamstart_app = blockvector_get_apparent_blocknumber(candidate->b,
        blockvector_get_num_blocks(candidate->b) - 1);
    int64_t total_apparent = filemirror_apparent_blocks(scalpel_state.filemirror);

    // Smallest xref offset beyond the header block = the next object to anchor on.
    int64_t next_off = -1;
    for (int i = 0; i < entry_count; i++) {
        if (entries[i].obj_offset >= (uint64_t)len &&
            (next_off < 0 || entries[i].obj_offset < (uint64_t)next_off)) {
            next_off = entries[i].obj_offset;
        }
    }
    if (next_off < 0) return 0;       // no second object beyond the header

    // Contiguous blocks past the header needed to cover next_off, bounded so a
    // bogus far offset can't drive a huge probe allocation/scan.
    const int64_t max_extend = 128;   // ~1 MB window at 8 KB blocks
    int64_t need = (next_off - len) / (int64_t)scalpel_state.blocksize + 1;
    if (need < 1 || need > max_extend) return 0;
    if ((int64_t)streamstart_app + need >= total_apparent) return 0;

    int64_t window_len = len + need * (int64_t)scalpel_state.blocksize;
    char *window = (char*)malloc((size_t)window_len);
    if (!window) return 0;
    memcpy(window, data, (size_t)len);

    bool ok = true;
    for (int64_t k = 1; k <= need; k++) {
        char *blk = (char*)get_apparent_block_data(scalpel_state.filemirror, streamstart_app + k);
        if (!blk) { ok = false; break; }
        memcpy(window + len + (k - 1) * (int64_t)scalpel_state.blocksize, blk, scalpel_state.blocksize);
        free(blk);
    }

    int confirmed = 0;
    if (ok) {
        for (int i = 0; i < entry_count; i++) {
            if (entries[i].obj_offset < (uint64_t)len) continue;          // already handled in Tier 1
            if (entries[i].obj_offset >= (uint64_t)window_len) continue;  // beyond the probe window
            if (validate_at_offset(window, entries[i].obj_offset, entries[i].obj_num, window_len) == 1)
                confirmed++;
        }
    }
    free(window);
    // in_header is 1 here; add whatever the extended window confirmed
    return confirmed ? in_header + confirmed : 0;
}

/**
 * @description  Verifies that a FlateDecode stream body actually decompresses --
 *               a direct content check on the stream-interior blocks that object-
 *               offset validation cannot see. Conservative: judges only bytes that
 *               form a valid zlib header (CM=8, CINFO<=7, FCHECK mod-31) and rejects
 *               only on definitive inflate corruption (Z_DATA_ERROR/Z_NEED_DICT), so
 *               a truncated stream or a non-zlib encoding (filter chain, raw) is
 *               never failed.
 * @param buf   The assembled stream body bytes.
 * @param len   Length of the body.
 * @return       false only if the bytes are a real zlib stream that inflate reports
 *               as corrupt; true otherwise.
 */
static bool pdf_flate_body_ok(const unsigned char *buf, size_t len) {
    if (len < 2) return true;
    unsigned cmf = buf[0], flg = buf[1];
    if ((cmf & 0x0f) != 8) return true;                 // not deflate
    if ((cmf >> 4) > 7) return true;                    // invalid window size
    if ((((unsigned)cmf << 8) | flg) % 31 != 0) return true;  // header checksum fails
    z_stream s; memset(&s, 0, sizeof s);
    if (inflateInit2(&s, 15) != Z_OK) return true;
    unsigned char out[16384];
    bool corrupt = false;
    s.next_in = (Bytef *)buf; s.avail_in = (uInt)len;
    for (;;) {
        s.next_out = out; s.avail_out = sizeof out;
        int ret = inflate(&s, Z_NO_FLUSH);
        if (ret == Z_DATA_ERROR || ret == Z_NEED_DICT) { corrupt = true; break; }
        if (ret == Z_STREAM_END) break;
        if (ret == Z_BUF_ERROR) break;                  // out of input; not definitive
        if (s.avail_in == 0 && s.avail_out != 0) break; // consumed all input
    }
    inflateEnd(&s);
    return !corrupt;
}

/**
 * @description  Verifies that a DCTDecode (JPEG) stream body is structurally intact
 *               by feeding it through the same marker/scan state machine the JPEG
 *               reassembler uses; a wrong interior block violates byte-stuffing or
 *               the marker grammar and sets r.malformed. Self-gates on the SOI
 *               signature (FF D8) so a filter chain or mis-associated dict is
 *               skipped, and rejects only on definitive corruption, never on merely
 *               failing to reach EOI.
 * @param buf   The assembled stream body bytes.
 * @param len   Length of the body.
 * @return       false only if the marker state machine flags malformation; true
 *               otherwise.
 */
static bool pdf_jpeg_body_ok(const unsigned char *buf, size_t len) {
    if (len < 3 || buf[0] != 0xFF || buf[1] != 0xD8) return true;   // not a JPEG SOI
    JpegStreamReassembler r;
    memset(&r, 0, sizeof r);
    r.state = J_START;
    r.stream_length = len;
    for (size_t i = 0; i < len; i++) {
        jpeg_feed_byte(&r, buf[i]);
        if (r.malformed) return false;
        if (r.state == J_DONE) break;                              // EOI reached
    }
    return true;
}

/**
 * @description  Returns false if any validated stream fails a content check -- i.e.
 *               a wrong block lives inside a stream body, which object-offset
 *               validation cannot see. Bounds each stream by the literal "stream"/
 *               "endstream" keywords and dispatches its body to the per-format
 *               verifier, each of which self-gates on its signature so an
 *               unrecognised or chained encoding is skipped, never failed.
 * @param data        The assembled candidate buffer.
 * @param length      Length of the buffer.
 * @param tables      The xref tables locating object headers.
 * @param num_tables  Count of those tables.
 * @return       false if a stream body fails its content check; true otherwise.
 */
static bool pdf_streams_decode_ok(char *data, uint64_t length,
                                  XrefTables *tables, int num_tables) {
    for (int t = 0; t < num_tables; t++) {
        if (!tables[t].entries) continue;
        for (int j = 0; j < tables[t].count; j++) {
            uint64_t off = tables[t].entries[j].obj_offset;
            if (off + 8 >= length) continue;

            char *endobj = (char*)memmem(data + off, length - off, "endobj", 6);
            uint64_t obj_end = endobj ? (uint64_t)(endobj - data) : length;
            char *sk = (char*)memmem(data + off, obj_end - off, "stream", 6);
            if (!sk) continue;                                    // not a stream object
            uint64_t dict_len = (uint64_t)(sk - (data + off));
            bool is_flate = memmem(data + off, dict_len, "FlateDecode", 11) != NULL;
            bool is_dct   = memmem(data + off, dict_len, "DCTDecode",   9)  != NULL;
            if (!is_flate && !is_dct) continue;

            uint64_t sdat = (uint64_t)(sk - data) + 6;            // past "stream"
            if (sdat < length && data[sdat] == '\r') sdat++;
            if (sdat < length && data[sdat] == '\n') sdat++;
            char *ek = (sdat < length)
                ? (char*)memmem(data + sdat, length - sdat, "endstream", 9) : NULL;
            uint64_t send = ek ? (uint64_t)(ek - data) : length;
            if (send <= sdat) continue;

            const unsigned char *body = (const unsigned char*)(data + sdat);
            size_t blen = send - sdat;
            // A filter chain names several filters; try both verifiers and let
            // each self-gate on its signature (the raw body matches at most one).
            if (is_flate && !pdf_flate_body_ok(body, blen)) return false;
            if (is_dct   && !pdf_jpeg_body_ok(body, blen))  return false;
        }
    }
    return true;
}

/*******************************************************/
/* BLOCK STATE FUNCTION DEFINITIONS                   */
/*******************************************************/

/**
 * @description  Serializes or deserializes a PDFBlockState (its object marker and
 *               xref parameters) to/from a checkpoint file, allocating the state on
 *               deserialize.
 * @param state  In/out: the block state pointer (allocated when deserializing).
 * @param fp     The checkpoint file.
 * @param mode   SERIALIZE or DESERIALIZE.
 * @return       true on success.
 */
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

/**
 * @description  Deep-copies a PDFBlockState, duplicating its xref parameter array.
 * @param srcstate  The block state to clone.
 * @return       A malloc'd copy (caller frees via pdf_free_block_state).
 */
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

/**
 * @description  Frees a PDFBlockState and its xref parameter array, nulling the
 *               caller's pointer.
 * @param state  In/out: address of the block state pointer to free.
 * @return       Void.
 */
static inline void pdf_free_block_state(void **state){
    PDFBlockState **s = ((PDFBlockState **)state);
    if (*s) {
        free((*s)->xref_block_data);
        free(*s);
        *s = NULL;
    }
}

/**
 * @description  Debug hook to print a PDFBlockState's fields (body currently
 *               disabled).
 * @param state  The block state to print.
 * @return       Void.
 */
static inline void pdf_print_block_state(const void *state) {
  PDFBlockState *s = (PDFBlockState *)state;

//   if (s) {
//     fprintf(stdout, "For this block, xref_start was %d, xref_end was %d and, obj was %d\n",
//             s->xref_start, s->xref_end, s->first_obj);
//   }
}

/**
 * @description  Resolves the per-block PDF state for an apparent block number,
 *               mapping it to its actual block and skipping blocks classified
 *               INVALID for this needle.
 * @param candidate   The candidate whose needle scopes the lookup.
 * @param apparent    The apparent block number.
 * @param out_actual  Out (optional): the actual block number.
 * @return       The block's PDFBlockState, or NULL if unavailable or invalid.
 */
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
/* CARVE STATE FUNCTION DEFINITIONS                   */
/*******************************************************/

/**
 * @description  Serializes or deserializes a PDFCarveState (its xref tables,
 *               object entries, and linearization fields) to/from a checkpoint file,
 *               allocating the state on deserialize.
 * @param state  In/out: the carve state pointer (allocated when deserializing).
 * @param fp     The checkpoint file.
 * @param mode   SERIALIZE or DESERIALIZE.
 * @return       true on success.
 */
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
        (*s)->linearized = false;
        (*s)->lin_L = -1;
        (*s)->lin_T = -1;
    }

    // Serialize/deserialize number of xref tables
    if (fb(&(*s)->num_tables, sizeof(size_t), 1, fp) != 1) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    // Linearization parameters. These must be written and read in the same
    // order as every other field: this changes the on-disk checkpoint format,
    // so checkpoints written before this field was added cannot be resumed.
    if (fb(&(*s)->linearized, sizeof(bool), 1, fp) != 1) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
    if (fb(&(*s)->lin_L, sizeof(int64_t), 1, fp) != 1) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
    if (fb(&(*s)->lin_T, sizeof(int64_t), 1, fp) != 1) {
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

/**
 * @description  Deep-copies a PDFCarveState, duplicating its array of xref tables
 *               and each table's object entries.
 * @param srcstate  The carve state to clone.
 * @return       A malloc'd copy (caller frees via pdf_free_carve_state), or NULL
 *               if srcstate is NULL.
 */
static inline void *pdf_clone_carve_state(const void *srcstate) {
    const PDFCarveState *s = (const PDFCarveState *)srcstate;
    if (!s) return NULL;

    PDFCarveState *d = malloc(sizeof(PDFCarveState));
    check_memory_allocation(d, __LINE__, __FILE__, "fpdf_clone_carve_state");

    /* Copy scalar fields */
    d->num_tables = s->num_tables;
    d->incomplete_obj = s->incomplete_obj;
    d->linearized = s->linearized;
    d->lin_L = s->lin_L;
    d->lin_T = s->lin_T;
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

/**
 * @description  Frees a PDFCarveState, releasing every xref table's entries, the
 *               table array, and the state itself, then nulls the caller's pointer.
 * @param state  In/out: address of the carve state pointer to free.
 * @return       Void.
 */
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

/**
 * @description  Debug hook to report a PDFCarveState's xref tables and entries
 *               (per-table body currently disabled).
 * @param state  The carve state to print.
 * @return       Void.
 */
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
/* REASSEMBLY FUNCTION DEFINITIONS                    */
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

/**
 * @description  Initialises a candidate's PDF carve state: reads the linearization
 *               parameters from the header block, then scans the candidate's own
 *               data for every xref (classic table or stream), analyses each into a
 *               table, and stores the state on the candidate.
 * @param id         The reassembly id (unused).
 * @param candidate  The candidate to initialise.
 * @param uuidp      The candidate's parent uuid string (unused).
 * @param uuidc      The candidate's uuid string (unused).
 * @return       Void.
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

    // Read the linearization parameters before scanning for xrefs: they decide
    // how a scanned xref gets anchored, and they are only readable from the
    // header block.
    pdf_detect_linearization(carve_state, data, length);

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
#ifdef PDF_TRACE_PLACEMENT
        pdf_trace_table_adopt(candidate, "INIT", xref_tables[xref_count].entries,
                              xref_tables[xref_count].count, -1);
#endif
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

/**
 * @description  Grows a candidate's block vector to make room for an extension,
 *               disabling the fast path: by one block for an object extension, or by
 *               num_blocks for an endstream extension, and updates best_validates_to.
 * @param id          The reassembly id (unused).
 * @param candidate   The candidate to grow.
 * @param num_blocks  Blocks to add for an ENDSTREAMEXTENSION.
 * @param mode        OBJECTEXTNSION or ENDSTREAMEXTENSION.
 * @return       Void.
 */
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

/**
 * @description  Selects the next block for an extension according to mode:
 *               NEXTOBJECT finds the block whose first object matches obj_num;
 *               FINDENDSTREAM finds a block carrying "endstream" at the expected
 *               local offset (spanning a boundary if needed); EXTENDSTREAMFROMSTART/
 *               EXTENDSTREAMFROMEND pick the contiguous block relative to the stream
 *               start or end. NEXTOBJECT and FINDENDSTREAM cross-check the block
 *               against target_slot's xref objects when target_slot >= 0.
 * @param candidate               The candidate being extended.
 * @param obj_num                 Object number sought (NEXTOBJECT).
 * @param endstream_local_offset  Block-local offset of endstream (FINDENDSTREAM).
 * @param streamstart_block_app   Apparent block of the stream start (EXTEND*FROMSTART).
 * @param endstream_block_app     Apparent block of the stream end (EXTEND*FROMEND).
 * @param stream_blocks_extended  Blocks already extended, offsetting the contiguous pick.
 * @param mode                    The selection mode.
 * @param target_slot             Slot to cross-check against the xref, or -1 to skip.
 * @return       The chosen apparent block number, or -1 if none qualifies.
 */
int64_t pdf_reassembly_get_block_choice(CarveInfo *candidate,
                                        int obj_num,
                                        int32_t endstream_local_offset,
                                        uint64_t streamstart_block_app,
                                        uint64_t endstream_block_app,
                                        int32_t stream_blocks_extended,
                                        int mode,
                                        int64_t target_slot){
    bool possible_match = false;
    BlockVector *scan_bv = NULL;
    uint64_t slot = 0;
    int64_t start = 0;
    uint64_t evaluated;
    int64_t block_choice;
    int64_t result = -1;
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
            if(match){
                if (target_slot >= 0 &&
                    !pdf_block_matches_xref_slot(candidate, block_choice, (uint64_t)target_slot))
                    continue;                  // first_obj collided; xref disagrees
                result = block_choice; goto cleanup;
            }
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
                    if (target_slot >= 0 &&
                        !pdf_block_matches_xref_slot(candidate, block_choice, (uint64_t)target_slot))
                        continue;              // syntactic match, wrong file: keep looking
                    result = block_choice;
                    goto cleanup;
                }
                free(data);
            }
        }
        // The endstream keyword straddles a block boundary: pair each block with
        // its apparent successor and look for the keyword across the seam.
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
                result = block_choice;
                goto cleanup;
            }
            free(data);
        }
    }

    if(mode == EXTENDSTREAMFROMSTART){
        block_choice = blockvector_get_choice(scan_bv, slot,
            streamstart_block_app + stream_blocks_extended, -1, &evaluated);
        if(block_choice != -1){ result = block_choice; goto cleanup; }
    }

    if(mode == EXTENDSTREAMFROMEND){
        block_choice = blockvector_get_choice(scan_bv, slot,
            endstream_block_app - stream_blocks_extended, -1, &evaluated);
        if(block_choice != -1){ result = block_choice; goto cleanup; }
    }
cleanup:
    free_blockvector(&scan_bv);
    return result;
}

/**
 * @description  Commits the block in candidate->newblock into a slot: records its
 *               apparent number, inflates that single new block, and extends the
 *               candidate's validated length by one block.
 * @param id                  The reassembly id (unused).
 * @param candidate           The candidate receiving the block.
 * @param logical_slot_index  The slot the block is written to.
 * @return       Void.
 */
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

/**
 * @description  Fills interior stream-body holes left after xref adoption. Positional
 *               xref placement lands object-HEADER blocks at their true slots but
 *               never reconstructs the streams BETWEEN them, so a linearized/gapped
 *               file can finish with correct headers and holed stream interiors. For
 *               each FlateDecode stream whose interior is holed, this verifies the
 *               disk-contiguous hypothesis by inflating the contiguous run to
 *               Z_STREAM_END (Adler-32) and, ONLY on success, places the interior
 *               blocks -- so a wrong guess can never be committed. Limited to zlib
 *               streams because their checksum makes the fill verifiable.
 * @param work       The thread work context (unused).
 * @param candidate  The candidate whose interior stream holes are filled.
 * @return       true if any hole was filled.
 */
static bool pdf_fill_interior_stream_holes(ThreadWork *work, CarveInfo *candidate){
    (void)work;
    FileMirror *fm = scalpel_state.filemirror;
    const int64_t bsz = (int64_t)scalpel_state.blocksize;
    bool any = false;

    PDFCarveState *cs = (PDFCarveState*)carve_get_state(candidate->carvehashkey);
    if(!cs) return false;

    char *data = blockvector_get_data_pointer(candidate->b);
    int64_t length = (int64_t)blockvector_get_data_length(candidate->b);

    for(int t = 0; t < (int)cs->num_tables; t++){
        XrefTables *tab = &cs->xref_tables[t];
        if(!tab->entries) continue;
        for(int e = 0; e < tab->count; e++){
            int64_t obj_off = (int64_t)tab->entries[e].obj_offset;
            if(obj_off < 0 || obj_off + 16 >= length) continue;
            if(blockvector_get_apparent_blocknumber(candidate->b, obj_off / bsz) < 0) continue; // header block a hole

            // The dict is object-header .. "stream". Bound the search to a small
            // window so a non-stream object doesn't match a far-away keyword.
            int64_t win = obj_off + 4000; if(win > length) win = length;
            char *sk = (char*)memmem(data + obj_off, (size_t)(win - obj_off), "stream", 6);
            if(!sk) continue;
            if(sk - data >= 3 && !memcmp(sk - 3, "end", 3)) continue;          // "endstream", not a dict
            int dict_len = (int)(sk - (data + obj_off));
            if(check_last_object_filter(data + obj_off, dict_len) != ZLIB) continue;

            uint64_t out_off = 0;
            int slen = check_last_object_length(data, (uint64_t)length, &out_off,
                          cs->xref_tables, (int)cs->num_tables, data + obj_off, dict_len, (uint64_t)obj_off);
            if(slen == LENGTHNOTFOUND || slen <= 0) continue;

            int64_t sdat = (sk - data) + 6;
            if(sdat < length && data[sdat] == '\r') sdat++;
            if(sdat < length && data[sdat] == '\n') sdat++;
            int64_t send = sdat + slen;
            int64_t sslot = sdat / bsz, eslot = (send - 1) / bsz;
            int span = (int)(eslot - sslot);                                   // blocks after the start block
            if(span <= 0 || span > 4096) continue;                            // single-block or implausibly large
            if(eslot >= (int64_t)blockvector_get_num_blocks(candidate->b)) continue;

            bool has_hole = false;
            for(int64_t s = sslot + 1; s <= eslot && !has_hole; s++)
                if(blockvector_get_apparent_blocknumber(candidate->b, s) < 0) has_hole = true;
            if(!has_hole) continue;

            // Inflate the stream from its start block, using each slot's ALREADY-
            // PLACED block where one exists and the disk-contiguous hypothesis
            // (D0+k) only for the actual holes. Place nothing unless Z_STREAM_END is
            // reached (Adler-32 over the whole output), and then fill only the holes
            // the verified run covered -- so a wrong contiguity guess can never be
            // committed, and a stream whose end (or other) blocks are placed non-
            // contiguously still verifies via those placed anchors.
            int64_t D0 = filemirror_actual_blocknumber(fm, blockvector_get_apparent_blocknumber(candidate->b, sslot));
            ZlibStreamReassembler r;
            if(zlib_stream_reassembler_init(&r, (const unsigned char*)(data + sslot * bsz),
                   (size_t)bsz, (size_t)(sdat - sslot * bsz), (size_t)slen) == -1) continue;
            bool ok = true, complete = false; int kdone = 0;
            for(int k = 1; k <= span; k++){
                int64_t sapp = blockvector_get_apparent_blocknumber(candidate->b, sslot + k);
                int64_t app = (sapp >= 0) ? sapp : filemirror_apparent_blocknumber(fm, D0 + k);
                if(app < 0){ ok = false; break; }
                unsigned char *blk = (unsigned char*)get_apparent_block_data(fm, app);
                if(!blk){ ok = false; break; }
                int chk = zlib_stream_reassembler_try_block(&r, blk, (size_t)bsz);
                free(blk);
                if(chk == 2){ complete = true; kdone = k; break; }
                if(chk != 1){ ok = false; break; }
                kdone = k;
            }
            zlib_stream_reassembler_free(&r);
            if(!(ok && complete)) continue;                                    // unverified: leave the holes

            for(int k = 1; k <= kdone; k++){
                if(blockvector_get_apparent_blocknumber(candidate->b, sslot + k) >= 0) continue; // already placed
                int64_t hb = D0 + k;
                if(pdf_place_blocks_at_slot(candidate, &hb, 1, (uint64_t)(sslot + k), "ZLIB_HOLE_FILL")){
                    any = true;
                    data = blockvector_get_data_pointer(candidate->b);
                    length = (int64_t)blockvector_get_data_length(candidate->b);
                }
            }
        }
    }
    pdf_free_carve_state((void**)&cs);
    return any;
}

/**
 * @description  Completes a candidate that assembled every object but is missing
 *               only its final trailer block(s). A PDF's last block holds the
 *               trailer keywords -- "startxref" and the terminal "%%EOF" -- but no
 *               indirect object, so the object-driven placement never pulls it in,
 *               nor does xref adoption (it is a separate block from the xref). A
 *               file that is byte-correct except for this tail cannot validate for
 *               want of its end. When a 0-hole candidate does not already end in
 *               "%%EOF", this walks the disk-contiguous continuation (last placed
 *               block + 1, then + 2) and appends ONLY blocks carrying the trailer
 *               signature, stopping at the one that ends the file. Safety rests on
 *               the trailer signature plus the final pdf_file_validate, which
 *               authenticates startxref -> xref -> root against the assembled body:
 *               a foreign or wrong tail cannot make a wrong body validate, so no
 *               byte-inexact candidate is promoted.
 * @param work       The thread work context (unused).
 * @param candidate  The candidate to complete.
 * @return       true if a trailer block was appended.
 */
static bool pdf_complete_trailer(ThreadWork *work, CarveInfo *candidate){
    (void)work;
    FileMirror *fm = scalpel_state.filemirror;
    const int64_t bsz = (int64_t)scalpel_state.blocksize;

    // The body must be complete: a hole reads as zeroes the validator could take
    // for content, and appending a tail past it would be premature.
    if(pdf_candidate_has_holes(candidate)) return false;
    uint64_t nblocks = blockvector_get_num_blocks(candidate->b);
    if(nblocks == 0) return false;

    int64_t last_app = blockvector_get_apparent_blocknumber(candidate->b, nblocks - 1);
    if(last_app < 0) return false;

    // Already terminated: the last block carries "%%EOF". This covers every
    // complete candidate -- including the recovered files -- so they are untouched.
    {
        unsigned char *lb = (unsigned char*)get_apparent_block_data(fm, last_app);
        if(!lb) return false;
        bool terminated = memmem(lb, (size_t)bsz, "%%EOF", 5) != NULL;
        free(lb);
        if(terminated) return false;
    }

    int64_t last_actual = filemirror_actual_blocknumber(fm, last_app);
    if(last_actual < 0) return false;

    const int MAX_TRAILER = 2;   // a trailer spans at most a block or two past the body
    bool appended = false;
    for(int k = 1; k <= MAX_TRAILER; k++){
        int64_t d_actual = last_actual + k;
        int64_t d_app = filemirror_apparent_blocknumber(fm, d_actual);
        if(d_app < 0) break;
        unsigned char *blk = (unsigned char*)get_apparent_block_data(fm, d_app);
        if(!blk) break;
        bool has_sx  = memmem(blk, (size_t)bsz, "startxref", 9) != NULL;
        bool has_eof = memmem(blk, (size_t)bsz, "%%EOF", 5) != NULL;
        free(blk);
        if(!has_sx && !has_eof) break;   // not a trailer continuation -- stop

        uint64_t slot = blockvector_get_num_blocks(candidate->b);
        if(!pdf_place_blocks_at_slot(candidate, &d_actual, 1, slot, "TRAILER_FILL")) break;
        appended = true;
        if(has_eof) break;               // reached the terminal block
    }
    return appended;
}

/**
 * @description  Top-level PDF reassembly driver for a candidate. Strategy 1 extends
 *               using the xref tables already in the candidate; strategies 2 and 3
 *               then loop, exhaustively scanning the image for a matching xref
 *               (kept by best-match score) and following /Prev chains, until neither
 *               extends the candidate further.
 * @param work   The thread work context.
 * @param c      In/out: the candidate being reassembled (may be replaced).
 * @param uuidp  The candidate's parent uuid string.
 * @param uuidc  The candidate's uuid string.
 * @return       Void.
 */
void pdf_reassembly(ThreadWork *work,
		            CarveInfo **c,
		            uuid_string_t uuidp,
		            uuid_string_t uuidc){

    CarveInfo *candidate = *c;
#ifdef PDF_TRACE_REASM
    uint64_t dbg_start_blocks = blockvector_get_num_blocks(candidate->b);
    int dbg_s2_scans = 0, dbg_s2_best = -1, dbg_s2_found = 0;
#endif

    /* === Strategy 1: extend using xref tables already in the candidate === */
    pdf_reassembly_init_candidate(work->id, candidate, uuidp, uuidc);
    {
        PDFCarveState *carve_state = (PDFCarveState*)carve_get_state(candidate->carvehashkey);
        if(carve_state) {
            for(size_t i = 0; i < carve_state->num_tables; i++)
                sort_xref_data_by_offset(&carve_state->xref_tables[i]);
            carve_put_state(candidate->carvehashkey, carve_state);
            pdf_free_carve_state((void**)&carve_state);
            pdf_reassembly_extension(work, c, NULL, 0, NULL, 0, -1, false);
            candidate = *c;
        }
    }

    /* === Strategies 2 & 3: loop until neither extends the candidate === */
    bool extended;
    
    do {
        extended = false;
        uint64_t blocks_before = blockvector_get_num_blocks(candidate->b);

        /* === Strategy 2: exhaustively scan for a matching xref === */
        {
            /*
             * Score EVERY xref the scan can reach and keep the strongest, rather
             * than accepting the first over a threshold. First-match is a multiple-
             * comparisons trap: with many files' xrefs in an image each ~1% likely
             * to falsely confirm, a false accept becomes near-certain, and an adopted
             * foreign xref pulls in whole relocated runs of another file that no
             * per-block check can detect. A file's own xref confirms 2..68 objects
             * here, a foreign one never more than 4; argmax exploits that gap.
             */
            const int MIN_CONFIRMATIONS = 2;   // minimum bar; argmax rejects foreign xrefs
            // No cap on the number of xrefs scored -- a file's own xref may sit
            // anywhere among the image's xref blocks. The loop self-terminates
            // when scan_blocks_for_xref runs out of xrefs.

            Object *entries = NULL;
            int entry_count = 0;
            int64_t *xref_blocks = NULL;
            int xref_block_count = 0;
            int32_t xref_local = -1;
            BlockVector *scan_bv = NULL;

            Object  *best_entries = NULL;
            int      best_entry_count = 0;
            int64_t *best_blocks = NULL;
            int      best_block_count = 0;
            int32_t  best_local = -1;
            int      best_score = 0;

            for(;;){
                free(entries); entries = NULL;
                free(xref_blocks); xref_blocks = NULL; xref_block_count = 0;
                entries = scan_blocks_for_xref(candidate, &scan_bv, &entry_count, &xref_blocks, &xref_block_count, &xref_local);
                if(!entries || entry_count <= 0){ free(entries); entries = NULL; break; }

                int score = pdf_xref_confirms_header(candidate, entries, entry_count);
#ifdef PDF_TRACE_REASM
                dbg_s2_scans++; dbg_s2_found = 1;
                if(score > dbg_s2_best) dbg_s2_best = score;
#endif
                if(score > best_score){
                    free(best_entries); free(best_blocks);
                    best_entries = entries;      entries = NULL;      // ownership moves
                    best_blocks  = xref_blocks;  xref_blocks = NULL;
                    best_entry_count = entry_count;
                    best_block_count = xref_block_count; xref_block_count = 0;
                    best_local  = xref_local;
                    best_score  = score;
                }
#ifdef PDF_FIRST_MATCH_XREF
                // Diagnostic mode: stop at the first xref over the bar, reproducing
                // the pre-argmax behaviour so the two can be diffed.
                if(best_score >= MIN_CONFIRMATIONS) break;
#endif
            }
            free(entries); entries = NULL;
            free(xref_blocks); xref_blocks = NULL;
            if(scan_bv) free_blockvector(&scan_bv);

            bool possible_match = (best_score >= MIN_CONFIRMATIONS);
            entries          = best_entries;
            entry_count      = best_entry_count;
            xref_blocks      = best_blocks;
            xref_block_count = best_block_count;
            xref_local       = best_local;

            if(possible_match){
                // The scan found WHICH blocks hold the xref; recover WHERE they
                // belong before handing them over. -1 means unresolved, and the
                // extension falls back to appending at the frontier.
                int64_t xref_slot = pdf_resolve_xref_slot(candidate, xref_blocks,
                                                          xref_block_count, xref_local);
                pdf_reassembly_extension(work, c, entries, entry_count, xref_blocks, xref_block_count, xref_slot, true);
            }
            else
                free(entries);
            free(xref_blocks);
            candidate = *c;
        }

        /* === Strategy 3: follow /Prev chain to a table outside the candidate === */
        {
            int xref_type;
            uint64_t search_pos = 0;
            const char *first_xref = scan_buf_for_xref(blockvector_get_data_pointer(candidate->b),
                blockvector_get_data_length(candidate->b), search_pos, &xref_type);
            int64_t xref_offset = first_xref - blockvector_get_data_pointer(candidate->b);
            int64_t prev_entry = find_prev_entry(blockvector_get_data_pointer(candidate->b),
                blockvector_get_data_length(candidate->b), xref_offset, xref_type);
            if(prev_entry > 0){
                int64_t tmp;
                int prev_check = detect_xref_type(blockvector_get_data_pointer(candidate->b),
                    prev_entry, blockvector_get_data_length(candidate->b), &tmp);
                if(prev_check == -1){
                    uint64_t xref_local_block_offset = prev_entry % scalpel_state.blocksize;
                    int prev_entry_count = 0;
                    int64_t *prev_xref_blocks = NULL;
                    int prev_xref_block_count = 0;
                    BlockVector *scan_bv = NULL;
                    Object *prev_entries = scan_blocks_for_xref_at_offset(candidate, scan_bv,
                        &prev_entry_count, &prev_xref_blocks, &prev_xref_block_count,
                        (int32_t)xref_local_block_offset);
                    if(prev_entries && prev_entry_count > 0){
                        bool xref_already_present = false;
                        for(int b = 0; b < prev_xref_block_count && !xref_already_present; b++){
                            uint64_t new_app = filemirror_apparent_blocknumber(scalpel_state.filemirror, prev_xref_blocks[b]);
                            for(uint64_t k = 0; k < blockvector_get_num_blocks(candidate->b) && !xref_already_present; k++){
                                if((uint64_t)blockvector_get_apparent_blocknumber(candidate->b, k) == new_app)
                                    xref_already_present = true;
                            }
                        }
                        // Attribute the /Prev table before adopting it: /Prev is read
                        // from the candidate's current bytes, so a foreign xref block
                        // would otherwise point its /Prev into that other file.
                        int prev_score = pdf_xref_confirms_header(candidate, prev_entries, prev_entry_count);
                        if(!xref_already_present && prev_score >= 2){
#ifdef PDF_TRACE_PLACEMENT
                            pdf_trace_table_adopt(candidate, "PREV", prev_entries, prev_entry_count, prev_score);
#endif
                            PDFCarveState *carve_state = (PDFCarveState*)carve_get_state(candidate->carvehashkey);
                            XrefTables prev_table;
                            prev_table.entries = prev_entries;
                            prev_table.count = prev_entry_count;
                            add_xref_table(carve_state, &prev_table, 0);
                            carve_put_state(candidate->carvehashkey, carve_state);
                            pdf_free_carve_state((void**)&carve_state);
                            prev_entries = NULL;

                            // prev_entry is an absolute file offset, so the slot is
                            // exact; scan_blocks_for_xref_at_offset() already confirmed
                            // these blocks carry the xref there.
                            pdf_place_blocks_at_slot(candidate, prev_xref_blocks,
                                prev_xref_block_count,
                                (uint64_t)(prev_entry / (int64_t)scalpel_state.blocksize),
                                "PREV_XREF");

                            pdf_reassembly_extension(work, c, NULL, 0, NULL, 0, -1, false);
                        }
                    }
                    free(prev_entries);
                    free(prev_xref_blocks);
                }
            }
            candidate = *c;
        }

        if(blockvector_get_num_blocks(candidate->b) > blocks_before)
            extended = true;

    } while(extended);

    candidate = *c;

    // Xref adoption places object-HEADER blocks but not the stream interiors
    // between them; fill any verifiable interior holes before validating.
    pdf_fill_interior_stream_holes(work, candidate);

    // A fully-assembled body can still lack its final trailer block (startxref +
    // %%EOF), which holds no object and so is never placed; append it so the file
    // can terminate and validate.
    pdf_complete_trailer(work, candidate);

    // Extension is done. Run the file validator on the assembled result: if it
    // validates as a complete PDF, trim the blockvector to the validated length
    // and promote to VALIDATED, otherwise write it as a PROMISING candidate.
#ifdef PDF_TRACE_REASM
    {
        uuid_string_t uu; uuid_unparse_lower(candidate->binuuid, uu);
        lock_fprintf(stdout,
            "[PDFREASM] uuid=%.8s start_blocks=%" PRIu64 " final_blocks=%" PRIu64
            " s2_scans=%d s2_found=%d s2_best_score=%d\n",
            uu, dbg_start_blocks, blockvector_get_num_blocks(candidate->b),
            dbg_s2_scans, dbg_s2_found, dbg_s2_best);
    }
#endif
    bool validates = false;
    bool promising = true;
    uint64_t validates_to = scalpel_state.blocksize - 1;
    pdf_file_validate(blockvector_get_data_pointer(candidate->b),
                      blockvector_get_data_length(candidate->b),
                      &validates, &validates_to, &promising,
                      candidate->needleidx, scalpel_state.blocksize,
                      candidate->carvehashkey);

    // Positional placement can leave unfilled slots between the frontier and an
    // anchored block. Those read back as zeroes, which the validator above can
    // mistake for real content, so a candidate with holes is never VALIDATED.
    if (validates && pdf_candidate_has_holes(candidate)) {
        validates = false;
        promising = true;
    }

    if (validates) {
        blockvector_set_data_length(candidate->b, validates_to + 1);
        resize_blockvector(candidate->b,
            CEILDIV(blockvector_get_data_length(candidate->b), scalpel_state.blocksize));

        // Atomically claim this file's body blocks; only the first candidate to
        // claim a given body is validated, so converging header candidates cannot
        // each emit a VALIDATED copy. A later duplicate is demoted to PROMISING.
        if (pdf_claim_body_blocks_or_duplicate(candidate)) {
            candidate->flavor = PROMISING;
            write_candidate(&candidate, true);
        } else {
            candidate->flavor = VALIDATED;
            write_candidate(&candidate, false);
        }
    } else {
        candidate->flavor = PROMISING;
        write_candidate(&candidate, true);
    }
    return;
}

/**
 * @description  Extends a candidate from its current xref knowledge: optionally
 *               adopts a newly scanned xref table (placing its blocks at xref_slot),
 *               then walks the objects the tables expect and appends the blocks that
 *               carry them, invoking the per-filter stream reassemblers for stream
 *               objects, until the candidate stops growing.
 * @param work             The thread work context.
 * @param c                In/out: the candidate being extended (may be replaced).
 * @param new_entries      A newly scanned xref's entries to adopt, or NULL.
 * @param new_entry_count  Count of those entries.
 * @param xref_blocks      The blocks holding the new xref, or NULL.
 * @param xref_block_count Count of those blocks.
 * @param xref_slot        The slot to place the new xref blocks at, or -1.
 * @param save_new_table   Whether to persist the new table into carve state.
 * @return       Void.
 */
static void pdf_reassembly_extension(ThreadWork *work,
                                     CarveInfo **c,
                                     Object *new_entries,
                                     int new_entry_count,
                                     int64_t *xref_blocks,
                                     int xref_block_count,
                                     int64_t xref_slot,
                                     bool save_new_table){
    CarveInfo *candidate = *c;
    XrefTables *temp_tables = NULL;
    XrefTables *test_tables = NULL;
    ObjectHashTable **xref_hashes = NULL;
    int obj_count = 0;
    int num_tables = 0;
    bool xref_validated = false;

    int *present_objects = list_candidate_objects(blockvector_get_data_pointer(candidate->b),
        blockvector_get_data_length(candidate->b), &obj_count);
    char *data = blockvector_get_data_pointer(candidate->b);

    {
        PDFCarveState *carve_state = (PDFCarveState*)carve_get_state(candidate->carvehashkey);
        if(carve_state){
            num_tables = (int)carve_state->num_tables;
            pdf_free_carve_state((void**)&carve_state);
        }
    }

    ObjectHashTable **temp_hashes = (ObjectHashTable**)realloc(xref_hashes, (num_tables + 1) * sizeof(ObjectHashTable*));
    if(temp_hashes == NULL){
        free(xref_hashes);
        free(present_objects);
        printf("FAILED TO REALLOCATE XREF_HASHES\n");
        pdf_inflight_tables = NULL; pdf_inflight_table_count = 0; return;
    }
    xref_hashes = temp_hashes;
    temp_tables = (XrefTables*)realloc(test_tables, (num_tables + 1) * sizeof(XrefTables));
    if(temp_tables == NULL){
        free(xref_hashes);
        free(present_objects);
        printf("FAILED TO REALLOCATE TEST_TABLES\n");
        pdf_inflight_tables = NULL; pdf_inflight_table_count = 0; return;
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

    test_tables[num_tables].count = new_entry_count;
    test_tables[num_tables].entries = new_entries;
    if(new_entries && new_entry_count > 0)
        sort_xref_data_by_offset(&test_tables[num_tables]);

    for(int i = 0; i <= num_tables; i++){
        if(test_tables[i].entries && test_tables[i].count > 0){
            int bucket_count = 101;
            if(test_tables[i].count > 100) bucket_count = 509;
            if(test_tables[i].count > 500) bucket_count = 1009;
            if(test_tables[i].count > 2000) bucket_count = 2017;
            xref_hashes[i] = hash_table_create(bucket_count);
            if(xref_hashes[i]){
                for(int j = 0; j < test_tables[i].count; j++){
                    hash_table_insert(xref_hashes[i],
                                 test_tables[i].entries[j].obj_num,
                                 j);
                }
            }
        } else {
            xref_hashes[i] = NULL;
        }
    }

    // Publish the tables this pass is working from so pdf_block_matches_xref_slot()
    // can see the table we just scanned, which is not in carve state yet.
    pdf_inflight_tables = test_tables;
    pdf_inflight_table_count = num_tables + 1;

    int current_table = -1;
    int current_object = -1;
    int current_object_idx = -1;
    int check = -1;
    for(int i = 0; i < num_tables + 1; i++){
        current_table = i;
        for(int j = 0; j < test_tables[i].count; j++){
            check = validate_at_offset(data, test_tables[i].entries[j].obj_offset,
                test_tables[i].entries[j].obj_num, blockvector_get_data_length(candidate->b));
            current_object = test_tables[i].entries[j].obj_num;
            current_object_idx = j;

            if(check == 1){
                xref_validated = true;
                int32_t endstream_local_offset = -1;
                int32_t startstream_local_offset = -1;
                data = blockvector_get_data_pointer(candidate->b);
                uint64_t length = blockvector_get_data_length(candidate->b);
                int blocks_to_extend = 0;
                uint64_t offset = 0;
                int64_t obj_off = find_last_object(data, length);
                int dict_len = 0;
                char *stream_dict = (obj_off >= 0)
                    ? extract_dict(work, candidate, data, length, (uint64_t)obj_off, &dict_len)
                    : NULL;
                // extract_dict may have extended the candidate if the dict crossed a block boundary;
                // refresh data, length, and streamstart_block_app to reflect the updated blockvector
                data = blockvector_get_data_pointer(candidate->b);
                length = blockvector_get_data_length(candidate->b);
                int64_t streamstart_block_app = blockvector_get_apparent_blocknumber(candidate->b,
                    blockvector_get_num_blocks(candidate->b) - 1);
                // The frontier slot can be a hole (-1) when positional xref placement
                // extended the candidate past the reconstruction frontier; there is no
                // block to reconstruct the last object's stream from, so skip it.
                if(streamstart_block_app < 0){ free(stream_dict); continue; }
                char *first_stream_block_data = (char*)get_apparent_block_data(scalpel_state.filemirror, streamstart_block_app);
                int stream_length = stream_dict
                    ? check_last_object_length(data, length, &offset, test_tables, num_tables + 1,
                                               stream_dict, dict_len, (uint64_t)obj_off)
                    : LENGTHNOTFOUND;
                int filter = stream_dict
                    ? check_last_object_filter(stream_dict, dict_len)
                    : NOFILTER;
                free(stream_dict);

                int stream_condition = (stream_length == LENGTHNOTFOUND)
                    ? LENGTHNOTFOUND
                    : calculate_stream_offsets(data, (uint64_t)stream_length, length, offset,
                          &startstream_local_offset, &endstream_local_offset, &blocks_to_extend);
#ifdef PDF_TRACE_STALL
                { uuid_string_t uu; uuid_unparse_lower(candidate->binuuid, uu);
                lock_fprintf(stdout,
                    "[PDFSDEC] uuid=%.8s obj_off=%" PRId64 " len=%d filter=%d cond=%d bte=%d "
                    "nblocks=%" PRIu64 "\n",
                    uu, obj_off, stream_length, filter, stream_condition, blocks_to_extend,
                    blockvector_get_num_blocks(candidate->b)); }
#endif
                if(stream_condition == LENGTHNOTFOUND || stream_condition == INBLOCK){
                    free(first_stream_block_data);
                    continue;
                }
                if(filter == ZLIB){
                    if(stream_condition == INNEXTBLOCK){
                        if(!reconstruct_zlib_stream(work, candidate, first_stream_block_data,
                                startstream_local_offset, endstream_local_offset, 0,
                                (uint64_t)stream_length, INNEXTBLOCK)){
#ifdef PDF_TRACE_STALL
                            { uuid_string_t uu; uuid_unparse_lower(candidate->binuuid, uu);
                              lock_fprintf(stdout,"[PDFSTALL] uuid=%.8s obj_off=%" PRId64 " ZLIB INNEXTBLOCK failed bte=%d\n", uu, obj_off, blocks_to_extend); }
#endif
                            free(first_stream_block_data);
                            pdf_inflight_tables = NULL; pdf_inflight_table_count = 0; return;
                        }
                    }
                    if(stream_condition == MULTIBLOCK){
                        if(!reconstruct_zlib_stream(work, candidate, first_stream_block_data,
                                startstream_local_offset, endstream_local_offset, blocks_to_extend,
                                (uint64_t)stream_length, MULTIBLOCK)){
#ifdef PDF_TRACE_STALL
                            { uuid_string_t uu; uuid_unparse_lower(candidate->binuuid, uu);
                              lock_fprintf(stdout,"[PDFSTALL] uuid=%.8s obj_off=%" PRId64 " ZLIB MULTIBLOCK failed bte=%d\n", uu, obj_off, blocks_to_extend); }
#endif
                            free(first_stream_block_data);
                            pdf_inflight_tables = NULL; pdf_inflight_table_count = 0; return;
                        }
                        data = blockvector_get_data_pointer(candidate->b);
                    }
                }
                else if(filter == XML){
                    if(stream_condition == INNEXTBLOCK){
                        if(!reconstruct_xml_stream(work, candidate, first_stream_block_data,
                                startstream_local_offset, endstream_local_offset, 0,
                                (uint64_t)stream_length, INNEXTBLOCK)){
                            free(first_stream_block_data);
                            pdf_inflight_tables = NULL; pdf_inflight_table_count = 0; return;
                        }
                    }
                    if(stream_condition == MULTIBLOCK){
                        if(!reconstruct_xml_stream(work, candidate, first_stream_block_data,
                                startstream_local_offset, endstream_local_offset, blocks_to_extend,
                                (uint64_t)stream_length, MULTIBLOCK)){
                            free(first_stream_block_data);
                            pdf_inflight_tables = NULL; pdf_inflight_table_count = 0; return;
                        }
                        data = blockvector_get_data_pointer(candidate->b);
                    }
                }
                else if(filter == NOFILTER){
                    // Unfiltered stream: no decoder exists, but the extent is
                    // known exactly. Without this branch the stream is skipped
                    // entirely and its interior blocks stay holes forever.
                    if(stream_condition == MULTIBLOCK){
                        if(!reconstruct_raw_stream(work, candidate,
                                endstream_local_offset, blocks_to_extend, MULTIBLOCK)){
                            free(first_stream_block_data);
                            return;
                        }
                        data = blockvector_get_data_pointer(candidate->b);
                    }
                }
                else if(filter == JPEG){
                    if(stream_condition == INNEXTBLOCK){
                        if(!reconstruct_jpeg_stream(work, candidate, first_stream_block_data,
                                startstream_local_offset, endstream_local_offset, 0,
                                (uint64_t)stream_length, INNEXTBLOCK)){
                            free(first_stream_block_data);
                            pdf_inflight_tables = NULL; pdf_inflight_table_count = 0; return;
                        }
                    }
                    if(stream_condition == MULTIBLOCK){
                        if(!reconstruct_jpeg_stream(work, candidate, first_stream_block_data,
                                startstream_local_offset, endstream_local_offset, blocks_to_extend,
                                (uint64_t)stream_length, MULTIBLOCK)){
                            free(first_stream_block_data);
                            pdf_inflight_tables = NULL; pdf_inflight_table_count = 0; return;
                        }
                        data = blockvector_get_data_pointer(candidate->b);
                    }
                }
                free(first_stream_block_data);
            }

            /*
             * Acquire the block backing this object. The trigger is "the slot
             * holding this object is missing", not "the offset is past the end":
             * placing xref blocks at their true slot extends the candidate beyond
             * the reconstruction frontier, so an unrecovered object reads as zeroes
             * (check -3/0) rather than falling off the end (check -2).
             */
            {
                uint64_t noff  = test_tables[i].entries[j].obj_offset;
                int      nobj  = test_tables[i].entries[j].obj_num;
                uint64_t nslot = noff / scalpel_state.blocksize;
                bool slot_missing =
                    (nslot >= blockvector_get_num_blocks(candidate->b)) ||
                    (blockvector_get_apparent_blocknumber(candidate->b, nslot) < 0);

                if(check != 1 && slot_missing){
                    // The object's position inside its block is absolute
                    // (noff % blocksize), independent of where the block lands.
                    int32_t nlocal = (int32_t)(noff % scalpel_state.blocksize);
                    bool prefilter_hit = true;
                    int64_t new_block =
                        pdf_reassembly_get_block_choice(candidate, nobj, -1, 0, 0, -1, NEXTOBJECT, (int64_t)nslot);
                    if(new_block != -1){
                        char *nb = (char*)get_apparent_block_data(scalpel_state.filemirror, new_block);
                        int nb_check = nb ? validate_at_offset(nb, nlocal, nobj, scalpel_state.blocksize) : -1;
                        free(nb);
                        // NEXTOBJECT matches only on the block's FIRST object
                        // number, which small integers make ambiguous across
                        // unrelated files. Requiring the object at its expected
                        // local offset is what distinguishes them.
                        if(nb_check != 1) new_block = -1;
                    }
                    if(new_block == -1){
                        // The object need not be its block's first, so the
                        // prefilter can miss legitimately; fall back to the
                        // offset-driven scan.
                        prefilter_hit = false;
                        new_block = scan_blocks_for_object(nobj, noff);
                    }
                    if(new_block != -1 && !pdf_block_matches_xref_slot(candidate, new_block, nslot)){
                        // Matched the object we searched for, but some other
                        // object the xref places in this slot is missing --
                        // the block is a coincidence, not this file's.
                        new_block = -1;
                    }
#ifdef PDF_TRACE_PLACEMENT
                    {
                        // How many objects does the xref place in this slot? If
                        // only the one we searched for, the cross-check adds
                        // nothing and a coincidental digit match wins.
                        int nconstraints = 0;
                        uint64_t lo = nslot * (uint64_t)scalpel_state.blocksize, hi = lo + scalpel_state.blocksize;
                        for(int tt = 0; tt <= num_tables; tt++)
                            for(int ee = 0; ee < test_tables[tt].count; ee++){
                                uint64_t oo = test_tables[tt].entries[ee].obj_offset;
                                if(oo >= lo && oo < hi) nconstraints++;
                            }
                        uuid_string_t uu; uuid_unparse_lower(candidate->binuuid, uu);
                        lock_fprintf(stdout,
                            "[PDFNOBJ] uuid=%.8s slot=%" PRIu64 " obj=%d off=%" PRIu64
                            " local=%d chosen=%" PRId64 " via=%s constraints=%d\n",
                            uu, nslot, nobj, noff, nlocal, new_block,
                            prefilter_hit ? "prefilter" : "scan", nconstraints);
                    }
#endif
                    if(new_block != -1){
                        int64_t nactual = filemirror_actual_blocknumber(scalpel_state.filemirror, new_block);
                        if(pdf_place_blocks_at_slot(candidate, &nactual, 1, nslot, "NEXTOBJ")){
                            data = blockvector_get_data_pointer(candidate->b);
                            check = validate_at_offset(data, noff, nobj,
                                                       blockvector_get_data_length(candidate->b));
                        }
                    }
                }
            }

            if(check != 1){
                for(int k = 0; k < num_tables + 1; k++){
                    if(k == current_table) continue;
                    if(!xref_hashes[k]) continue;
                    int entry_idx;
                    if(hash_table_lookup(xref_hashes[k], current_object, &entry_idx)){
                        check = validate_at_offset(data, test_tables[k].entries[entry_idx].obj_offset,
                            test_tables[k].entries[entry_idx].obj_num, blockvector_get_data_length(candidate->b));
                        if(check == 1) break;
                    }
                }
            }
        }
    }

    if(xref_validated){
        if(save_new_table){
#ifdef PDF_TRACE_PLACEMENT
            pdf_trace_table_adopt(candidate, "SCAN", test_tables[num_tables].entries,
                                  test_tables[num_tables].count, -1);
#endif
            PDFCarveState *carve_state = (PDFCarveState*)carve_get_state(candidate->carvehashkey);
            add_xref_table(carve_state, test_tables, num_tables);
            carve_put_state(candidate->carvehashkey, carve_state);
            pdf_free_carve_state((void**)&carve_state);
            test_tables[num_tables].entries = NULL;
            test_tables[num_tables].count = 0;
        }
        // Place the xref at its true file slot when the document's own metadata
        // confirms one; otherwise append at the frontier, which is correct once
        // body reconstruction has reached the xref's position and is how a
        // contiguous file's trailer lands.
        bool placed_by_slot = false;
        bool xref_vetoed = false;
        if(xref_slot >= 0){
            for(int i = 0; i < xref_block_count; i++){
                uint64_t app = filemirror_apparent_blocknumber(scalpel_state.filemirror, xref_blocks[i]);
                if(!pdf_block_matches_xref_slot(candidate, (int64_t)app,
                                                (uint64_t)xref_slot + (uint64_t)i)){
                    xref_vetoed = true;
                    break;
                }
            }
            if(!xref_vetoed)
                placed_by_slot = pdf_place_blocks_at_slot(candidate, xref_blocks,
                                                          xref_block_count,
                                                          (uint64_t)xref_slot, "XREF_SLOT");
        }
        // Only append when no slot resolved at all. If the metadata located this
        // xref but placement was declined (slots occupied or range implausible),
        // the frontier is not where it belongs and appending would plant a
        // known-wrong block past the end of the file.
        if(xref_slot < 0 && !placed_by_slot && !xref_vetoed){
            for(int i = 0; i < xref_block_count; i++){
                uint64_t num_blocks = blockvector_get_num_blocks(candidate->b);
                uint64_t new_app = filemirror_apparent_blocknumber(scalpel_state.filemirror, xref_blocks[i]);
                bool already_present = false;
                for(uint64_t b = 0; b < num_blocks && !already_present; b++){
                    if((uint64_t)blockvector_get_apparent_blocknumber(candidate->b, b) == new_app)
                        already_present = true;
                }
                if(already_present) continue;
                pdf_reassembly_prepare_for_extension(work->id, candidate, 1, OBJECTEXTNSION);
                candidate->newblock = xref_blocks[i];
                PDF_PLACE(work->id, candidate, num_blocks, "XREF_APPEND", i, xref_block_count);
            }
        }
    }

    test_tables[num_tables].entries = NULL;
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

    pdf_inflight_tables = NULL; pdf_inflight_table_count = 0;
    return;
}

/*******************************************************/
/* VALIDATION FUNCTION DEFINITIONS                    */
/*******************************************************/

/**
 * @description  Per-block validator: scans one block for its first object number
 *               and any xref/trailer markers, records them in a PDFBlockState kept
 *               under blockhashkey, and reports whether the block is plausible PDF
 *               content. Bounds the scan by the block's valid data length so a final
 *               partial block does not surface markers from its padding.
 * @param data          The block's bytes.
 * @param length        Valid data length in the block.
 * @param decision      Out: the block confidence decision.
 * @param validates_to  Out: the last byte offset validated.
 * @param needleidx     The needle (file type) index.
 * @param blocksize     The full block size.
 * @param blockhashkey  Key under which the block's PDFBlockState is stored.
 * @return       The needle index.
 */
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

    // Bound the scan by the block's valid data length, not the full block-buffer
    // size. On the final partial block length < blocksize, and iterating to
    // blocksize would scan the block's padding (in-buffer, so not a memory
    // over-read, but it can surface spurious xref/trailer markers).
    for(uint32_t i = 0; i < length; i++){
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
#ifdef PDF_TRACE_VALIDATE
    int dbg_pass = 0, dbg_fail = 0, dbg_outer = 0;
#endif


    // Start at end of file and find startxref to store offset of most recent xref table
    uint64_t search_pos = 0;
    //int no_prev_count = 0;
    bool search_more = true;
    while(search_pos < length){
        int xref_type = 0;
        const char *first_xref = scan_buf_for_xref(data, length, search_pos, &xref_type);
        if(!first_xref || xref_type <= 0) break;
        // first_xref is the earliest xref in the file. Follow /Prev entries; stop
        // the loop once a table has no /Prev or a /Prev points at an invalid xref.
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
                    // j is on the char before the first digit of the object number,
                    // while /XRefStm points at that first digit, so j + 1 is compared
                    // against the supplemental stream's expected offset.
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
#ifdef PDF_TRACE_VALIDATE
                    dbg_fail++;
                    if(validated == 1)
                        lock_fprintf(stdout, "[PDFVAL] len=%" PRIu64 " BAIL validated=1 already; "
                            "obj %d @ %" PRIu64 " failed (table %d/%d) pass=%d fail=%d\n",
                            length, current_object, xref_tables[i].entries[j].obj_offset,
                            i, xref_count, dbg_pass, dbg_fail);
#endif
                    if(validated == 1) goto stop_validation;
                    if(check != 1){
                        fail_count++;
                        goto leave_loop;
                    }
                }
                else {
#ifdef PDF_TRACE_VALIDATE
                    dbg_pass++;
#endif
                    if(validation_cutoff < xref_tables[i].entries[j].obj_offset){
                    validation_cutoff = xref_tables[i].entries[j].obj_offset;
                }
                }
            }
        }
        leave_loop:
        if(check == 1){
            kg_validation_cutoff = validation_cutoff;
#ifdef PDF_TRACE_VALIDATE
            if(!validated)
                lock_fprintf(stdout, "[PDFVAL] len=%" PRIu64 " VALIDATED-SET after table %d/%d "
                    "obj_idx=%d pass=%d fail=%d outer=%d\n",
                    length, current_table, xref_count, current_object_idx,
                    dbg_pass, dbg_fail, dbg_outer);
#endif
            validated = 1;
        }
#ifdef PDF_TRACE_VALIDATE
        dbg_outer++;
#endif
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
    // Object offsets only prove header blocks are placed; a wrong block inside a
    // stream body is invisible to them. Reject if a validated FlateDecode stream
    // fails to decompress -- must run before the tables are freed below.
    if(validated == 1 && !pdf_streams_decode_ok(data, length, xref_tables, xref_count)){
        validated = 0;
#ifdef PDF_TRACE_VALIDATE
        lock_fprintf(stdout, "[PDFVAL] len=%" PRIu64 " REJECTED by stream decode check\n", length);
#endif
    }
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

/**
 * @description  Standalone test harness (PDFTESTING builds only): loads a PDF file,
 *               feeds it block by block through the validator, and reports the
 *               validation outcome. Not compiled into the carver itself.
 * @param argc  Argument count.
 * @param argv  Arguments: the PDF filename and optional blocksize.
 * @return       Process exit status.
 */
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
