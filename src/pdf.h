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
#include <openssl/evp.h>
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

// Bound image-wide xref scanning between remote-control/checkpoint polls.
#define PDF_XREF_SCAN_QUANTUM 256

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

typedef struct PDFEncryptionContext {
    bool active;
    bool encrypt_metadata;
    bool aes;
    bool identity;
    unsigned char file_key[16];
    size_t file_key_length;
} PDFEncryptionContext;

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
    int32_t num_xrefs;
} PDFBlockState;

typedef struct PDFXrefSearchState{
    bool active;
    bool exhausted;
    roaring64_bitmap_t *excluded_actual_blocks;
    Object *best_entries;
    int best_entry_count;
    int64_t *best_blocks;
    int best_block_count;
    int32_t best_local;
    int best_score;
} PDFXrefSearchState;

typedef struct PDFStreamMetadata {
    int64_t length;
    bool has_length;
    bool flate;
    bool has_filter;
    bool jpeg;
    bool xml;
    bool incomplete;
} PDFStreamMetadata;

typedef struct PDFPrefixScan {
    uint64_t length;
    uint64_t objects;
    uint64_t complete_length;
    uint64_t stream_offset;
    uint64_t stream_length;
    bool stream_flate;
    bool stream_jpeg;
    bool needs_more;
    bool interrupted;
    bool stream_progress;
} PDFPrefixScan;

// Immutable partial mapping shared by carve-state copies; no file bytes or
// reservations are retained. Each state owns one reference.
typedef struct PDFPartialPrefix {
    atomic_uint references;
    uint64_t length;
    uint64_t count;
    int64_t actual[];
} PDFPartialPrefix;

// A replacement scan resumes at the next actual block, independently of
// apparent-block renumbering at checkpoints. No speculative bytes are retained.
typedef struct PDFStreamRepairCursor {
    bool active;
    int32_t prefix_limit;
    int32_t prefix_length;
    int32_t run_length;
    int64_t next_actual;
} PDFStreamRepairCursor;

// Search decisions, not decoder scratch. Sources are physical block numbers.
typedef struct PDFBackboneSearch {
    uint32_t active;
    uint32_t preferred_done;
    uint64_t signature;
    uint64_t insert;
    int64_t next_actual;
} PDFBackboneSearch;

typedef struct PDFZlibBackboneSearch {
    PDFBackboneSearch cursor;
    uint32_t complete;
} PDFZlibBackboneSearch;

typedef struct PDFICCSearch {
    uint32_t active;
    uint64_t signature;
    int64_t next_actual;
    uint64_t viable_runs;
    uint64_t best_score;
    uint64_t second_score;
    int64_t best_actual;
    int64_t second_actual;
} PDFICCSearch;

typedef struct PDFZeroRunSearch {
    uint32_t active;
    uint64_t signature;
    int64_t next_actual;
} PDFZeroRunSearch;

typedef struct PDFInteriorSplitSearch {
    uint32_t active;
    uint64_t signature;
    int32_t next_split;
} PDFInteriorSplitSearch;

typedef struct PDFInteriorSearchState {
    bool active;
    size_t table;
    int32_t entry;
    PDFStreamRepairCursor repair;
    uint64_t gap_extra;
    uint64_t gap_slot;
    PDFBackboneSearch jpeg;
    PDFICCSearch icc;
    PDFZeroRunSearch zero;
    PDFInteriorSplitSearch split;
    PDFZlibBackboneSearch zlib;
} PDFInteriorSearchState;

enum PDFZlibSearchPhase {
    PDF_ZLIB_THREE_RUN = 0,
    PDF_ZLIB_TWO_RUN = 1,
    PDF_ZLIB_BACKBONE = 2
};

// Deferred stream trials retain their phase, cursor and anchor identities,
// never a zlib pointer or an unverified block assignment.
typedef struct PDFThreeRunSearch {
    bool active;
    uint64_t candidate_signature;
    uint64_t context_signature;
    uint64_t stream_length;
    uint64_t initial_blocks;
    int32_t stream_offset;
    int32_t block_span;
    int64_t anchors[2];
    int32_t anchor_count;
    int32_t anchor_index;
    int32_t prefix_limit;
    int32_t middle_length;
    int32_t prefix_length;
    int64_t next_actual;
    uint32_t phase;
    PDFZlibBackboneSearch backbone;
} PDFThreeRunSearch;

// A layout search must retain its first success until uniqueness is established.
typedef struct PDFPhysicalRunSearch {
    uint32_t active;
    uint32_t enumerated;
    uint32_t complete;
    uint64_t signature;
    uint64_t boundary_count;
    uint64_t total_slots;
    uint64_t valid_layouts;
    uint64_t trials;
    uint64_t solution_length;
    uint64_t next_footer;
    uint64_t *boundaries;
    int64_t *solution_actuals;
} PDFPhysicalRunSearch;

typedef struct PDFCarveState{
    XrefTables *xref_tables;  // Points to linked list of XrefTables
    size_t num_tables;       // Number of xref tables found
    bool incomplete_obj;
    bool initialized; // initial candidate xref discovery has completed
    bool speculative_blocks; // candidate contains a heuristic, non-oracle block assignment
    // Linearization parameters, read once from the candidate's header block.
    // A linearized file places its entry-point xref at the FRONT, so its final
    // startxref does NOT locate the main table; lin_T does. See
    // pdf_detect_linearization().
    bool    linearized;      // /Linearized dict present as the first object
    int64_t lin_L;           // /L: declared total length of that revision, -1 if absent
    int64_t lin_T;           // /T: offset of that revision's main xref, -1 if absent
    PDFXrefSearchState xref_search;
    PDFPartialPrefix *partial_prefix;
    bool partial_search_active;
    uint64_t partial_search_length;
    int64_t partial_search_next;
    PDFInteriorSearchState interior_search;
    PDFThreeRunSearch three_run;
    bool physical_search_active;
    PDFPhysicalRunSearch physical_search[2];
} PDFCarveState;

typedef struct PDFSlotDelta {
    int64_t delta;
    uint64_t slot;
} PDFSlotDelta;

typedef struct PDFRunEvidence {
    int64_t delta;
    uint64_t min_slot;
    uint64_t max_slot;
    uint64_t count;
} PDFRunEvidence;

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
    // Declared /Length and bytes supplied: needed to reach Z_STREAM_END, where
    // zlib verifies the Adler-32 over the whole output -- DEFLATE's only integrity
    // check, since a wrong block otherwise decodes to plausible garbage.
    size_t stream_length;    // 0 = unknown, no completion gate
    size_t fed;              // bytes supplied from the declared stream extent
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

int check_last_object_length(char *data, uint64_t length, uint64_t *out_offset, XrefTables *test_tables, int num_tables, const char *dict, int dict_len, uint64_t obj_offset, bool search_image);

int check_last_object_filter(const char *dict, int dict_len);

int calculate_stream_offsets(char *data, uint64_t object_length, uint64_t length, uint64_t offset, int32_t *out_startstream_local_offset, int32_t *out_endstream_local_offset, int *out_blocks_to_extend);

static bool pdf_zlib_extent_complete(const z_stream *stream, size_t supplied, size_t declared);

int zlib_stream_reassembler_init(ZlibStreamReassembler *r, const unsigned char *first_block, size_t block_size, size_t stream_offset, size_t stream_length);

int zlib_stream_reassembler_try_block(ZlibStreamReassembler *r, const unsigned char *block, size_t block_size);

void zlib_stream_reassembler_free(ZlibStreamReassembler *r);

static int pdf_zlib_contiguous_prefix_blocks(const unsigned char *first_block,
                                            size_t stream_offset,
                                            size_t stream_length,
                                            int64_t first_apparent,
                                            int maximum);

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

static bool pdf_jpeg_extent_complete(const JpegStreamReassembler *r);

int jpeg_stream_reassembler_init(JpegStreamReassembler *r, const unsigned char *first_block, size_t block_size, size_t stream_offset, size_t stream_length);

int jpeg_stream_reassembler_try_block(JpegStreamReassembler *r, const unsigned char *block, size_t block_size);

void jpeg_stream_reassembler_free(JpegStreamReassembler *r);

bool reconstruct_jpeg_stream(ThreadWork *work, CarveInfo *candidate, const char *first_stream_block_data, int32_t startstream_local_offset, int32_t endstream_local_offset, int blocks_to_extend, uint64_t stream_length, int mode);

Object* scan_blocks_for_xref_at_offset(CarveInfo *candidate, BlockVector *scan_bv, int *entry_count, int64_t **out_xref_blocks, int *out_xref_block_count, int32_t expected_offset);

Object* scan_blocks_for_xref(CarveInfo *candidate, BlockVector **scan_bv, int *entry_count, int64_t **out_xref_blocks, int *out_xref_block_count, int32_t *out_xref_local, int64_t *next_apparent, uint64_t block_budget, bool *more_work);

const char *scan_buf_for_xref(char *data, uint64_t length, uint64_t search_pos, int *xref_type);

static int64_t pdf_lin_param(const char *dict, int dict_len, const char *key, int key_len);

static void pdf_detect_linearization(PDFCarveState *s, const char *data, uint64_t length);

static bool pdf_place_blocks_at_slot(CarveInfo *candidate, const int64_t *actual_blocks, int count, uint64_t first_slot, const char *site);

static bool pdf_repair_interior_zlib_backbone(ThreadWork *work, CarveInfo *candidate, int64_t stream_at, int stream_len, int64_t start_slot, int64_t end_slot, bool exhaustive, PDFZlibBackboneSearch *search);
static bool pdf_repair_interior_zlib_zero_run(ThreadWork *work, CarveInfo *candidate, int64_t stream_at, int stream_len, int64_t start_slot, int64_t end_slot, PDFZeroRunSearch *search);

static bool pdf_repair_mapped_zlib_run(CarveInfo *candidate, int64_t stream_at,
                                      int stream_len, int64_t start_slot,
                                      int64_t end_slot,
                                      PDFStreamRepairCursor *cursor);

static bool pdf_repair_gapped_zlib_run(CarveInfo *candidate, int64_t stream_at,
                                      int stream_len, int64_t start_slot,
                                      int64_t end_slot,
                                      PDFInteriorSearchState *search);

static void pdf_store_interior_search(CarveInfo *candidate,
                                      const PDFInteriorSearchState *search);

static bool pdf_repair_interior_jpeg_backbone(ThreadWork *work, CarveInfo *candidate, int64_t stream_at, int stream_len, int64_t start_slot, int64_t end_slot, bool exhaustive, PDFBackboneSearch *search);

static inline uint32_t pdf_icc_lut_value(const unsigned char *profile,
                                         size_t offset,
                                         unsigned int bytes_per_value);

static bool pdf_repair_interior_icc_lut(ThreadWork *work, CarveInfo *candidate, int64_t stream_at, int stream_len, int64_t start_slot, int64_t end_slot, PDFICCSearch *search);
static bool pdf_serialize_auxiliary_search(PDFInteriorSearchState *search,
                                          FILE *fp, StateSerialization mode);
static bool pdf_serialize_interior_zlib_search(PDFInteriorSearchState *search,
                                              FILE *fp, StateSerialization mode);
static bool pdf_serialize_zlib_backbone_search(PDFZlibBackboneSearch *search,
                                              FILE *fp, StateSerialization mode);
static void pdf_physical_search_clear(PDFPhysicalRunSearch *search);
static void pdf_physical_search_copy(PDFPhysicalRunSearch *dest,
                                     const PDFPhysicalRunSearch *source);
static bool pdf_serialize_physical_search(PDFPhysicalRunSearch *search,
                                          FILE *fp, StateSerialization mode);
static bool pdf_physical_solution_available(CarveInfo *candidate,
                                             const PDFPhysicalRunSearch *search);
static void pdf_store_physical_search(CarveInfo *candidate, bool logical_groups,
                                       const PDFPhysicalRunSearch *search);
static uint64_t pdf_interior_signature(CarveInfo *candidate,
                                        int64_t stream_at, int stream_len);

static int pdf_collect_xref_anchors(const char *data, uint64_t length, int64_t *out, int max_out);

static int64_t pdf_resolve_xref_slot(CarveInfo *candidate, const int64_t *xref_blocks, int xref_block_count, int32_t xref_local);

static int pdf_xref_slot_object_count(CarveInfo *candidate, uint64_t slot);

static bool pdf_block_matches_xref_slot(CarveInfo *candidate, int64_t apparent_block, uint64_t slot);

static bool pdf_candidate_has_holes(CarveInfo *candidate);

static bool pdf_fill_physically_bridged_holes(ThreadWork *work,
                                               CarveInfo *candidate);

static bool pdf_xref_offset_is_unique(CarveInfo *candidate,
                                      int32_t expected_offset);

static size_t pdf_group_slot_runs(const PDFSlotDelta *observations, size_t count,
                                  PDFRunEvidence *groups);

static int pdf_compare_slot_delta(const void *a, const void *b);

static bool pdf_try_linearized_physical_runs(ThreadWork *work, CarveInfo *candidate,
                                            bool logical_groups);

static int pdf_compare_run_evidence(const void *a, const void *b);

static bool pdf_complete_linearized_physical_runs(ThreadWork *work,
                                                   CarveInfo *candidate);

static bool pdf_complete_trailer(ThreadWork *work, CarveInfo *candidate);
static bool pdf_xref_block_continuation(const unsigned char *data, size_t length);

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

static bool pdf_xml_body_ok(const unsigned char *buf, size_t len);

static void pdf_store_three_run_search(CarveInfo *candidate,
                                        const PDFThreeRunSearch *search);
static bool pdf_serialize_three_run_search(PDFThreeRunSearch *search, FILE *fp,
                                            StateSerialization mode);
static uint64_t pdf_three_run_signature(CarveInfo *candidate,
                                         int64_t first, int64_t count,
                                         uint64_t seed);

static bool pdf_first_stream_filter_is(const unsigned char *dictionary,
                                        size_t length, const char *name);

static bool pdf_streams_decode_ok(char *data, uint64_t length, XrefTables *tables,
                                  const XrefObject *xrefs, int num_tables,
                                  bool *damaged_metadata);

static bool pdf_find_name_value(const unsigned char *data, size_t length,
                                const char *name, size_t *value_offset);

static bool pdf_token_end(const unsigned char *data, size_t length,
                           size_t offset, size_t *end);

static bool pdf_parse_signed_integer(const unsigned char *data, size_t length,
                                     size_t offset, int64_t *value,
                                     size_t *end_offset);

static bool pdf_parse_string(const unsigned char *data, size_t length,
                             size_t offset, unsigned char *output,
                             size_t output_capacity, size_t *output_length);

static bool pdf_parse_indirect_reference(const unsigned char *data,
                                         size_t length, size_t offset,
                                         int *object_number);

static bool pdf_incremental_update_prefix(const unsigned char *data,
                                          size_t length);

static bool pdf_md5(const unsigned char *data, size_t length,
                    unsigned char digest[16]);

static void pdf_rc4_crypt(const unsigned char *key, size_t key_length,
                          const unsigned char *input, unsigned char *output,
                          size_t length);

static bool pdf_xref_dictionary(const unsigned char *data, uint64_t length,
                                 const XrefObject *xrefs, int num_tables,
                                 int table, uint64_t *start, uint64_t *end);

static bool pdf_initialize_encryption_context(
    const unsigned char *data, uint64_t length, XrefTables *tables,
    const XrefObject *xrefs, int num_tables, PDFEncryptionContext *context);

static bool pdf_decrypt_stream(const PDFEncryptionContext *context,
                               int object_number, int generation,
                               const unsigned char *input, size_t length,
                               unsigned char *output, size_t *output_length);

static inline bool pdf_lexical_space(unsigned char c);

static inline bool pdf_lexical_delimiter(unsigned char c);

static uint64_t pdf_skip_space_and_comments(const unsigned char *data,
                                            uint64_t offset,
                                            uint64_t limit);

static int pdf_indirect_object_header(const unsigned char *data,
                                       uint64_t offset, uint64_t limit,
                                       int expected_object,
                                       uint64_t *body_start, int *generation);

static bool pdf_indirect_object_body_start(const unsigned char *data,
                                           uint64_t offset,
                                           uint64_t limit,
                                           int expected_object,
                                           uint64_t *body_start,
                                           int *generation);

static bool pdf_syntax_push(unsigned char **stack, size_t *stack_capacity,
                            size_t depth, unsigned char delimiter);

static bool pdf_nonstream_object_well_formed(const unsigned char *data,
                                             uint64_t offset,
                                             uint64_t limit,
                                             int expected_object,
                                             unsigned char **stack,
                                             size_t *stack_capacity);
static bool pdf_nonstream_object_end(const unsigned char *data,
                                    uint64_t offset, uint64_t limit,
                                    int expected_object, unsigned char **stack,
                                    size_t *stack_capacity, uint64_t *end,
                                    PDFStreamMetadata *metadata, bool (*stop)(void));

static uint64_t pdf_embedded_stream_prefix(const unsigned char *data,
                                           uint64_t available, uint64_t declared,
                                           uint64_t stream_offset,
                                           uint32_t blocksize, bool is_jpeg,
                                           bool (*stop)(void), bool *interrupted);

static bool pdf_nonstream_objects_well_formed(char *data, uint64_t length,
                                               XrefTables *tables,
                                               int num_tables);

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
static void pdf_file_validate_content(char *data, uint64_t length, bool *validates,
    uint64_t *validates_to, bool *promising, uint32_t needleidx,
    uint32_t blocksize, void *carvehashkey, bool *unverified_complete);
static uint64_t pdf_include_trailing_whitespace(const char *data,
                                                uint64_t length, uint64_t end);
static uint64_t pdf_partial_skip_space(const unsigned char *data, uint64_t cursor,
                                       uint64_t limit, bool (*stop)(void));
static PDFPrefixScan pdf_scan_forward_prefix(const unsigned char *data,
                                             uint64_t length, uint32_t blocksize,
                                             bool (*stop)(void));
static bool pdf_prefix_checkpoint_requested(void);
static void pdf_partial_prefix_release(PDFPartialPrefix *prefix);
static void pdf_preserve_partial_prefix(CarveInfo *candidate);
static bool pdf_partial_endstream_at(int64_t actual, uint64_t offset);
static bool pdf_partial_jpeg_complete(const unsigned char *data, size_t length);
static void pdf_extend_partial_prefix(CarveInfo *candidate);
static void pdf_write_partial_prefix(CarveInfo *candidate);
static void pdf_candidate_preserve_prefix(CarveInfo *candidate, bool *validates,
                                           uint64_t *validates_to, bool *promising);

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

// Physical-run trials need a lexical oracle to distinguish layouts whose xref
// headers and stream checks are identical but whose non-stream objects differ.
static __thread bool pdf_require_object_syntax = false;

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
    if (count == 0) {
        return NULL;
    }
    Object *entries = (Object*)malloc(sizeof(Object) * count);
    if (!entries) return NULL;

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
 * @return              1 for a complete header, 0 for a contradiction, -1 for
 *                      a missing buffer, -2 for an out-of-range offset, or -3
 *                      when more bytes are required.
 */
int validate_at_offset(char *data, int64_t offset, int obj_num1, int64_t length) {
    if (!data) {
        return -1;
    }
    if (offset < 0 || offset >= length) {
        return -2;
    }
    uint64_t body_start = 0;
    int status = pdf_indirect_object_header((const unsigned char *)data,
        (uint64_t)offset, (uint64_t)length, obj_num1, &body_start, NULL);
    return status > 0 ? 1 : (status == 0 ? -3 : 0);
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
    if (!data || !entry_count || !xref_end_offset || offset < 0 || offset >= length) {
        return NULL;
    }
    *entry_count = 0;
    int column_length = 0;
    size_t predictor_columns = 1;
    size_t *index_array = NULL;
    size_t index_count = 0;
    int w_array[3] = {0, 0, 0};
    int num_references = 0;
    int num_type1 = 0;
    int num_entries = 0;
    Object *entries = NULL;
    bool predictor_present = false;

    // Xref stream discovery normally finds the /Type /XRef marker inside the
    // object dictionary. Normalize that marker to the containing object's start;
    // otherwise detect_xref_type() searches forward and can inspect the next
    // object instead of the xref stream that was actually found.
    if (offset >= 0 && offset < length &&
        ((offset + 10 <= length && !memcmp(&data[offset], "/Type/XRef", 10)) ||
         (offset + 11 <= length && !memcmp(&data[offset], "/Type /XRef", 11)))) {
        int64_t object_start = find_xref_stream_start(data, offset);
        if (object_start >= 0) {
            offset = object_start;
        }
    }
    int xref_type = detect_xref_type(data, offset, length, &offset);

    if (xref_type <= 0) {
        return NULL;
    }

    // Parse through stream dictionary for important information needed for decoding
    if (xref_type == 2) {
        // Dictionary syntax, including strings, determines its end. Encryption
        // dictionaries can themselves contain dictionaries and hexadecimal data.
        char *dict_start = memmem(&data[offset], length - offset, "<<", 2);
        if (!dict_start) {
            return NULL;
        }
        uint64_t dictionary_end = 0;
        unsigned char *stack = NULL;
        size_t stack_capacity = 0;
        bool complete = pdf_nonstream_object_end((unsigned char *)data,
            dict_start - data, length, -1, &stack, &stack_capacity,
            &dictionary_end, NULL, NULL);
        free(stack);
        if (!complete) {
            return NULL;
        }
        const unsigned char *dictionary = (unsigned char *)dict_start;
        size_t dictionary_length = dictionary_end - (uint64_t)(dict_start - data);
        size_t value = 0;
        if (!pdf_find_name_value(dictionary, dictionary_length, "W", &value)
            || dictionary[value++] != '[') {
            return NULL;
        }
        for (int i = 0; i < 3; i++) {
            int64_t width = 0;
            if (!pdf_parse_signed_integer(dictionary, dictionary_length,
                                            value, &width, &value)
                || width < 0 || width > 4) {
                return NULL;
            }
            w_array[i] = (int)width;
            column_length += w_array[i];
        }
        value = pdf_skip_space_and_comments(dictionary, value, dictionary_length);
        if (value >= dictionary_length || dictionary[value] != ']'
            || column_length == 0) {
            return NULL;
        }
        int64_t count = 0;
        if (!pdf_find_name_value(dictionary, dictionary_length, "Size", &value)
            || !pdf_parse_signed_integer(dictionary, dictionary_length, value,
                                           &count, NULL)
            || count <= 0 || count > INT_MAX) {
            return NULL;
        }
        num_references = (int)count;
        if (pdf_find_name_value(dictionary, dictionary_length, "Index", &value)) {
            if (extract_index_array((char *)dictionary, value, &index_array,
                                      &index_count, dictionary_length) != 0
                || index_count == 0 || (index_count & 1) != 0) {
                free(index_array);
                return NULL;
            }
        }
        bool flate = false;
        if (pdf_find_name_value(dictionary, dictionary_length, "Filter", &value)) {
            if (dictionary[value] == '[') {
                value = pdf_skip_space_and_comments(dictionary, value + 1,
                                                     dictionary_length);
            }
            size_t filter_end = 0;
            flate = pdf_token_end(dictionary, dictionary_length, value, &filter_end)
                && filter_end - value == 12
                && !memcmp(dictionary + value, "/FlateDecode", 12);
            if (!flate) {
                free(index_array);
                return NULL;
            }
        }
        if (pdf_find_name_value(dictionary, dictionary_length, "DecodeParms", &value)) {
            if (dictionary[value] == '[') {
                value = pdf_skip_space_and_comments(dictionary, value + 1,
                                                     dictionary_length);
            }
            size_t predictor = 0;
            int64_t prediction = 1;
            if (pdf_find_name_value(dictionary + value, dictionary_length - value,
                                     "Predictor", &predictor)) {
                if (!pdf_parse_signed_integer(dictionary + value,
                        dictionary_length - value, predictor, &prediction, NULL)
                    || (prediction != 1 && (prediction < 10 || prediction > 15))) {
                    free(index_array);
                    return NULL;
                }
                predictor_present = prediction >= 10;
                const unsigned char *parameters = dictionary + value;
                size_t parameters_length = dictionary_length - value;
                int64_t columns = 1, colors = 1, bits = 8;
                if ((pdf_find_name_value(parameters, parameters_length, "Columns", &predictor)
                     && !pdf_parse_signed_integer(parameters, parameters_length,
                                                   predictor, &columns, NULL))
                    || (pdf_find_name_value(parameters, parameters_length, "Colors", &predictor)
                        && !pdf_parse_signed_integer(parameters, parameters_length,
                                                      predictor, &colors, NULL))
                    || (pdf_find_name_value(parameters, parameters_length, "BitsPerComponent", &predictor)
                        && !pdf_parse_signed_integer(parameters, parameters_length,
                                                      predictor, &bits, NULL))
                    || columns <= 0 || (uint64_t)columns > SIZE_MAX
                    || colors != 1 || bits != 8) {
                    free(index_array);
                    return NULL;
                }
                predictor_columns = (size_t)columns;
            }
        }
        int64_t declared_length = 0;
        if (!pdf_find_name_value(dictionary, dictionary_length, "Length", &value)
            || !pdf_parse_signed_integer(dictionary, dictionary_length, value,
                                           &declared_length, NULL)
            || declared_length <= 0) {
            free(index_array);
            return NULL;
        }
        uint64_t stream_start = pdf_skip_space_and_comments((unsigned char *)data,
                                                            dictionary_end, length);
        if ((uint64_t)length - stream_start < 7
            || memcmp(data + stream_start, "stream", 6)) {
            free(index_array);
            return NULL;
        }
        stream_start += 6;
        if (data[stream_start] == '\r') {
            stream_start++;
            if (stream_start < (uint64_t)length && data[stream_start] == '\n') {
                stream_start++;
            }
        } else if (data[stream_start] == '\n') {
            stream_start++;
        } else {
            free(index_array);
            return NULL;
        }
        if ((uint64_t)declared_length > (uint64_t)length - stream_start) {
            free(index_array);
            return NULL;
        }
        uint64_t stream_end = pdf_skip_space_and_comments((unsigned char *)data,
            stream_start + (uint64_t)declared_length, length);
        if ((uint64_t)length - stream_end < 9
            || memcmp(data + stream_end, "endstream", 9)) {
            free(index_array);
            return NULL;
        }
        *xref_end_offset = stream_end + 9;
        size_t decompressed_length = 0;
        size_t decoded_length = 0;
        char *decompressed_data = NULL;
        if (flate) {
            decompressed_data = decompress_with_uncompress(data + stream_start,
                (size_t)declared_length, &decompressed_length);
        } else {
            decompressed_length = (size_t)declared_length;
            decompressed_data = malloc(decompressed_length);
            check_memory_allocation(decompressed_data, __LINE__, __FILE__,
                                    "PDF xref stream");
            memcpy(decompressed_data, data + stream_start, decompressed_length);
        }
        if (!decompressed_data) {
            free(index_array);
            return NULL;
        }

        char *decoded_data = NULL;
        if (predictor_present) {
            decoded_data = apply_png_predictor_up(decompressed_data, decompressed_length,
                                                  predictor_columns, &decoded_length);
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
 * @param offset        The offset of the Index array's opening bracket.
 * @param index_array_out   A pointer to store the extracted index array.
 * @param index_count_out   A pointer to store the count of entries in the index array
 * @param length        The length of the buffer.
 *
 * @return              0 on success, negative values on failure.
 */
int extract_index_array(const char *data, int64_t offset, size_t **index_array_out, size_t *index_count_out, int64_t length) {
    if (!data || !index_array_out || !index_count_out || offset < 0
        || offset >= length) {
        return -1;
    }
    size_t cursor = pdf_skip_space_and_comments((const unsigned char *)data,
                                                offset, length);
    if (cursor >= (uint64_t)length || data[cursor++] != '[') {
        return -2;
    }
    size_t capacity = 8;
    size_t count = 0;
    size_t *index_array = malloc(capacity * sizeof(*index_array));
    check_memory_allocation(index_array, __LINE__, __FILE__, "PDF xref index");
    for (;;) {
        cursor = pdf_skip_space_and_comments((const unsigned char *)data,
                                              cursor, length);
        if (cursor < (uint64_t)length && data[cursor] == ']') {
            break;
        }
        int64_t value = 0;
        if (!pdf_parse_signed_integer((const unsigned char *)data, length,
                                        cursor, &value, &cursor)
            || value < 0 || value > INT_MAX) {
            free(index_array);
            return -3;
        }
        if (count == capacity) {
            if (capacity > SIZE_MAX / (2 * sizeof(*index_array))) {
                free(index_array);
                return -4;
            }
            capacity *= 2;
            size_t *grown = realloc(index_array, capacity * sizeof(*index_array));
            check_memory_allocation(grown, __LINE__, __FILE__, "PDF xref index");
            index_array = grown;
        }
        index_array[count++] = (size_t)value;
    }
    if (count == 0 || (count & 1) != 0) {
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

    // Compressed bytes, including Adler-32, may end with textual whitespace.
    // Inflate stops at its own end marker; never trim bytes from the tail.

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
 * @description         Reverses PNG row filters in decompressed PDF stream data.
 *
 * @param input         The buffer containing the decompressed data.
 * @param input_length  The length of the decompressed data.
 * @param columns       The number of data columns per row (from /DecodeParms /Columns).
 * @param out_length    A pointer to store the length of the decoded data.
 *
 * @return              A pointer to the decoded data (caller must free).
 */
char *apply_png_predictor_up(const char *input, size_t input_length, size_t columns, size_t *out_length) {

    if (!input || !out_length || columns == 0 || columns >= input_length) {
        if (out_length) {
            *out_length = 0;
        }
        return NULL;
    }

    size_t row_stride = columns + 1;  // filter byte + data
    size_t row_count = input_length / row_stride;
    size_t remainder = input_length % row_stride;

    if (row_count == 0 || remainder != 0) {
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
        if (filter_byte > 4) {
            free(output);
            *out_length = 0;
            return NULL;
        }
        const unsigned char *in_row = in + in_offset + 1;  // skip filter byte
        unsigned char *out_row = out + (row * columns);
        unsigned char *above_row = (row == 0) ? NULL : out_row - columns;

        for (size_t col = 0; col < columns; col++) {
            unsigned char above = above_row ? above_row[col] : 0;
            unsigned char left = col > 0 ? out_row[col - 1] : 0;
            unsigned char upper_left = above_row && col > 0 ? above_row[col - 1] : 0;
            int predictor = 0;
            if (filter_byte == 1) {
                predictor = left;
            } else if (filter_byte == 2) {
                predictor = above;
            } else if (filter_byte == 3) {
                predictor = (left + above) / 2;
            } else if (filter_byte == 4) {
                int estimate = left + above - upper_left;
                int pa = abs(estimate - left);
                int pb = abs(estimate - above);
                int pc = abs(estimate - upper_left);
                predictor = pa <= pb && pa <= pc ? left : (pb <= pc ? above : upper_left);
            }
            out_row[col] = (unsigned char)(in_row[col] + predictor);
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

static inline bool pdf_lexical_space(unsigned char c) {
    return c == 0 || c == '\t' || c == '\n' || c == '\f' || c == '\r' ||
           c == ' ';
}

static inline bool pdf_lexical_delimiter(unsigned char c) {
    return c == '(' || c == ')' || c == '<' || c == '>' || c == '[' ||
           c == ']' || c == '{' || c == '}' || c == '/' || c == '%';
}

static uint64_t pdf_skip_space_and_comments(const unsigned char *data,
                                            uint64_t offset,
                                            uint64_t limit) {
    for (;;) {
        while (offset < limit && pdf_lexical_space(data[offset])) {
            offset++;
        }
        if (offset >= limit || data[offset] != '%') {
            return offset;
        }
        while (offset < limit && data[offset] != '\r' && data[offset] != '\n') {
            offset++;
        }
    }
}

// Parse an indirect object header: 1 is complete, 0 needs more bytes, and -1
// contradicts the expected header. A number alone does not identify an object.
static int pdf_indirect_object_header(const unsigned char *data,
                                           uint64_t offset,
                                           uint64_t limit,
                                           int expected_object,
                                           uint64_t *body_start,
                                           int *generation) {
    if (!data || !body_start || expected_object < 0 || offset >= limit) {
        return -1;
    }

    offset = pdf_skip_space_and_comments(data, offset, limit);
    if (offset == limit) {
        return 0;
    }
    uint64_t object_number = 0;
    uint64_t digit_start = offset;
    while (offset < limit && isdigit(data[offset])) {
        unsigned int digit = (unsigned int)(data[offset] - '0');
        if (object_number > ((uint64_t)INT_MAX - digit) / 10U) {
            return -1;
        }
        object_number = object_number * 10U + digit;
        offset++;
    }
    if (offset == limit) {
        return object_number <= (uint64_t)expected_object ? 0 : -1;
    }
    if (offset == digit_start || object_number != (uint64_t)expected_object) {
        return -1;
    }

    uint64_t separator = offset;
    offset = pdf_skip_space_and_comments(data, offset, limit);
    if (offset == separator) {
        return -1;
    }
    if (offset == limit) {
        return 0;
    }

    uint64_t generation_number = 0;
    digit_start = offset;
    while (offset < limit && isdigit(data[offset])) {
        unsigned int digit = (unsigned int)(data[offset] - '0');
        if (generation_number > ((uint64_t)INT_MAX - digit) / 10U) {
            return -1;
        }
        generation_number = generation_number * 10U + digit;
        offset++;
    }
    if (offset == digit_start) {
        return -1;
    }
    if (offset == limit) {
        return 0;
    }

    separator = offset;
    offset = pdf_skip_space_and_comments(data, offset, limit);
    if (offset == separator) {
        return -1;
    }
    if (limit - offset < 3) {
        return memcmp(data + offset, "obj", (size_t)(limit - offset)) ? -1 : 0;
    }
    if (memcmp(data + offset, "obj", 3)) {
        return -1;
    }
    offset += 3;
    if (offset < limit && !pdf_lexical_space(data[offset]) &&
        !pdf_lexical_delimiter(data[offset])) {
        return -1;
    }

    *body_start = offset;
    if (generation) {
        *generation = (int)generation_number;
    }
    return 1;
}

static bool pdf_indirect_object_body_start(const unsigned char *data,
                                           uint64_t offset, uint64_t limit,
                                           int expected_object,
                                           uint64_t *body_start,
                                           int *generation) {
    return pdf_indirect_object_header(data, offset, limit, expected_object,
                                      body_start, generation) == 1;
}

// Skip one lexical token without interpreting names inside strings as keys.
static bool pdf_token_end(const unsigned char *data, size_t length,
                           size_t offset, size_t *end) {
    if (offset >= length) {
        return false;
    }
    unsigned char first = data[offset++];
    if (first == '(') {
        size_t depth = 1;
        while (offset < length && depth > 0) {
            unsigned char c = data[offset++];
            if (c == '\\') {
                if (offset == length) {
                    return false;
                }
                offset++;
            } else if (c == '(') {
                depth++;
            } else if (c == ')') {
                depth--;
            }
        }
        if (depth != 0) {
            return false;
        }
    } else if (first == '<' && (offset == length || data[offset] != '<')) {
        while (offset < length && data[offset] != '>') {
            if (!isxdigit(data[offset]) && !pdf_lexical_space(data[offset])) {
                return false;
            }
            offset++;
        }
        if (offset == length) {
            return false;
        }
        offset++;
    } else if ((first == '<' || first == '>') && offset < length
               && data[offset] == first) {
        offset++;
    } else if (first == '/' || !pdf_lexical_delimiter(first)) {
        while (offset < length && !pdf_lexical_space(data[offset])
               && !pdf_lexical_delimiter(data[offset])) {
            offset++;
        }
    }
    *end = offset;
    return true;
}

// Look up an outer dictionary entry, excluding nested keys and name values.
static bool pdf_find_name_value(const unsigned char *data, size_t length,
                                const char *name, size_t *value_offset) {
    if (!data || !name || !value_offset) {
        return false;
    }
    size_t name_length = strlen(name);
    if (name_length == 0 || name_length > length) {
        return false;
    }
    size_t offset = pdf_skip_space_and_comments(data, 0, length);
    if (length - offset < 2 || memcmp(data + offset, "<<", 2)) {
        return false;
    }
    offset += 2;
    while (offset < length) {
        offset = pdf_skip_space_and_comments(data, offset, length);
        if (offset >= length || data[offset] != '/') {
            return false;
        }
        size_t end = 0;
        if (!pdf_token_end(data, length, offset, &end)) {
            return false;
        }
        size_t value = pdf_skip_space_and_comments(data, end, length);
        if (end - offset == name_length + 1
            && !memcmp(data + offset + 1, name, name_length)) {
            *value_offset = value;
            return value < length;
        }
        size_t depth = 0;
        offset = value;
        do {
            offset = pdf_skip_space_and_comments(data, offset, length);
            if (!pdf_token_end(data, length, offset, &end)) {
                return false;
            }
            bool opening = data[offset] == '['
                || (end - offset == 2 && !memcmp(data + offset, "<<", 2));
            bool closing = data[offset] == ']'
                || (end - offset == 2 && !memcmp(data + offset, ">>", 2));
            if (opening) {
                depth++;
            } else if (closing) {
                if (depth == 0) {
                    return false;
                }
                depth--;
            }
            offset = end;
        } while (depth > 0);
        int reference = -1;
        if (pdf_parse_indirect_reference(data, length, value, &reference)) {
            for (int token = 0; token < 2; token++) {
                offset = pdf_skip_space_and_comments(data, offset, length);
                if (!pdf_token_end(data, length, offset, &offset)) {
                    return false;
                }
            }
        }
    }
    return false;
}

static bool pdf_parse_signed_integer(const unsigned char *data, size_t length,
                                     size_t offset, int64_t *value,
                                     size_t *end_offset) {
    if (!data || !value || offset >= length) {
        return false;
    }

    offset = (size_t)pdf_skip_space_and_comments(
        data, (uint64_t)offset, (uint64_t)length);
    bool negative = false;
    if (offset < length && (data[offset] == '+' || data[offset] == '-')) {
        negative = data[offset] == '-';
        offset++;
    }
    if (offset >= length || !isdigit(data[offset])) {
        return false;
    }

    uint64_t magnitude = 0;
    uint64_t maximum = negative ? (uint64_t)INT64_MAX + 1U
                                : (uint64_t)INT64_MAX;
    while (offset < length && isdigit(data[offset])) {
        unsigned int digit = (unsigned int)(data[offset] - '0');
        if (magnitude > (maximum - digit) / 10U) {
            return false;
        }
        magnitude = magnitude * 10U + digit;
        offset++;
    }

    if (negative) {
        *value = magnitude == (uint64_t)INT64_MAX + 1U
                     ? INT64_MIN
                     : -(int64_t)magnitude;
    } else {
        *value = (int64_t)magnitude;
    }
    if (end_offset) {
        *end_offset = offset;
    }
    return true;
}

static bool pdf_parse_string(const unsigned char *data, size_t length,
                             size_t offset, unsigned char *output,
                             size_t output_capacity, size_t *output_length) {
    if (!data || !output || !output_length || offset >= length) {
        return false;
    }
    offset = (size_t)pdf_skip_space_and_comments(
        data, (uint64_t)offset, (uint64_t)length);
    *output_length = 0;

    if (offset < length && data[offset] == '<' &&
        (offset + 1 >= length || data[offset + 1] != '<')) {
        int high_nibble = -1;
        for (offset++; offset < length; offset++) {
            unsigned char c = data[offset];
            if (c == '>') {
                if (high_nibble >= 0) {
                    if (*output_length >= output_capacity) {
                        return false;
                    }
                    output[(*output_length)++] =
                        (unsigned char)(high_nibble << 4);
                }
                return true;
            }
            if (pdf_lexical_space(c)) {
                continue;
            }
            int nibble = -1;
            if (c >= '0' && c <= '9') {
                nibble = c - '0';
            } else if (c >= 'A' && c <= 'F') {
                nibble = c - 'A' + 10;
            } else if (c >= 'a' && c <= 'f') {
                nibble = c - 'a' + 10;
            } else {
                return false;
            }
            if (high_nibble < 0) {
                high_nibble = nibble;
            } else {
                if (*output_length >= output_capacity) {
                    return false;
                }
                output[(*output_length)++] =
                    (unsigned char)((high_nibble << 4) | nibble);
                high_nibble = -1;
            }
        }
        return false;
    }

    if (offset >= length || data[offset] != '(') {
        return false;
    }
    size_t depth = 1;
    for (offset++; offset < length; offset++) {
        unsigned char c = data[offset];
        if (c == '\\') {
            offset++;
            if (offset >= length) {
                return false;
            }
            c = data[offset];
            if (c == '\r' || c == '\n') {
                if (c == '\r' && offset + 1 < length &&
                    data[offset + 1] == '\n') {
                    offset++;
                }
                continue;
            }
            switch (c) {
                case 'n': c = '\n'; break;
                case 'r': c = '\r'; break;
                case 't': c = '\t'; break;
                case 'b': c = '\b'; break;
                case 'f': c = '\f'; break;
                case '(':
                case ')':
                case '\\':
                    break;
                default:
                    if (c >= '0' && c <= '7') {
                        unsigned int octal = c - '0';
                        int digits = 1;
                        while (digits < 3 && offset + 1 < length &&
                               data[offset + 1] >= '0' &&
                               data[offset + 1] <= '7') {
                            offset++;
                            octal = octal * 8U +
                                    (unsigned int)(data[offset] - '0');
                            digits++;
                        }
                        c = (unsigned char)octal;
                    }
                    break;
            }
        } else if (c == '(') {
            depth++;
        } else if (c == ')') {
            depth--;
            if (depth == 0) {
                return true;
            }
        }

        if (*output_length >= output_capacity) {
            return false;
        }
        output[(*output_length)++] = c;
    }
    return false;
}

static bool pdf_parse_indirect_reference(const unsigned char *data,
                                         size_t length, size_t offset,
                                         int *object_number) {
    int64_t object = 0;
    int64_t generation = 0;
    size_t cursor = 0;
    if (!object_number ||
        !pdf_parse_signed_integer(data, length, offset, &object, &cursor) ||
        object < 0 || object > INT_MAX ||
        !pdf_parse_signed_integer(data, length, cursor, &generation, &cursor) ||
        generation < 0 || generation > 65535) {
        return false;
    }
    cursor = (size_t)pdf_skip_space_and_comments(
        data, (uint64_t)cursor, (uint64_t)length);
    if (cursor >= length || data[cursor] != 'R' ||
        (cursor + 1 < length && !pdf_lexical_space(data[cursor + 1]) &&
         !pdf_lexical_delimiter(data[cursor + 1]))) {
        return false;
    }
    *object_number = (int)object;
    return true;
}

static bool pdf_incremental_update_prefix(const unsigned char *data,
                                          size_t length) {
    if (!data || length == 0) {
        return false;
    }
    size_t cursor = (size_t)pdf_skip_space_and_comments(
        data, 0, (uint64_t)length);
    if (cursor + 4 <= length && !memcmp(data + cursor, "xref", 4) &&
        (cursor + 4 == length ||
         pdf_lexical_space(data[cursor + 4]) ||
         pdf_lexical_delimiter(data[cursor + 4]))) {
        return true;
    }

    int64_t object_number = 0;
    int64_t generation = 0;
    if (!pdf_parse_signed_integer(data, length, cursor, &object_number,
                                  &cursor) ||
        object_number < 0 || object_number > INT_MAX ||
        !pdf_parse_signed_integer(data, length, cursor, &generation,
                                  &cursor) ||
        generation < 0 || generation > 65535) {
        return false;
    }
    cursor = (size_t)pdf_skip_space_and_comments(
        data, (uint64_t)cursor, (uint64_t)length);
    return cursor + 3 <= length && !memcmp(data + cursor, "obj", 3) &&
           (cursor + 3 == length ||
            pdf_lexical_space(data[cursor + 3]) ||
            pdf_lexical_delimiter(data[cursor + 3]));
}

static bool pdf_md5(const unsigned char *data, size_t length,
                    unsigned char digest[16]) {
    if (!data || !digest) {
        return false;
    }
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (!context) {
        return false;
    }
    unsigned int digest_length = 0;
    bool success = EVP_DigestInit_ex(context, EVP_md5(), NULL) == 1 &&
                   EVP_DigestUpdate(context, data, length) == 1 &&
                   EVP_DigestFinal_ex(context, digest, &digest_length) == 1 &&
                   digest_length == 16;
    EVP_MD_CTX_free(context);
    return success;
}

static void pdf_rc4_crypt(const unsigned char *key, size_t key_length,
                          const unsigned char *input, unsigned char *output,
                          size_t length) {
    unsigned char state[256];
    for (size_t i = 0; i < sizeof(state); i++) {
        state[i] = (unsigned char)i;
    }

    unsigned int j = 0;
    for (unsigned int i = 0; i < 256; i++) {
        j = (j + state[i] + key[i % key_length]) & 0xffU;
        unsigned char swap = state[i];
        state[i] = state[j];
        state[j] = swap;
    }

    unsigned int i = 0;
    j = 0;
    for (size_t offset = 0; offset < length; offset++) {
        i = (i + 1U) & 0xffU;
        j = (j + state[i]) & 0xffU;
        unsigned char swap = state[i];
        state[i] = state[j];
        state[j] = swap;
        unsigned int index = (state[i] + state[j]) & 0xffU;
        output[offset] = input[offset] ^ state[index];
    }
}

// A classic xref's trailer and an xref stream's dictionary carry document
// metadata. Keep their lookup inside the dictionary, not the candidate's tail.
static bool pdf_xref_dictionary(const unsigned char *data, uint64_t length,
                                 const XrefObject *xrefs, int num_tables,
                                 int table, uint64_t *start, uint64_t *end) {
    if (!data || !xrefs || !start || !end || table < 0 || table >= num_tables
        || xrefs[table].offset < 0 || (uint64_t)xrefs[table].offset >= length
        || length > SIZE_MAX) {
        return false;
    }
    uint64_t offset = (uint64_t)xrefs[table].offset;
    uint64_t limit = length;
    if (table + 1 < num_tables && xrefs[table + 1].offset > xrefs[table].offset
        && (uint64_t)xrefs[table + 1].offset < limit) {
        limit = (uint64_t)xrefs[table + 1].offset;
    }
    const unsigned char *dictionary = memmem(data + offset, (size_t)(limit - offset),
                                              "<<", 2);
    if (!dictionary) {
        return false;
    }
    *start = (uint64_t)(dictionary - data);
    unsigned char *stack = NULL;
    size_t capacity = 0;
    bool found = pdf_nonstream_object_end(data, *start, limit, -1, &stack,
                                           &capacity, end, NULL, NULL);
    free(stack);
    return found;
}

static bool pdf_initialize_encryption_context(
    const unsigned char *data, uint64_t length, XrefTables *tables,
    const XrefObject *xrefs, int num_tables, PDFEncryptionContext *context) {
    static const unsigned char password_padding[32] = {
        0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41,
        0x64, 0x00, 0x4e, 0x56, 0xff, 0xfa, 0x01, 0x08,
        0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80,
        0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a
    };
    if (!data || length == 0 || length > SIZE_MAX || !tables || !xrefs
        || num_tables <= 0 || !context) {
        return false;
    }
    memset(context, 0, sizeof(*context));
    context->encrypt_metadata = true;

    int encrypt_object = -1;
    const unsigned char *encryption_dictionary = NULL;
    size_t encryption_dictionary_length = 0;
    unsigned char document_id[64];
    size_t document_id_length = 0;
    for (int table = 0; table < num_tables; table++) {
        uint64_t start = 0;
        uint64_t end = 0;
        if (!tables[table].entries || tables[table].count <= 0
            || !pdf_xref_dictionary(data, length, xrefs, num_tables, table,
                                     &start, &end)) {
            continue;
        }
        const unsigned char *dictionary = data + start;
        size_t dictionary_length = (size_t)(end - start);
        size_t relative_value = 0;
        int candidate_object = -1;
        if (pdf_find_name_value(dictionary, dictionary_length,
                                 "Encrypt", &relative_value)) {
            if (pdf_parse_indirect_reference(dictionary, dictionary_length,
                                              relative_value, &candidate_object)) {
                encrypt_object = candidate_object;
                encryption_dictionary = NULL;
                encryption_dictionary_length = 0;
            }
            else if (dictionary_length - relative_value >= 2
                     && !memcmp(dictionary + relative_value, "<<", 2)) {
                unsigned char *stack = NULL;
                size_t capacity = 0;
                uint64_t dictionary_end = 0;
                bool found = pdf_nonstream_object_end(
                    dictionary, relative_value, dictionary_length, -1,
                    &stack, &capacity, &dictionary_end, NULL, NULL);
                free(stack);
                if (found) {
                    encrypt_object = -1;
                    encryption_dictionary = dictionary + relative_value;
                    encryption_dictionary_length = (size_t)(dictionary_end - relative_value);
                }
            }
        }
        if (!pdf_find_name_value(dictionary, dictionary_length, "ID",
                                  &relative_value)) {
            continue;
        }
        if (relative_value < dictionary_length && dictionary[relative_value] == '[') {
            unsigned char candidate_id[64];
            size_t candidate_length = 0;
            if (pdf_parse_string(dictionary, dictionary_length, relative_value + 1,
                                 candidate_id, sizeof(candidate_id),
                                 &candidate_length) &&
                candidate_length > 0) {
                memcpy(document_id, candidate_id, candidate_length);
                document_id_length = candidate_length;
            }
        }
    }
    if ((encrypt_object < 0 && !encryption_dictionary) || document_id_length == 0) {
        return false;
    }

    if (!encryption_dictionary) {
        uint64_t encrypt_offset = search_tables_for_object(
            tables, num_tables, encrypt_object);
        if (encrypt_offset >= length) {
            return false;
        }
        char *end_object = memmem(data + encrypt_offset,
                                  (size_t)(length - encrypt_offset),
                                  "endobj", 6);
        uint64_t encrypt_limit = end_object
                                     ? (uint64_t)(end_object - (char *)data) + 6
                                     : length;
        uint64_t dictionary_start = 0;
        if (!pdf_indirect_object_body_start(data, encrypt_offset, encrypt_limit,
                                            encrypt_object, &dictionary_start,
                                            NULL)) {
            return false;
        }
        encryption_dictionary = data + dictionary_start;
        encryption_dictionary_length = (size_t)(encrypt_limit - dictionary_start);
    }
    const unsigned char *dictionary = encryption_dictionary;
    size_t dictionary_length = encryption_dictionary_length;

    size_t value_offset = 0;
    if (!pdf_find_name_value(dictionary, dictionary_length, "Filter",
                             &value_offset) ||
        value_offset + 9 > dictionary_length ||
        memcmp(dictionary + value_offset, "/Standard", 9) ||
        (value_offset + 9 < dictionary_length &&
         !pdf_lexical_space(dictionary[value_offset + 9]) &&
         !pdf_lexical_delimiter(dictionary[value_offset + 9]))) {
        return false;
    }

    int64_t revision = 0;
    int64_t version = 0;
    int64_t permissions = 0;
    int64_t key_bits = 40;
    if (!pdf_find_name_value(dictionary, dictionary_length, "R",
                             &value_offset) ||
        !pdf_parse_signed_integer(dictionary, dictionary_length, value_offset,
                                  &revision, NULL) ||
        !pdf_find_name_value(dictionary, dictionary_length, "V",
                             &value_offset) ||
        !pdf_parse_signed_integer(dictionary, dictionary_length, value_offset,
                                  &version, NULL) ||
        !pdf_find_name_value(dictionary, dictionary_length, "P",
                             &value_offset) ||
        !pdf_parse_signed_integer(dictionary, dictionary_length, value_offset,
                                  &permissions, NULL)) {
        return false;
    }
    if (revision == 2) {
        if (version != 1 && version != 2) {
            return false;
        }
        key_bits = 40;
    } else if ((revision == 3 && version == 2) || (revision == 4 && version == 4)) {
        if (pdf_find_name_value(dictionary, dictionary_length, "Length",
                                &value_offset) &&
            !pdf_parse_signed_integer(dictionary, dictionary_length,
                                      value_offset, &key_bits, NULL)) {
            return false;
        }
        if (key_bits < 40 || key_bits > 128 || key_bits % 8 != 0) {
            return false;
        }
    } else {
        return false;
    }

    if (revision == 4) {
        size_t method = 0, filters = 0, selected = 0;
        if (pdf_find_name_value(dictionary, dictionary_length, "EncryptMetadata",
                                &value_offset)) {
            size_t end = 0;
            if (!pdf_token_end(dictionary, dictionary_length, value_offset, &end)) {
                return false;
            }
            if (end - value_offset == 5 && !memcmp(dictionary + value_offset, "false", 5)) {
                context->encrypt_metadata = false;
            } else if (end - value_offset != 4 || memcmp(dictionary + value_offset, "true", 4)) {
                return false;
            }
        }
        context->identity = true;
        if (pdf_find_name_value(dictionary, dictionary_length, "StmF", &selected)) {
            size_t end = 0;
            if (!pdf_token_end(dictionary, dictionary_length, selected, &end) ||
                dictionary[selected] != '/' || end - selected < 2 || end - selected > 128) {
                return false;
            }
            char name[128];
            memcpy(name, dictionary + selected + 1, end - selected - 1);
            name[end - selected - 1] = 0;
            if (strcmp(name, "Identity")) {
                if (!pdf_find_name_value(dictionary, dictionary_length, "CF", &filters) ||
                    !pdf_find_name_value(dictionary + filters, dictionary_length - filters,
                                         name, &selected)) {
                    return false;
                }
                selected += filters;
                if (!pdf_find_name_value(dictionary + selected, dictionary_length - selected,
                                         "CFM", &method)) {
                    return false;
                }
                method += selected;
                if (!pdf_token_end(dictionary, dictionary_length, method, &end)) {
                    return false;
                }
                context->aes = end - method == 6 && !memcmp(dictionary + method, "/AESV2", 6);
                context->identity = end - method == 5 && !memcmp(dictionary + method, "/None", 5);
                if (!context->aes && !context->identity &&
                    (end - method != 3 || memcmp(dictionary + method, "/V2", 3))) {
                    return false;
                }
                if (context->aes && key_bits != 128) {
                    return false;
                }
            }
        }
    }

    unsigned char owner_entry[64];
    unsigned char user_entry[64];
    size_t owner_length = 0;
    size_t user_length = 0;
    if (!pdf_find_name_value(dictionary, dictionary_length, "O",
                             &value_offset) ||
        !pdf_parse_string(dictionary, dictionary_length, value_offset,
                          owner_entry, sizeof(owner_entry), &owner_length) ||
        owner_length != 32 ||
        !pdf_find_name_value(dictionary, dictionary_length, "U",
                             &value_offset) ||
        !pdf_parse_string(dictionary, dictionary_length, value_offset,
                          user_entry, sizeof(user_entry), &user_length)) {
        return false;
    }

    size_t key_length = revision == 2 ? 5 : (size_t)(key_bits / 8);
    unsigned char key_input[32 + 32 + 4 + sizeof(document_id) + 4];
    size_t key_input_length = 0;
    memcpy(key_input + key_input_length, password_padding,
           sizeof(password_padding));
    key_input_length += sizeof(password_padding);
    memcpy(key_input + key_input_length, owner_entry, 32);
    key_input_length += 32;
    uint32_t permissions_word = (uint32_t)permissions;
    for (int byte = 0; byte < 4; byte++) {
        key_input[key_input_length++] =
            (unsigned char)((permissions_word >> (byte * 8)) & 0xffU);
    }
    memcpy(key_input + key_input_length, document_id, document_id_length);
    key_input_length += document_id_length;
    if (revision >= 4 && !context->encrypt_metadata) {
        memset(key_input + key_input_length, 0xff, 4);
        key_input_length += 4;
    }

    unsigned char digest[16];
    if (!pdf_md5(key_input, key_input_length, digest)) {
        return false;
    }
    if (revision >= 3) {
        for (int round = 0; round < 50; round++) {
            if (!pdf_md5(digest, key_length, digest)) {
                return false;
            }
        }
    }

    unsigned char expected_user[32];
    if (revision == 2) {
        if (user_length != 32) {
            return false;
        }
        pdf_rc4_crypt(digest, key_length, password_padding, expected_user,
                      sizeof(expected_user));
        if (memcmp(expected_user, user_entry, sizeof(expected_user))) {
            return false;
        }
    } else {
        if (user_length < 16) {
            return false;
        }
        unsigned char user_seed[32 + sizeof(document_id)];
        memcpy(user_seed, password_padding, sizeof(password_padding));
        memcpy(user_seed + sizeof(password_padding), document_id,
               document_id_length);
        if (!pdf_md5(user_seed, sizeof(password_padding) + document_id_length,
                     expected_user)) {
            return false;
        }
        unsigned char encrypted_user[16];
        pdf_rc4_crypt(digest, key_length, expected_user, encrypted_user,
                      sizeof(encrypted_user));
        for (unsigned int round = 1; round <= 19; round++) {
            unsigned char round_key[16];
            for (size_t byte = 0; byte < key_length; byte++) {
                round_key[byte] = digest[byte] ^ (unsigned char)round;
            }
            pdf_rc4_crypt(round_key, key_length, encrypted_user,
                          encrypted_user, sizeof(encrypted_user));
        }
        if (memcmp(encrypted_user, user_entry, sizeof(encrypted_user))) {
            return false;
        }
    }

    memcpy(context->file_key, digest, key_length);
    context->file_key_length = key_length;
    context->active = true;
    return true;
}

static bool pdf_decrypt_stream(const PDFEncryptionContext *context,
                               int object_number, int generation,
                               const unsigned char *input, size_t length,
                               unsigned char *output, size_t *output_length) {
    if (!context || !context->active || context->file_key_length == 0 ||
        context->file_key_length > sizeof(context->file_key) ||
        object_number < 0 || generation < 0 || generation > 65535 ||
        (!input && length != 0) || (!output && length != 0) || !output_length) {
        return false;
    }
    *output_length = 0;
    if (context->identity) {
        memcpy(output, input, length);
        *output_length = length;
        return true;
    }

    unsigned char key_material[25];
    memcpy(key_material, context->file_key, context->file_key_length);
    size_t key_material_length = context->file_key_length;
    key_material[key_material_length++] = (unsigned char)(object_number & 0xff);
    key_material[key_material_length++] =
        (unsigned char)((object_number >> 8) & 0xff);
    key_material[key_material_length++] =
        (unsigned char)((object_number >> 16) & 0xff);
    key_material[key_material_length++] = (unsigned char)(generation & 0xff);
    key_material[key_material_length++] =
        (unsigned char)((generation >> 8) & 0xff);
    if (context->aes) {
        memcpy(key_material + key_material_length, "sAlT", 4);
        key_material_length += 4;
    }

    unsigned char digest[16];
    if (!pdf_md5(key_material, key_material_length, digest)) {
        return false;
    }
    size_t object_key_length = context->file_key_length + 5;
    if (object_key_length > sizeof(digest)) {
        object_key_length = sizeof(digest);
    }
    if (context->aes) {
        if (length < 32 || length % 16 != 0 || length - 16 > INT_MAX) {
            return false;
        }
        EVP_CIPHER_CTX *cipher = EVP_CIPHER_CTX_new();
        if (!cipher) {
            return false;
        }
        int produced = 0, final = 0;
        bool ok = EVP_DecryptInit_ex(cipher, EVP_aes_128_cbc(), NULL, digest, input) == 1
            && EVP_DecryptUpdate(cipher, output, &produced, input + 16, (int)(length - 16)) == 1
            && EVP_DecryptFinal_ex(cipher, output + produced, &final) == 1;
        EVP_CIPHER_CTX_free(cipher);
        if (!ok) {
            return false;
        }
        *output_length = (size_t)produced + (size_t)final;
        return true;
    }
    pdf_rc4_crypt(digest, object_key_length, input, output, length);
    *output_length = length;
    return true;
}

static bool pdf_syntax_push(unsigned char **stack, size_t *stack_capacity,
                            size_t depth, unsigned char delimiter) {
    if (depth == *stack_capacity) {
        size_t new_capacity = *stack_capacity == 0 ? 64 : *stack_capacity * 2;
        if (new_capacity <= *stack_capacity) {
            return false;
        }
        unsigned char *grown = realloc(*stack, new_capacity);
        if (!grown) {
            return false;
        }
        *stack = grown;
        *stack_capacity = new_capacity;
    }
    (*stack)[depth] = delimiter;
    return true;
}

static bool pdf_nonstream_object_well_formed(const unsigned char *data,
                                             uint64_t offset,
                                             uint64_t limit,
                                             int expected_object,
                                             unsigned char **stack,
                                             size_t *stack_capacity) {
    return pdf_nonstream_object_end(data, offset, limit, expected_object,
                                    stack, stack_capacity, NULL, NULL, NULL);
}

static bool pdf_nonstream_object_end(const unsigned char *data,
                                    uint64_t offset, uint64_t limit,
                                    int expected_object, unsigned char **stack,
                                    size_t *stack_capacity, uint64_t *end,
                                    PDFStreamMetadata *metadata, bool (*stop)(void)) {
    // A negative object number scans a standalone trailer dictionary.
    uint64_t cursor = offset;
    if (expected_object >= 0
        && !pdf_indirect_object_body_start(data, offset, limit,
                                            expected_object, &cursor, NULL)) {
        return false;
    }

    size_t depth = 0;
    uint32_t work = 0;
    bool saw_dictionary = false;
    while (cursor < limit) {
        if (stop && (work++ & 1023) == 0 && stop()) {
            return false;
        }
        unsigned char c = data[cursor];
        if (pdf_lexical_space(c)) {
            cursor++;
            continue;
        }
        if (c == '%') {
            if (stop) {
                while (cursor < limit && data[cursor] != '\r' && data[cursor] != '\n') {
                    if ((work++ & 1023) == 0 && stop()) {
                        return false;
                    }
                    cursor++;
                }
                continue;
            }
            cursor = pdf_skip_space_and_comments(data, cursor, limit);
            continue;
        }
        if (c == '(') {
            uint64_t paren_depth = 1;
            cursor++;
            while (cursor < limit && paren_depth > 0) {
                if (stop && (work++ & 1023) == 0 && stop()) {
                    return false;
                }
                c = data[cursor++];
                if (c == '\\') {
                    if (cursor >= limit) {
                        if (metadata) {
                            metadata->incomplete = true;
                        }
                        return false;
                    }
                    if (data[cursor] == '\r') {
                        cursor++;
                        if (cursor < limit && data[cursor] == '\n') {
                            cursor++;
                        }
                    } else {
                        cursor++;
                    }
                } else if (c == '(') {
                    paren_depth++;
                } else if (c == ')') {
                    paren_depth--;
                }
            }
            if (paren_depth != 0) {
                if (metadata) {
                    metadata->incomplete = true;
                }
                return false;
            }
            continue;
        }
        if (c == '<') {
            if (cursor + 1 < limit && data[cursor + 1] == '<') {
                if (!pdf_syntax_push(stack, stack_capacity, depth, '<')) {
                    return false;
                }
                depth++;
                saw_dictionary = true;
                cursor += 2;
                continue;
            }
            cursor++;
            while (cursor < limit && data[cursor] != '>') {
                if (stop && (work++ & 1023) == 0 && stop()) {
                    return false;
                }
                c = data[cursor++];
                if (!pdf_lexical_space(c) && !isxdigit(c)) {
                    return false;
                }
            }
            if (cursor >= limit) {
                if (metadata) {
                    metadata->incomplete = true;
                }
                return false;
            }
            cursor++;
            continue;
        }
        if (c == '>') {
            if (cursor + 1 >= limit || data[cursor + 1] != '>' || depth == 0 ||
                (*stack)[depth - 1] != '<') {
                if (metadata && cursor + 1 == limit && depth > 0
                    && (*stack)[depth - 1] == '<') {
                    metadata->incomplete = true;
                }
                return false;
            }
            depth--;
            cursor += 2;
            if (depth == 0 && expected_object < 0) {
                if (end) {
                    *end = cursor;
                }
                return saw_dictionary;
            }
            continue;
        }
        if (c == '[') {
            if (!pdf_syntax_push(stack, stack_capacity, depth, '[')) {
                return false;
            }
            depth++;
            cursor++;
            continue;
        }
        if (c == ']') {
            if (depth == 0 || (*stack)[depth - 1] != '[') {
                return false;
            }
            depth--;
            cursor++;
            continue;
        }
        if (c == ')' || c == '{' || c == '}') {
            return false;
        }
        if (c == '/') {
            cursor++;
            uint64_t name_start = cursor;
            while (cursor < limit && !pdf_lexical_space(data[cursor]) &&
                   !pdf_lexical_delimiter(data[cursor])) {
                if (stop && (work++ & 1023) == 0 && stop()) {
                    return false;
                }
                if (data[cursor] < 32) {
                    return false;
                }
                cursor++;
            }
            // Stream attributes belong to the outer dictionary, not strings
            // or nested dictionaries such as DecodeParms.
            if (metadata && depth == 1 && (*stack)[0] == '<') {
                uint64_t value = pdf_partial_skip_space(data, cursor, limit, stop);
                if (cursor - name_start == 6
                    && !memcmp(data + name_start, "Length", 6)) {
                    size_t value_end = 0;
                    metadata->has_length = pdf_parse_signed_integer(
                        data, limit, value, &metadata->length, &value_end)
                        && metadata->length >= 0;
                    if (metadata->has_length) {
                        uint64_t next = pdf_partial_skip_space(data, value_end, limit, stop);
                        if (next < limit && isdigit(data[next])) {
                            metadata->has_length = false;
                        }
                    }
                }
                else if (cursor - name_start == 6
                         && !memcmp(data + name_start, "Filter", 6)) {
                    metadata->has_filter = true;
                    if (value < limit && data[value] == '[') {
                        value = pdf_partial_skip_space(data, value + 1, limit, stop);
                    }
                    const char filter[] = "/FlateDecode";
                    size_t filter_length = sizeof(filter) - 1;
                    metadata->flate = value <= limit && filter_length <= limit - value
                        && !memcmp(data + value, filter, filter_length)
                        && (value + filter_length == limit
                            || pdf_lexical_space(data[value + filter_length])
                            || pdf_lexical_delimiter(data[value + filter_length]));
                    const char jpeg_filter[] = "/DCTDecode";
                    filter_length = sizeof(jpeg_filter) - 1;
                    metadata->jpeg = value <= limit && filter_length <= limit - value
                        && !memcmp(data + value, jpeg_filter, filter_length)
                        && (value + filter_length == limit
                            || pdf_lexical_space(data[value + filter_length])
                            || pdf_lexical_delimiter(data[value + filter_length]));
                }
                else if (cursor - name_start == 7
                         && !memcmp(data + name_start, "Subtype", 7)) {
                    metadata->xml = value <= limit && 4 <= limit - value
                        && !memcmp(data + value, "/XML", 4)
                        && (value + 4 == limit || pdf_lexical_space(data[value + 4])
                            || pdf_lexical_delimiter(data[value + 4]));
                }
            }
            continue;
        }
        if (c < 32) {
            return false;
        }

        uint64_t token_start = cursor;
        while (cursor < limit && !pdf_lexical_space(data[cursor]) &&
               !pdf_lexical_delimiter(data[cursor])) {
            if (stop && (work++ & 1023) == 0 && stop()) {
                return false;
            }
            if (data[cursor] < 32) {
                return false;
            }
            cursor++;
        }
        uint64_t token_length = cursor - token_start;
        if (depth == 0 && token_length == 6 &&
            !memcmp(data + token_start, "stream", 6)) {
            if (saw_dictionary && end) {
                *end = cursor;
            }
            return saw_dictionary;
        }
        if (depth == 0 && token_length == 6 &&
            !memcmp(data + token_start, "endobj", 6)) {
            if (end) {
                *end = cursor;
            }
            return true;
        }
    }
    if (metadata) {
        metadata->incomplete = true;
    }
    return false;
}

static bool pdf_nonstream_objects_well_formed(char *data, uint64_t length,
                                               XrefTables *tables,
                                               int num_tables) {
    if (!data || !tables || num_tables <= 0) {
        return false;
    }

    size_t object_capacity = 0;
    for (int table = 0; table < num_tables; table++) {
        if (tables[table].entries && tables[table].count > 0) {
            size_t table_count = (size_t)tables[table].count;
            if (table_count > SIZE_MAX - object_capacity) {
                return false;
            }
            object_capacity += table_count;
        }
    }
    if (object_capacity == 0) {
        return false;
    }

    Object *objects = malloc(object_capacity * sizeof(*objects));
    check_memory_allocation(objects, __LINE__, __FILE__,
                            "PDF syntax object list");
    size_t object_count = 0;
    for (int table = 0; table < num_tables; table++) {
        if (!tables[table].entries || tables[table].count <= 0) {
            continue;
        }
        for (int entry = 0; entry < tables[table].count; entry++) {
            Object object = tables[table].entries[entry];
            if (object.obj_num >= 0 && object.obj_offset < length) {
                objects[object_count++] = object;
            }
        }
    }
    if (object_count == 0) {
        free(objects);
        return false;
    }
    qsort(objects, object_count, sizeof(*objects), compare_objects);

    size_t unique_count = 0;
    for (size_t i = 0; i < object_count; i++) {
        if (unique_count > 0 &&
            objects[i].obj_offset == objects[unique_count - 1].obj_offset) {
            if (objects[i].obj_num != objects[unique_count - 1].obj_num) {
                free(objects);
                return false;
            }
            continue;
        }
        objects[unique_count++] = objects[i];
    }

    unsigned char *stack = NULL;
    size_t stack_capacity = 0;
    bool well_formed = true;
    for (size_t i = 0; i < unique_count; i++) {
        uint64_t limit = i + 1 < unique_count
                             ? objects[i + 1].obj_offset
                             : length;
        if (limit <= objects[i].obj_offset ||
            !pdf_nonstream_object_well_formed(
                (const unsigned char *)data, objects[i].obj_offset, limit,
                objects[i].obj_num, &stack, &stack_capacity)) {
            well_formed = false;
            break;
        }
    }

    free(stack);
    free(objects);
    return well_formed;
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
 * @description  Verifies the startxref immediately preceding the accepted EOF.
 *               Other occurrences can be ordinary text inside objects or streams.
 * @param data              The candidate buffer.
 * @param validation_cutoff The byte offset to stop scanning at.
 * @return       1 if the terminal reference resolves, 0 otherwise.
 */
int check_startxref(char *data, uint64_t validation_cutoff) {
    if (!data || validation_cutoff == UINT64_MAX) {
        return 0;
    }
    uint64_t end = validation_cutoff + 1;
    while (end && pdf_lexical_space((unsigned char)data[end - 1])) {
        end--;
    }
    if (end < 5 || memcmp(data + end - 5, "%%EOF", 5)) {
        return 0;
    }
    uint64_t eof = end - 5;
    for (uint64_t pos = eof; pos > 0;) {
        pos--;
        if (eof - pos < 9 || memcmp(data + pos, "startxref", 9)) {
            continue;
        }
        size_t value = pdf_skip_space_and_comments(
            (const unsigned char *)data, pos + 9, eof);
        size_t after = 0;
        int64_t target = -1;
        if (!pdf_parse_signed_integer((const unsigned char *)data, eof,
                                       value, &target, &after)
            || pdf_skip_space_and_comments((const unsigned char *)data, after, eof) != eof
            || target < 0 || (uint64_t)target >= pos) {
            return 0;
        }
        // Linearized first-page sections can use a zero terminal reference.
        if (target == 0) {
            return 1;
        }
        return detect_xref_type(data, target, (int64_t)end, &target) >= 1;
    }
    return 0;
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
    int64_t incomplete = -1;
    init_blockvector(scalpel_state.filemirror, &scan_bv, 1, false);
    uint64_t local_offset = obj_offset % scalpel_state.blocksize;

    while ((block_choice = blockvector_get_choice(scan_bv, slot, start, -1, &evaluated)) != -1) {
        blockvector_remove_choice(scan_bv, slot, block_choice);
        start = block_choice + 1;
        if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
            incomplete = -1;
            break;
        }
        unsigned char *blk = (unsigned char *)get_apparent_block_data(
            scalpel_state.filemirror, block_choice);
        uint64_t body_start = 0;
        uint64_t length = scalpel_state.blocksize;
        int check = pdf_indirect_object_header(blk, local_offset, length,
                                               obj_num, &body_start, NULL);
        if (check == 0 && incomplete < 0) {
            incomplete = block_choice;
        }
        int64_t actual = filemirror_actual_blocknumber(
            scalpel_state.filemirror, block_choice);
        uint64_t image_blocks = CEILDIV(filemirror_filesize(scalpel_state.filemirror),
                                        scalpel_state.blocksize);
        // Prefer a complete header, including one crossing adjacent blocks.
        // If its continuation is displaced, keep the partial match as a fallback.
        while (check == 0 && actual >= 0 && (uint64_t)actual + 1 < image_blocks &&
               !atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
            actual++;
            int64_t next = filemirror_apparent_blocknumber(
                scalpel_state.filemirror, actual);
            if (next < 0 || length > SIZE_MAX - scalpel_state.blocksize) {
                break;
            }
            unsigned char *tail = (unsigned char *)get_apparent_block_data(
                scalpel_state.filemirror, next);
            if (!tail) {
                break;
            }
            blk = realloc(blk, (size_t)(length + scalpel_state.blocksize));
            check_memory_allocation(blk, __LINE__, __FILE__, "PDF object header");
            memcpy(blk + length, tail, scalpel_state.blocksize);
            free(tail);
            length += scalpel_state.blocksize;
            check = pdf_indirect_object_header(blk, local_offset, length,
                                               obj_num, &body_start, NULL);
        }
        free(blk);
        if (check == 1) {
            result = block_choice;
            break;
        }
    }
    free_blockvector(&scan_bv);
    return result >= 0 ? result : incomplete;
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
 * @param search_image Allow reassembly to look outside the assembled candidate.
 * @return       The stream length, or LENGTHNOTFOUND if none could be resolved.
 */
int check_last_object_length(char *data, uint64_t length, uint64_t *out_offset,
                              XrefTables *test_tables, int num_tables,
                              const char *dict, int dict_len, uint64_t obj_offset,
                              bool search_image) {
    int64_t object_length = 0;
    int obj_num = -1;
    for(int64_t i = 0; i + 7 < dict_len; i++){
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
                if(object_length <= 0 && search_image){
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
 * @description  Confirms that zlib reached its checksum while accounting for the
 *               complete declared stream extent. PDF producers occasionally
 *               include PDF whitespace after the zlib member in /Length; those
 *               bytes are accepted, but arbitrary unconsumed data is not.
 * @param stream    The zlib state after Z_STREAM_END.
 * @param supplied  Bytes supplied from the declared extent.
 * @param declared  Declared stream length.
 * @return       true when all declared bytes were consumed or the only
 *               unconsumed bytes are PDF whitespace.
 */
static bool pdf_zlib_extent_complete(const z_stream *stream,
                                     size_t supplied,
                                     size_t declared) {
    if (!stream || supplied != declared || stream->total_in > declared) {
        return false;
    }

    size_t trailing = declared - (size_t)stream->total_in;
    if (trailing == 0) {
        return true;
    }
    if (!stream->next_in || stream->avail_in != trailing) {
        return false;
    }

    for (size_t i = 0; i < trailing; i++) {
        unsigned char c = stream->next_in[i];
        if (c != 0 && c != '\t' && c != '\n' && c != '\f' &&
            c != '\r' && c != ' ') {
            return false;
        }
    }
    return true;
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
    bool stream_ended = false;

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

        if (ret == Z_STREAM_END) {
            stream_ended = true;
            break;
        }

    } while (r->strm.avail_out == 0);

    if ((stream_ended && stream_length &&
         !pdf_zlib_extent_complete(&r->strm, r->fed, stream_length)) ||
        (!stream_ended && stream_length && r->fed >= stream_length)) {
        inflateEnd(&r->strm);
        free(r->output);
        r->output = NULL;
        return -1;
    }

    // Snapshot this as our first checkpoint
    if (inflateCopy(&r->checkpoint, &r->strm) != Z_OK) {
        inflateEnd(&r->strm);
        free(r->output);
        r->output = NULL;
        return -1;
    }

    r->total_verified = r->output_len;
    r->ended = stream_ended;
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

    r->fed += take;

    /*
     * Completion gate. Once the declared /Length has been consumed the stream
     * MUST have terminated: Z_STREAM_END is where zlib verifies the Adler-32
     * checksum over the entire decompressed output, and that checksum is the
     * only redundancy DEFLATE retains. Reaching the end of the data without it
     * proves the assembled block sequence is wrong, even though every
     * individual block decoded without error.
     */
    if ((stream_ended && r->stream_length &&
         !pdf_zlib_extent_complete(&r->strm, r->fed,
                                   r->stream_length)) ||
        (!stream_ended && r->stream_length &&
         r->fed >= r->stream_length)) {
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

// Count forward blocks that can precede a replacement run in an unfinished
// Flate stream. Once a prefix fails, changing later blocks cannot repair it.
// Return -1 on a checkpoint request or -2 if the initial stream is unusable.
static int pdf_zlib_contiguous_prefix_blocks(const unsigned char *first_block,
                                            size_t stream_offset,
                                            size_t stream_length,
                                            int64_t first_apparent,
                                            int maximum) {
    if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
        return -1;
    }
    ZlibStreamReassembler prefix;
    if (zlib_stream_reassembler_init(&prefix, first_block,
                                    scalpel_state.blocksize, stream_offset,
                                    stream_length) == -1) {
        return -2;
    }
    if (prefix.ended) {
        zlib_stream_reassembler_free(&prefix);
        return -2;
    }

    int accepted = 0;
    int64_t total = (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror);
    while (accepted < maximum && first_apparent >= 0 &&
           first_apparent < total - 1 - accepted) {
        if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
            zlib_stream_reassembler_free(&prefix);
            return -1;
        }
        const unsigned char *block = get_apparent_block_data(
            scalpel_state.filemirror, first_apparent + 1 + accepted);
        if (!block) {
            break;
        }
        int status = zlib_stream_reassembler_try_block(
            &prefix, block, scalpel_state.blocksize);
        free((void *)block);
        if (status != 1) {
            break;
        }
        accepted++;
    }
    zlib_stream_reassembler_free(&prefix);
    return accepted;
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

                // Placing the block can relocate the candidate's data buffer.
                data = blockvector_get_data_pointer(candidate->b);
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

// Update only the deferred cursor, preserving the candidate's other PDF state.
static void pdf_store_three_run_search(CarveInfo *candidate,
                                        const PDFThreeRunSearch *search) {
    PDFCarveState *state = carve_get_state(candidate->carvehashkey);
    if (state) {
        state->three_run = *search;
        carve_put_state(candidate->carvehashkey, state);
        pdf_free_carve_state((void **)&state);
    }
}

// Hash actual identities so unrelated apparent-block renumbering is harmless.
// A changed fixed mapping invalidates the saved search assumptions.
static uint64_t pdf_three_run_signature(CarveInfo *candidate,
                                         int64_t first, int64_t count,
                                         uint64_t seed) {
    int64_t total = (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror);
    for (int64_t i = 0; i < count; i++) {
        int64_t app = candidate
            ? blockvector_get_apparent_blocknumber(candidate->b, (uint64_t)i)
            : first + i;
        int64_t actual = app >= 0 && app < total
            ? filemirror_actual_blocknumber(scalpel_state.filemirror, app) : -1;
        seed = XXH64(&actual, sizeof(actual), seed);
    }
    return seed;
}

// Changing the fixed candidate or stream makes the previous query obsolete;
// unrelated blockmap compaction does not change physical source identities.
static uint64_t pdf_interior_signature(CarveInfo *candidate,
                                        int64_t stream_at, int stream_len) {
    const uint64_t fields[] = {
        (uint64_t)stream_at, (uint64_t)stream_len,
        blockvector_get_data_length(candidate->b),
        blockvector_get_num_blocks(candidate->b), scalpel_state.blocksize
    };
    return pdf_three_run_signature(candidate, 0, (int64_t)fields[3],
        XXH64(fields, sizeof(fields), 0));
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
        if (stream_check < 0) {
            // Allocation or inflate-copy failure can leave the live decoder
            // advanced. It must not be reused to test a different block.
            zlib_stream_reassembler_free(&r);
            free((void *)stream_block);
            return false;
        }
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
        return stream_check == 1 || stream_check == 2;
    }

    if (mode == MULTIBLOCK) {
        /*
         * Reconstruct the interior of a multi-block zlib stream by searching for
         * the fragment-switch point, using stream completion (the Adler-32 at
         * Z_STREAM_END) as the oracle and committing nothing until it verifies.
         * DEFLATE has no local check to test a single block against, so the only
         * sound question is the global one -- does this whole assignment complete?
         * -- asked once per candidate split. Try two physical runs first, then
         * the more general reconstruction paths below.
         */
        if (blocks_to_extend <= 0) return false;
        const int64_t tot_app = (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror);
        const uint64_t nb_before = blockvector_get_num_blocks(candidate->b);
        PDFCarveState *saved = carve_get_state(candidate->carvehashkey);
        PDFThreeRunSearch search = saved ? saved->three_run : (PDFThreeRunSearch){0};
        pdf_free_carve_state((void **)&saved);
        uint64_t signature = pdf_three_run_signature(candidate, 0, (int64_t)nb_before, 0);
        bool resume = search.active && search.candidate_signature == signature
            && search.initial_blocks == nb_before && search.stream_length == stream_length
            && search.stream_offset == startstream_local_offset
            && search.block_span == blocks_to_extend;

        // Endstream-block candidates, tried in order: the contiguous position
        // first (streams are usually contiguous, and content-only FINDENDSTREAM
        // often matches "endstream" coincidentally in a foreign block), then
        // FINDENDSTREAM as the fallback for tails in another fragment.
        int64_t es_cands[2];
        int n_es = 0;
        int64_t contig_es = (int64_t)streamstart_block_app + blocks_to_extend;
        int64_t findes = -1;
        if (resume) {
            n_es = search.anchor_count;
            for (int i = 0; i < n_es; i++) {
                es_cands[i] = filemirror_apparent_blocknumber(
                    scalpel_state.filemirror, search.anchors[i]);
                if (es_cands[i] < 0 || filemirror_actual_block_covered(
                        scalpel_state.filemirror, search.anchors[i])) {
                    resume = false;
                    break;
                }
            }
        }
        if (!resume) {
            n_es = 0;
            if (contig_es >= 0 && contig_es < tot_app) {
                es_cands[n_es++] = contig_es;
            }
            findes = pdf_reassembly_get_block_choice(candidate, -1,
                endstream_local_offset, 0, 0, -1, FINDENDSTREAM,
                (int64_t)nb_before + (int64_t)blocks_to_extend - 1);
            if (findes >= 0 && findes < tot_app && findes != contig_es) {
                es_cands[n_es++] = findes;
            }
        }
        uint64_t context = pdf_three_run_signature(NULL,
            (int64_t)streamstart_block_app, blocks_to_extend + (int64_t)1, signature);
        for (int i = 0; i < n_es; i++) {
            context = pdf_three_run_signature(NULL, es_cands[i] - blocks_to_extend,
                blocks_to_extend + (int64_t)1, context);
        }
        resume = resume && context == search.context_signature;
        const bool resume_three = resume && search.phase == PDF_ZLIB_THREE_RUN;
#ifdef PDF_TRACE_STALL
        lock_fprintf(stdout,
            "[PDFZMB] candidates streamstart=%" PRIu64
            " contig=%" PRId64 " found=%" PRId64 " count=%d bte=%d\n",
            streamstart_block_app, contig_es, findes, n_es,
            blocks_to_extend);
#endif
        if (n_es == 0) return false;

        const int      n_interior  = blocks_to_extend - 1;   // last slot is the endstream block
        if (!resume) {
            memset(&search, 0, sizeof(search));
            search.active = true;
            search.phase = PDF_ZLIB_TWO_RUN;
            search.candidate_signature = signature;
            search.context_signature = context;
            search.stream_length = stream_length;
            search.initial_blocks = nb_before;
            search.stream_offset = startstream_local_offset;
            search.block_span = blocks_to_extend;
            search.anchor_count = n_es;
            search.prefix_length = n_interior;
            for (int i = 0; i < n_es; i++) {
                search.anchors[i] = filemirror_actual_blocknumber(
                    scalpel_state.filemirror, es_cands[i]);
            }
        }
        int64_t *chosen = (int64_t*)malloc(sizeof(int64_t) * (size_t)blocks_to_extend);
        if (!chosen) return false;

        bool solved = false;
        uint64_t endstream_block_apparent = (uint64_t)es_cands[0];
        const int first_anchor = search.anchor_index;
        const int first_split = search.prefix_length;
        for (int ei = first_anchor;
             search.phase == PDF_ZLIB_TWO_RUN && ei < n_es && !solved; ei++) {
            endstream_block_apparent = (uint64_t)es_cands[ei];
            for (int m = ei == first_anchor ? first_split : n_interior;
                 m >= 0 && !solved; m--) {
                if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
                    search.anchor_index = ei;
                    search.prefix_length = m;
                    pdf_store_three_run_search(candidate, &search);
                    free(chosen);
                    return false;
                }
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
        if (!solved && search.phase == PDF_ZLIB_TWO_RUN) {
            search.phase = PDF_ZLIB_BACKBONE;
            search.anchor_index = 0;
            memset(&search.backbone, 0, sizeof(search.backbone));
        }
#ifdef PDF_TRACE_STALL
        if (solved) {
            lock_fprintf(stdout,
                "[PDFZMB] two-run solved streamstart=%" PRIu64
                " end=%" PRIu64 " bte=%d\n",
                streamstart_block_app, endstream_block_apparent,
                blocks_to_extend);
        }
#endif

        /*
         * A stream spanning both a physical gap and a displaced run needs more
         * than the two physical runs above. Build that exact hypothesis on a
         * clone so the active candidate remains untouched; the helper commits
         * to the clone only after the complete Flate checksum verifies.
         */
        for (int ei = search.anchor_index;
             search.phase == PDF_ZLIB_BACKBONE && ei < n_es && !solved; ei++) {
            if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
                search.anchor_index = ei;
                pdf_store_three_run_search(candidate, &search);
                free(chosen);
                return false;
            }
            int64_t end_actual = filemirror_actual_blocknumber(
                scalpel_state.filemirror, es_cands[ei]);
            if (end_actual < 0) {
                continue;
            }

            BlockVector *trial_bv = NULL;
            clone_blockvector(candidate->b, &trial_bv, false);
            CarveInfo trial = *candidate;
            trial.b = trial_bv;
            int64_t start_slot = (int64_t)nb_before - 1;
            int64_t end_slot = start_slot + blocks_to_extend;
            bool placed_end = pdf_place_blocks_at_slot(
                &trial, &end_actual, 1, (uint64_t)end_slot,
                "ZLIB_BACKBONE_END");
#ifdef PDF_TRACE_STALL
            lock_fprintf(stdout,
                "[PDFZMB] backbone attempt streamstart=%" PRIu64
                " end=%" PRId64 " bte=%d placed=%d\n",
                streamstart_block_app, es_cands[ei], blocks_to_extend,
                placed_end ? 1 : 0);
#endif
            if (placed_end && stream_length <= (uint64_t)INT_MAX &&
                pdf_repair_interior_zlib_backbone(
                                  work, &trial,
                                  start_slot * (int64_t)scalpel_state.blocksize +
                                      startstream_local_offset,
                                  (int)stream_length, start_slot, end_slot,
                                  false, &search.backbone)) {
                solved = true;
                endstream_block_apparent = (uint64_t)es_cands[ei];
                for (int i = 0; i < blocks_to_extend; i++) {
                    chosen[i] = blockvector_get_apparent_blocknumber(
                        trial.b, (uint64_t)(start_slot + i + 1));
                    if (chosen[i] < 0) {
                        solved = false;
                        break;
                    }
                }
            }
            free_blockvector(&trial_bv);
            if (!solved && atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
                search.anchor_index = ei;
                pdf_store_three_run_search(candidate, &search);
                free(chosen);
                return false;
            }
            memset(&search.backbone, 0, sizeof(search.backbone));
        }

        /*
         * A displaced run can sit between an otherwise contiguous prefix and
         * tail. The two-run split above cannot represent that shape. Search the
         * exact three-run assignments, shortest displaced run first, and still
         * commit only after zlib verifies the complete stream checksum.
         */
        resume = resume_three;
        int prefix_limit = resume ? search.prefix_limit : n_interior - 1;
        if (!resume && !solved && n_interior > 0) {
            prefix_limit = pdf_zlib_contiguous_prefix_blocks(
                (const unsigned char *)first_stream_block_data,
                startstream_local_offset, (size_t)stream_length,
                (int64_t)streamstart_block_app, prefix_limit);
            if (prefix_limit < 0) {
                free(chosen);
                return false;
            }
        }
        if (!resume) {
            memset(&search, 0, sizeof(search));
            search.candidate_signature = signature;
            search.context_signature = context;
            search.stream_length = stream_length;
            search.initial_blocks = nb_before;
            search.stream_offset = startstream_local_offset;
            search.block_span = blocks_to_extend;
            search.anchor_count = n_es;
            search.prefix_limit = prefix_limit;
            for (int i = 0; i < n_es; i++) {
                search.anchors[i] = filemirror_actual_blocknumber(
                    scalpel_state.filemirror, es_cands[i]);
            }
        }
        for (int ei = resume ? search.anchor_index : 0; ei < n_es && !solved; ei++) {
            endstream_block_apparent = (uint64_t)es_cands[ei];
            for (int middle_len = resume ? search.middle_length : 1;
                 middle_len <= n_interior && !solved; middle_len++) {
                int max_prefix = n_interior - middle_len;
                if (max_prefix > prefix_limit) {
                    max_prefix = prefix_limit;
                }
                for (int prefix_len = resume ? search.prefix_length : max_prefix;
                     prefix_len >= 0 && !solved;
                     prefix_len--) {
                    int tail_len = n_interior - prefix_len - middle_len;
                    BlockVector *scan_bv = NULL;
                    uint64_t evaluated = 0;
                    int64_t scan_start = 0;
                    int64_t middle_start = -1;

                    if (resume) {
                        const int64_t actual_count = (int64_t)CEILDIV(
                            filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);
                        while (search.next_actual < actual_count) {
                            scan_start = filemirror_apparent_blocknumber(
                                scalpel_state.filemirror, search.next_actual);
                            if (scan_start >= 0) {
                                break;
                            }
                            search.next_actual++;
                        }
                        if (search.next_actual >= actual_count) {
                            scan_start = tot_app;
                        }
                        resume = false;
                    }

                    init_blockvector(scalpel_state.filemirror, &scan_bv, 1, false);

                    while (!solved &&
                           (middle_start = blockvector_get_choice(
                                scan_bv, 0, scan_start, -1, &evaluated)) != -1) {
                        blockvector_remove_choice(scan_bv, 0, middle_start);
                        scan_start = middle_start + 1;

                        if (middle_start > tot_app - middle_len) {
                            continue;
                        }

                        if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                                 memory_order_acquire)) {
                            search.active = true;
                            search.anchor_index = ei;
                            search.middle_length = middle_len;
                            search.prefix_length = prefix_len;
                            search.next_actual = filemirror_actual_blocknumber(
                                scalpel_state.filemirror, middle_start);
                            pdf_store_three_run_search(candidate, &search);
                            free_blockvector(&scan_bv);
                            free(chosen);
                            return false;
                        }

                        int out = 0;
                        for (int i = 1; i <= prefix_len; i++) {
                            chosen[out++] = (int64_t)streamstart_block_app + i;
                        }
                        for (int i = 0; i < middle_len; i++) {
                            chosen[out++] = middle_start + i;
                        }
                        for (int i = tail_len; i > 0; i--) {
                            chosen[out++] = (int64_t)endstream_block_apparent - i;
                        }
                        chosen[out++] = (int64_t)endstream_block_apparent;

                        bool viable = out == blocks_to_extend;
                        for (int i = 0; i < out && viable; i++) {
                            int64_t app = chosen[i];
                            if (app < 0 || app >= tot_app ||
                                apparent_block_in_blockvector(candidate->b, app)) {
                                viable = false;
                                break;
                            }
                            int64_t actual = filemirror_actual_blocknumber(
                                scalpel_state.filemirror, app);
                            if (actual < 0 ||
                                filemirror_actual_block_covered(
                                    scalpel_state.filemirror, actual) ||
                                filemirror_actual_block_is_zero(
                                    scalpel_state.filemirror, actual)) {
                                viable = false;
                                break;
                            }
                            for (int j = 0; j < i; j++) {
                                if (chosen[j] == app) {
                                    viable = false;
                                    break;
                                }
                            }
                        }
                        if (!viable) {
                            continue;
                        }

                        ZlibStreamReassembler r;
                        if (zlib_stream_reassembler_init(
                                &r, (const unsigned char *)first_stream_block_data,
                                scalpel_state.blocksize, startstream_local_offset,
                                (size_t)stream_length) == -1) {
                            break;
                        }

                        bool ok = true;
                        for (int i = 0; i < blocks_to_extend && ok; i++) {
                            const unsigned char *blk =
                                (const unsigned char *)get_apparent_block_data(
                                    scalpel_state.filemirror, chosen[i]);
                            if (!blk) {
                                ok = false;
                                break;
                            }
                            int chk = zlib_stream_reassembler_try_block(
                                &r, blk, scalpel_state.blocksize);
                            free((void *)blk);
                            if (i + 1 == blocks_to_extend) {
                                ok = chk == 2;
                            } else {
                                ok = chk == 1;
                            }
                        }
                        solved = ok && r.ended;
                        zlib_stream_reassembler_free(&r);
                    }
                    free_blockvector(&scan_bv);
                }
            }
        }
        memset(&search, 0, sizeof(search));
        pdf_store_three_run_search(candidate, &search);
#ifdef PDF_TRACE_STALL
        if (solved) {
            lock_fprintf(stdout,
                "[PDFZMB] deferred solver complete streamstart=%" PRIu64
                " end=%" PRIu64 " bte=%d\n",
                streamstart_block_app, endstream_block_apparent,
                blocks_to_extend);
        }
#endif

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

    // A known zero or covered block cannot substantiate this unchecksummed
    // contiguous hypothesis. It may be gap filler (and was in the repeated-run
    // safety corpus), while the endpoint and xref beyond it can still look valid.
    // Leave such a stream unresolved unless a stronger format-specific path can
    // identify its interior blocks.
    for (int k = 1; k <= blocks_to_extend; k++) {
        int64_t actual = filemirror_actual_blocknumber(
            scalpel_state.filemirror,
            (int64_t)streamstart_block_app + k);
        if (actual < 0 ||
            filemirror_actual_block_covered(scalpel_state.filemirror, actual) ||
            filemirror_actual_block_is_zero(scalpel_state.filemirror, actual)) {
            return false;
        }
    }

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
        return stream_check == 2;
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
 * @description  Confirms that a JPEG stream reached EOI while accounting for
 *               its complete declared extent. PDF producers may include PDF
 *               whitespace after EOI in /Length; arbitrary trailing bytes are
 *               rejected rather than silently ignored.
 * @param r  The JPEG reassembler after all declared bytes were supplied.
 * @return   true when the extent contains a complete JPEG and only optional
 *           PDF whitespace follows EOI.
 */
static bool pdf_jpeg_extent_complete(const JpegStreamReassembler *r) {
    if (!r || r->fed != r->stream_length || !r->saw_sos || !r->saw_eoi ||
        r->state != J_DONE || r->pos > r->fed || r->output_len < r->fed) {
        return false;
    }

    for (size_t i = r->pos; i < r->fed; i++) {
        unsigned char c = r->output[i];
        if (c != 0 && c != '\t' && c != '\n' && c != '\f' &&
            c != '\r' && c != ' ') {
            return false;
        }
    }
    return true;
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
    if (r->malformed ||
        (r->fed >= r->stream_length && !pdf_jpeg_extent_complete(r))) {
        free(r->output);
        r->output = NULL;
        return -1;
    }
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
        if (pdf_jpeg_extent_complete(r)) {
            return 2;
        }
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
        return stream_check == 2;
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

        int64_t *chosen = (int64_t*)malloc(sizeof(int64_t) * (size_t)blocks_to_extend);
        if (!chosen) {
            return false;
        }

        bool solved = false;
        bool interrupted = false;
        uint64_t endstream_block_apparent = (uint64_t)es_cands[0];
        for (int ei = 0; ei < n_es && !solved; ei++) {
            endstream_block_apparent = (uint64_t)es_cands[ei];
            for (int m = n_interior; m >= 0 && !solved; m--) {
                if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                         memory_order_acquire)) {
                    interrupted = true;
                    break;
                }
                JpegStreamReassembler r;
                if (jpeg_stream_reassembler_init(&r, (const unsigned char*)first_stream_block_data,
                        scalpel_state.blocksize, startstream_local_offset, (size_t)stream_length) == -1) {
                    break;
                }

                bool ok = true;
                for (int i = 1; i <= n_interior && ok; i++) {
                    int64_t app = (i <= m) ? (int64_t)streamstart_block_app + i
                                           : (int64_t)endstream_block_apparent - (blocks_to_extend - i);
                    if (app < 0 || app >= tot_app) {
                        ok = false;
                        break;
                    }
                    const unsigned char *blk =
                        (const unsigned char*)get_apparent_block_data(scalpel_state.filemirror, app);
                    if (!blk) {
                        ok = false;
                        break;
                    }
                    int chk = jpeg_stream_reassembler_try_block(&r, blk, scalpel_state.blocksize);
                    free((void*)blk);
                    if (chk != 1) {
                        ok = false;
                        break;
                    }
                    chosen[i-1] = app;
                }

                if (ok) {
                    const unsigned char *blk =
                        (const unsigned char*)get_apparent_block_data(scalpel_state.filemirror, endstream_block_apparent);
                    if (!blk) {
                        ok = false;
                    } else {
                        int chk = jpeg_stream_reassembler_try_block(&r, blk, scalpel_state.blocksize);
                        free((void*)blk);
                        if (chk != 2) {
                            ok = false;
                        }
                    }
                }
                chosen[blocks_to_extend-1] = (int64_t)endstream_block_apparent;

                // Accept only on completion: EOI reached having consumed /Length.
                solved = ok && pdf_jpeg_extent_complete(&r);
                jpeg_stream_reassembler_free(&r);
            }
            if (interrupted) {
                break;
            }
        }

        if (!solved) {
            free(chosen);
            return false;
        }

        for (int i = 0; i < blocks_to_extend; i++) {
            uint64_t slot = nb_before + (uint64_t)i;
            if (!pdf_block_matches_xref_slot(candidate, chosen[i], slot)) {
                free(chosen);
                return false;
            }
        }

        pdf_reassembly_prepare_for_extension(work->id, candidate, blocks_to_extend, ENDSTREAMEXTENSION);
        for (int i = 0; i < blocks_to_extend; i++) {
            uint64_t slot = nb_before + (uint64_t)i;
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
 * @description  Determines whether exactly one xref marker in the available
 *               image begins at a specified block-local offset. A /Prev value
 *               supplies an exact logical byte offset, but many unrelated PDF
 *               xrefs can exist in the same image. Uniqueness at the required
 *               local offset provides a conservative fallback when the linked
 *               older table has no objects in common with the current header.
 *               A checkpoint request stops the scan without asserting
 *               uniqueness; the caller will return the unchanged candidate.
 * @param candidate        Candidate whose block states are consulted.
 * @param expected_offset  Required xref offset within its block.
 * @return       true only when exactly one xref marker has that offset.
 */
static bool pdf_xref_offset_is_unique(CarveInfo *candidate,
                                      int32_t expected_offset) {
    if (!candidate || expected_offset < 0 ||
        expected_offset >= (int32_t)scalpel_state.blocksize) {
        return false;
    }

    int matches = 0;
    int64_t total = filemirror_apparent_blocks(scalpel_state.filemirror);
    for (int64_t apparent = 0; apparent < total; apparent++) {
        if ((apparent & (PDF_XREF_SCAN_QUANTUM - 1)) == 0 &&
            atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                 memory_order_acquire)) {
            return false;
        }

        PDFBlockState *state =
            pdf_get_blockstate_from_apparent(candidate, apparent, NULL);
        if (!state) {
            continue;
        }
        for (int i = 0; i < state->num_xrefs; i++) {
            if (state->xref_block_data[i].xref_start == expected_offset) {
                matches++;
                if (matches > 1) {
                    pdf_free_block_state((void **)&state);
                    return false;
                }
            }
        }
        pdf_free_block_state((void **)&state);
    }
    return matches == 1;
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
                      int32_t *out_xref_local,
                      int64_t *next_apparent,
                      uint64_t block_budget,
                      bool *more_work){
    if(out_xref_local) *out_xref_local = -1;
    if (more_work) {
        *more_work = false;
    }
    if(*scan_bv == NULL){
        init_blockvector(scalpel_state.filemirror, scan_bv, 1, false);
    }
    BlockVector *bv = *scan_bv;

    *out_xref_blocks = NULL;
    *out_xref_block_count = 0;

    uint64_t slot = 0;
    int64_t start = next_apparent && *next_apparent >= 0
                        ? *next_apparent
                        : 0;
    int64_t block_choice = -1;
    char *buf = NULL;
    uint64_t evaluated;
    int64_t tmp;
    Object *entries = NULL;
    uint64_t xref_end_offset;
    uint64_t examined = 0;
    while ((block_choice = blockvector_get_choice(bv, slot, start, -1, &evaluated)) != -1) {
        if(block_budget > 0 && examined >= block_budget){
            if (more_work) {
                *more_work = true;
            }
            return NULL;
        }
        examined++;
        blockvector_remove_choice(bv, slot, block_choice);
        start = block_choice + 1;
        if(next_apparent) {
            *next_apparent = start;
        }

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
    if (!s) {
        return;
    }
    s->linearized = false;
    s->lin_L = -1;
    s->lin_T = -1;
    if (!data || length == 0) {
        return;
    }

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
    }

    uint64_t want = (last_slot + 1) * (uint64_t)scalpel_state.blocksize;
    if (want > blockvector_get_data_length(candidate->b)) {
        candidate->best_validates_to = want - 1;
        blockvector_set_data_length(candidate->b, want);
    }

    // Positional placement can leave multiple unmapped slots between the
    // current frontier and this run. The single-block inflater requires every
    // other slot to be valid, so normalize and inflate the complete vector to
    // materialize the run and zero-fill all intervening holes.
    inflate_blockvector(candidate->b);

#ifdef PDF_TRACE_PLACEMENT
    for (int b = 0; b < count; b++) {
        uint64_t slot = first_slot + (uint64_t)b;
        {
            uuid_string_t uuidp;
            uuid_unparse_lower(candidate->binuuid, uuidp);
            lock_fprintf(stdout,
                "[PDFPLACE] uuid=%.8s slot=%" PRIu64 " apparent=%" PRId64 " actual=%" PRId64
                " slots=%" PRIu64 " len=%" PRIu64 " site=%-14s line=%d c1=%d c2=%d\n",
                uuidp, slot,
                filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                                actual_blocks[b]),
                actual_blocks[b],
                blockvector_get_num_blocks(candidate->b),
                blockvector_get_data_length(candidate->b),
                site, __LINE__, b, count);
        }
    }
#endif

    return true;
}

/**
 * @description  Replaces an existing run after a format oracle has verified the
 *               complete assignment. Unlike pdf_place_blocks_at_slot(), this is
 *               allowed to displace mapped blocks, so callers must defer the call
 *               until their global integrity check succeeds. The full run is
 *               checked before any blockvector mutation.
 * @param candidate      The candidate being repaired.
 * @param actual_blocks  Verified actual blocks, in logical order.
 * @param count          Number of blocks to replace.
 * @param first_slot     First logical slot to replace.
 * @param site           Trace label.
 * @return       true if the complete replacement was applied.
 */
static bool pdf_replace_blocks_at_slot(CarveInfo *candidate,
                                       const int64_t *actual_blocks,
                                       int count,
                                       uint64_t first_slot,
                                       const char *site) {
    (void)site;
    if (!candidate || !actual_blocks || count <= 0 ||
        first_slot + (uint64_t)count >
            blockvector_get_num_blocks(candidate->b)) {
#ifdef PDF_TRACE_PLACEMENT
        lock_fprintf(stdout,
            "[PDFREPLACE-REJECT] site=%s reason=range first=%" PRIu64
            " count=%d slots=%" PRIu64 "\n",
            site ? site : "?", first_slot, count,
            candidate && candidate->b
                ? blockvector_get_num_blocks(candidate->b) : 0);
#endif
        return false;
    }

    FileMirror *fm = scalpel_state.filemirror;
    int64_t total_actual =
        (int64_t)CEILDIV(filemirror_filesize(fm), scalpel_state.blocksize);
    for (int i = 0; i < count; i++) {
        int64_t actual = actual_blocks[i];
        if (actual < 0 || actual >= total_actual ||
            filemirror_actual_block_covered(fm, actual) ||
            filemirror_actual_block_is_zero(fm, actual)) {
#ifdef PDF_TRACE_PLACEMENT
            lock_fprintf(stdout,
                "[PDFREPLACE-REJECT] site=%s reason=state index=%d"
                " actual=%" PRId64 " covered=%d zero=%d\n",
                site ? site : "?", i, actual,
                actual >= 0 && actual < total_actual
                    ? filemirror_actual_block_covered(fm, actual) : -1,
                actual >= 0 && actual < total_actual
                    ? filemirror_actual_block_is_zero(fm, actual) : -1);
#endif
            return false;
        }
        int64_t app = filemirror_apparent_blocknumber(fm, actual);
        if (app < 0) {
#ifdef PDF_TRACE_PLACEMENT
            lock_fprintf(stdout,
                "[PDFREPLACE-REJECT] site=%s reason=unmapped index=%d"
                " actual=%" PRId64 "\n",
                site ? site : "?", i, actual);
#endif
            return false;
        }
        for (uint64_t slot = 0;
             slot < blockvector_get_num_blocks(candidate->b);
             slot++) {
            if (slot >= first_slot &&
                slot < first_slot + (uint64_t)count) {
                continue;
            }
            if (blockvector_get_apparent_blocknumber(candidate->b, slot) == app) {
#ifdef PDF_TRACE_PLACEMENT
                lock_fprintf(stdout,
                    "[PDFREPLACE-REJECT] site=%s reason=outside-duplicate"
                    " index=%d actual=%" PRId64 " slot=%" PRIu64 "\n",
                    site ? site : "?", i, actual, slot);
#endif
                return false;
            }
        }
        for (int prior = 0; prior < i; prior++) {
            if (actual_blocks[prior] == actual) {
#ifdef PDF_TRACE_PLACEMENT
                lock_fprintf(stdout,
                    "[PDFREPLACE-REJECT] site=%s reason=input-duplicate"
                    " index=%d prior=%d actual=%" PRId64 "\n",
                    site ? site : "?", i, prior, actual);
#endif
                return false;
            }
        }
    }

    candidate->fastpath = false;
    for (int i = 0; i < count; i++) {
        int64_t app = filemirror_apparent_blocknumber(fm, actual_blocks[i]);
        candidate->newblock = actual_blocks[i];
        blockvector_set_apparent_blocknumber(
            candidate->b, first_slot + (uint64_t)i, app);
    }

    // Apply the complete verified replacement in one synchronized byte view.
    // This also keeps the helper correct if the candidate already contains
    // unmapped slots from an earlier positional placement.
    inflate_blockvector(candidate->b);

#ifdef PDF_TRACE_PLACEMENT
    for (int i = 0; i < count; i++) {
        uint64_t slot = first_slot + (uint64_t)i;
        int64_t app = filemirror_apparent_blocknumber(fm, actual_blocks[i]);
        {
            uuid_string_t uuidp;
            uuid_unparse_lower(candidate->binuuid, uuidp);
            lock_fprintf(stdout,
                "[PDFREPLACE] uuid=%.8s slot=%" PRIu64
                " apparent=%" PRId64 " actual=%" PRId64
                " site=%-14s index=%d count=%d\n",
                uuidp, slot, app, actual_blocks[i], site, i, count);
        }
    }
#endif
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
    char *joined = NULL;
    bool  ok  = true;
#ifdef PDF_TRACE_PLACEMENT
    int   objs_seen = 0;
#endif

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
                int64_t local = (int64_t)(off - lo);
                int object_check = validate_at_offset(
                    blk, local, tabs[t].entries[e].obj_num, (int64_t)bsz);

                /*
                 * Any part of the object header may cross this block boundary.
                 * Validate that constraint against the
                 * next logical block when it is already known; otherwise the
                 * boundary-spanning header is not evidence against this block.
                 */
                if (object_check == -3) {
                    if (!joined) {
                        uint64_t next_slot = slot + 1;
                        int64_t next_app =
                            next_slot < blockvector_get_num_blocks(candidate->b)
                                ? blockvector_get_apparent_blocknumber(candidate->b,
                                                                       next_slot)
                                : -1;
                        if (next_app >= 0) {
                            char *next = (char *)get_apparent_block_data(
                                scalpel_state.filemirror, next_app);
                            if (next) {
                                joined = malloc(2 * bsz);
                                check_memory_allocation(joined, __LINE__, __FILE__,
                                                        "PDF xref boundary block");
                                memcpy(joined, blk, bsz);
                                memcpy(joined + bsz, next, bsz);
                                free(next);
                            }
                        }
                    }
                    if (!joined) {
                        continue;
                    }
                    object_check = validate_at_offset(
                        joined, local, tabs[t].entries[e].obj_num,
                        (int64_t)(2 * bsz));
                    if (object_check == -3) {
                        continue;
                    }
                }

#ifdef PDF_TRACE_PLACEMENT
                objs_seen++;
#endif
                if (object_check != 1) {
                    ok = false;                        // object absent where the xref puts it
                }
            }
        }
    }
done:
    free(joined);
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

/**
 * @description  Whether a candidate has an unfilled slot within a validator-
 *               confirmed byte range. Speculative blocks and holes beyond the
 *               confirmed endpoint are irrelevant because successful validation
 *               trims them before publication.
 * @param candidate      Candidate being checked.
 * @param validates_to   Inclusive last validated byte.
 * @return       true if a hole intersects the validated range.
 */
static bool pdf_candidate_has_holes_through(CarveInfo *candidate,
                                            uint64_t validates_to) {
    uint64_t required = validates_to / scalpel_state.blocksize + 1;
    uint64_t available = blockvector_get_num_blocks(candidate->b);
    if (required > available) {
        return true;
    }
    for (uint64_t slot = 0; slot < required; slot++) {
        if (blockvector_get_apparent_blocknumber(candidate->b, slot) < 0) {
            return true;
        }
    }
    return false;
}

/**
 * @description  Returns the byte length of the candidate's contiguous trusted
 *               prefix. Positioned blocks beyond the first unfilled slot remain
 *               useful reassembly evidence, but cannot extend a range presented
 *               to the final file validator.
 * @param candidate  Candidate whose logical slots are inspected.
 * @return       Candidate data length, capped at the first unfilled slot.
 */
static uint64_t pdf_candidate_trusted_prefix_length(CarveInfo *candidate) {
    uint64_t length = blockvector_get_data_length(candidate->b);
    uint64_t slots = blockvector_get_num_blocks(candidate->b);

    for (uint64_t slot = 0; slot < slots; slot++) {
        if (blockvector_get_apparent_blocknumber(candidate->b, slot) < 0) {
            uint64_t prefix = slot * (uint64_t)scalpel_state.blocksize;
            return prefix < length ? prefix : length;
        }
    }
    return length;
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
 * @description  Verifies an XMP/XML metadata stream with the same structural
 *               state machine used during fragmented stream reconstruction.
 *               The caller invokes this only when an ASCII XML signature is
 *               present, so other legal encodings are left to the ordinary PDF
 *               checks rather than rejected here.
 * @param buf  Complete stream body.
 * @param len  Stream body length.
 * @return       true when the XML text and nesting are structurally complete.
 */
static bool pdf_xml_body_ok(const unsigned char *buf, size_t len) {
    if (!buf || len == 0 || !xml_has_signature(buf, len)) {
        return true;
    }

    XmlStreamReassembler parser;
    memset(&parser, 0, sizeof(parser));
    parser.state = X_TEXT;
    for (size_t i = 0; i < len; i++) {
        xml_feed_byte(&parser, buf[i]);
        if (parser.malformed) {
            return false;
        }
    }
    return parser.state == X_TEXT && parser.tag_depth == 0;
}

// Only the first decoder in a filter chain can inspect the raw stream body.
static bool pdf_first_stream_filter_is(const unsigned char *dictionary,
                                        size_t length, const char *name) {
    size_t value = 0;
    if (!pdf_find_name_value(dictionary, length, "Filter", &value)) {
        return false;
    }
    if (value < length && dictionary[value] == '[') {
        value = pdf_skip_space_and_comments(dictionary, value + 1, length);
    }
    size_t end = 0;
    size_t name_length = strlen(name);
    return value < length && dictionary[value] == '/'
        && pdf_token_end(dictionary, length, value, &end)
        && end - value == name_length + 1
        && !memcmp(dictionary + value + 1, name, name_length);
}

/**
 * @description  Returns false if any validated stream fails a content check -- i.e.
 *               a wrong block lives inside a stream body, which object-offset
 *               validation cannot see. A declared /Length bounds the body when it
 *               can be resolved; otherwise the endstream keyword is the fallback.
 *               For supported RC4 and AES-128 Standard Security Handler revisions,
 *               check the empty password and decrypt streams before inspection.
 *               Unsupported encryption remains unverified. Chained
 *               encodings are inspected only where the raw-body codec is known.
 * @param data        The assembled candidate buffer.
 * @param length      Length of the buffer.
 * @param tables      The xref tables locating object headers.
 * @param xrefs       Locations of the accepted cross-reference sections.
 * @param num_tables  Count of those tables.
 * @return       false if a stream body fails its content check; true otherwise.
 */
static bool pdf_streams_decode_ok(char *data, uint64_t length,
                                  XrefTables *tables, const XrefObject *xrefs,
                                  int num_tables, bool *damaged_metadata) {
    *damaged_metadata = false;
    PDFEncryptionContext encryption;
    bool decrypt_streams = pdf_initialize_encryption_context(
        (const unsigned char *)data, length, tables, xrefs, num_tables, &encryption);
    bool encrypted = decrypt_streams;
    if (!encrypted) {
        for (int t = 0; t < num_tables; t++) {
            uint64_t start = 0, end = 0;
            size_t value = 0;
            if (pdf_xref_dictionary((const unsigned char *)data, length,
                    xrefs, num_tables, t, &start, &end) &&
                pdf_find_name_value((const unsigned char *)data + start,
                    end - start, "Encrypt", &value) &&
                (end - start - value < 4 || memcmp(data + start + value, "null", 4))) {
                encrypted = true;
                break;
            }
        }
    }
    *damaged_metadata = encrypted && !decrypt_streams;

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
            bool is_xml = check_last_object_filter(data + off,
                                                   (int)dict_len) == XML;
            if (!is_flate && !is_dct && !is_xml) continue;

            uint64_t object_body = 0;
            int generation = 0;
            if (!pdf_indirect_object_body_start(
                    (const unsigned char *)data, off, obj_end,
                    tables[t].entries[j].obj_num, &object_body, &generation)
                || object_body > (uint64_t)(sk - data)) {
                return false;
            }
            const unsigned char *dictionary = (const unsigned char *)data + object_body;
            size_t dictionary_length = (uint64_t)(sk - data) - object_body;
            if (encrypted && pdf_first_stream_filter_is(dictionary, dictionary_length, "Crypt")) {
                // A per-stream crypt filter overrides the document default.
                *damaged_metadata = true;
                continue;
            }

            bool is_xref_stream =
                memmem(data + off, dict_len, "/Type", 5) != NULL &&
                memmem(data + off, dict_len, "/XRef", 5) != NULL;
            bool is_metadata_stream =
                memmem(data + off, dict_len, "/Type", 5) != NULL &&
                memmem(data + off, dict_len, "/Metadata", 9) != NULL;
            if (encrypted && !decrypt_streams && !is_xref_stream) {
                // Ciphertext is not a compressed stream. Preserve the candidate
                // as unverified rather than testing random bytes as a codec.
                *damaged_metadata = true;
                continue;
            }

            uint64_t sdat = (uint64_t)(sk - data) + 6;            // past "stream"
            if (sdat < length && data[sdat] == '\r') sdat++;
            if (sdat < length && data[sdat] == '\n') sdat++;

            uint64_t stream_length_offset = 0;
            int declared_length = check_last_object_length(
                data, length, &stream_length_offset, tables, num_tables,
                data + off, (int)dict_len, off, false);
            uint64_t send = length;
            if (declared_length > 0 &&
                (uint64_t)declared_length <= length - sdat) {
                send = sdat + (uint64_t)declared_length;
            } else {
                char *ek = (sdat < length)
                    ? (char*)memmem(data + sdat, length - sdat,
                                    "endstream", 9)
                    : NULL;
                send = ek ? (uint64_t)(ek - data) : length;
            }
            if (send <= sdat) continue;

            const unsigned char *body = (const unsigned char*)(data + sdat);
            size_t blen = send - sdat;
            unsigned char *decrypted = NULL;
            if (decrypt_streams && !is_xref_stream &&
                (encryption.encrypt_metadata || !is_metadata_stream)) {
                decrypted = malloc(blen);
                check_memory_allocation(decrypted, __LINE__, __FILE__,
                                        "PDF decrypted stream");
                if (pdf_decrypt_stream(
                        &encryption, tables[t].entries[j].obj_num,
                        generation, body, blen, decrypted, &blen)) {
                    body = decrypted;
                } else {
                    free(decrypted);
                    return false;
                }
            }
            // A filter chain names several filters; try both verifiers and let
            // each self-gate on its signature (the raw body matches at most one).
            bool valid = (!is_flate || pdf_flate_body_ok(body, blen)) &&
                         (!is_dct || pdf_jpeg_body_ok(body, blen));
            if (decrypted) {
                // Decryption must not turn a damaged first decoder signature
                // into an unrecognised encoding that silently skips validation.
                if (pdf_first_stream_filter_is(dictionary, dictionary_length, "FlateDecode")) {
                    valid = valid && blen >= 2 && (body[0] & 15) == 8
                        && (body[0] >> 4) <= 7 && !(body[1] & 0x20)
                        && (((unsigned)body[0] << 8) | body[1]) % 31 == 0;
                }
                if (pdf_first_stream_filter_is(dictionary, dictionary_length, "DCTDecode")) {
                    valid = valid && blen >= 3 && body[0] == 0xff && body[1] == 0xd8;
                }
            }
            if (is_xml && !pdf_xml_body_ok(body, blen)) {
                if (is_metadata_stream) {
                    // A metadata object wholly within one block cannot acquire
                    // an internal splice during block reassembly. Its XML may
                    // be malformed in the source while the PDF remains intact.
                    uint64_t endstream = pdf_skip_space_and_comments(
                        (const unsigned char *)data, send, length);
                    bool anchored = declared_length > 0
                        && endstream <= length && length - endstream >= 9
                        && !memcmp(data + endstream, "endstream", 9);
                    uint64_t end = anchored ? pdf_skip_space_and_comments(
                        (const unsigned char *)data, endstream + 9, length) : length;
                    anchored = anchored && end <= length && length - end >= 6
                        && !memcmp(data + end, "endobj", 6)
                        && scalpel_state.blocksize > 0
                        && off / scalpel_state.blocksize
                           == (end + 5) / scalpel_state.blocksize;
                    if (!anchored) {
                        *damaged_metadata = true;
                    }
                } else {
                    valid = false;
                }
            }
            free(decrypted);
            if (!valid) {
#ifdef PDF_TRACE_VALIDATE
                lock_fprintf(stdout, "[PDFVAL] stream obj=%d off=%" PRIu64
                    " length=%zu flate=%d jpeg=%d xml=%d metadata=%d\n",
                    tables[t].entries[j].obj_num, off, blen, is_flate,
                    is_dct, is_xml, is_metadata_stream);
#endif
                return false;
            }
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

static inline void pdf_xref_search_state_init(PDFXrefSearchState *state) {
    if (!state) {
        return;
    }
    memset(state, 0, sizeof(*state));
    state->best_local = -1;
}

static inline void pdf_xref_search_state_clear(PDFXrefSearchState *state) {
    if (!state) {
        return;
    }
    if (state->excluded_actual_blocks) {
        roaring64_bitmap_free(state->excluded_actual_blocks);
    }
    free(state->best_entries);
    free(state->best_blocks);
    pdf_xref_search_state_init(state);
}

static inline void pdf_xref_search_state_copy(PDFXrefSearchState *destination,
                                               const PDFXrefSearchState *source) {
    pdf_xref_search_state_init(destination);
    if (!source) {
        return;
    }

    destination->active = source->active;
    destination->exhausted = source->exhausted;
    destination->best_entry_count = source->best_entry_count;
    destination->best_block_count = source->best_block_count;
    destination->best_local = source->best_local;
    destination->best_score = source->best_score;

    if (source->excluded_actual_blocks) {
        destination->excluded_actual_blocks =
            roaring64_bitmap_copy(source->excluded_actual_blocks);
        check_memory_allocation(destination->excluded_actual_blocks, __LINE__,
                                __FILE__, "PDF xref scan exclusions");
    }
    if (source->best_entry_count > 0 && source->best_entries) {
        destination->best_entries = malloc(
            (size_t)source->best_entry_count * sizeof(*source->best_entries));
        check_memory_allocation(destination->best_entries, __LINE__, __FILE__,
                                "PDF xref scan entries");
        memcpy(destination->best_entries, source->best_entries,
               (size_t)source->best_entry_count * sizeof(*source->best_entries));
    }
    if (source->best_block_count > 0 && source->best_blocks) {
        destination->best_blocks = malloc(
            (size_t)source->best_block_count * sizeof(*source->best_blocks));
        check_memory_allocation(destination->best_blocks, __LINE__, __FILE__,
                                "PDF xref scan blocks");
        memcpy(destination->best_blocks, source->best_blocks,
               (size_t)source->best_block_count * sizeof(*source->best_blocks));
    }
}

static inline void pdf_store_xref_search(CarveInfo *candidate,
                                          BlockVector *scan_blockvector,
                                          bool exhausted,
                                          const Object *best_entries,
                                          int best_entry_count,
                                          const int64_t *best_blocks,
                                          int best_block_count,
                                          int32_t best_local,
                                          int best_score) {
    PDFCarveState *state =
        (PDFCarveState *)carve_get_state(candidate->carvehashkey);
    if (!state) {
        state = calloc(1, sizeof(*state));
        check_memory_allocation(state, __LINE__, __FILE__,
                                "PDF carve state");
        state->lin_L = -1;
        state->lin_T = -1;
        pdf_xref_search_state_init(&state->xref_search);
    }

    pdf_xref_search_state_clear(&state->xref_search);
    state->xref_search.active = true;
    state->xref_search.exhausted = exhausted;
    state->xref_search.best_entry_count = best_entry_count;
    state->xref_search.best_block_count = best_block_count;
    state->xref_search.best_local = best_local;
    state->xref_search.best_score = best_score;

    if (scan_blockvector) {
        state->xref_search.excluded_actual_blocks =
            blockvector_clone_choice_exclusions(scan_blockvector, 0);
    }
    if (best_entry_count > 0 && best_entries) {
        state->xref_search.best_entries = malloc(
            (size_t)best_entry_count * sizeof(*best_entries));
        check_memory_allocation(state->xref_search.best_entries, __LINE__,
                                __FILE__, "PDF xref scan entries");
        memcpy(state->xref_search.best_entries, best_entries,
               (size_t)best_entry_count * sizeof(*best_entries));
    }
    if (best_block_count > 0 && best_blocks) {
        state->xref_search.best_blocks = malloc(
            (size_t)best_block_count * sizeof(*best_blocks));
        check_memory_allocation(state->xref_search.best_blocks, __LINE__,
                                __FILE__, "PDF xref scan blocks");
        memcpy(state->xref_search.best_blocks, best_blocks,
               (size_t)best_block_count * sizeof(*best_blocks));
    }

    carve_put_state(candidate->carvehashkey, state);
    pdf_free_carve_state((void **)&state);
}

static inline bool pdf_restore_xref_search(CarveInfo *candidate,
                                            BlockVector **scan_blockvector,
                                            bool *exhausted,
                                            Object **best_entries,
                                            int *best_entry_count,
                                            int64_t **best_blocks,
                                            int *best_block_count,
                                            int32_t *best_local,
                                            int *best_score) {
    PDFCarveState *state =
        (PDFCarveState *)carve_get_state(candidate->carvehashkey);
    if (!state || !state->xref_search.active) {
        pdf_free_carve_state((void **)&state);
        return false;
    }

    init_blockvector(scalpel_state.filemirror, scan_blockvector, 1, false);
    if (state->xref_search.excluded_actual_blocks) {
        blockvector_restore_choice_exclusions(
            *scan_blockvector, 0,
            state->xref_search.excluded_actual_blocks);
    }

    *exhausted = state->xref_search.exhausted;
    *best_entries = state->xref_search.best_entries;
    *best_entry_count = state->xref_search.best_entry_count;
    *best_blocks = state->xref_search.best_blocks;
    *best_block_count = state->xref_search.best_block_count;
    *best_local = state->xref_search.best_local;
    *best_score = state->xref_search.best_score;
    state->xref_search.best_entries = NULL;
    state->xref_search.best_blocks = NULL;

    pdf_free_carve_state((void **)&state);
    return true;
}

static inline void pdf_clear_xref_search(CarveInfo *candidate) {
    PDFCarveState *state =
        (PDFCarveState *)carve_get_state(candidate->carvehashkey);
    if (!state) {
        return;
    }
    pdf_xref_search_state_clear(&state->xref_search);
    carve_put_state(candidate->carvehashkey, state);
    pdf_free_carve_state((void **)&state);
}

static inline bool pdf_serialize_xref_search_state(
    PDFXrefSearchState *state, FILE *fp, StateSerialization mode) {
    size_t (*fb)(void *ptr, size_t size, size_t nitems, FILE *stream) =
        mode == SERIALIZE
            ? (size_t (*)(void *, size_t, size_t, FILE *))fwrite
            : (size_t (*)(void *, size_t, size_t, FILE *))fread;

    if (mode == DESERIALIZE) {
        pdf_xref_search_state_init(state);
    }
    if (fb(&state->active, sizeof(state->active), 1, fp) != 1
        || fb(&state->exhausted, sizeof(state->exhausted), 1, fp) != 1) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
    if (!state->active) {
        return true;
    }

    size_t bitmap_length = 0;
    if (mode == SERIALIZE && state->excluded_actual_blocks) {
        bitmap_length = roaring64_bitmap_portable_size_in_bytes(
            state->excluded_actual_blocks);
    }
    if (fb(&bitmap_length, sizeof(bitmap_length), 1, fp) != 1) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
    if (bitmap_length > 0) {
        char *serialized_bitmap = malloc(bitmap_length);
        check_memory_allocation(serialized_bitmap, __LINE__, __FILE__,
                                "PDF xref scan exclusions");
        if (mode == SERIALIZE) {
            roaring64_bitmap_portable_serialize(
                state->excluded_actual_blocks, serialized_bitmap);
        }
        if (fb(serialized_bitmap, 1, bitmap_length, fp) != bitmap_length) {
            free(serialized_bitmap);
            handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
        }
        if (mode == DESERIALIZE) {
            state->excluded_actual_blocks =
                roaring64_bitmap_portable_deserialize_safe(serialized_bitmap,
                                                            bitmap_length);
            if (!state->excluded_actual_blocks
                || !roaring64_bitmap_internal_validate(
                    state->excluded_actual_blocks, NULL)) {
                free(serialized_bitmap);
                handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__,
                             __FILE__);
            }
        }
        free(serialized_bitmap);
    }

    if (fb(&state->best_entry_count, sizeof(state->best_entry_count), 1, fp)
            != 1
        || fb(&state->best_block_count, sizeof(state->best_block_count), 1, fp)
            != 1
        || fb(&state->best_local, sizeof(state->best_local), 1, fp) != 1
        || fb(&state->best_score, sizeof(state->best_score), 1, fp) != 1) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
    if (state->best_entry_count < 0 || state->best_block_count < 0) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    if (mode == DESERIALIZE && state->best_entry_count > 0) {
        state->best_entries = malloc(
            (size_t)state->best_entry_count * sizeof(*state->best_entries));
        check_memory_allocation(state->best_entries, __LINE__, __FILE__,
                                "PDF xref scan entries");
    }
    if (state->best_entry_count > 0
        && fb(state->best_entries, sizeof(*state->best_entries),
              (size_t)state->best_entry_count, fp)
               != (size_t)state->best_entry_count) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    if (mode == DESERIALIZE && state->best_block_count > 0) {
        state->best_blocks = malloc(
            (size_t)state->best_block_count * sizeof(*state->best_blocks));
        check_memory_allocation(state->best_blocks, __LINE__, __FILE__,
                                "PDF xref scan blocks");
    }
    if (state->best_block_count > 0
        && fb(state->best_blocks, sizeof(*state->best_blocks),
              (size_t)state->best_block_count, fp)
               != (size_t)state->best_block_count) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
    return true;
}

/*******************************************************/
/* CARVE STATE FUNCTION DEFINITIONS                   */
/*******************************************************/

// INT03 extends only PDF state; older PDF checkpoint records start with an
// inactive three-run search. Encode fields explicitly, without struct padding.
static bool pdf_serialize_three_run_search(PDFThreeRunSearch *s, FILE *fp,
                                            StateSerialization mode) {
    size_t (*fb)(void *, size_t, size_t, FILE *) = mode == SERIALIZE
        ? (size_t (*)(void *, size_t, size_t, FILE *))fwrite : fread;
    if (fb(&s->active, sizeof(s->active), 1, fp) != 1
        || fb(&s->candidate_signature, sizeof(s->candidate_signature), 1, fp) != 1
        || fb(&s->context_signature, sizeof(s->context_signature), 1, fp) != 1
        || fb(&s->stream_length, sizeof(s->stream_length), 1, fp) != 1
        || fb(&s->initial_blocks, sizeof(s->initial_blocks), 1, fp) != 1
        || fb(&s->stream_offset, sizeof(s->stream_offset), 1, fp) != 1
        || fb(&s->block_span, sizeof(s->block_span), 1, fp) != 1
        || fb(s->anchors, sizeof(*s->anchors), 2, fp) != 2
        || fb(&s->anchor_count, sizeof(s->anchor_count), 1, fp) != 1
        || fb(&s->anchor_index, sizeof(s->anchor_index), 1, fp) != 1
        || fb(&s->prefix_limit, sizeof(s->prefix_limit), 1, fp) != 1
        || fb(&s->middle_length, sizeof(s->middle_length), 1, fp) != 1
        || fb(&s->prefix_length, sizeof(s->prefix_length), 1, fp) != 1
        || fb(&s->next_actual, sizeof(s->next_actual), 1, fp) != 1) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
    if (s->phase > PDF_ZLIB_BACKBONE
        || (s->active && (s->initial_blocks == 0 || s->stream_length == 0
        || s->stream_offset < 0 || (uint32_t)s->stream_offset >= scalpel_state.blocksize
        || s->block_span < 1 || s->anchor_count < 1 || s->anchor_count > 2
        || s->anchor_index < 0 || s->anchor_index >= s->anchor_count
        || s->anchors[0] < 0 || (s->anchor_count == 2 && s->anchors[1] < 0)
        || (s->phase == PDF_ZLIB_TWO_RUN
            && (s->prefix_length < 0 || s->prefix_length >= s->block_span))
        || (s->phase == PDF_ZLIB_THREE_RUN && (s->block_span < 2
        || s->prefix_limit < 0 || s->prefix_limit >= s->block_span - 1
        || s->middle_length < 1 || s->middle_length >= s->block_span
        || s->prefix_length < 0 || s->prefix_length > s->prefix_limit
        || s->prefix_length > s->block_span - 1 - s->middle_length
        || s->next_actual < 0))))) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
    return true;
}

// Preserve auxiliary stream-search decisions and reject malformed cursors.
static bool pdf_serialize_auxiliary_search(PDFInteriorSearchState *search,
                                          FILE *fp, StateSerialization mode) {
    size_t (*io)(void *, size_t, size_t, FILE *) = mode == SERIALIZE
        ? (size_t (*)(void *, size_t, size_t, FILE *))fwrite : fread;
#define PDF_AUX_FIELD(field) \
    if (io(&search->field, sizeof(search->field), 1, fp) != 1) { return false; }
    PDF_AUX_FIELD(jpeg.active);
    PDF_AUX_FIELD(jpeg.preferred_done);
    PDF_AUX_FIELD(jpeg.signature);
    PDF_AUX_FIELD(jpeg.insert);
    PDF_AUX_FIELD(jpeg.next_actual);
    PDF_AUX_FIELD(icc.active);
    PDF_AUX_FIELD(icc.signature);
    PDF_AUX_FIELD(icc.next_actual);
    PDF_AUX_FIELD(icc.viable_runs);
    PDF_AUX_FIELD(icc.best_score);
    PDF_AUX_FIELD(icc.second_score);
    PDF_AUX_FIELD(icc.best_actual);
    PDF_AUX_FIELD(icc.second_actual);
#undef PDF_AUX_FIELD
    return search->jpeg.active <= 1 && search->jpeg.preferred_done <= 1
        && search->jpeg.next_actual >= 0 && search->jpeg.insert <= INT64_MAX
        && search->icc.active <= 1 && search->icc.next_actual >= 0
        && search->icc.best_actual >= -1 && search->icc.second_actual >= -1
        && (!(search->jpeg.active || search->icc.active) || search->active)
        && (!search->icc.active
            || (search->icc.best_score <= search->icc.second_score
                && ((search->icc.best_actual < 0)
                    == (search->icc.best_score == UINT64_MAX))
                && ((search->icc.second_actual < 0)
                    == (search->icc.second_score == UINT64_MAX))));
}

// Physical replacement and logical split cursors have separate scopes.
static bool pdf_serialize_interior_zlib_search(PDFInteriorSearchState *search,
                                              FILE *fp, StateSerialization mode) {
    size_t (*io)(void *, size_t, size_t, FILE *) = mode == SERIALIZE
        ? (size_t (*)(void *, size_t, size_t, FILE *))fwrite : fread;
#define PDF_ZLIB_FIELD(field) \
    if (io(&search->field, sizeof(search->field), 1, fp) != 1) { return false; }
    PDF_ZLIB_FIELD(zero.active);
    PDF_ZLIB_FIELD(zero.signature);
    PDF_ZLIB_FIELD(zero.next_actual);
    PDF_ZLIB_FIELD(split.active);
    PDF_ZLIB_FIELD(split.signature);
    PDF_ZLIB_FIELD(split.next_split);
#undef PDF_ZLIB_FIELD
    return search->zero.active <= 1 && search->zero.next_actual >= 0
        && search->split.active <= 1 && search->split.next_split >= -1
        && (!(search->zero.active || search->split.active) || search->active);
}

// Release the layout frontier independently of disposable parser state.
static void pdf_physical_search_clear(PDFPhysicalRunSearch *search) {
    free(search->boundaries);
    free(search->solution_actuals);
    memset(search, 0, sizeof(*search));
}

// State clones own their frontier and first successful layout.
static void pdf_physical_search_copy(PDFPhysicalRunSearch *dest,
                                     const PDFPhysicalRunSearch *source) {
    *dest = *source;
    dest->boundaries = NULL;
    dest->solution_actuals = NULL;
    if (source->boundary_count) {
        dest->boundaries = malloc(source->boundary_count * sizeof(*dest->boundaries));
        check_memory_allocation(dest->boundaries, __LINE__, __FILE__, "PDF boundaries");
        memcpy(dest->boundaries, source->boundaries,
               source->boundary_count * sizeof(*dest->boundaries));
    }
    if (source->total_slots) {
        dest->solution_actuals = malloc(source->total_slots * sizeof(*dest->solution_actuals));
        check_memory_allocation(dest->solution_actuals, __LINE__, __FILE__, "PDF layout");
        memcpy(dest->solution_actuals, source->solution_actuals,
               source->total_slots * sizeof(*dest->solution_actuals));
    }
}

// Encode physical layouts without pointers or native struct padding.
static bool pdf_serialize_physical_search(PDFPhysicalRunSearch *search,
                                          FILE *fp, StateSerialization mode) {
    size_t (*io)(void *, size_t, size_t, FILE *) = mode == SERIALIZE
        ? (size_t (*)(void *, size_t, size_t, FILE *))fwrite : fread;
#define PDF_PHYSICAL_FIELD(field) \
    if (io(&search->field, sizeof(search->field), 1, fp) != 1) { return false; }
    PDF_PHYSICAL_FIELD(active);
    PDF_PHYSICAL_FIELD(enumerated);
    PDF_PHYSICAL_FIELD(complete);
    PDF_PHYSICAL_FIELD(signature);
    PDF_PHYSICAL_FIELD(boundary_count);
    PDF_PHYSICAL_FIELD(total_slots);
    PDF_PHYSICAL_FIELD(valid_layouts);
    PDF_PHYSICAL_FIELD(trials);
    PDF_PHYSICAL_FIELD(solution_length);
    PDF_PHYSICAL_FIELD(next_footer);
#undef PDF_PHYSICAL_FIELD
    if (search->active > 1 || search->enumerated > 1 || search->complete > 1
        || search->valid_layouts > 2
        || search->boundary_count > SIZE_MAX / sizeof(*search->boundaries)
        || search->total_slots > SIZE_MAX / sizeof(*search->solution_actuals)
        || (!search->active && (search->boundary_count || search->total_slots
            || search->enumerated || search->complete || search->valid_layouts))
        || (search->active && (search->boundary_count == 0
            || search->boundary_count >= search->total_slots
            || search->solution_length == 0 || scalpel_state.blocksize == 0
            || 1 + (search->solution_length - 1) / scalpel_state.blocksize
                < search->total_slots))) {
        return false;
    }
    if (mode == DESERIALIZE && search->active) {
        search->boundaries = malloc(search->boundary_count * sizeof(*search->boundaries));
        search->solution_actuals = malloc(search->total_slots * sizeof(*search->solution_actuals));
        check_memory_allocation(search->boundaries, __LINE__, __FILE__, "PDF boundaries");
        check_memory_allocation(search->solution_actuals, __LINE__, __FILE__, "PDF layout");
    }
    if ((search->boundary_count && io(search->boundaries, sizeof(*search->boundaries),
            search->boundary_count, fp) != search->boundary_count)
        || (search->total_slots && io(search->solution_actuals, sizeof(*search->solution_actuals),
            search->total_slots, fp) != search->total_slots)) {
        return false;
    }
    for (uint64_t i = 0; i < search->boundary_count; i++) {
        if (search->boundaries[i] == 0 || search->boundaries[i] >= search->total_slots
            || (i && search->boundaries[i] <= search->boundaries[i - 1])) {
            return false;
        }
    }
    for (uint64_t i = 0; search->valid_layouts && i < search->total_slots; i++) {
        if (search->solution_actuals[i] < 0) {
            return false;
        }
    }
    return true;
}

// Decoder state is reconstructed; completed source trials and phase decisions persist.
static bool pdf_serialize_zlib_backbone_search(PDFZlibBackboneSearch *search,
                                              FILE *fp, StateSerialization mode) {
    size_t (*io)(void *, size_t, size_t, FILE *) = mode == SERIALIZE
        ? (size_t (*)(void *, size_t, size_t, FILE *))fwrite : fread;
#define PDF_BACKBONE_FIELD(field) \
    if (io(&search->field, sizeof(search->field), 1, fp) != 1) { return false; }
    PDF_BACKBONE_FIELD(cursor.active);
    PDF_BACKBONE_FIELD(cursor.preferred_done);
    PDF_BACKBONE_FIELD(cursor.signature);
    PDF_BACKBONE_FIELD(cursor.insert);
    PDF_BACKBONE_FIELD(cursor.next_actual);
    PDF_BACKBONE_FIELD(complete);
#undef PDF_BACKBONE_FIELD
    return search->cursor.active <= 1 && search->cursor.preferred_done <= 1
        && search->cursor.insert <= INT64_MAX && search->cursor.next_actual >= 0
        && search->complete <= 1 && (!search->complete || search->cursor.active);
}

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
        (*s)->initialized = false;
        (*s)->speculative_blocks = false;
        (*s)->linearized = false;
        (*s)->lin_L = -1;
        (*s)->lin_T = -1;
        (*s)->partial_prefix = NULL;
        (*s)->partial_search_active = false;
        (*s)->partial_search_length = 0;
        (*s)->partial_search_next = 0;
        memset(&(*s)->interior_search, 0, sizeof((*s)->interior_search));
        memset(&(*s)->three_run, 0, sizeof((*s)->three_run));
        (*s)->physical_search_active = false;
        memset((*s)->physical_search, 0, sizeof((*s)->physical_search));
        pdf_xref_search_state_init(&(*s)->xref_search);
    }

    // Serialize/deserialize number of xref tables
    if (fb(&(*s)->num_tables, sizeof(size_t), 1, fp) != 1) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    if (fb(&(*s)->initialized, sizeof((*s)->initialized), 1, fp) != 1 ||
        fb(&(*s)->speculative_blocks,
           sizeof((*s)->speculative_blocks), 1, fp) != 1) {
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
    pdf_serialize_xref_search_state(&(*s)->xref_search, fp, mode);

    uint64_t interior_version = UINT64_C(0x504446494e543037);
    PDFInteriorSearchState *interior = &(*s)->interior_search;
    if (fb(&interior_version, sizeof(interior_version), 1, fp) != 1
        || (interior_version != UINT64_C(0x504446494e543031)
            && interior_version != UINT64_C(0x504446494e543032)
            && interior_version != UINT64_C(0x504446494e543033)
            && interior_version != UINT64_C(0x504446494e543034)
            && interior_version != UINT64_C(0x504446494e543035)
            && interior_version != UINT64_C(0x504446494e543036)
            && interior_version != UINT64_C(0x504446494e543037))
        || fb(&interior->active, sizeof(interior->active), 1, fp) != 1
        || fb(&interior->table, sizeof(interior->table), 1, fp) != 1
        || fb(&interior->entry, sizeof(interior->entry), 1, fp) != 1
        || fb(&interior->repair.active, sizeof(interior->repair.active), 1, fp) != 1
        || fb(&interior->repair.prefix_limit, sizeof(interior->repair.prefix_limit), 1, fp) != 1
        || fb(&interior->repair.prefix_length, sizeof(interior->repair.prefix_length), 1, fp) != 1
        || fb(&interior->repair.run_length, sizeof(interior->repair.run_length), 1, fp) != 1
        || fb(&interior->repair.next_actual, sizeof(interior->repair.next_actual), 1, fp) != 1
        || interior->table > (*s)->num_tables || interior->entry < 0
        || interior->repair.next_actual < 0
        || (interior->repair.active
            && (!interior->active || interior->repair.run_length < 1
                || interior->repair.prefix_limit < 0
                || interior->repair.prefix_length < 0
                || interior->repair.prefix_length > interior->repair.prefix_limit))) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
    if (interior_version >= UINT64_C(0x504446494e543032)
        && (fb(&interior->gap_extra, sizeof(interior->gap_extra), 1, fp) != 1
            || fb(&interior->gap_slot, sizeof(interior->gap_slot), 1, fp) != 1
            || (interior->gap_extra != 0
                && (!interior->active || interior->gap_slot == 0)))) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
    if (interior_version >= UINT64_C(0x504446494e543036)
        && (fb(&(*s)->three_run.phase, sizeof((*s)->three_run.phase), 1, fp) != 1
            || !pdf_serialize_zlib_backbone_search(&(*s)->three_run.backbone, fp, mode)
            || !pdf_serialize_zlib_backbone_search(&interior->zlib, fp, mode))) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
    if (interior_version >= UINT64_C(0x504446494e543033)) {
        pdf_serialize_three_run_search(&(*s)->three_run, fp, mode);
    }
    if (interior_version >= UINT64_C(0x504446494e543034)
        && !pdf_serialize_auxiliary_search(interior, fp, mode)) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
    if (interior_version >= UINT64_C(0x504446494e543035)
        && !pdf_serialize_interior_zlib_search(interior, fp, mode)) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    uint64_t prefix_version = UINT64_C(0x5044465052465832);
    if (interior_version >= UINT64_C(0x504446494e543037)
        && (fb(&(*s)->physical_search_active, sizeof((*s)->physical_search_active), 1, fp) != 1
            || !pdf_serialize_physical_search(&(*s)->physical_search[0], fp, mode)
            || !pdf_serialize_physical_search(&(*s)->physical_search[1], fp, mode))) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
    uint64_t prefix_length = (*s)->partial_prefix ? (*s)->partial_prefix->length : 0;
    uint64_t prefix_count = (*s)->partial_prefix ? (*s)->partial_prefix->count : 0;
    if (fb(&prefix_version, sizeof(prefix_version), 1, fp) != 1
        || prefix_version != UINT64_C(0x5044465052465832)
        || fb(&prefix_length, sizeof(prefix_length), 1, fp) != 1
        || fb(&prefix_count, sizeof(prefix_count), 1, fp) != 1
        || fb(&(*s)->partial_search_active, sizeof((*s)->partial_search_active), 1, fp) != 1
        || fb(&(*s)->partial_search_length, sizeof((*s)->partial_search_length), 1, fp) != 1
        || fb(&(*s)->partial_search_next, sizeof((*s)->partial_search_next), 1, fp) != 1
        || (*s)->partial_search_next < 0
        || (*s)->partial_search_length > prefix_length
        || ((*s)->partial_search_active && (*s)->partial_search_length == 0)
        || prefix_count > (SIZE_MAX - sizeof(PDFPartialPrefix)) / sizeof(int64_t)
        || (prefix_length == 0) != (prefix_count == 0)
        || scalpel_state.blocksize == 0
        || (prefix_length != 0
            && 1 + (prefix_length - 1) / scalpel_state.blocksize != prefix_count)) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
    if (mode == DESERIALIZE && prefix_count != 0) {
        PDFPartialPrefix *prefix = malloc(sizeof(*prefix) + prefix_count * sizeof(int64_t));
        check_memory_allocation(prefix, __LINE__, __FILE__, "PDF partial mapping");
        atomic_init(&prefix->references, 1);
        prefix->length = prefix_length;
        prefix->count = prefix_count;
        (*s)->partial_prefix = prefix;
    }
    if (prefix_count != 0
        && fb((*s)->partial_prefix->actual, sizeof(int64_t), prefix_count, fp) != prefix_count) {
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
    d->initialized = s->initialized;
    d->speculative_blocks = s->speculative_blocks;
    d->linearized = s->linearized;
    d->lin_L = s->lin_L;
    d->lin_T = s->lin_T;
    d->partial_prefix = s->partial_prefix;
    d->partial_search_active = s->partial_search_active;
    d->partial_search_length = s->partial_search_length;
    d->partial_search_next = s->partial_search_next;
    d->interior_search = s->interior_search;
    d->three_run = s->three_run;
    d->physical_search_active = s->physical_search_active;
    for (size_t i = 0; i < 2; i++) {
        pdf_physical_search_copy(&d->physical_search[i], &s->physical_search[i]);
    }
    if (d->partial_prefix) {
        atomic_fetch_add_explicit(&d->partial_prefix->references, 1, memory_order_relaxed);
    }
    d->xref_tables = NULL;
    pdf_xref_search_state_copy(&d->xref_search, &s->xref_search);

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
    pdf_xref_search_state_clear(&s->xref_search);
    pdf_partial_prefix_release(s->partial_prefix);
    for (size_t i = 0; i < 2; i++) {
        pdf_physical_search_clear(&s->physical_search[i]);
    }
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
        check_memory_allocation(carve_state, __LINE__, __FILE__,
                                "PDF carve state");
        carve_state->lin_L = -1;
        carve_state->lin_T = -1;
        pdf_xref_search_state_init(&carve_state->xref_search);
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
    carve_state->initialized = true;
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
 * @description  Feeds one compressed extent to a zlib state while discarding
 *               output. This is an integrity oracle for replacement searches:
 *               callers retain only whether DEFLATE accepted the bytes and
 *               whether its terminal Adler-32 was verified.
 * @param stream  Initialized zlib state.
 * @param data    Compressed bytes to feed.
 * @param length  Number of bytes to feed.
 * @return       2 at Z_STREAM_END, 1 when accepted but incomplete, 0 on invalid
 *               compressed data, and -1 on an allocation failure.
 */
static int pdf_zlib_oracle_feed(z_stream *stream,
                                const unsigned char *data,
                                size_t length) {
    unsigned char output[65536];
    stream->next_in = (Bytef *)data;
    stream->avail_in = (uInt)length;

    do {
        uInt before = stream->avail_in;
        stream->next_out = output;
        stream->avail_out = (uInt)sizeof(output);
        int ret = inflate(stream, Z_NO_FLUSH);
        if (ret == Z_STREAM_END) {
            return 2;
        }
        if (ret == Z_MEM_ERROR) {
            return -1;
        }
        if (ret != Z_OK && ret != Z_BUF_ERROR) {
            return 0;
        }
        if (ret == Z_BUF_ERROR && stream->avail_in == before &&
            stream->avail_out == sizeof(output)) {
            return 0;
        }
    } while (stream->avail_in > 0 || stream->avail_out == 0);

    return 1;
}

static int pdf_try_zlib_backbone_insertion(
    z_stream *prefix,
    size_t prefix_fed,
    const int64_t *backbone,
    size_t backbone_count,
    size_t insert,
    size_t missing,
    size_t stream_len,
    int64_t total_actual,
    const roaring64_bitmap_t *outside_apps,
    const roaring64_bitmap_t *backbone_apps,
    int64_t *replacement,
    uint64_t *probes, PDFBackboneSearch *search) {
    FileMirror *fm = scalpel_state.filemirror;
    const size_t bsz = scalpel_state.blocksize;
#ifdef PDF_TRACE_STALL
    uLong best_total_in = 0;
    int64_t best_run_start = -1;
    int best_status = 0;
#endif

    if (search->insert != insert) {
        search->insert = insert;
        search->next_actual = 0;
    }
    for (int64_t run_start = search->next_actual;
         run_start <= total_actual - (int64_t)missing;
         run_start++) {
        if (((++*probes & 0xffU) == 0U) &&
            atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                 memory_order_acquire)) {
            return -1;
        }

        search->next_actual = run_start + 1;

        bool viable = true;
        for (size_t i = 0; i < missing; i++) {
            int64_t actual = run_start + (int64_t)i;
            int64_t app = filemirror_apparent_blocknumber(fm, actual);
            if (app < 0 || filemirror_actual_block_covered(fm, actual) ||
                filemirror_actual_block_is_zero(fm, actual) ||
                roaring64_bitmap_contains(outside_apps, (uint64_t)app) ||
                roaring64_bitmap_contains(backbone_apps, (uint64_t)app)) {
                viable = false;
                break;
            }
            replacement[i] = actual;
        }
        if (!viable) {
            continue;
        }

        z_stream trial;
        memset(&trial, 0, sizeof(trial));
        if (inflateCopy(&trial, prefix) != Z_OK) {
            return -1;
        }

        size_t trial_fed = prefix_fed;
        int trial_status = 1;
        bool trial_extent_complete = false;
        for (size_t i = 0; i < missing && trial_status == 1; i++) {
            if (trial_fed >= stream_len) {
                trial_status = 0;
                break;
            }
            size_t take = bsz;
            if (take > stream_len - trial_fed) {
                take = stream_len - trial_fed;
            }
            int64_t app = filemirror_apparent_blocknumber(fm, replacement[i]);
            const unsigned char *block =
                (const unsigned char *)get_apparent_block_data(fm, app);
            if (!block) {
                trial_status = 0;
                break;
            }
            trial_status = pdf_zlib_oracle_feed(&trial, block, take);
            trial_fed += take;
            if (trial_status == 2) {
                trial_extent_complete = pdf_zlib_extent_complete(
                    &trial, trial_fed, stream_len);
            }
            free((void *)block);
            if (trial_status == 2) {
                trial_status = 0;
            }
        }

        for (size_t i = insert;
             i < backbone_count && trial_status == 1;
             i++) {
            if (trial_fed >= stream_len) {
                trial_status = 0;
                break;
            }
            size_t take = bsz;
            if (take > stream_len - trial_fed) {
                take = stream_len - trial_fed;
            }
            int64_t app = filemirror_apparent_blocknumber(fm, backbone[i]);
            const unsigned char *block =
                (const unsigned char *)get_apparent_block_data(fm, app);
            if (!block) {
                trial_status = 0;
                break;
            }
            trial_status = pdf_zlib_oracle_feed(&trial, block, take);
            trial_fed += take;
            if (trial_status == 2) {
                trial_extent_complete = pdf_zlib_extent_complete(
                    &trial, trial_fed, stream_len);
            }
            free((void *)block);
            if (trial_status == 2 && i + 1 < backbone_count) {
                trial_status = 0;
            }
        }

        bool solved = trial_status == 2 && trial_extent_complete;
#ifdef PDF_TRACE_STALL
        if (trial.total_in > best_total_in) {
            best_total_in = trial.total_in;
            best_run_start = run_start;
            best_status = trial_status;
        }
#endif
        inflateEnd(&trial);
        if (solved) {
            return 1;
        }
    }
#ifdef PDF_TRACE_STALL
    lock_fprintf(stdout,
        "[PDFBACKBONE] insertion=%zu missing=%zu best_run=%" PRId64
        " best_input=%lu/%zu status=%d\n",
        insert, missing, best_run_start, (unsigned long)best_total_in,
        stream_len, best_status);
#endif
    return 0;
}

/**
 * @description  Repairs a FlateDecode stream assembled across both a physical
 *               gap and one displaced run. The trusted start and end blocks
 *               bound a physical backbone; unavailable zero/covered blocks are
 *               omitted, and the resulting block deficit is searched as one
 *               contiguous run at every interior logical position. No candidate
 *               mapping changes until zlib consumes the declared stream length
 *               and reaches Z_STREAM_END, thereby verifying the final Adler-32.
 * @param work       Thread context, used for checkpoint responsiveness.
 * @param candidate  Candidate containing the stream.
 * @param stream_at  Absolute logical byte offset of compressed stream data.
 * @param stream_len Declared compressed stream length.
 * @param start_slot Slot containing the stream start.
 * @param end_slot   Slot containing the stream end.
 * @return       true if an exact complete assignment was committed.
 */
static bool pdf_repair_interior_zlib_backbone(ThreadWork *work,
                                              CarveInfo *candidate,
                                              int64_t stream_at,
                                              int stream_len,
                                              int64_t start_slot,
                                              int64_t end_slot,
                                              bool exhaustive,
                                              PDFZlibBackboneSearch *search) {
    (void)work;
    if (!candidate || stream_len <= 0 || start_slot < 0 ||
        end_slot <= start_slot ||
        end_slot >= (int64_t)blockvector_get_num_blocks(candidate->b)) {
        return false;
    }

    FileMirror *fm = scalpel_state.filemirror;
    const size_t bsz = scalpel_state.blocksize;
    const int64_t total_actual =
        (int64_t)CEILDIV(filemirror_filesize(fm), bsz);
    const size_t expected = (size_t)(end_slot - start_slot + 1);
    int64_t start_app = blockvector_get_apparent_blocknumber(
        candidate->b, (uint64_t)start_slot);
    int64_t end_app = blockvector_get_apparent_blocknumber(
        candidate->b, (uint64_t)end_slot);
    if (start_app < 0 || end_app < 0) {
        return false;
    }

    int64_t start_actual = filemirror_actual_blocknumber(fm, start_app);
    int64_t end_actual = filemirror_actual_blocknumber(fm, end_app);
    if (start_actual < 0 || end_actual <= start_actual ||
        end_actual >= total_actual) {
        return false;
    }

    roaring64_bitmap_t *outside_apps = roaring64_bitmap_create();
    roaring64_bitmap_t *backbone_apps = roaring64_bitmap_create();
    if (!outside_apps || !backbone_apps) {
        roaring64_bitmap_free(outside_apps);
        roaring64_bitmap_free(backbone_apps);
        return false;
    }

    uint64_t candidate_blocks = blockvector_get_num_blocks(candidate->b);
    for (uint64_t slot = 0; slot < candidate_blocks; slot++) {
        if (slot >= (uint64_t)start_slot && slot <= (uint64_t)end_slot) {
            continue;
        }
        int64_t app = blockvector_get_apparent_blocknumber(candidate->b, slot);
        if (app >= 0) {
            roaring64_bitmap_add(outside_apps, (uint64_t)app);
        }
    }

    int64_t *backbone = malloc(expected * sizeof(*backbone));
    int64_t *replacement = malloc(expected * sizeof(*replacement));
    int64_t *assignment = malloc(expected * sizeof(*assignment));
    check_memory_allocation(backbone, __LINE__, __FILE__,
                            "PDF zlib physical backbone");
    check_memory_allocation(replacement, __LINE__, __FILE__,
                            "PDF zlib displaced run");
    check_memory_allocation(assignment, __LINE__, __FILE__,
                            "PDF zlib exact assignment");

    size_t backbone_count = 0;
    size_t preferred_insert = 0;
    bool overflow = false;
    bool skipping = false;
    for (int64_t actual = start_actual; actual <= end_actual; actual++) {
        int64_t app = filemirror_apparent_blocknumber(fm, actual);
        if (app < 0 || filemirror_actual_block_covered(fm, actual) ||
            filemirror_actual_block_is_zero(fm, actual) ||
            roaring64_bitmap_contains(outside_apps, (uint64_t)app)) {
            if (!skipping && backbone_count > 0) {
                preferred_insert = backbone_count;
            }
            skipping = true;
            continue;
        }
        skipping = false;
        if (backbone_count == expected) {
            overflow = true;
            break;
        }
        backbone[backbone_count++] = actual;
        roaring64_bitmap_add(backbone_apps, (uint64_t)app);
    }

    bool solved = false;
    bool completed = false;
    size_t solved_insert = 0;
    size_t missing = (!overflow && backbone_count < expected)
                         ? expected - backbone_count
                         : 0;
#ifdef PDF_TRACE_STALL
    lock_fprintf(stdout,
        "[PDFBACKBONE] start=%" PRId64 " end=%" PRId64
        " expected=%zu backbone=%zu missing=%zu preferred=%zu overflow=%d\n",
        start_actual, end_actual, expected, backbone_count, missing,
        preferred_insert, overflow ? 1 : 0);
#endif
    const uint64_t signature = XXH64(backbone,
        backbone_count * sizeof(*backbone),
        pdf_interior_signature(candidate, stream_at, stream_len));
    if (!search->cursor.active || search->cursor.signature != signature) {
        memset(search, 0, sizeof(*search));
        search->cursor.active = 1;
        search->cursor.signature = signature;
    }
    if (search->complete) {
        goto cleanup;
    }
    if (overflow || backbone_count < 2 || backbone[0] != start_actual ||
        backbone[backbone_count - 1] != end_actual) {
        completed = true;
        goto cleanup;
    }

    size_t first_offset = (size_t)(stream_at - start_slot * (int64_t)bsz);
    if (first_offset >= bsz) {
        goto cleanup;
    }

    z_stream prefix;
    memset(&prefix, 0, sizeof(prefix));
    if (inflateInit2(&prefix, 15) != Z_OK) {
        goto cleanup;
    }

    size_t prefix_fed = 0;
    size_t take = bsz - first_offset;
    if (take > (size_t)stream_len) {
        take = (size_t)stream_len;
    }
    const unsigned char *block =
        (const unsigned char *)get_apparent_block_data(fm, start_app);
    int prefix_status = 0;
    bool prefix_extent_complete = false;
    if (block) {
        prefix_status = pdf_zlib_oracle_feed(&prefix, block + first_offset,
                                             take);
        prefix_fed = take;
        if (prefix_status == 2) {
            prefix_extent_complete = pdf_zlib_extent_complete(
                &prefix, prefix_fed, (size_t)stream_len);
        }
        free((void *)block);
    }

    if (missing == 0) {
        size_t fed = prefix_fed;
        int status = prefix_status;
        bool extent_complete = prefix_extent_complete;
        for (size_t i = 1; i < backbone_count && status == 1; i++) {
            if (((i & 0xffU) == 0U) &&
                atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                     memory_order_acquire)) {
                status = -1;
                break;
            }
            if (fed >= (size_t)stream_len) {
                status = 0;
                break;
            }
            take = bsz;
            if (take > (size_t)stream_len - fed) {
                take = (size_t)stream_len - fed;
            }
            int64_t app = filemirror_apparent_blocknumber(fm, backbone[i]);
            block = (const unsigned char *)get_apparent_block_data(fm, app);
            if (!block) {
                status = 0;
                break;
            }
            status = pdf_zlib_oracle_feed(&prefix, block, take);
            fed += take;
            if (status == 2) {
                extent_complete = pdf_zlib_extent_complete(
                    &prefix, fed, (size_t)stream_len);
            }
            free((void *)block);
            if (status == 2 && i + 1 < backbone_count) {
                status = 0;
            }
        }
        solved = status == 2 && extent_complete;
        completed = status >= 0;
        inflateEnd(&prefix);
        if (solved) {
            memcpy(assignment, backbone, expected * sizeof(*assignment));
            solved = pdf_replace_blocks_at_slot(
                candidate, assignment, (int)expected,
                (uint64_t)start_slot, "ZLIB_BACKBONE");
        }
#ifdef PDF_TRACE_STALL
        lock_fprintf(stdout,
            "[PDFBACKBONE] direct count=%zu committed=%d\n",
            backbone_count, solved ? 1 : 0);
#endif
        goto cleanup;
    }

    uint64_t probes = 0;
    if (!search->cursor.preferred_done
        && preferred_insert > 0 && preferred_insert < backbone_count) {
        z_stream preferred;
        memset(&preferred, 0, sizeof(preferred));
        if (inflateInit2(&preferred, 15) != Z_OK) {
            inflateEnd(&prefix);
            goto cleanup;
        }

        size_t preferred_fed = 0;
        int preferred_status = 1;
        for (size_t i = 0; i < preferred_insert && preferred_status == 1; i++) {
            if (preferred_fed >= (size_t)stream_len) {
                preferred_status = 0;
                break;
            }
            size_t offset = i == 0 ? first_offset : 0;
            take = bsz - offset;
            if (take > (size_t)stream_len - preferred_fed) {
                take = (size_t)stream_len - preferred_fed;
            }
            int64_t app = filemirror_apparent_blocknumber(fm, backbone[i]);
            block = (const unsigned char *)get_apparent_block_data(fm, app);
            if (!block) {
                preferred_status = 0;
                break;
            }
            preferred_status = pdf_zlib_oracle_feed(
                &preferred, block + offset, take);
            free((void *)block);
            preferred_fed += take;
        }
        if (preferred_status == 1) {
            int result = pdf_try_zlib_backbone_insertion(
                &preferred, preferred_fed, backbone, backbone_count,
                preferred_insert, missing, (size_t)stream_len, total_actual,
                outside_apps, backbone_apps, replacement, &probes, &search->cursor);
            if (result < 0) {
                inflateEnd(&preferred);
                inflateEnd(&prefix);
                goto cleanup;
            }
            solved = result == 1;
            if (solved) {
                solved_insert = preferred_insert;
            }
#ifdef PDF_TRACE_STALL
            lock_fprintf(stdout,
                "[PDFBACKBONE] preferred=%zu result=%d probes=%" PRIu64
                "\n",
                preferred_insert, result, probes);
#endif
        }
        inflateEnd(&preferred);
    }
    if (!search->cursor.preferred_done) {
        search->cursor.preferred_done = 1;
        search->cursor.insert = 1;
        search->cursor.next_actual = 0;
    }

    if (!solved && !exhaustive) {
        completed = true;
        inflateEnd(&prefix);
        goto cleanup;
    }

    const uint64_t resume_insert = search->cursor.insert;
    for (size_t insert = 1;
         prefix_status == 1 && insert < backbone_count && !solved;
         insert++) {
        if (insert >= resume_insert && insert != preferred_insert) {
            int result = pdf_try_zlib_backbone_insertion(
                &prefix, prefix_fed, backbone, backbone_count, insert, missing,
                (size_t)stream_len, total_actual, outside_apps, backbone_apps,
                replacement, &probes, &search->cursor);
            if (result < 0) {
                inflateEnd(&prefix);
                goto cleanup;
            }
            solved = result == 1;
            if (solved) {
                solved_insert = insert;
            }
        }

        if (!solved) {
            if (prefix_fed >= (size_t)stream_len) {
                prefix_status = 0;
                break;
            }
            take = bsz;
            if (take > (size_t)stream_len - prefix_fed) {
                take = (size_t)stream_len - prefix_fed;
            }
            int64_t app = filemirror_apparent_blocknumber(fm, backbone[insert]);
            block = (const unsigned char *)get_apparent_block_data(fm, app);
            if (!block) {
                prefix_status = 0;
                break;
            }
            prefix_status = pdf_zlib_oracle_feed(&prefix, block, take);
            free((void *)block);
            prefix_fed += take;
        }
    }
    completed = prefix_status >= 0;
    inflateEnd(&prefix);

    if (solved) {
        size_t out = 0;
        for (size_t i = 0; i < solved_insert; i++) {
            assignment[out++] = backbone[i];
        }
        for (size_t i = 0; i < missing; i++) {
            assignment[out++] = replacement[i];
        }
        for (size_t i = solved_insert; i < backbone_count; i++) {
            assignment[out++] = backbone[i];
        }
        solved = out == expected && pdf_replace_blocks_at_slot(
            candidate, assignment, (int)expected, (uint64_t)start_slot,
            "ZLIB_BACKBONE");
#ifdef PDF_TRACE_STALL
        lock_fprintf(stdout,
            "[PDFBACKBONE] solved insert=%zu missing=%zu committed=%d\n",
            solved_insert, missing, solved ? 1 : 0);
#endif
    }

cleanup:
    if (completed && !atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
        search->complete = 1;
    }
    free(assignment);
    free(replacement);
    free(backbone);
    roaring64_bitmap_free(backbone_apps);
    roaring64_bitmap_free(outside_apps);
    return solved;
}

static int pdf_try_jpeg_backbone_insertion(
    const JpegStreamReassembler *prefix,
    const int64_t *backbone,
    size_t backbone_count,
    size_t insert,
    size_t missing,
    int64_t total_actual,
    const roaring64_bitmap_t *outside_apps,
    const roaring64_bitmap_t *backbone_apps,
    int64_t *replacement,
    uint64_t *probes, PDFBackboneSearch *search) {
    FileMirror *fm = scalpel_state.filemirror;
    const size_t bsz = scalpel_state.blocksize;

    if (search->insert != insert) {
        search->insert = insert;
        search->next_actual = 0;
    }
    for (int64_t run_start = search->next_actual;
         run_start <= total_actual - (int64_t)missing;
         run_start++) {
        if (((++*probes & 0xffU) == 0U) &&
            atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                 memory_order_acquire)) {
            return -1;
        }
        search->next_actual = run_start + 1;

        bool viable = true;
        for (size_t i = 0; i < missing; i++) {
            int64_t actual = run_start + (int64_t)i;
            int64_t app = filemirror_apparent_blocknumber(fm, actual);
            if (app < 0 || filemirror_actual_block_covered(fm, actual) ||
                filemirror_actual_block_is_zero(fm, actual) ||
                roaring64_bitmap_contains(outside_apps, (uint64_t)app) ||
                roaring64_bitmap_contains(backbone_apps, (uint64_t)app)) {
                viable = false;
                break;
            }
            replacement[i] = actual;
        }
        if (!viable) {
            continue;
        }

        /*
         * The parser state is scalar and its output buffer is preallocated.
         * A by-value copy therefore gives this trial an independent parser
         * position; trial bytes overwrite only scratch output that no parser
         * decision reads.
         */
        JpegStreamReassembler trial = *prefix;
        int status = 1;
        for (size_t i = 0; i < missing && status == 1; i++) {
            int64_t app = filemirror_apparent_blocknumber(fm, replacement[i]);
            const unsigned char *block =
                (const unsigned char *)get_apparent_block_data(fm, app);
            if (!block) {
                status = 0;
                break;
            }
            status = jpeg_stream_reassembler_try_block(&trial, block, bsz);
            free((void *)block);
            if (status != 1) {
                status = 0;
            }
        }

        for (size_t i = insert;
             i < backbone_count && status == 1;
             i++) {
            int64_t app = filemirror_apparent_blocknumber(fm, backbone[i]);
            const unsigned char *block =
                (const unsigned char *)get_apparent_block_data(fm, app);
            if (!block) {
                status = 0;
                break;
            }
            status = jpeg_stream_reassembler_try_block(&trial, block, bsz);
            free((void *)block);
            if (i + 1 < backbone_count && status != 1) {
                status = 0;
            }
        }

        if (status == 2 && pdf_jpeg_extent_complete(&trial)) {
            return 1;
        }
    }
    return 0;
}

/**
 * @description  Repairs a DCTDecode stream whose xref-positioned start and end
 *               blocks bracket interior holes. Available blocks between those
 *               anchors form a physical backbone. If blocks were displaced,
 *               every insertion position for the missing contiguous run is
 *               tested. The candidate changes only after the complete declared
 *               extent satisfies JPEG marker, table, scan, restart, EOI, and
 *               trailing-whitespace checks.
 * @param work       Thread context, used for checkpoint responsiveness.
 * @param candidate  Candidate containing the stream.
 * @param stream_at  Absolute logical byte offset of JPEG stream data.
 * @param stream_len Declared stream length.
 * @param start_slot Slot containing the stream start.
 * @param end_slot   Slot containing the stream end.
 * @param exhaustive Search every insertion position when the physical-gap
 *                   position does not solve the stream.
 * @return       true if a complete structurally verified assignment was committed.
 */
static bool pdf_repair_interior_jpeg_backbone(ThreadWork *work,
                                              CarveInfo *candidate,
                                              int64_t stream_at,
                                              int stream_len,
                                              int64_t start_slot,
                                              int64_t end_slot,
                                              bool exhaustive,
                                              PDFBackboneSearch *search) {
    (void)work;
    if (!candidate || !search || stream_len <= 0 || start_slot < 0 ||
        end_slot <= start_slot ||
        end_slot >= (int64_t)blockvector_get_num_blocks(candidate->b)) {
        return false;
    }

    FileMirror *fm = scalpel_state.filemirror;
    const size_t bsz = scalpel_state.blocksize;
    const int64_t total_actual =
        (int64_t)CEILDIV(filemirror_filesize(fm), bsz);
    const size_t expected = (size_t)(end_slot - start_slot + 1);
    if (expected > (size_t)INT_MAX) {
        return false;
    }

    int64_t start_app = blockvector_get_apparent_blocknumber(
        candidate->b, (uint64_t)start_slot);
    int64_t end_app = blockvector_get_apparent_blocknumber(
        candidate->b, (uint64_t)end_slot);
    if (start_app < 0 || end_app < 0) {
        return false;
    }

    int64_t start_actual = filemirror_actual_blocknumber(fm, start_app);
    int64_t end_actual = filemirror_actual_blocknumber(fm, end_app);
    if (start_actual < 0 || end_actual <= start_actual ||
        end_actual >= total_actual) {
        return false;
    }

    roaring64_bitmap_t *outside_apps = roaring64_bitmap_create();
    roaring64_bitmap_t *backbone_apps = roaring64_bitmap_create();
    if (!outside_apps || !backbone_apps) {
        roaring64_bitmap_free(outside_apps);
        roaring64_bitmap_free(backbone_apps);
        return false;
    }

    uint64_t candidate_blocks = blockvector_get_num_blocks(candidate->b);
    for (uint64_t slot = 0; slot < candidate_blocks; slot++) {
        if (slot >= (uint64_t)start_slot && slot <= (uint64_t)end_slot) {
            continue;
        }
        int64_t app = blockvector_get_apparent_blocknumber(candidate->b, slot);
        if (app >= 0) {
            roaring64_bitmap_add(outside_apps, (uint64_t)app);
        }
    }

    int64_t *backbone = malloc(expected * sizeof(*backbone));
    int64_t *replacement = malloc(expected * sizeof(*replacement));
    int64_t *assignment = malloc(expected * sizeof(*assignment));
    check_memory_allocation(backbone, __LINE__, __FILE__,
                            "PDF JPEG physical backbone");
    check_memory_allocation(replacement, __LINE__, __FILE__,
                            "PDF JPEG displaced run");
    check_memory_allocation(assignment, __LINE__, __FILE__,
                            "PDF JPEG exact assignment");

    size_t backbone_count = 0;
    size_t preferred_insert = 0;
    bool overflow = false;
    bool skipping = false;
    for (int64_t actual = start_actual; actual <= end_actual; actual++) {
        int64_t app = filemirror_apparent_blocknumber(fm, actual);
        if (app < 0 || filemirror_actual_block_covered(fm, actual) ||
            filemirror_actual_block_is_zero(fm, actual) ||
            roaring64_bitmap_contains(outside_apps, (uint64_t)app)) {
            if (!skipping && backbone_count > 0) {
                preferred_insert = backbone_count;
            }
            skipping = true;
            continue;
        }
        skipping = false;
        if (backbone_count == expected) {
            overflow = true;
            break;
        }
        backbone[backbone_count++] = actual;
        roaring64_bitmap_add(backbone_apps, (uint64_t)app);
    }

    bool solved = false;
    size_t solved_insert = 0;
    size_t missing = (!overflow && backbone_count < expected)
                         ? expected - backbone_count
                         : 0;
    if (overflow || backbone_count < 2 || backbone[0] != start_actual ||
        backbone[backbone_count - 1] != end_actual) {
        goto cleanup;
    }

    size_t first_offset = (size_t)(stream_at - start_slot * (int64_t)bsz);
    if (first_offset >= bsz) {
        goto cleanup;
    }

    const unsigned char *first_block =
        (const unsigned char *)get_apparent_block_data(fm, start_app);
    if (!first_block) {
        goto cleanup;
    }
    JpegStreamReassembler prefix;
    int init_status = jpeg_stream_reassembler_init(
        &prefix, first_block, bsz, first_offset, (size_t)stream_len);
    free((void *)first_block);
    if (init_status == -1) {
        goto cleanup;
    }

    if (missing == 0) {
        int status = 1;
        for (size_t i = 1; i < backbone_count && status == 1; i++) {
            if (((i & 0xffU) == 0U) &&
                atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                     memory_order_acquire)) {
                status = -1;
                break;
            }
            int64_t app = filemirror_apparent_blocknumber(fm, backbone[i]);
            const unsigned char *block =
                (const unsigned char *)get_apparent_block_data(fm, app);
            if (!block) {
                status = 0;
                break;
            }
            status = jpeg_stream_reassembler_try_block(&prefix, block, bsz);
            free((void *)block);
            if (i + 1 < backbone_count && status != 1) {
                status = 0;
            }
        }
        solved = status == 2 && pdf_jpeg_extent_complete(&prefix);
        jpeg_stream_reassembler_free(&prefix);
        if (solved) {
            memcpy(assignment, backbone, expected * sizeof(*assignment));
            solved = pdf_replace_blocks_at_slot(
                candidate, assignment, (int)expected,
                (uint64_t)start_slot, "JPEG_BACKBONE");
        }
        goto cleanup;
    }

    uint64_t probes = 0;
    const uint64_t signature = XXH64(backbone,
        backbone_count * sizeof(*backbone),
        pdf_interior_signature(candidate, stream_at, stream_len));
    if (!search->active || search->signature != signature) {
        memset(search, 0, sizeof(*search));
        search->active = 1;
        search->signature = signature;
    }
    if (!search->preferred_done
        && preferred_insert > 0 && preferred_insert < backbone_count) {
        JpegStreamReassembler preferred = prefix;
        int status = 1;
        for (size_t i = 1; i < preferred_insert && status == 1; i++) {
            int64_t app = filemirror_apparent_blocknumber(fm, backbone[i]);
            const unsigned char *block =
                (const unsigned char *)get_apparent_block_data(fm, app);
            if (!block) {
                status = 0;
                break;
            }
            status = jpeg_stream_reassembler_try_block(&preferred, block, bsz);
            free((void *)block);
            if (status != 1) {
                status = 0;
            }
        }
        if (status == 1) {
            int result = pdf_try_jpeg_backbone_insertion(
                &preferred, backbone, backbone_count, preferred_insert, missing,
                total_actual, outside_apps, backbone_apps, replacement, &probes,
                search);
            if (result < 0) {
                jpeg_stream_reassembler_free(&prefix);
                goto cleanup;
            }
            solved = result == 1;
            if (solved) {
                solved_insert = preferred_insert;
            }
        }
    }
    if (!search->preferred_done) {
        search->preferred_done = 1;
        search->insert = 1;
        search->next_actual = 0;
    }

    if (!solved && exhaustive) {
        const uint64_t resume_insert = search->insert;
        int prefix_status = 1;
        for (size_t insert = 1;
             insert < backbone_count && prefix_status == 1 && !solved;
             insert++) {
            // Recreate decoder context without repeating completed source trials.
            if (insert >= resume_insert && insert != preferred_insert) {
                int result = pdf_try_jpeg_backbone_insertion(
                    &prefix, backbone, backbone_count, insert, missing,
                    total_actual, outside_apps, backbone_apps, replacement,
                    &probes, search);
                if (result < 0) {
                    break;
                }
                solved = result == 1;
                if (solved) {
                    solved_insert = insert;
                }
            }

            if (!solved) {
                int64_t app = filemirror_apparent_blocknumber(
                    fm, backbone[insert]);
                const unsigned char *block =
                    (const unsigned char *)get_apparent_block_data(fm, app);
                if (!block) {
                    prefix_status = 0;
                    break;
                }
                prefix_status = jpeg_stream_reassembler_try_block(
                    &prefix, block, bsz);
                free((void *)block);
                if (prefix_status != 1) {
                    prefix_status = 0;
                }
            }
        }
    }
    jpeg_stream_reassembler_free(&prefix);

    if (solved) {
        size_t out = 0;
        for (size_t i = 0; i < solved_insert; i++) {
            assignment[out++] = backbone[i];
        }
        for (size_t i = 0; i < missing; i++) {
            assignment[out++] = replacement[i];
        }
        for (size_t i = solved_insert; i < backbone_count; i++) {
            assignment[out++] = backbone[i];
        }
        solved = out == expected && pdf_replace_blocks_at_slot(
            candidate, assignment, (int)expected, (uint64_t)start_slot,
            "JPEG_BACKBONE");
    }

cleanup:
    if (!atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
        memset(search, 0, sizeof(*search));
    }
    free(assignment);
    free(replacement);
    free(backbone);
    roaring64_bitmap_free(backbone_apps);
    roaring64_bitmap_free(outside_apps);
    return solved;
}

/**
 * @description  Repairs one mapped all-zero run inside a FlateDecode stream.
 *               A vacated displaced run can appear mapped rather than holed when
 *               fragmentator or an acquisition image fills its old location with
 *               zeroes. The valid compressed prefix is inflated once, each
 *               available physical run of the same length is tried from a cloned
 *               zlib state, and replacement occurs only when the complete stream
 *               reaches Z_STREAM_END and verifies its Adler-32.
 * @param work       Thread context, used for checkpoint responsiveness.
 * @param candidate  Candidate containing the stream.
 * @param stream_at  Absolute logical byte offset of compressed stream data.
 * @param stream_len Declared compressed stream length.
 * @param start_slot Slot containing the stream start.
 * @param end_slot   Slot containing the stream end.
 * @return       true if a verified displaced run was restored.
 */
static bool pdf_repair_interior_zlib_zero_run(ThreadWork *work,
                                              CarveInfo *candidate,
                                              int64_t stream_at,
                                              int stream_len,
                                              int64_t start_slot,
                                              int64_t end_slot,
                                              PDFZeroRunSearch *search) {
    (void)work;
    FileMirror *fm = scalpel_state.filemirror;
    const size_t bsz = scalpel_state.blocksize;
    const int64_t total_actual =
        (int64_t)CEILDIV(filemirror_filesize(fm), bsz);

    int64_t zero_first = -1;
    int64_t zero_last = -1;
    bool second_run = false;
    for (int64_t slot = start_slot; slot <= end_slot; slot++) {
        int64_t app = blockvector_get_apparent_blocknumber(candidate->b,
                                                           (uint64_t)slot);
        if (app < 0) {
            return false;
        }
        int64_t actual = filemirror_actual_blocknumber(fm, app);
        if (!filemirror_actual_block_is_zero(fm, actual)) {
            continue;
        }
        if (zero_first < 0) {
            zero_first = slot;
            zero_last = slot;
        } else if (slot == zero_last + 1) {
            zero_last = slot;
        } else {
            second_run = true;
            break;
        }
    }
    if (zero_first < 0 || second_run || zero_first == start_slot) {
        return false;
    }

    int run_length = (int)(zero_last - zero_first + 1);
    z_stream prefix;
    memset(&prefix, 0, sizeof(prefix));
    if (inflateInit2(&prefix, 15) != Z_OK) {
        return false;
    }

    size_t fed = 0;
    size_t first_offset = (size_t)(stream_at - start_slot * (int64_t)bsz);
    size_t take = bsz - first_offset;
    if (take > (size_t)stream_len) {
        take = (size_t)stream_len;
    }
    const unsigned char *candidate_data =
        (const unsigned char *)blockvector_get_data_pointer(candidate->b);
    int status = pdf_zlib_oracle_feed(
        &prefix, candidate_data + start_slot * (int64_t)bsz +
                     (int64_t)first_offset,
        take);
    fed += take;

    for (int64_t slot = start_slot + 1;
         status == 1 && slot < zero_first;
         slot++) {
        if (fed >= (size_t)stream_len) {
            status = 0;
            break;
        }
        take = bsz;
        if (take > (size_t)stream_len - fed) {
            take = (size_t)stream_len - fed;
        }
        int64_t app = blockvector_get_apparent_blocknumber(candidate->b,
                                                           (uint64_t)slot);
        const unsigned char *blk =
            (const unsigned char *)get_apparent_block_data(fm, app);
        if (!blk) {
            status = 0;
            break;
        }
        status = pdf_zlib_oracle_feed(&prefix, blk, take);
        free((void *)blk);
        fed += take;
    }
    if (status != 1 || fed >= (size_t)stream_len) {
        inflateEnd(&prefix);
        return false;
    }

    int64_t *replacement = malloc((size_t)run_length * sizeof(*replacement));
    check_memory_allocation(replacement, __LINE__, __FILE__,
                            "PDF zlib displaced run");
    bool solved = false;
    uint64_t probes = 0;

    const uint64_t signature = pdf_interior_signature(candidate, stream_at, stream_len);
    if (!search->active || search->signature != signature) {
        *search = (PDFZeroRunSearch){.active = 1, .signature = signature};
    }
    for (int64_t run_start = search->next_actual;
         run_start <= total_actual - run_length && !solved;
         run_start++) {
        if (((++probes & 0xffU) == 0U) &&
            atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                 memory_order_acquire)) {
            break;
        }
        search->next_actual = run_start + 1;

        bool viable = true;
        for (int i = 0; i < run_length; i++) {
            int64_t actual = run_start + i;
            int64_t app = filemirror_apparent_blocknumber(fm, actual);
            if (app < 0 || filemirror_actual_block_covered(fm, actual) ||
                filemirror_actual_block_is_zero(fm, actual) ||
                apparent_block_in_blockvector(candidate->b, app)) {
                viable = false;
                break;
            }
            replacement[i] = actual;
        }
        if (!viable) {
            continue;
        }

        z_stream trial;
        memset(&trial, 0, sizeof(trial));
        if (inflateCopy(&trial, &prefix) != Z_OK) {
            break;
        }

        size_t trial_fed = fed;
        int trial_status = 1;
        bool trial_extent_complete = false;
        for (int i = 0; i < run_length && trial_status == 1; i++) {
            if (trial_fed >= (size_t)stream_len) {
                trial_status = 0;
                break;
            }
            take = bsz;
            if (take > (size_t)stream_len - trial_fed) {
                take = (size_t)stream_len - trial_fed;
            }
            int64_t app = filemirror_apparent_blocknumber(fm, replacement[i]);
            const unsigned char *blk =
                (const unsigned char *)get_apparent_block_data(fm, app);
            if (!blk) {
                trial_status = 0;
                break;
            }
            trial_status = pdf_zlib_oracle_feed(&trial, blk, take);
            trial_fed += take;
            if (trial_status == 2) {
                trial_extent_complete = pdf_zlib_extent_complete(
                    &trial, trial_fed, (size_t)stream_len);
            }
            free((void *)blk);
            if (trial_status == 2 && zero_first + i != end_slot) {
                trial_status = 0;
            }
        }

        for (int64_t slot = zero_last + 1;
             trial_status == 1 && slot <= end_slot;
             slot++) {
            if (trial_fed >= (size_t)stream_len) {
                trial_status = 0;
                break;
            }
            take = bsz;
            if (take > (size_t)stream_len - trial_fed) {
                take = (size_t)stream_len - trial_fed;
            }
            int64_t app = blockvector_get_apparent_blocknumber(
                candidate->b, (uint64_t)slot);
            const unsigned char *blk =
                (const unsigned char *)get_apparent_block_data(fm, app);
            if (!blk) {
                trial_status = 0;
                break;
            }
            trial_status = pdf_zlib_oracle_feed(&trial, blk, take);
            trial_fed += take;
            if (trial_status == 2) {
                trial_extent_complete = pdf_zlib_extent_complete(
                    &trial, trial_fed, (size_t)stream_len);
            }
            free((void *)blk);
            if (trial_status == 2 && slot != end_slot) {
                trial_status = 0;
            }
        }

        solved = trial_status == 2 && trial_extent_complete;
        inflateEnd(&trial);
    }

    inflateEnd(&prefix);
    bool replaced = solved && pdf_replace_blocks_at_slot(
        candidate, replacement, run_length, (uint64_t)zero_first,
        "ZLIB_ZERO_RUN");
    free(replacement);
    return replaced;
}

// Repair a mapped Flate stream by substituting a physical run at each interior
// position. The first and last blocks remain fixed. The prefix is inflated once
// per position, and a trial is committed only after the full stream checksum and
// declared extent agree. The cursor always names the next untested actual run.
static bool pdf_repair_mapped_zlib_run(CarveInfo *candidate,
                                       int64_t stream_at,
                                       int stream_len,
                                       int64_t start_slot,
                                       int64_t end_slot,
                                       PDFStreamRepairCursor *cursor) {
    const size_t bsz = scalpel_state.blocksize;
    FileMirror *fm = scalpel_state.filemirror;
    if (!candidate || !cursor || bsz == 0 || stream_at < 0 || stream_len <= 0
        || start_slot < 0 || end_slot <= start_slot || end_slot - start_slot <= 1
        || end_slot >= (int64_t)blockvector_get_num_blocks(candidate->b)
        || (uint64_t)stream_at / bsz != (uint64_t)start_slot
        || (uint64_t)stream_at + (uint64_t)stream_len
            > blockvector_get_data_length(candidate->b)
        || ((uint64_t)stream_at + (uint64_t)stream_len - 1) / bsz
            != (uint64_t)end_slot
        || end_slot - start_slot > INT_MAX) {
        return false;
    }
    const int32_t interior = (int32_t)(end_slot - start_slot - 1);
    const int64_t total_actual = (int64_t)CEILDIV(filemirror_filesize(fm), bsz);
    const unsigned char *data =
        (const unsigned char *)blockvector_get_data_pointer(candidate->b);
    const size_t offset = (size_t)((uint64_t)stream_at % bsz);
    const size_t first_length = bsz - offset;
    for (int64_t slot = start_slot; slot <= end_slot; slot++) {
        if (blockvector_get_apparent_blocknumber(candidate->b, (uint64_t)slot) < 0) {
            return false;
        }
    }

    if (!cursor->active) {
        z_stream probe = {0};
        if (inflateInit(&probe) != Z_OK) {
            return false;
        }
        int32_t status = pdf_zlib_oracle_feed(&probe, data + stream_at, first_length);
        size_t supplied = first_length;
        int32_t failed_slot = 0;
        for (int32_t i = 1; status == 1 && i <= interior + 1; i++) {
            if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
                inflateEnd(&probe);
                return false;
            }
            size_t take = (size_t)stream_len - supplied;
            if (take > bsz) {
                take = bsz;
            }
            status = pdf_zlib_oracle_feed(&probe,
                data + ((uint64_t)start_slot + (uint64_t)i) * bsz, take);
            supplied += take;
            if (status != 1) {
                failed_slot = i;
            }
        }
        bool complete = status == 2
            && pdf_zlib_extent_complete(&probe, supplied, (size_t)stream_len);
        inflateEnd(&probe);
        if (status == 1 && supplied == (size_t)stream_len) {
            failed_slot = interior + 1;
        }
        if (complete || failed_slot == 0 || status < 0) {
            return false;
        }
        cursor->active = true;
        cursor->prefix_limit = failed_slot - 1;
        if (cursor->prefix_limit >= interior) {
            cursor->prefix_limit = interior - 1;
        }
        cursor->run_length = 1;
        cursor->prefix_length = cursor->prefix_limit;
        cursor->next_actual = 0;
    }
    if (cursor->run_length < 1 || cursor->run_length > interior
        || cursor->prefix_limit < 0 || cursor->prefix_limit >= interior
        || cursor->prefix_length < 0 || cursor->prefix_length > cursor->prefix_limit
        || cursor->prefix_length > interior - cursor->run_length
        || cursor->next_actual < 0) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    int64_t *replacement = malloc((size_t)interior * sizeof(*replacement));
    check_memory_allocation(replacement, __LINE__, __FILE__, "PDF Flate replacement");
    bool solved = false;
    while (cursor->run_length <= interior && !solved) {
        if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
            break;
        }
        int64_t first = start_slot + cursor->prefix_length + 1;
        int64_t last = first + cursor->run_length - 1;
        if (first <= start_slot || last >= end_slot) {
            handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
        }
        z_stream prefix = {0};
        if (inflateInit(&prefix) != Z_OK) {
            break;
        }
        int32_t status = pdf_zlib_oracle_feed(&prefix, data + stream_at, first_length);
        size_t supplied = first_length;
        for (int32_t i = 1; status == 1 && i <= cursor->prefix_length; i++) {
            if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
                inflateEnd(&prefix);
                free(replacement);
                return false;
            }
            status = pdf_zlib_oracle_feed(&prefix,
                data + ((uint64_t)start_slot + (uint64_t)i) * bsz, bsz);
            supplied += bsz;
        }

        roaring64_bitmap_t *outside = roaring64_bitmap_create();
        check_memory_allocation(outside, __LINE__, __FILE__, "PDF fixed stream blocks");
        for (uint64_t slot = 0; slot < blockvector_get_num_blocks(candidate->b); slot++) {
            if (slot >= (uint64_t)first && slot <= (uint64_t)last) {
                continue;
            }
            int64_t app = blockvector_get_apparent_blocknumber(candidate->b, slot);
            if (app >= 0) {
                roaring64_bitmap_add(outside, (uint64_t)app);
            }
        }

        while (status == 1 && cursor->next_actual <= total_actual - cursor->run_length) {
            if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
                break;
            }
            bool viable = true;
            for (int32_t i = 0; i < cursor->run_length; i++) {
                int64_t actual = cursor->next_actual + i;
                int64_t app = filemirror_apparent_blocknumber(fm, actual);
                if (app < 0 || filemirror_actual_block_covered(fm, actual)
                    || filemirror_actual_block_is_zero(fm, actual)
                    || roaring64_bitmap_contains(outside, (uint64_t)app)) {
                    viable = false;
                    break;
                }
                replacement[i] = actual;
            }
            if (viable) {
                z_stream trial = {0};
                if (inflateCopy(&trial, &prefix) != Z_OK) {
                    roaring64_bitmap_free(outside);
                    inflateEnd(&prefix);
                    free(replacement);
                    return false;
                }
                int32_t trial_status = 1;
                size_t trial_fed = supplied;
                for (int32_t i = 0; i < cursor->run_length && trial_status == 1; i++) {
                    uint64_t available = 0;
                    const unsigned char *block = (const unsigned char *)
                        filemirror_actual_block_data_pointer(fm, replacement[i], &available);
                    if (!block || available < bsz) {
                        trial_status = 0;
                        break;
                    }
                    trial_status = pdf_zlib_oracle_feed(&trial, block, bsz);
                    trial_fed += bsz;
                    if (trial_status == 2) {
                        trial_status = 0;
                    }
                    if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
                        break;
                    }
                }
                bool complete = false;
                for (int64_t slot = last + 1; trial_status == 1 && slot <= end_slot; slot++) {
                    if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
                        break;
                    }
                    size_t take = (size_t)stream_len - trial_fed;
                    if (take > bsz) {
                        take = bsz;
                    }
                    trial_status = pdf_zlib_oracle_feed(&trial, data + (uint64_t)slot * bsz, take);
                    trial_fed += take;
                    complete = slot == end_slot && trial_status == 2
                        && pdf_zlib_extent_complete(&trial, trial_fed, (size_t)stream_len);
                }
                inflateEnd(&trial);
                if (complete && pdf_replace_blocks_at_slot(candidate, replacement,
                        cursor->run_length, (uint64_t)first, "ZLIB_MAPPED_RUN")) {
                    solved = true;
                    break;
                }
                if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
                    break;
                }
            }
            cursor->next_actual++;
        }
        roaring64_bitmap_free(outside);
        inflateEnd(&prefix);
        if (solved || atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
            break;
        }
        cursor->next_actual = 0;
        if (cursor->prefix_length > 0) {
            cursor->prefix_length--;
        } else {
            cursor->run_length++;
            cursor->prefix_length = interior - cursor->run_length;
            if (cursor->prefix_length > cursor->prefix_limit) {
                cursor->prefix_length = cursor->prefix_limit;
            }
        }
    }
    if (solved || cursor->run_length > interior) {
        memset(cursor, 0, sizeof(*cursor));
    }
    free(replacement);
    return solved;
}

// A stream terminator displaced by whole blocks supplies possible gap lengths.
// Remove each such gap on a clone, then test an interior replacement run. The
// original mapping changes only after the stream checksum and full PDF agree.
// gap_extra/gap_slot and the actual-block cursor retain the next trial at a
// checkpoint; temporary mappings never become candidate state.
static bool pdf_repair_gapped_zlib_run(CarveInfo *candidate, int64_t stream_at,
                                      int stream_len, int64_t start_slot,
                                      int64_t end_slot,
                                      PDFInteriorSearchState *search) {
    if (!candidate || !search || stream_at < 0 || stream_len <= 0
        || start_slot < 0 || end_slot <= start_slot
        || scalpel_state.blocksize == 0) {
        return false;
    }
    const uint64_t bsz = scalpel_state.blocksize;
    const uint64_t length = blockvector_get_data_length(candidate->b);
    const uint64_t count = blockvector_get_num_blocks(candidate->b);
    const uint64_t send = (uint64_t)stream_at + (uint64_t)stream_len;
    if (send > length || (uint64_t)end_slot >= count
        || send / bsz < (uint64_t)end_slot) {
        return false;
    }
    const char *data = blockvector_get_data_pointer(candidate->b);
    if (search->gap_extra == 0) {
        // A stream that already passes its checksum needs no gap search, even
        // if later objects happen to end at the same offset within a block.
        z_stream probe = {0};
        if (inflateInit(&probe) != Z_OK) {
            return false;
        }
        size_t supplied = 0;
        int status = 1;
        while (status == 1 && supplied < (size_t)stream_len) {
            if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
                inflateEnd(&probe);
                return false;
            }
            size_t take = (size_t)stream_len - supplied;
            if (take > bsz) {
                take = bsz;
            }
            status = pdf_zlib_oracle_feed(&probe,
                (const unsigned char *)data + stream_at + supplied, take);
            supplied += take;
        }
        bool complete = status == 2
            && pdf_zlib_extent_complete(&probe, supplied, (size_t)stream_len);
        inflateEnd(&probe);
        if (complete || status < 0) {
            return false;
        }
        search->gap_extra = 1;
        search->gap_slot = (uint64_t)start_slot + 1;
        memset(&search->repair, 0, sizeof(search->repair));
    }
    if (search->gap_slot <= (uint64_t)start_slot
        || search->gap_slot > (uint64_t)end_slot) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
    for (; search->gap_extra <= (length - send) / bsz;
         search->gap_extra++, search->gap_slot = (uint64_t)start_slot + 1) {
        if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
            return false;
        }
        uint64_t marker = send + search->gap_extra * bsz;
        if (marker < length && data[marker] == '\r') {
            marker++;
        }
        if (marker < length && data[marker] == '\n') {
            marker++;
        }
        if (length - marker < 9 || memcmp(data + marker, "endstream", 9)) {
            continue;
        }
        for (; search->gap_slot <= (uint64_t)end_slot; search->gap_slot++) {
            if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
                return false;
            }
            BlockVector *trial_bv = NULL;
            clone_blockvector(candidate->b, &trial_bv, false);
            const uint64_t trial_count = count - search->gap_extra;
            for (uint64_t slot = search->gap_slot; slot < trial_count; slot++) {
                blockvector_set_apparent_blocknumber(trial_bv, slot,
                    blockvector_get_apparent_blocknumber(candidate->b,
                        slot + search->gap_extra));
            }
            resize_blockvector(trial_bv, trial_count);
            blockvector_set_data_length(trial_bv, length - search->gap_extra * bsz);
            inflate_blockvector(trial_bv);
            CarveInfo trial = *candidate;
            trial.b = trial_bv;

            bool complete = false;
            z_stream stream = {0};
            if (inflateInit(&stream) == Z_OK) {
                int status = pdf_zlib_oracle_feed(&stream,
                    (const unsigned char *)blockvector_get_data_pointer(trial_bv)
                        + stream_at, (size_t)stream_len);
                complete = status == 2 && pdf_zlib_extent_complete(&stream,
                    (size_t)stream_len, (size_t)stream_len);
                inflateEnd(&stream);
            }
            if (!complete) {
                complete = pdf_repair_mapped_zlib_run(&trial, stream_at,
                    stream_len, start_slot, end_slot, &search->repair);
            }
            if (complete && !atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                                   memory_order_acquire)) {
                bool validates = false;
                bool promising = false;
                uint64_t validates_to = 0;
                pdf_file_validate(blockvector_get_data_pointer(trial_bv),
                    blockvector_get_data_length(trial_bv), &validates,
                    &validates_to, &promising, candidate->needleidx,
                    (uint32_t)bsz, NULL);
                if (validates && validates_to >= send
                    && !pdf_candidate_has_holes_through(&trial, validates_to)) {
                    blockvector_set_data_length(trial_bv, validates_to + 1);
                    free_blockvector(&candidate->b);
                    candidate->b = trial_bv;
                    candidate->fastpath = false;
                    candidate->best_validates_to = validates_to;
                    search->gap_extra = 0;
                    search->gap_slot = 0;
                    memset(&search->repair, 0, sizeof(search->repair));
                    return true;
                }
            }
            free_blockvector(&trial_bv);
            if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
                return false;
            }
            memset(&search->repair, 0, sizeof(search->repair));
        }
    }
    search->gap_extra = 0;
    search->gap_slot = 0;
    memset(&search->repair, 0, sizeof(search->repair));
    return false;
}

// Save only the interior scan state; other repair helpers can independently
// update the candidate's xref evidence or speculative-mapping flag.
static void pdf_store_interior_search(CarveInfo *candidate,
                                      const PDFInteriorSearchState *search) {
    PDFCarveState *state = (PDFCarveState *)carve_get_state(candidate->carvehashkey);
    if (state) {
        state->interior_search = *search;
        carve_put_state(candidate->carvehashkey, state);
        pdf_free_carve_state((void **)&state);
    }
}

static inline uint32_t pdf_icc_lut_value(const unsigned char *profile,
                                         size_t offset,
                                         unsigned int bytes_per_value) {
    if (bytes_per_value == 1) {
        return profile[offset];
    }
    return ((uint32_t)profile[offset] << 8) | profile[offset + 1];
}

/**
 * @description  Repairs one displaced run inside an uncompressed ICC lookup
 *               table. ICC mft1/mft2 tables are sampled on a regular
 *               multidimensional grid, so adjacent entries normally vary
 *               smoothly. Every viable physical run is ranked by total
 *               variation on the grid edges affected by the hole. A run is
 *               accepted only when it is structurally plausible and clearly
 *               separated from the runner-up. ICC v2 has no checksum for this
 *               table, so the candidate is persistently marked speculative and
 *               remains PROMISING even if the completed PDF validates.
 * @param work       Thread context, used for checkpoint responsiveness.
 * @param candidate  Candidate containing the ICC stream.
 * @param stream_at  Absolute logical byte offset of the profile.
 * @param stream_len Declared profile stream length.
 * @param start_slot Slot containing the beginning of the profile.
 * @param end_slot   Slot containing the end of the profile.
 * @return       true if a uniquely ranked run was committed.
 */
static bool pdf_repair_interior_icc_lut(ThreadWork *work,
                                        CarveInfo *candidate,
                                        int64_t stream_at,
                                        int stream_len,
                                        int64_t start_slot,
                                        int64_t end_slot, PDFICCSearch *search) {
    (void)work;
    if (!candidate || !search || stream_at < 0 || stream_len < 132 || start_slot < 0 ||
        end_slot <= start_slot ||
        end_slot >= (int64_t)blockvector_get_num_blocks(candidate->b)) {
        return false;
    }

    FileMirror *fm = scalpel_state.filemirror;
    const uint64_t bsz = scalpel_state.blocksize;
    const uint64_t candidate_length =
        blockvector_get_data_length(candidate->b);
    if ((uint64_t)stream_at > candidate_length ||
        (uint64_t)stream_len > candidate_length - (uint64_t)stream_at) {
        return false;
    }

    int64_t hole_first = -1;
    int64_t hole_last = -1;
    bool hole_closed = false;
    for (int64_t slot = start_slot; slot <= end_slot; slot++) {
        bool hole = blockvector_get_apparent_blocknumber(
                        candidate->b, (uint64_t)slot) < 0;
        if (hole) {
            if (hole_closed) {
                return false;
            }
            if (hole_first < 0) {
                hole_first = slot;
            }
            hole_last = slot;
        } else if (hole_first >= 0) {
            hole_closed = true;
        }
    }
    if (hole_first <= start_slot || hole_last >= end_slot) {
        return false;
    }

    uint64_t stream_start = (uint64_t)stream_at;
    uint64_t stream_end = stream_start + (uint64_t)stream_len;
    uint64_t hole_byte_start = (uint64_t)hole_first * bsz;
    uint64_t hole_byte_end = ((uint64_t)hole_last + 1) * bsz;
    if (hole_byte_start < stream_start || hole_byte_end > stream_end) {
        return false;
    }
    size_t hole_profile_start = (size_t)(hole_byte_start - stream_start);
    size_t hole_profile_end = (size_t)(hole_byte_end - stream_start);

    inflate_blockvector(candidate->b);
    const unsigned char *candidate_data =
        (const unsigned char *)blockvector_get_data_pointer(candidate->b);
    if (!candidate_data) {
        return false;
    }

    unsigned char *profile = malloc((size_t)stream_len);
    check_memory_allocation(profile, __LINE__, __FILE__, "PDF ICC profile");
    memcpy(profile, candidate_data + stream_start, (size_t)stream_len);

    size_t profile_size = read_be(profile, 4, (size_t)stream_len);
    if (profile_size < 132 || profile_size > (size_t)stream_len ||
        memcmp(profile + 36, "acsp", 4)) {
        free(profile);
        return false;
    }

    uint32_t tag_count = read_be(profile + 128, 4, profile_size - 128);
    if (tag_count == 0 || tag_count > (profile_size - 132) / 12) {
        free(profile);
        return false;
    }

    size_t clut_offset = 0;
    size_t clut_end = 0;
    uint64_t node_count = 0;
    unsigned int input_channels = 0;
    unsigned int output_channels = 0;
    unsigned int grid_points = 0;
    unsigned int bytes_per_value = 0;
    bool layout_found = false;

    for (uint32_t tag = 0; tag < tag_count; tag++) {
        size_t entry = 132 + (size_t)tag * 12;
        size_t tag_offset = read_be(profile + entry + 4, 4,
                                    profile_size - entry - 4);
        size_t tag_size = read_be(profile + entry + 8, 4,
                                  profile_size - entry - 8);
        if (tag_offset > profile_size || tag_size > profile_size - tag_offset ||
            tag_size < 48) {
            continue;
        }

        const unsigned char *lut = profile + tag_offset;
        bool mft1 = !memcmp(lut, "mft1", 4);
        bool mft2 = !memcmp(lut, "mft2", 4);
        if (!mft1 && !mft2) {
            continue;
        }

        unsigned int in_ch = lut[8];
        unsigned int out_ch = lut[9];
        unsigned int grid = lut[10];
        unsigned int value_bytes = mft2 ? 2U : 1U;
        size_t header_size = mft2 ? 52U : 48U;
        if (in_ch == 0 || in_ch > 15 || out_ch == 0 || out_ch > 15 ||
            grid < 2 || header_size > tag_size) {
            continue;
        }

        unsigned int input_entries = 256;
        unsigned int output_entries = 256;
        if (mft2) {
            input_entries = read_be(lut + 48, 2, tag_size - 48);
            output_entries = read_be(lut + 50, 2, tag_size - 50);
            if (input_entries < 2 || output_entries < 2) {
                continue;
            }
        }

        uint64_t nodes = 1;
        bool overflow = false;
        for (unsigned int channel = 0; channel < in_ch; channel++) {
            if (nodes > UINT64_MAX / grid) {
                overflow = true;
                break;
            }
            nodes *= grid;
        }
        if (overflow || nodes > SIZE_MAX / out_ch ||
            nodes * out_ch > SIZE_MAX / value_bytes) {
            continue;
        }

        uint64_t input_table_bytes =
            (uint64_t)in_ch * input_entries * value_bytes;
        uint64_t clut_bytes = nodes * out_ch * value_bytes;
        uint64_t output_table_bytes =
            (uint64_t)out_ch * output_entries * value_bytes;
        uint64_t local_clut = (uint64_t)header_size + input_table_bytes;
        uint64_t local_end = local_clut + clut_bytes;
        if (local_clut > tag_size || local_end > tag_size ||
            output_table_bytes > tag_size - local_end) {
            continue;
        }

        size_t absolute_clut = tag_offset + (size_t)local_clut;
        size_t absolute_end = tag_offset + (size_t)local_end;
        if (hole_profile_start < absolute_clut ||
            hole_profile_end > absolute_end) {
            continue;
        }

        if (layout_found &&
            (clut_offset != absolute_clut || clut_end != absolute_end ||
             node_count != nodes || input_channels != in_ch ||
             output_channels != out_ch || grid_points != grid ||
             bytes_per_value != value_bytes)) {
            free(profile);
            return false;
        }

        layout_found = true;
        clut_offset = absolute_clut;
        clut_end = absolute_end;
        node_count = nodes;
        input_channels = in_ch;
        output_channels = out_ch;
        grid_points = grid;
        bytes_per_value = value_bytes;
    }

    if (!layout_found) {
        free(profile);
        return false;
    }

    uint64_t known_score = 0;
    uint64_t known_edges = 0;
    uint64_t affected_edges = 0;
    uint64_t stride = 1;
    for (unsigned int dimension = 0;
         dimension < input_channels;
         dimension++) {
        for (uint64_t node = 0; node < node_count; node++) {
            if (((node / stride) % grid_points) + 1 >= grid_points) {
                continue;
            }
            uint64_t neighbor = node + stride;
            for (unsigned int channel = 0;
                 channel < output_channels;
                 channel++) {
                size_t left = clut_offset +
                    (size_t)(node * output_channels + channel) *
                    bytes_per_value;
                size_t right = clut_offset +
                    (size_t)(neighbor * output_channels + channel) *
                    bytes_per_value;
                bool left_affected =
                    left < hole_profile_end &&
                    left + bytes_per_value > hole_profile_start;
                bool right_affected =
                    right < hole_profile_end &&
                    right + bytes_per_value > hole_profile_start;
                if (left_affected || right_affected) {
                    affected_edges++;
                    continue;
                }

                uint32_t a = pdf_icc_lut_value(profile, left,
                                               bytes_per_value);
                uint32_t b = pdf_icc_lut_value(profile, right,
                                               bytes_per_value);
                known_score += a > b ? a - b : b - a;
                known_edges++;
            }
        }
        stride *= grid_points;
    }

    if (known_edges < 16 || affected_edges < 16) {
        free(profile);
        return false;
    }

    roaring64_bitmap_t *outside_apps = roaring64_bitmap_create();
    if (!outside_apps) {
        free(profile);
        return false;
    }
    uint64_t candidate_blocks = blockvector_get_num_blocks(candidate->b);
    for (uint64_t slot = 0; slot < candidate_blocks; slot++) {
        if (slot >= (uint64_t)hole_first && slot <= (uint64_t)hole_last) {
            continue;
        }
        int64_t app = blockvector_get_apparent_blocknumber(candidate->b, slot);
        if (app >= 0) {
            roaring64_bitmap_add(outside_apps, (uint64_t)app);
        }
    }

    int run_length = (int)(hole_last - hole_first + 1);
    int64_t total_actual =
        (int64_t)CEILDIV(filemirror_filesize(fm), bsz);
    int64_t *replacement = malloc((size_t)run_length * sizeof(*replacement));
    int64_t *best_replacement =
        malloc((size_t)run_length * sizeof(*best_replacement));
    check_memory_allocation(replacement, __LINE__, __FILE__,
                            "PDF ICC trial run");
    check_memory_allocation(best_replacement, __LINE__, __FILE__,
                            "PDF ICC best run");

    const uint64_t signature = pdf_interior_signature(candidate, stream_at, stream_len);
    bool retained_available = search->active && search->signature == signature;
    const int64_t retained[] = {search->best_actual, search->second_actual};
    for (size_t rank = 0; retained_available && rank < 2; rank++) {
        if (retained[rank] < 0) {
            continue;
        }
        if (retained[rank] > total_actual - run_length) {
            retained_available = false;
            break;
        }
        for (int i = 0; i < run_length; i++) {
            int64_t actual = retained[rank] + i;
            int64_t app = filemirror_apparent_blocknumber(fm, actual);
            if (app < 0 || filemirror_actual_block_covered(fm, actual)
                || filemirror_actual_block_is_zero(fm, actual)
                || roaring64_bitmap_contains(outside_apps, (uint64_t)app)) {
                retained_available = false;
                break;
            }
        }
    }
    if (!retained_available) {
        *search = (PDFICCSearch){.active = 1, .signature = signature,
            .best_score = UINT64_MAX, .second_score = UINT64_MAX,
            .best_actual = -1, .second_actual = -1};
    }
    uint64_t best_score = search->best_score;
    uint64_t second_score = search->second_score;
    uint64_t viable_runs = search->viable_runs;
    if (search->best_actual >= 0) {
        for (int i = 0; i < run_length; i++) {
            best_replacement[i] = search->best_actual + i;
        }
    }
    uint64_t probes = 0;
    bool interrupted = false;

    for (int64_t run_start = search->next_actual;
         run_start <= total_actual - run_length;
         run_start++) {
        if (((++probes & 0xffU) == 0U) &&
            atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                 memory_order_acquire)) {
            interrupted = true;
            break;
        }
        search->next_actual = run_start + 1;

        bool viable = true;
        for (int i = 0; i < run_length; i++) {
            int64_t actual = run_start + i;
            int64_t app = filemirror_apparent_blocknumber(fm, actual);
            if (app < 0 || filemirror_actual_block_covered(fm, actual) ||
                filemirror_actual_block_is_zero(fm, actual) ||
                roaring64_bitmap_contains(outside_apps, (uint64_t)app)) {
                viable = false;
                break;
            }
            replacement[i] = actual;
        }
        if (!viable) {
            continue;
        }

        for (int i = 0; i < run_length; i++) {
            uint64_t block_length = 0;
            const unsigned char *block =
                (const unsigned char *)filemirror_actual_block_data_pointer(
                    fm, replacement[i], &block_length);
            uint64_t logical_start = ((uint64_t)hole_first + (uint64_t)i) * bsz;
            uint64_t copy_start = logical_start > stream_start
                                      ? logical_start : stream_start;
            uint64_t logical_end = logical_start + bsz;
            uint64_t copy_end = logical_end < stream_end
                                    ? logical_end : stream_end;
            size_t source_offset = (size_t)(copy_start - logical_start);
            size_t copy_length = (size_t)(copy_end - copy_start);
            if (!block || source_offset > block_length ||
                copy_length > block_length - source_offset) {
                viable = false;
                break;
            }
            memcpy(profile + (copy_start - stream_start),
                   block + source_offset, copy_length);
        }
        if (!viable) {
            continue;
        }
        viable_runs++;

        uint64_t score = 0;
        bool pruned = false;
        stride = 1;
        for (unsigned int dimension = 0;
             dimension < input_channels && !pruned;
             dimension++) {
            for (uint64_t node = 0; node < node_count && !pruned; node++) {
                if (((node / stride) % grid_points) + 1 >= grid_points) {
                    continue;
                }
                uint64_t neighbor = node + stride;
                for (unsigned int channel = 0;
                     channel < output_channels;
                     channel++) {
                    size_t left = clut_offset +
                        (size_t)(node * output_channels + channel) *
                        bytes_per_value;
                    size_t right = clut_offset +
                        (size_t)(neighbor * output_channels + channel) *
                        bytes_per_value;
                    bool affected =
                        (left < hole_profile_end &&
                         left + bytes_per_value > hole_profile_start) ||
                        (right < hole_profile_end &&
                         right + bytes_per_value > hole_profile_start);
                    if (!affected) {
                        continue;
                    }

                    uint32_t a = pdf_icc_lut_value(profile, left,
                                                   bytes_per_value);
                    uint32_t b = pdf_icc_lut_value(profile, right,
                                                   bytes_per_value);
                    score += a > b ? a - b : b - a;
                    if (second_score != UINT64_MAX &&
                        score >= second_score) {
                        pruned = true;
                        break;
                    }
                }
            }
            stride *= grid_points;
        }
        if (pruned) {
            continue;
        }

        if (score < best_score) {
            search->second_actual = search->best_actual;
            search->best_actual = run_start;
            second_score = best_score;
            best_score = score;
            memcpy(best_replacement, replacement,
                   (size_t)run_length * sizeof(*best_replacement));
        } else if (score < second_score) {
            second_score = score;
            search->second_actual = run_start;
        }
    }
    search->best_score = best_score;
    search->second_score = second_score;
    search->viable_runs = viable_runs;

    bool accepted = !interrupted && viable_runs >= 2 &&
                    best_score != UINT64_MAX &&
                    second_score != UINT64_MAX;
    if (accepted) {
        long double known_mean =
            (long double)known_score / (long double)known_edges;
        long double best_mean =
            (long double)best_score / (long double)affected_edges;
        long double second_mean =
            (long double)second_score / (long double)affected_edges;
        accepted = (known_mean == 0.0L ? best_mean == 0.0L
                                      : best_mean <= known_mean * 4.0L) &&
                   second_mean >= best_mean * 1.25L &&
                   (best_mean != 0.0L || second_mean > 0.0L);
    }

    bool replaced = accepted && pdf_replace_blocks_at_slot(
        candidate, best_replacement, run_length, (uint64_t)hole_first,
        "ICC_LUT_RUN");
    if (replaced) {
        PDFCarveState *state =
            (PDFCarveState *)carve_get_state(candidate->carvehashkey);
        if (state) {
            state->speculative_blocks = true;
            carve_put_state(candidate->carvehashkey, state);
            pdf_free_carve_state((void **)&state);
        }
    }

    if (!interrupted) {
        memset(search, 0, sizeof(*search));
    }
    free(best_replacement);
    free(replacement);
    roaring64_bitmap_free(outside_apps);
    free(profile);
    return replaced;
}

/**
 * @description  Fills interior stream-body holes left after xref adoption. Positional
 *               xref placement lands object-HEADER blocks at their true slots but
 *               never reconstructs the streams BETWEEN them, so a linearized/gapped
 *               file can finish with correct headers and holed stream interiors. For
 *               each FlateDecode or DCTDecode stream whose interior is holed,
 *               this verifies a complete assignment with the format-specific
 *               stream oracle before placing any blocks. Uncompressed ICC LUTs
 *               may also be reconstructed from their grid structure, but are
 *               retained as PROMISING because that evidence is not a checksum.
 * @param work       The thread work context (unused).
 * @param candidate  The candidate whose interior stream holes are filled.
 * @return       true if any hole was filled.
 */
static bool pdf_fill_interior_stream_holes(ThreadWork *work, CarveInfo *candidate){
    FileMirror *fm = scalpel_state.filemirror;
    const int64_t bsz = (int64_t)scalpel_state.blocksize;
    const int64_t total_actual =
        (int64_t)CEILDIV(filemirror_filesize(fm), scalpel_state.blocksize);
    bool any = false;

    PDFCarveState *cs = (PDFCarveState*)carve_get_state(candidate->carvehashkey);
    if(!cs) return false;
    PDFInteriorSearchState *search = &cs->interior_search;
    if (!search->active) {
        memset(search, 0, sizeof(*search));
        search->active = true;
    }
    roaring64_bitmap_t *processed_streams = roaring64_bitmap_create();
    if (!processed_streams) {
        pdf_free_carve_state((void **)&cs);
        return false;
    }

    char *data = blockvector_get_data_pointer(candidate->b);
    int64_t length = (int64_t)blockvector_get_data_length(candidate->b);

    for(int t = (int)search->table; t < (int)cs->num_tables; t++, search->entry = 0){
        search->table = (size_t)t;
        XrefTables *tab = &cs->xref_tables[t];
        if(!tab->entries) continue;
        for(int e = search->entry; e < tab->count; e++){
            search->entry = e;
            if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
                goto interrupted;
            }
            // A prior repair may have re-inflated and relocated the blockvector
            // even when its structural oracle ultimately rejected the repair.
            data = blockvector_get_data_pointer(candidate->b);
            length = (int64_t)blockvector_get_data_length(candidate->b);
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
            int filter = check_last_object_filter(data + obj_off, dict_len);
            if (filter != ZLIB && filter != JPEG && filter != NOFILTER) {
                continue;
            }

            uint64_t out_off = 0;
            int slen = check_last_object_length(data, (uint64_t)length, &out_off,
                          cs->xref_tables, (int)cs->num_tables, data + obj_off,
                          dict_len, (uint64_t)obj_off, true);
            if(slen == LENGTHNOTFOUND || slen <= 0) continue;

            int64_t sdat = (sk - data) + 6;
            if(sdat < length && data[sdat] == '\r') sdat++;
            if(sdat < length && data[sdat] == '\n') sdat++;
            if (roaring64_bitmap_contains(processed_streams,
                                          (uint64_t)sdat)) {
                continue;
            }
            roaring64_bitmap_add(processed_streams, (uint64_t)sdat);
            int64_t send = sdat + slen;
            int64_t sslot = sdat / bsz, eslot = (send - 1) / bsz;
            int span = (int)(eslot - sslot);                                   // blocks after the start block
            if(span <= 0 || span > 4096) continue;                            // single-block or implausibly large
            if(eslot >= (int64_t)blockvector_get_num_blocks(candidate->b)) continue;
            if (blockvector_get_apparent_blocknumber(candidate->b, (uint64_t)sslot) < 0) {
                continue;
            }

            bool has_hole = false;
            for (int64_t s = sslot + 1; s <= eslot && !has_hole; s++) {
                if (blockvector_get_apparent_blocknumber(candidate->b, s) < 0) {
                    has_hole = true;
                }
            }

            if (filter == NOFILTER) {
                if (has_hole && pdf_repair_interior_icc_lut(
                        work, candidate, sdat, slen, sslot, eslot, &search->icc)) {
                    any = true;
                    data = blockvector_get_data_pointer(candidate->b);
                    length = (int64_t)blockvector_get_data_length(candidate->b);
                }
                if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
                    goto interrupted;
                }
                memset(&search->icc, 0, sizeof(search->icc));
                continue;
            }

            if (filter == JPEG) {
                if (pdf_repair_interior_jpeg_backbone(
                        work, candidate, sdat, slen, sslot, eslot, true, &search->jpeg)) {
                    any = true;
                    data = blockvector_get_data_pointer(candidate->b);
                    length = (int64_t)blockvector_get_data_length(candidate->b);
                }
                if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
                    goto interrupted;
                }
                memset(&search->jpeg, 0, sizeof(search->jpeg));
                continue;
            }

            if(!has_hole){
                bool repaired = false;
                if (search->gap_extra == 0 && !search->repair.active) {
                    repaired = pdf_repair_interior_zlib_zero_run(
                        work, candidate, sdat, slen, sslot, eslot, &search->zero);
                }
                if (!repaired && search->gap_extra == 0 &&
                    !atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
                    repaired = pdf_repair_mapped_zlib_run(
                        candidate, sdat, slen, sslot, eslot, &search->repair);
                }
                if (!repaired &&
                    !atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
                    repaired = pdf_repair_gapped_zlib_run(
                        candidate, sdat, slen, sslot, eslot, search);
                }
                if(repaired){
                    any = true;
                    data = blockvector_get_data_pointer(candidate->b);
                    length = (int64_t)blockvector_get_data_length(candidate->b);
                }
                if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
                    goto interrupted;
                }
                memset(&search->repair, 0, sizeof(search->repair));
                continue;
            }

            bool backbone_repaired = pdf_repair_interior_zlib_backbone(
                work, candidate, sdat, slen, sslot, eslot, true, &search->zlib);
            if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
                goto interrupted;
            }
            data = blockvector_get_data_pointer(candidate->b);
            length = (int64_t)blockvector_get_data_length(candidate->b);
            if (backbone_repaired) {
                any = true;
                continue;
            }

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

            /*
             * If a physical gap splits the stream, the start-contiguous run
             * above is wrong after the split. Derive the stream's last actual
             * block from the nearest already placed block to its right, then
             * try every exact two-run split. Nothing is placed until the whole
             * declared stream reaches Z_STREAM_END and verifies its Adler-32.
             */
            int64_t *split_actual = NULL;
            if (!(ok && complete)) {
                int64_t end_actual = -1;
                int64_t end_app = blockvector_get_apparent_blocknumber(
                    candidate->b, (uint64_t)eslot);
                if (end_app >= 0) {
                    end_actual = filemirror_actual_blocknumber(fm, end_app);
                } else {
                    uint64_t candidate_blocks =
                        blockvector_get_num_blocks(candidate->b);
                    for (uint64_t right_slot = (uint64_t)eslot + 1;
                         right_slot < candidate_blocks;
                         right_slot++) {
                        int64_t right_app = blockvector_get_apparent_blocknumber(
                            candidate->b, right_slot);
                        if (right_app < 0) {
                            continue;
                        }
                        int64_t right_actual =
                            filemirror_actual_blocknumber(fm, right_app);
                        uint64_t distance = right_slot - (uint64_t)eslot;
                        if ((uint64_t)right_actual >= distance) {
                            end_actual = right_actual - (int64_t)distance;
                        }
                        break;
                    }
                }

                if (end_actual >= 0 && end_actual < total_actual) {
                    split_actual = malloc((size_t)span * sizeof(*split_actual));
                    check_memory_allocation(split_actual, __LINE__, __FILE__,
                                            "PDF interior zlib split");

                    uint64_t probes = 0;
                    bool interrupted = false;
                    const uint64_t geometry[] = {(uint64_t)D0, (uint64_t)end_actual,
                        (uint64_t)span};
                    const uint64_t signature = XXH64(geometry, sizeof(geometry),
                        pdf_interior_signature(candidate, sdat, slen));
                    if (!search->split.active || search->split.signature != signature) {
                        search->split = (PDFInteriorSplitSearch){.active = 1,
                            .signature = signature, .next_split = span};
                    }
                    for (int split = search->split.next_split;
                         split >= 0 && !complete; split--) {
                        if (((++probes & 0x0fU) == 0U) &&
                            atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                                 memory_order_acquire)) {
                            interrupted = true;
                            break;
                        }

                        ZlibStreamReassembler sr;
                        if (zlib_stream_reassembler_init(
                                &sr,
                                (const unsigned char *)(data + sslot * bsz),
                                (size_t)bsz,
                                (size_t)(sdat - sslot * bsz),
                                (size_t)slen) == -1) {
                            break;
                        }
                        search->split.next_split = split - 1;

                        bool split_ok = true;
                        for (int k = 1; k <= span && split_ok; k++) {
                            int64_t slot_app =
                                blockvector_get_apparent_blocknumber(
                                    candidate->b, (uint64_t)(sslot + k));
                            int64_t actual;
                            if (slot_app >= 0) {
                                actual = filemirror_actual_blocknumber(fm,
                                                                      slot_app);
                            } else if (k <= split) {
                                actual = D0 + k;
                            } else {
                                actual = end_actual - (span - k);
                            }

                            if (actual < 0 || actual >= total_actual) {
                                split_ok = false;
                                break;
                            }

                            int64_t app =
                                filemirror_apparent_blocknumber(fm, actual);
                            if (app < 0) {
                                split_ok = false;
                                break;
                            }

                            if (slot_app < 0) {
                                if (filemirror_actual_block_covered(fm, actual) ||
                                    filemirror_actual_block_is_zero(fm, actual) ||
                                    apparent_block_in_blockvector(candidate->b,
                                                                 app)) {
                                    split_ok = false;
                                    break;
                                }
                                for (int prior = 0; prior < k - 1; prior++) {
                                    if (split_actual[prior] == actual) {
                                        split_ok = false;
                                        break;
                                    }
                                }
                                if (!split_ok) {
                                    break;
                                }
                            }
                            split_actual[k - 1] = actual;

                            const unsigned char *blk =
                                (const unsigned char *)get_apparent_block_data(
                                    fm, app);
                            if (!blk) {
                                split_ok = false;
                                break;
                            }
                            int chk = zlib_stream_reassembler_try_block(
                                &sr, blk, (size_t)bsz);
                            free((void *)blk);
                            split_ok = (k == span) ? (chk == 2) : (chk == 1);
                        }

                        complete = split_ok && sr.ended;
                        if (complete) {
                            kdone = span;
                        }
                        zlib_stream_reassembler_free(&sr);
                    }

                    if (interrupted) {
                        free(split_actual);
                        goto interrupted;
                    }
                }
            }

            if (!(ok && complete) && !split_actual) {
                continue;
            }
            if (!complete) {
                free(split_actual);
                continue;
            }

            for(int k = 1; k <= kdone; k++){
                if(blockvector_get_apparent_blocknumber(candidate->b, sslot + k) >= 0) continue; // already placed
                int64_t hb = split_actual ? split_actual[k - 1] : D0 + k;
                if(pdf_place_blocks_at_slot(candidate, &hb, 1, (uint64_t)(sslot + k), "ZLIB_HOLE_FILL")){
                    any = true;
                    data = blockvector_get_data_pointer(candidate->b);
                    length = (int64_t)blockvector_get_data_length(candidate->b);
                }
            }
            free(split_actual);
            if(pdf_repair_interior_zlib_zero_run(work, candidate, sdat, slen,
                                                 sslot, eslot, &search->zero)){
                any = true;
                data = blockvector_get_data_pointer(candidate->b);
                length = (int64_t)blockvector_get_data_length(candidate->b);
            }
            if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
                goto interrupted;
            }
        }
    }
    memset(search, 0, sizeof(*search));
interrupted:
    pdf_store_interior_search(candidate, search);
    roaring64_bitmap_free(processed_streams);
    pdf_free_carve_state((void**)&cs);
    return any;
}

/**
 * @description  Completes a candidate whose remaining holes are bracketed by
 *               correctly placed blocks that preserve both logical and physical
 *               distance. All inferred blocks are staged in a cloned blockvector;
 *               the original candidate is changed only if the completed clone
 *               passes full PDF validation, including any adjacent trailer
 *               continuation. This handles ordinary contiguous
 *               regions between xref-anchored objects without allowing a failed
 *               contiguity hypothesis to poison later recovery.
 * @param work       Reassembly worker passed to trailer completion.
 * @param candidate  The candidate whose bracketed holes are considered.
 * @return       true if every remaining hole was verified and filled.
 */
static bool pdf_fill_physically_bridged_holes(ThreadWork *work,
                                               CarveInfo *candidate) {
    if (!candidate || !pdf_candidate_has_holes(candidate)) {
        return false;
    }

    FileMirror *fm = scalpel_state.filemirror;
    uint64_t nblocks = blockvector_get_num_blocks(candidate->b);
    int64_t total_actual =
        (int64_t)CEILDIV(filemirror_filesize(fm), scalpel_state.blocksize);
    uint64_t *slots = malloc(nblocks * sizeof(*slots));
    int64_t *actuals = malloc(nblocks * sizeof(*actuals));
    check_memory_allocation(slots, __LINE__, __FILE__,
                            "PDF bridged-hole slots");
    check_memory_allocation(actuals, __LINE__, __FILE__,
                            "PDF bridged-hole blocks");

    size_t count = 0;
    bool all_bridged = true;
    uint64_t slot = 0;
    while (slot < nblocks) {
        if (blockvector_get_apparent_blocknumber(candidate->b, slot) >= 0) {
            slot++;
            continue;
        }

        uint64_t first_hole = slot;
        while (slot < nblocks &&
               blockvector_get_apparent_blocknumber(candidate->b, slot) < 0) {
            slot++;
        }
        uint64_t after_hole = slot;
        if (first_hole == 0 || after_hole >= nblocks) {
            all_bridged = false;
            break;
        }

        int64_t left_app = blockvector_get_apparent_blocknumber(
            candidate->b, first_hole - 1);
        int64_t right_app = blockvector_get_apparent_blocknumber(
            candidate->b, after_hole);
        int64_t left_actual = filemirror_actual_blocknumber(fm, left_app);
        int64_t right_actual = filemirror_actual_blocknumber(fm, right_app);
        uint64_t logical_distance = after_hole - (first_hole - 1);
        if (right_actual <= left_actual ||
            (uint64_t)(right_actual - left_actual) != logical_distance) {
            all_bridged = false;
            break;
        }

        for (uint64_t fill_slot = first_hole;
             fill_slot < after_hole;
             fill_slot++) {
            int64_t actual = left_actual +
                (int64_t)(fill_slot - (first_hole - 1));
            if (actual < 0 || actual >= total_actual ||
                filemirror_actual_block_covered(fm, actual) ||
                filemirror_actual_block_is_zero(fm, actual)) {
                all_bridged = false;
                break;
            }
            int64_t app = filemirror_apparent_blocknumber(fm, actual);
            if (app < 0 ||
                apparent_block_in_blockvector(candidate->b, app)) {
                all_bridged = false;
                break;
            }
            for (size_t prior = 0; prior < count; prior++) {
                if (actuals[prior] == actual) {
                    all_bridged = false;
                    break;
                }
            }
            if (!all_bridged) {
                break;
            }
            slots[count] = fill_slot;
            actuals[count] = actual;
            count++;
        }
        if (!all_bridged) {
            break;
        }
    }

    bool verified = false;
    if (all_bridged && count > 0) {
        BlockVector *trial_bv = NULL;
        clone_blockvector(candidate->b, &trial_bv, false);
        CarveInfo trial = *candidate;
        trial.b = trial_bv;

        bool placed = true;
        for (size_t i = 0; i < count && placed; i++) {
            placed = pdf_place_blocks_at_slot(&trial, &actuals[i], 1,
                                              slots[i], "BRIDGE_TRIAL");
        }

        if (placed && !pdf_candidate_has_holes(&trial)) {
            pdf_complete_trailer(work, &trial);
            bool validates = false;
            bool promising = true;
            uint64_t validates_to = scalpel_state.blocksize - 1;
            uint64_t trial_length = blockvector_get_data_length(trial.b);
            bool previous_syntax_requirement = pdf_require_object_syntax;
            pdf_require_object_syntax = true;
            pdf_file_validate(blockvector_get_data_pointer(trial.b),
                              trial_length,
                              &validates, &validates_to, &promising,
                              trial.needleidx, scalpel_state.blocksize,
                              trial.carvehashkey);
            pdf_require_object_syntax = previous_syntax_requirement;
            // An earlier revision cannot establish the newly filled tail.
            verified = validates && validates_to < trial_length &&
                validates_to / scalpel_state.blocksize ==
                    blockvector_get_num_blocks(trial.b) - 1;
            if (verified) {
                uint64_t trial_blocks = blockvector_get_num_blocks(trial.b);
                resize_blockvector(candidate->b, trial_blocks);
                for (size_t i = 0; i < count; i++) {
                    blockvector_set_apparent_blocknumber(
                        candidate->b, slots[i],
                        blockvector_get_apparent_blocknumber(trial.b, slots[i]));
                }
                for (uint64_t tail = nblocks; tail < trial_blocks; tail++) {
                    blockvector_set_apparent_blocknumber(
                        candidate->b, tail,
                        blockvector_get_apparent_blocknumber(trial.b, tail));
                }
                // Keep later incremental revisions visible to final validation.
                blockvector_set_data_length(candidate->b, trial_length);
                inflate_blockvector(candidate->b);
                candidate->best_validates_to = validates_to;
                candidate->fastpath = false;
            }
        }
        free_blockvector(&trial_bv);
    }

    free(actuals);
    free(slots);
    return verified;
}

static int pdf_compare_slot_delta(const void *a, const void *b) {
    const PDFSlotDelta *left = (const PDFSlotDelta *)a;
    const PDFSlotDelta *right = (const PDFSlotDelta *)b;
    if (left->delta < right->delta) {
        return -1;
    }
    if (left->delta > right->delta) {
        return 1;
    }
    if (left->slot < right->slot) {
        return -1;
    }
    if (left->slot > right->slot) {
        return 1;
    }
    return 0;
}

// Group adjacent observations with equal displacement. In logical-slot order,
// the same displacement on both sides of a displaced run forms distinct groups.
// The output array has room for count entries; missing slots are not observations.
static size_t pdf_group_slot_runs(const PDFSlotDelta *observations, size_t count,
                                  PDFRunEvidence *groups) {
    size_t group_count = 0;
    for (size_t first = 0; first < count;) {
        size_t end = first + 1;
        while (end < count && observations[end].delta == observations[first].delta) {
            end++;
        }
        groups[group_count].delta = observations[first].delta;
        groups[group_count].min_slot = observations[first].slot;
        groups[group_count].max_slot = observations[end - 1].slot;
        groups[group_count].count = end - first;
        group_count++;
        first = end;
    }
    return group_count;
}

static int pdf_compare_run_evidence(const void *a, const void *b) {
    const PDFRunEvidence *left = (const PDFRunEvidence *)a;
    const PDFRunEvidence *right = (const PDFRunEvidence *)b;
    if (left->min_slot < right->min_slot) {
        return -1;
    }
    if (left->min_slot > right->min_slot) {
        return 1;
    }
    if (left->count > right->count) {
        return -1;
    }
    if (left->count < right->count) {
        return 1;
    }
    return 0;
}

// A saved layout may become unavailable when another recovery consumes blocks.
static bool pdf_physical_solution_available(CarveInfo *candidate,
                                             const PDFPhysicalRunSearch *search) {
    if (!search->valid_layouts) {
        return true;
    }
    FileMirror *fm = scalpel_state.filemirror;
    uint64_t slots = CEILDIV(search->solution_length, scalpel_state.blocksize);
    uint64_t image_blocks = CEILDIV(filemirror_filesize(fm), scalpel_state.blocksize);
    int64_t last = search->solution_actuals[search->total_slots - 1];
    if (last < 0) {
        return false;
    }
    for (uint64_t slot = 0; slot < slots; slot++) {
        uint64_t extra = slot < search->total_slots ? 0 : slot - search->total_slots + 1;
        if (extra > (uint64_t)(INT64_MAX - last)) {
            return false;
        }
        int64_t actual = slot < search->total_slots ? search->solution_actuals[slot]
            : last + (int64_t)extra;
        if (actual < 0 || (uint64_t)actual >= image_blocks) {
            return false;
        }
        int64_t apparent = filemirror_apparent_blocknumber(fm, actual);
        if (apparent < 0 || filemirror_actual_block_is_zero(fm, actual)
            || (filemirror_actual_block_covered(fm, actual)
                && !apparent_block_in_blockvector(candidate->b, apparent))) {
            return false;
        }
    }
    return true;
}

// Preserve only this helper's state; validation may have updated other fields.
static void pdf_store_physical_search(CarveInfo *candidate, bool logical_groups,
                                       const PDFPhysicalRunSearch *search) {
    PDFCarveState *state = carve_get_state(candidate->carvehashkey);
    if (state) {
        PDFPhysicalRunSearch *saved = &state->physical_search[logical_groups ? 1 : 0];
        pdf_physical_search_clear(saved);
        pdf_physical_search_copy(saved, search);
        carve_put_state(candidate->carvehashkey, state);
        pdf_free_carve_state((void **)&state);
    }
}

/**
 * @description  Completes a linearized PDF assembled from multiple physically
 *               contiguous runs. Xref-positioned objects provide mappings of
 *               logical slots to actual blocks; mappings from one physical run
 *               share the same actual-minus-logical displacement. The /L value
 *               supplies the baseline revision length. This routine retains runs
 *               with at least three agreeing mappings, enumerates only the
 *               unresolved boundaries between those runs, and tests every layout
 *               on a private blockvector. If a later incremental revision follows
 *               physically, its discovered EOF is also tested and the farthest
 *               fully validated revision is retained. The original candidate is
 *               changed only after the selected PDF validates through its end.
 * @param work       Reassembly worker, used for checkpoint responsiveness.
 * @param candidate  Candidate to repair.
 * @param logical_groups  Keep observations in logical order rather than grouping
 *                        all observations with the same displacement together.
 * @return       true if a complete verified layout was committed.
 */
static bool pdf_try_linearized_physical_runs(ThreadWork *work,
                                            CarveInfo *candidate,
                                            bool logical_groups) {
    (void)work;
    if (!candidate || !candidate->b) {
        return false;
    }

    PDFCarveState *state =
        (PDFCarveState *)carve_get_state(candidate->carvehashkey);
    if (!state || !state->linearized || state->lin_L <= 0) {
        pdf_free_carve_state((void **)&state);
        return false;
    }

    const uint64_t blocksize = (uint64_t)scalpel_state.blocksize;
    const uint64_t exact_length = (uint64_t)state->lin_L;
    const uint64_t total_slots = CEILDIV(exact_length, blocksize);
    const int64_t image_blocks =
        (int64_t)CEILDIV(filemirror_filesize(scalpel_state.filemirror),
                         scalpel_state.blocksize);
    pdf_free_carve_state((void **)&state);

    if (total_slots < 2 || total_slots > (uint64_t)image_blocks) {
        return false;
    }

    uint64_t current_slots = blockvector_get_num_blocks(candidate->b);
    PDFSlotDelta *observations =
        malloc(current_slots * sizeof(*observations));
    check_memory_allocation(observations, __LINE__, __FILE__,
                            "PDF physical-run observations");

    size_t observation_count = 0;
    for (uint64_t slot = 0; slot < current_slots && slot < total_slots; slot++) {
        int64_t actual =
            blockvector_get_actual_blocknumber(candidate->b, slot);
        if (actual < 0) {
            continue;
        }
        observations[observation_count].delta = actual - (int64_t)slot;
        observations[observation_count].slot = slot;
        observation_count++;
    }
    if (observation_count < 6) {
        free(observations);
        return false;
    }

    if (!logical_groups) {
        qsort(observations, observation_count, sizeof(*observations), pdf_compare_slot_delta);
    }

    PDFRunEvidence *groups =
        malloc(observation_count * sizeof(*groups));
    PDFRunEvidence *eligible =
        malloc(observation_count * sizeof(*eligible));
    PDFRunEvidence *chain =
        malloc(observation_count * sizeof(*chain));
    check_memory_allocation(groups, __LINE__, __FILE__,
                            "PDF physical-run groups");
    check_memory_allocation(eligible, __LINE__, __FILE__,
                            "PDF eligible physical runs");
    check_memory_allocation(chain, __LINE__, __FILE__,
                            "PDF physical-run chain");

    size_t group_count = pdf_group_slot_runs(observations, observation_count, groups);

    int64_t first_actual =
        blockvector_get_actual_blocknumber(candidate->b, 0);
    int64_t first_delta = first_actual;
    size_t eligible_count = 0;
    for (size_t i = 0; i < group_count; i++) {
        bool is_header_run = groups[i].delta == first_delta &&
                             groups[i].min_slot == 0;
        if ((is_header_run || groups[i].count >= 3) &&
            groups[i].max_slot < total_slots) {
            eligible[eligible_count++] = groups[i];
        }
    }
    qsort(eligible, eligible_count, sizeof(*eligible),
          pdf_compare_run_evidence);

    size_t chain_count = 0;
    for (size_t i = 0; i < eligible_count; i++) {
        if (chain_count == 0) {
            if (eligible[i].delta == first_delta &&
                eligible[i].min_slot == 0) {
                chain[chain_count++] = eligible[i];
            }
            continue;
        }
        if (eligible[i].delta != chain[chain_count - 1].delta &&
            eligible[i].min_slot > chain[chain_count - 1].max_slot) {
            chain[chain_count++] = eligible[i];
        }
    }

    free(groups);
    free(eligible);
    free(observations);
    if (chain_count < 2) {
        free(chain);
        return false;
    }

    size_t boundary_count = chain_count - 1;
    uint64_t *boundary_lo =
        malloc(boundary_count * sizeof(*boundary_lo));
    uint64_t *boundary_hi =
        malloc(boundary_count * sizeof(*boundary_hi));
    uint64_t *boundaries =
        malloc(boundary_count * sizeof(*boundaries));
    int64_t *actuals = malloc(total_slots * sizeof(*actuals));
    int64_t *solution_actuals =
        calloc(total_slots, sizeof(*solution_actuals));
    check_memory_allocation(boundary_lo, __LINE__, __FILE__,
                            "PDF physical-run boundary minima");
    check_memory_allocation(boundary_hi, __LINE__, __FILE__,
                            "PDF physical-run boundary maxima");
    check_memory_allocation(boundaries, __LINE__, __FILE__,
                            "PDF physical-run boundaries");
    check_memory_allocation(actuals, __LINE__, __FILE__,
                            "PDF physical-run trial blocks");
    check_memory_allocation(solution_actuals, __LINE__, __FILE__,
                            "PDF physical-run verified blocks");

    bool ranges_valid = true;
    for (size_t i = 0; i < boundary_count; i++) {
        boundary_lo[i] = chain[i].max_slot + 1;
        boundary_hi[i] = chain[i + 1].min_slot;
        boundaries[i] = boundary_lo[i];
        if (boundary_lo[i] > boundary_hi[i]) {
            ranges_valid = false;
        }
    }

    uint64_t signature = pdf_interior_signature(candidate, 0, 0);
    signature = XXH64(&exact_length, sizeof(exact_length), signature);
    for (size_t i = 0; i < chain_count; i++) {
        uint64_t fields[] = { (uint64_t)chain[i].delta, chain[i].min_slot,
                              chain[i].max_slot, chain[i].count };
        signature = XXH64(fields, sizeof(fields), signature);
    }
    PDFPhysicalRunSearch search = { .active = 1, .signature = signature,
        .boundary_count = boundary_count, .total_slots = total_slots,
        .solution_length = exact_length, .boundaries = boundaries,
        .solution_actuals = solution_actuals };
    state = carve_get_state(candidate->carvehashkey);
    if (state) {
        PDFPhysicalRunSearch *saved = &state->physical_search[logical_groups ? 1 : 0];
        bool resume = saved->active && saved->signature == signature
            && saved->boundary_count == boundary_count && saved->total_slots == total_slots;
        for (size_t i = 0; resume && i < boundary_count; i++) {
            resume = saved->boundaries[i] >= boundary_lo[i]
                && saved->boundaries[i] <= boundary_hi[i];
        }
        if (resume && pdf_physical_solution_available(candidate, saved)) {
            search = *saved;
            search.boundaries = boundaries;
            search.solution_actuals = solution_actuals;
            memcpy(boundaries, saved->boundaries, boundary_count * sizeof(*boundaries));
            memcpy(solution_actuals, saved->solution_actuals, total_slots * sizeof(*solution_actuals));
        }
        pdf_free_carve_state((void **)&state);
    }

    bool done = search.enumerated || !ranges_valid;
    bool interrupted = false;
    uint64_t valid_layouts = search.valid_layouts;
    uint64_t trials = search.trials;
    while (!search.complete && !done && valid_layouts < 2) {
        if ((trials & 31U) == 0 &&
            atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                 memory_order_acquire)) {
            interrupted = true;
            break;
        }
        trials++;

        bool layout_ok = true;
        uint64_t segment_start = 0;
        for (size_t run = 0; run < chain_count && layout_ok; run++) {
            uint64_t segment_end = run < boundary_count
                                       ? boundaries[run] - 1
                                       : total_slots - 1;
            int64_t actual_start =
                (int64_t)segment_start + chain[run].delta;
            int64_t actual_end =
                (int64_t)segment_end + chain[run].delta;
            if (actual_start < 0 || actual_end < actual_start ||
                actual_end >= image_blocks) {
                layout_ok = false;
                break;
            }
            for (size_t prior = 0; prior < run; prior++) {
                uint64_t prior_start = prior == 0 ? 0 : boundaries[prior - 1];
                uint64_t prior_end = boundaries[prior] - 1;
                int64_t prior_actual_start =
                    (int64_t)prior_start + chain[prior].delta;
                int64_t prior_actual_end =
                    (int64_t)prior_end + chain[prior].delta;
                if (!(actual_end < prior_actual_start ||
                      actual_start > prior_actual_end)) {
                    layout_ok = false;
                    break;
                }
            }
            for (uint64_t slot = segment_start;
                 slot <= segment_end && layout_ok;
                 slot++) {
                int64_t actual = (int64_t)slot + chain[run].delta;
                int64_t apparent = filemirror_apparent_blocknumber(
                    scalpel_state.filemirror, actual);
                bool already_present = apparent >= 0 &&
                    apparent_block_in_blockvector(candidate->b, apparent);
                if (apparent < 0 ||
                    filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                                    actual) ||
                    (filemirror_actual_block_covered(scalpel_state.filemirror,
                                                     actual) &&
                     !already_present)) {
                    layout_ok = false;
                    break;
                }
                actuals[slot] = actual;
            }
            segment_start = segment_end + 1;
        }

        if (layout_ok) {
            BlockVector *trial_bv = NULL;
            clone_blockvector(candidate->b, &trial_bv, false);
            resize_blockvector(trial_bv, total_slots);
            for (uint64_t slot = 0; slot < total_slots; slot++) {
                blockvector_set_apparent_blocknumber(
                    trial_bv, slot,
                    filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                                    actuals[slot]));
            }
            blockvector_set_data_length(trial_bv, exact_length);
            inflate_blockvector(trial_bv);

            CarveInfo trial = *candidate;
            trial.b = trial_bv;
            bool validates = false;
            bool promising = true;
            uint64_t validates_to = blocksize - 1;
            bool previous_syntax_requirement = pdf_require_object_syntax;
            pdf_require_object_syntax = true;
            pdf_file_validate(blockvector_get_data_pointer(trial_bv),
                              exact_length, &validates, &validates_to,
                              &promising, trial.needleidx,
                              scalpel_state.blocksize, trial.carvehashkey);
            pdf_require_object_syntax = previous_syntax_requirement;
            bool trial_validates =
                validates && validates_to + 1 == exact_length &&
                !pdf_candidate_has_holes(&trial);
            if (trial_validates) {
                if (valid_layouts == 0) {
                    memcpy(solution_actuals, actuals,
                           total_slots * sizeof(*solution_actuals));
                }
                valid_layouts++;
            }
            free_blockvector(&trial_bv);
        }

        bool advanced = false;
        for (size_t i = boundary_count; i-- > 0;) {
            if (boundaries[i] < boundary_hi[i]) {
                boundaries[i]++;
                for (size_t reset = i + 1;
                     reset < boundary_count; reset++) {
                    boundaries[reset] = boundary_lo[reset];
                }
                advanced = true;
                break;
            }
        }
        done = !advanced;
    }

    bool verified = !search.complete && !interrupted && done && valid_layouts == 1;
    uint64_t solution_length = search.solution_length;
    uint64_t solution_slots = CEILDIV(solution_length, blocksize);
    bool incremental_update_evidence = false;

    /*
     * A linearized PDF can acquire incremental updates without changing the
     * first revision's /L value. When the verified baseline run continues
     * physically to another discovered %%EOF, test that complete revision too.
     * Multiple successful EOFs are nested revisions of the same physical run,
     * so retaining the farthest one preserves the complete current document.
     */
    if (verified && candidate->needleidx >= 0 &&
        (uint32_t)candidate->needleidx < scalpel_state.num_specs) {
        SearchSpecOffsets *offsets =
            &scalpel_state.search_specs[candidate->needleidx].offsets;
        int64_t baseline_last_actual = solution_actuals[total_slots - 1];
        uint64_t baseline_tail =
            exact_length - (total_slots - 1) * blocksize;
        uint64_t image_size =
            filemirror_filesize(scalpel_state.filemirror);

        if (baseline_last_actual >= 0 &&
            (uint64_t)baseline_last_actual <=
                (UINT64_MAX - baseline_tail) / blocksize) {
            uint64_t baseline_physical_end =
                (uint64_t)baseline_last_actual * blocksize + baseline_tail;

            unsigned char update_prefix[128];
            size_t update_prefix_length = 0;
            uint64_t read_position = baseline_physical_end;
            while (update_prefix_length < sizeof(update_prefix) &&
                   read_position < image_size) {
                int64_t read_block_number =
                    (int64_t)(read_position / blocksize);
                uint64_t read_block_length = 0;
                char *read_block = filemirror_actual_block_data_pointer(
                    scalpel_state.filemirror, read_block_number,
                    &read_block_length);
                uint64_t read_local = read_position % blocksize;
                if (!read_block || read_local >= read_block_length) {
                    break;
                }
                size_t available = (size_t)(read_block_length - read_local);
                size_t needed = sizeof(update_prefix) - update_prefix_length;
                size_t take = available < needed ? available : needed;
                memcpy(update_prefix + update_prefix_length,
                       read_block + read_local, take);
                update_prefix_length += take;
                read_position += take;
            }
            incremental_update_evidence = pdf_incremental_update_prefix(
                update_prefix, update_prefix_length);

            for (uint64_t footer_index = 0;
                 footer_index < offsets->numfooters; footer_index++) {
                uint64_t footer_start = offsets->footers[footer_index];
                if (footer_start < search.next_footer) {
                    continue;
                }
                if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                         memory_order_acquire)) {
                    interrupted = true;
                    verified = false;
                    break;
                }

                search.next_footer = footer_start == UINT64_MAX
                    ? UINT64_MAX : footer_start + 1;
                size_t footer_length = offsets->footerlens
                                           ? offsets->footerlens[footer_index]
                                           : 5;
                if (footer_length == 0 ||
                    footer_start > UINT64_MAX - footer_length) {
                    continue;
                }
                uint64_t physical_end = footer_start + footer_length;
                if (physical_end <= baseline_physical_end ||
                    physical_end > image_size) {
                    continue;
                }

                uint64_t tail_block_length = 0;
                int64_t tail_block_number =
                    (int64_t)(physical_end / blocksize);
                char *tail_block = filemirror_actual_block_data_pointer(
                    scalpel_state.filemirror, tail_block_number,
                    &tail_block_length);
                uint64_t tail_local = physical_end % blocksize;
                if (tail_block && tail_local < tail_block_length) {
                    if (tail_block[tail_local] == '\r') {
                        physical_end++;
                        tail_local++;
                        if (tail_local >= tail_block_length &&
                            physical_end < image_size) {
                            tail_block_number++;
                            tail_block = filemirror_actual_block_data_pointer(
                                scalpel_state.filemirror, tail_block_number,
                                &tail_block_length);
                            tail_local = 0;
                        }
                        if (tail_block && tail_local < tail_block_length &&
                            tail_block[tail_local] == '\n') {
                            physical_end++;
                        }
                    } else if (tail_block[tail_local] == '\n') {
                        physical_end++;
                    }
                }

                uint64_t physical_extension =
                    physical_end - baseline_physical_end;
                if (exact_length > UINT64_MAX - physical_extension) {
                    continue;
                }
                uint64_t trial_length = exact_length + physical_extension;
                if (trial_length <= solution_length ||
                    trial_length > (uint64_t)scalpel_state
                                       .search_specs[candidate->needleidx]
                                       .MAXIMUMSIZE) {
                    continue;
                }
                uint64_t trial_slots = CEILDIV(trial_length, blocksize);
                if (trial_slots < total_slots ||
                    trial_slots > (uint64_t)image_blocks) {
                    continue;
                }

                bool extension_available = true;
                for (uint64_t slot = total_slots;
                     slot < trial_slots && extension_available; slot++) {
                    int64_t actual = baseline_last_actual +
                                     (int64_t)(slot - total_slots) + 1;
                    if (actual < 0 || actual >= image_blocks) {
                        extension_available = false;
                        break;
                    }
                    int64_t apparent = filemirror_apparent_blocknumber(
                        scalpel_state.filemirror, actual);
                    bool already_present = apparent >= 0 &&
                        apparent_block_in_blockvector(candidate->b, apparent);
                    if (apparent < 0 ||
                        filemirror_actual_block_is_zero(
                            scalpel_state.filemirror, actual) ||
                        (filemirror_actual_block_covered(
                             scalpel_state.filemirror, actual) &&
                         !already_present)) {
                        extension_available = false;
                        break;
                    }
                    for (uint64_t prior = 0; prior < total_slots; prior++) {
                        if (solution_actuals[prior] == actual) {
                            extension_available = false;
                            break;
                        }
                    }
                }
                if (!extension_available) {
                    continue;
                }

                BlockVector *trial_bv = NULL;
                clone_blockvector(candidate->b, &trial_bv, false);
                resize_blockvector(trial_bv, trial_slots);
                for (uint64_t slot = 0; slot < total_slots; slot++) {
                    blockvector_set_apparent_blocknumber(
                        trial_bv, slot,
                        filemirror_apparent_blocknumber(
                            scalpel_state.filemirror,
                            solution_actuals[slot]));
                }
                for (uint64_t slot = total_slots; slot < trial_slots; slot++) {
                    int64_t actual = baseline_last_actual +
                                     (int64_t)(slot - total_slots) + 1;
                    blockvector_set_apparent_blocknumber(
                        trial_bv, slot,
                        filemirror_apparent_blocknumber(
                            scalpel_state.filemirror, actual));
                }
                blockvector_set_data_length(trial_bv, trial_length);
                inflate_blockvector(trial_bv);

                CarveInfo trial = *candidate;
                trial.b = trial_bv;
                bool validates = false;
                bool promising = true;
                uint64_t validates_to = blocksize - 1;
                bool previous_syntax_requirement =
                    pdf_require_object_syntax;
                pdf_require_object_syntax = true;
                pdf_file_validate(blockvector_get_data_pointer(trial_bv),
                                  trial_length, &validates, &validates_to,
                                  &promising, trial.needleidx,
                                  scalpel_state.blocksize,
                                  trial.carvehashkey);
                pdf_require_object_syntax = previous_syntax_requirement;
                bool trial_validates =
                    validates && validates_to + 1 == trial_length &&
                    !pdf_candidate_has_holes(&trial);
                if (trial_validates) {
                    solution_length = trial_length;
                    solution_slots = trial_slots;
                }
                free_blockvector(&trial_bv);
            }
        }
    }

    if (verified && solution_length == exact_length &&
        incremental_update_evidence) {
        verified = false;
    }

    if (verified) {
        resize_blockvector(candidate->b, solution_slots);
        for (uint64_t slot = 0; slot < total_slots; slot++) {
            blockvector_set_apparent_blocknumber(
                candidate->b, slot,
                filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                                solution_actuals[slot]));
        }
        int64_t baseline_last_actual = solution_actuals[total_slots - 1];
        for (uint64_t slot = total_slots; slot < solution_slots; slot++) {
            int64_t actual = baseline_last_actual +
                             (int64_t)(slot - total_slots) + 1;
            blockvector_set_apparent_blocknumber(
                candidate->b, slot,
                filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                                actual));
        }
        blockvector_set_data_length(candidate->b, solution_length);
        inflate_blockvector(candidate->b);
        candidate->best_validates_to = solution_length - 1;
        candidate->fastpath = false;

        PDFCarveState *committed =
            (PDFCarveState *)carve_get_state(candidate->carvehashkey);
        if (committed) {
            committed->speculative_blocks = false;
            carve_put_state(candidate->carvehashkey, committed);
            pdf_free_carve_state((void **)&committed);
        }
    }

    search.enumerated = done;
    search.valid_layouts = valid_layouts;
    search.trials = trials;
    search.solution_length = solution_length;
    search.complete = !interrupted;
    pdf_store_physical_search(candidate, logical_groups, &search);
    free(solution_actuals);
    free(actuals);
    free(boundaries);
    free(boundary_hi);
    free(boundary_lo);
    free(chain);
    return verified;
}

// Displacement consensus tolerates isolated incorrect mappings. Logical groups
// retain separated runs when the same displacement recurs after another run.
// Both interpretations use the same complete-file and unique-layout checks.
static bool pdf_complete_linearized_physical_runs(ThreadWork *work,
                                                   CarveInfo *candidate) {
    bool solved = pdf_try_linearized_physical_runs(work, candidate, false);
    if (!solved && !atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
        solved = pdf_try_linearized_physical_runs(work, candidate, true);
    }
    PDFCarveState *state = carve_get_state(candidate->carvehashkey);
    if (state) {
        state->physical_search_active =
            atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire);
        carve_put_state(candidate->carvehashkey, state);
        pdf_free_carve_state((void **)&state);
    }
    return solved;
}

// Recognize classic xref rows between arbitrary carving block boundaries.
static bool pdf_xref_block_continuation(const unsigned char *data, size_t length) {
    if (!data || length == 0) {
        return false;
    }
    size_t cursor = 0;
    size_t rows = 0;
    // A block can begin within an entry; check the following complete rows.
    while (cursor < length && data[cursor] != '\r' && data[cursor] != '\n') {
        cursor++;
    }
    while (cursor < length) {
        if (data[cursor] == '\r') {
            cursor++;
        }
        if (cursor < length && data[cursor] == '\n') {
            cursor++;
        }
        size_t start = cursor;
        while (cursor < length && data[cursor] != '\r' && data[cursor] != '\n') {
            cursor++;
        }
        if (cursor == length) {
            break;
        }
        size_t width = cursor - start;
        if ((width != 18 && width != 19) || data[start + 10] != ' '
            || data[start + 16] != ' '
            || (data[start + 17] != 'n' && data[start + 17] != 'f')
            || (width == 19 && data[start + 18] != ' ')) {
            return false;
        }
        for (size_t offset = 0; offset < 16; offset++) {
            if (offset != 10 && (data[start + offset] < '0' || data[start + offset] > '9')) {
                return false;
            }
        }
        rows++;
    }
    return rows != 0;
}

// Append adjacent cross-reference rows and trailer blocks to a hole-free body.
// Full validation still checks the resulting xref and object relationships.
static bool pdf_complete_trailer(ThreadWork *work, CarveInfo *candidate) {
    (void)work;
    if (!candidate || !candidate->b || scalpel_state.blocksize == 0) {
        return false;
    }
    FileMirror *fm = scalpel_state.filemirror;
    const int64_t bsz = (int64_t)scalpel_state.blocksize;

    // The body must be complete: a hole reads as zeroes the validator could take
    // for content, and appending a tail past it would be premature.
    if (pdf_candidate_has_holes(candidate)) {
        return false;
    }
    uint64_t nblocks = blockvector_get_num_blocks(candidate->b);
    if (nblocks == 0) {
        return false;
    }

    int64_t last_app = blockvector_get_apparent_blocknumber(candidate->b, nblocks - 1);
    if (last_app < 0) {
        return false;
    }

    // A terminal marker in the last block leaves nothing to append here.
    {
        unsigned char *lb = (unsigned char*)get_apparent_block_data(fm, last_app);
        if (!lb) {
            return false;
        }
        bool terminated = memmem(lb, (size_t)bsz, "%%EOF", 5) != NULL;
        free(lb);
        if (terminated) {
            return false;
        }
    }

    int64_t last_actual = filemirror_actual_blocknumber(fm, last_app);
    if (last_actual < 0) {
        return false;
    }

    const uint64_t image_blocks = CEILDIV(filemirror_filesize(fm), scalpel_state.blocksize);
    bool appended = false;
    for (uint64_t next = (uint64_t)last_actual + 1; next < image_blocks; next++) {
        if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
            break;
        }
        int64_t d_actual = (int64_t)next;
        int64_t d_app = filemirror_apparent_blocknumber(fm, d_actual);
        if (d_app < 0) {
            break;
        }
        unsigned char *blk = (unsigned char*)get_apparent_block_data(fm, d_app);
        if (!blk) {
            break;
        }
        bool has_sx  = memmem(blk, (size_t)bsz, "startxref", 9) != NULL;
        bool has_eof = memmem(blk, (size_t)bsz, "%%EOF", 5) != NULL;
        bool xref_rows = pdf_xref_block_continuation(blk, (size_t)bsz);
        free(blk);
        if (!has_sx && !has_eof && !xref_rows) {
            break;
        }

        uint64_t slot = blockvector_get_num_blocks(candidate->b);
        if (!pdf_place_blocks_at_slot(candidate, &d_actual, 1, slot, "TRAILER_FILL")) {
            break;
        }
        appended = true;
        if (has_eof) {
            break;
        }
    }
    return appended;
}

static bool pdf_reassembly_poll(ThreadWork *work,
                                CarveInfo **candidate,
                                uuid_string_t uuidp,
                                uuid_string_t uuidc) {
    if (!work || !candidate || !*candidate) {
        return true;
    }
    if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
        return true;
    }
    if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)
        && reassembly_time_to_checkpoint(work->id, *candidate, uuidp, uuidc)) {
        return true;
    }
    return false;
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
    bool resume_xref_scan = false;
    bool state_initialized = false;
    bool resume_interior_scan = false;
    bool resume_partial_search = false;
    bool resume_physical_search = false;
#ifdef PDF_TRACE_REASM
    uint64_t dbg_start_blocks = blockvector_get_num_blocks(candidate->b);
    int dbg_s2_scans = 0, dbg_s2_best = -1, dbg_s2_found = 0;
#endif

    {
        PDFCarveState *state =
            (PDFCarveState *)carve_get_state(candidate->carvehashkey);
        resume_xref_scan = state && state->xref_search.active;
        state_initialized = state && state->initialized;
        resume_interior_scan = state && state->interior_search.active;
        resume_partial_search = state && state->partial_search_active;
        resume_physical_search = state && state->physical_search_active;
        pdf_free_carve_state((void **)&state);
    }

    if (resume_partial_search) {
        goto finish_partial;
    }
    if (resume_physical_search) {
        goto finish_physical;
    }
    if (resume_interior_scan) {
        goto finish_interiors;
    }

    /* === Strategy 1: extend using xref tables already in the candidate === */
    if (!resume_xref_scan) {
        if (!state_initialized) {
            pdf_reassembly_init_candidate(work->id, candidate, uuidp, uuidc);
        }
        {
            PDFCarveState *carve_state =
                (PDFCarveState *)carve_get_state(candidate->carvehashkey);
            if (carve_state) {
                for (size_t i = 0; i < carve_state->num_tables; i++) {
                    sort_xref_data_by_offset(&carve_state->xref_tables[i]);
                }
                carve_put_state(candidate->carvehashkey, carve_state);
                pdf_free_carve_state((void **)&carve_state);
                pdf_reassembly_extension(work, c, NULL, 0, NULL, 0, -1,
                                         false);
                candidate = *c;
            }
        }
        if (pdf_reassembly_poll(work, c, uuidp, uuidc)) {
            return;
        }
        candidate = *c;
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

            bool scan_exhausted = false;
            int64_t scan_cursor = 0;
            pdf_restore_xref_search(candidate, &scan_bv, &scan_exhausted,
                                    &best_entries, &best_entry_count,
                                    &best_blocks, &best_block_count,
                                    &best_local, &best_score);

            while (!scan_exhausted) {
                free(entries);
                entries = NULL;
                free(xref_blocks);
                xref_blocks = NULL;
                xref_block_count = 0;
                entry_count = 0;
                bool more_work = false;
                entries = scan_blocks_for_xref(
                    candidate, &scan_bv, &entry_count, &xref_blocks,
                    &xref_block_count, &xref_local, &scan_cursor,
                    PDF_XREF_SCAN_QUANTUM, &more_work);
                if (!entries || entry_count <= 0) {
                    free(entries);
                    entries = NULL;
                    if (!more_work) {
                        scan_exhausted = true;
                    }
                }

                int score = entries
                                ? pdf_xref_confirms_header(candidate, entries,
                                                           entry_count)
                                : 0;
                bool xref_already_present = entries && xref_block_count > 0;
                for (int b = 0; b < xref_block_count && xref_already_present; b++) {
                    int64_t xref_app = filemirror_apparent_blocknumber(
                        scalpel_state.filemirror, xref_blocks[b]);
                    bool block_present = false;
                    for (uint64_t k = 0;
                         k < blockvector_get_num_blocks(candidate->b) && !block_present;
                         k++) {
                        block_present =
                            blockvector_get_apparent_blocknumber(candidate->b, k) == xref_app;
                    }
                    xref_already_present = block_present;
                }
                // Xrefs already in the candidate were parsed during candidate
                // initialization or /Prev adoption. Rescoring them can starve a
                // later incremental xref whose smaller table is still needed.
                if (xref_already_present) {
                    score = 0;
                }
#ifdef PDF_TRACE_REASM
                if (entries) {
                    dbg_s2_scans++;
                    dbg_s2_found = 1;
                    if (score > dbg_s2_best) {
                        dbg_s2_best = score;
                    }
                }
#endif
                bool prefer_xref = entries && score > best_score;
                if (entries && best_entries && score == best_score &&
                    score >= MIN_CONFIRMATIONS) {
                    int64_t candidate_slot = pdf_resolve_xref_slot(
                        candidate, xref_blocks, xref_block_count, xref_local);
                    int64_t current_slot = pdf_resolve_xref_slot(
                        candidate, best_blocks, best_block_count, best_local);
                    // A terminal xref and a linearized front hint can contain the
                    // same entries. Prefer the one whose own trailer identifies
                    // its exact file position; content score remains the primary
                    // discriminator and the normal confirmation threshold still
                    // applies.
                    prefer_xref = candidate_slot >= 0 && current_slot < 0;
                }
                if (prefer_xref) {
                    free(best_entries);
                    free(best_blocks);
                    best_entries = entries;
                    entries = NULL;
                    best_blocks = xref_blocks;
                    xref_blocks = NULL;
                    best_entry_count = entry_count;
                    best_block_count = xref_block_count;
                    xref_block_count = 0;
                    best_local = xref_local;
                    best_score = score;
                }
#ifdef PDF_FIRST_MATCH_XREF
                // Diagnostic mode: stop at the first xref over the bar, reproducing
                // the pre-argmax behaviour so the two can be diffed.
                if (best_score >= MIN_CONFIRMATIONS) {
                    scan_exhausted = true;
                }
#endif

                if (reassembly_check_kill_queue(work, c, uuidp, uuidc)) {
                    free(entries);
                    entries = NULL;
                    free(xref_blocks);
                    xref_blocks = NULL;
                    free(best_entries);
                    best_entries = NULL;
                    free(best_blocks);
                    best_blocks = NULL;
                    if (scan_bv) {
                        free_blockvector(&scan_bv);
                    }
                    return;
                }
                if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                         memory_order_acquire)) {
                    pdf_store_xref_search(
                        candidate, scan_bv, scan_exhausted, best_entries,
                        best_entry_count, best_blocks, best_block_count,
                        best_local, best_score);
                    free(entries);
                    free(xref_blocks);
                    free(best_entries);
                    free(best_blocks);
                    if (scan_bv) {
                        free_blockvector(&scan_bv);
                    }
                    if (reassembly_time_to_checkpoint(work->id, candidate,
                                                      uuidp, uuidc)) {
                        return;
                    }
                    pdf_restore_xref_search(
                        candidate, &scan_bv, &scan_exhausted,
                        &best_entries, &best_entry_count, &best_blocks,
                        &best_block_count, &best_local, &best_score);
                    scan_cursor = 0;
                }
            }
            free(entries);
            entries = NULL;
            free(xref_blocks);
            xref_blocks = NULL;

            // Keep the completed argmax result restartable until its extension
            // has been committed to the candidate and carve state.
            pdf_store_xref_search(candidate, scan_bv, true, best_entries,
                                  best_entry_count, best_blocks,
                                  best_block_count, best_local, best_score);
            if (scan_bv) {
                free_blockvector(&scan_bv);
            }

            bool possible_match = (best_score >= MIN_CONFIRMATIONS);
            entries          = best_entries;
            entry_count      = best_entry_count;
            xref_blocks      = best_blocks;
            xref_block_count = best_block_count;
            xref_local       = best_local;

            if (possible_match) {
                // The scan found WHICH blocks hold the xref; recover WHERE they
                // belong before handing them over. -1 means unresolved, and the
                // extension falls back to appending at the frontier.
                int64_t xref_slot = pdf_resolve_xref_slot(candidate, xref_blocks,
                                                          xref_block_count, xref_local);
                pdf_reassembly_extension(work, c, entries, entry_count,
                                         xref_blocks, xref_block_count,
                                         xref_slot, true);
            }
            else {
                free(entries);
            }
            free(xref_blocks);
            candidate = *c;
            // An interrupted extension still needs the selected xref on resume.
            if (!atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
                pdf_clear_xref_search(candidate);
                resume_xref_scan = false;
            }
            if (pdf_reassembly_poll(work, c, uuidp, uuidc)) {
                return;
            }
            candidate = *c;
        }

        /* === Strategy 3: follow /Prev chain to a table outside the candidate === */
        {
            int xref_type;
            uint64_t search_pos = 0;
            const char *first_xref = scan_buf_for_xref(blockvector_get_data_pointer(candidate->b),
                blockvector_get_data_length(candidate->b), search_pos, &xref_type);
            int64_t xref_offset = first_xref
                                      ? first_xref
                                            - blockvector_get_data_pointer(candidate->b)
                                      : -1;
            int64_t prev_entry = xref_offset >= 0
                                     ? find_prev_entry(
                                           blockvector_get_data_pointer(candidate->b),
                                           blockvector_get_data_length(candidate->b),
                                           xref_offset, xref_type)
                                     : -1;
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
                        int prev_score = pdf_xref_confirms_header(
                            candidate, prev_entries, prev_entry_count);
                        bool exact_link_unique = prev_score < 2 &&
                            pdf_xref_offset_is_unique(
                                candidate,
                                (int32_t)xref_local_block_offset);
                        if (!xref_already_present &&
                            (prev_score >= 2 || exact_link_unique)) {
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

        if (pdf_reassembly_poll(work, c, uuidp, uuidc)) {
            return;
        }
        candidate = *c;

        if(blockvector_get_num_blocks(candidate->b) > blocks_before)
            extended = true;

    } while(extended);

    candidate = *c;

finish_interiors:
    candidate = *c;
    // The displaced trailer can contain the stream's missing tail. Acquire it
    // before asking the stream checksum to guide interior gap removal.
    pdf_complete_trailer(work, candidate);
    if (pdf_reassembly_poll(work, c, uuidp, uuidc)) {
        return;
    }
    candidate = *c;
    // Xref adoption places object-HEADER blocks but not the stream interiors
    // between them; fill any verifiable interior holes before validating.
    pdf_fill_interior_stream_holes(work, candidate);
    if (pdf_reassembly_poll(work, c, uuidp, uuidc)) {
        return;
    }
    candidate = *c;
    pdf_fill_physically_bridged_holes(work, candidate);
finish_physical:
    candidate = *c;
    pdf_complete_linearized_physical_runs(work, candidate);
    if (pdf_reassembly_poll(work, c, uuidp, uuidc)) {
        return;
    }
    candidate = *c;

    // A fully-assembled body can still lack its final trailer block (startxref +
    // %%EOF), which holds no object and so is never placed; append it so the file
    // can terminate and validate.
    pdf_complete_trailer(work, candidate);
    if (pdf_reassembly_poll(work, c, uuidp, uuidc)) {
        return;
    }
    candidate = *c;

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
    uint64_t validation_length = pdf_candidate_trusted_prefix_length(candidate);
    pdf_file_validate(blockvector_get_data_pointer(candidate->b),
                      validation_length,
                      &validates, &validates_to, &promising,
                      candidate->needleidx, scalpel_state.blocksize,
                      candidate->carvehashkey);

    PDFCarveState *final_state =
        (PDFCarveState *)carve_get_state(candidate->carvehashkey);
    bool speculative_blocks =
        final_state && final_state->speculative_blocks;
    pdf_free_carve_state((void **)&final_state);
    if (validates && speculative_blocks) {
        blockvector_set_data_length(candidate->b, validates_to + 1);
        resize_blockvector(
            candidate->b,
            CEILDIV(blockvector_get_data_length(candidate->b),
                    scalpel_state.blocksize));
        validates = false;
        promising = true;
    }

    // Positional placement can leave unfilled slots between the frontier and an
    // anchored block. A hole inside the validated byte range reads as zeroes and
    // cannot be trusted; holes after validates_to are discarded by the trim below.
    if (validates &&
        pdf_candidate_has_holes_through(candidate, validates_to)) {
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
            if (scalpel_state.write_promising) {
                write_candidate(c, false);
            }
            else {
                destroy_candidate(c);
            }
        } else {
            candidate->flavor = VALIDATED;
            write_candidate(c, false);
        }
    } else {
        pdf_preserve_partial_prefix(candidate);
finish_partial:
        pdf_extend_partial_prefix(candidate);
        if (pdf_reassembly_poll(work, c, uuidp, uuidc)) {
            return;
        }
        candidate = *c;
        pdf_write_partial_prefix(candidate);
        candidate->flavor = PROMISING;
        if (scalpel_state.write_promising) {
            write_candidate(c, false);
        }
        else {
            destroy_candidate(c);
        }
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
            if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
                goto extension_done;
            }
            // Reassembly can relocate the blockvector data buffer between objects.
            data = blockvector_get_data_pointer(candidate->b);
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
                                               stream_dict, dict_len, (uint64_t)obj_off, true)
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
                        bool reconstructed = reconstruct_zlib_stream(work, candidate,
                                first_stream_block_data, startstream_local_offset,
                                endstream_local_offset, 0, (uint64_t)stream_length,
                                INNEXTBLOCK);
#ifdef PDF_TRACE_STALL
                        if(!reconstructed){
                            { uuid_string_t uu; uuid_unparse_lower(candidate->binuuid, uu);
                              lock_fprintf(stdout,"[PDFSTALL] uuid=%.8s obj_off=%" PRId64 " ZLIB INNEXTBLOCK failed bte=%d\n", uu, obj_off, blocks_to_extend); }
                        }
#else
                        (void)reconstructed;
#endif
                    }
                    if(stream_condition == MULTIBLOCK){
                        bool reconstructed = reconstruct_zlib_stream(work, candidate, first_stream_block_data,
                                startstream_local_offset, endstream_local_offset, blocks_to_extend,
                                (uint64_t)stream_length, MULTIBLOCK);
                        if(!reconstructed){
#ifdef PDF_TRACE_STALL
                            { uuid_string_t uu; uuid_unparse_lower(candidate->binuuid, uu);
                              lock_fprintf(stdout,"[PDFSTALL] uuid=%.8s obj_off=%" PRId64 " ZLIB MULTIBLOCK failed bte=%d\n", uu, obj_off, blocks_to_extend); }
#endif
                        }
                        if(reconstructed){
                            data = blockvector_get_data_pointer(candidate->b);
                        }
                    }
                }
                else if(filter == XML){
                    if(stream_condition == INNEXTBLOCK){
                        (void)reconstruct_xml_stream(work, candidate, first_stream_block_data,
                                startstream_local_offset, endstream_local_offset, 0,
                                (uint64_t)stream_length, INNEXTBLOCK);
                    }
                    if(stream_condition == MULTIBLOCK){
                        bool reconstructed = reconstruct_xml_stream(work, candidate, first_stream_block_data,
                                startstream_local_offset, endstream_local_offset, blocks_to_extend,
                                (uint64_t)stream_length, MULTIBLOCK);
                        if(reconstructed){
                            data = blockvector_get_data_pointer(candidate->b);
                        }
                    }
                }
                else if(filter == NOFILTER){
                    // Unfiltered stream: no decoder exists, but the extent is
                    // known exactly. Without this branch the stream is skipped
                    // entirely and its interior blocks stay holes forever.
                    if(stream_condition == MULTIBLOCK){
                        bool reconstructed = reconstruct_raw_stream(work, candidate,
                                endstream_local_offset, blocks_to_extend, MULTIBLOCK);
                        if(reconstructed){
                            data = blockvector_get_data_pointer(candidate->b);
                        }
                    }
                }
                else if(filter == JPEG){
                    if(stream_condition == INNEXTBLOCK){
                        (void)reconstruct_jpeg_stream(work, candidate, first_stream_block_data,
                                startstream_local_offset, endstream_local_offset, 0,
                                (uint64_t)stream_length, INNEXTBLOCK);
                    }
                    if(stream_condition == MULTIBLOCK){
                        bool reconstructed = reconstruct_jpeg_stream(work, candidate, first_stream_block_data,
                                startstream_local_offset, endstream_local_offset, blocks_to_extend,
                                (uint64_t)stream_length, MULTIBLOCK);
                        if(reconstructed){
                            data = blockvector_get_data_pointer(candidate->b);
                        }
                    }
                }
                free(first_stream_block_data);
            }

            // A stream search interrupted for a checkpoint is not exhausted.
            // Keep its frontier rather than jumping to a later object anchor.
            if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
                goto extension_done;
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
                data = blockvector_get_data_pointer(candidate->b);
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

    if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
        goto extension_done;
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

extension_done:
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
    void *blockhashkey) {

    *decision = BLOCK_CONFIDENCE_INVALID;
    *validates_to = 0;
    if (!data || length == 0 || length > blocksize) {
        return needleidx;
    }
    *decision = BLOCK_CONFIDENCE_VALID;
    *validates_to = length - 1;
    PDFBlockState *s = calloc(1, sizeof(*s));
    check_memory_allocation(s, __LINE__, __FILE__, "PDF block state");
    s->first_obj = -1;
    char *obj_pos = memmem(data, length, " obj", 4);
    if (obj_pos) {
        s->first_obj = extract_obj_num(data, (size_t)(obj_pos - data), length);
    }

    size_t capacity = 0;
    bool no_trailer = false;
    bool no_endstream = false;
    // Marker and endpoint searches only inspect the bytes supplied by the caller.
    for (uint64_t i = 0; i < length; i++) {
        uint64_t remaining = length - i;
        XrefParameters entry = {.xref_start = -1, .xref_end = -1};
        if (remaining >= 4 && !memcmp(data + i, "xref", 4)
            && (i == 0 || isspace((unsigned char)data[i - 1]))
            && (remaining == 4 || isspace((unsigned char)data[i + 4]))) {
            entry.xref_start = (int64_t)i;
            entry.xref_type = 1;
            if (!no_trailer) {
                char *end = memmem(data + i, remaining, "trailer", 7);
                if (end) {
                    entry.xref_end = (int64_t)(end - data);
                    i = (uint64_t)entry.xref_end + 1;
                }
                else {
                    no_trailer = true;
                }
            }
        }
        else if (remaining >= 7 && !memcmp(data + i, "trailer", 7)) {
            entry.xref_end = (int64_t)i;
            entry.xref_type = 1;
        }
        else if ((remaining >= 10 && !memcmp(data + i, "/Type/XRef", 10))
                 || (remaining >= 11 && !memcmp(data + i, "/Type /XRef", 11))) {
            entry.xref_start = find_xref_stream_start(data, (int64_t)i);
            entry.xref_type = 2;
            if (entry.xref_start == (int64_t)i) {
                entry.conditional_flag = INCOMPLETESTREAMDICT;
            }
            if (!no_endstream) {
                char *end = memmem(data + i, remaining, "endstream", 9);
                if (end) {
                    entry.xref_end = (int64_t)(end - data);
                    i = (uint64_t)entry.xref_end + 1;
                }
                else {
                    no_endstream = true;
                }
            }
        }
        else {
            continue;
        }

        if ((size_t)s->num_xrefs == capacity) {
            size_t next_capacity = capacity ? capacity * 2 : 8;
            if (next_capacity < capacity
                || next_capacity > SIZE_MAX / sizeof(*s->xref_block_data)) {
                handle_error(SCALPEL_GENERAL_ABORT, NULL, __LINE__, __FILE__);
            }
            XrefParameters *entries = realloc(
                s->xref_block_data, next_capacity * sizeof(*entries));
            check_memory_allocation(entries, __LINE__, __FILE__, "PDF xref markers");
            s->xref_block_data = entries;
            capacity = next_capacity;
        }
        s->xref_block_data[s->num_xrefs++] = entry;
    }
    block_put_state(blockhashkey, s);
    return needleidx;
}

// Preserve PDF trailing whitespace without consuming arbitrary image padding.
static uint64_t pdf_include_trailing_whitespace(const char *data,
                                                uint64_t length,
                                                uint64_t end) {
    for (unsigned count = 0; length > 0 && end < length - 1 && count < 8; count++) {
        unsigned char c = (unsigned char)data[end + 1];
        if (c != '\t' && c != '\n' && c != '\f' && c != '\r' && c != ' ') {
            break;
        }
        end++;
    }
    return end;
}

// Validate xref locations, object structure and supported stream encodings.
// unverified_complete distinguishes a complete structural hypothesis from an
// incomplete prefix, without claiming unsupported ciphertext has been decoded.
static void pdf_file_validate_content(char *data,
    uint64_t length,
    bool *validates,
    uint64_t *validates_to,
    bool *promising,
    uint32_t needleidx,
    uint32_t blocksize,
    void *carvehashkey, bool *unverified_complete){
    *unverified_complete = false;
    if (!data || length < 9 || blocksize == 0) {
        *validates = false;
        *promising = false;
        *validates_to = 0;
        return;
    }
    *promising = true;
    *validates = false;
    *validates_to = blocksize - 1;
#ifdef NOFRAG
    // A candidate may include the next independent PDF. Validate its prefix
    // first, using this same routine and all stream checks. On failure retain
    // the full search, including fragmented and embedded-header cases.
    for (uint64_t next = blocksize; next < length && length - next >= 9;
         next += blocksize) {
        if (!memcmp(data + next, "%PDF-", 5) &&
            (data[next + 5] == '1' || data[next + 5] == '2') &&
            data[next + 6] == '.' && data[next + 7] >= '0' &&
            data[next + 7] <= '7' &&
            (data[next + 8] == '\r' || data[next + 8] == '\n')) {
            pdf_file_validate_content(data, next, validates, validates_to, promising,
                                      needleidx, blocksize, carvehashkey,
                                      unverified_complete);
            if (*validates || *unverified_complete) {
                return;
            }
            *validates_to = blocksize - 1;
            *promising = true;
            break;
        }
    }
    XrefObject *xref_list = NULL;
    int xref_count = 0;
    int validated_xref_count = 0;
    int8_t check = 0;
    uint64_t validation_cutoff = 0;
    int64_t *supp_stms = (int64_t*)malloc(sizeof(int64_t));
    int supp_count = 0;
    XrefTables* xref_tables = malloc(sizeof(XrefTables));
    ObjectHashTable **xref_hashes = NULL;
    uint64_t kg_validation_cutoff = blocksize - 1;
    int8_t validated = 0;
    uint8_t fail_count = 0;
    uint64_t xref_end_offset = 0;
    bool damaged_metadata = false;
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
#ifdef PDF_TRACE_VALIDATE
        lock_fprintf(stdout, "[PDFVAL] table offset=%" PRIu64 " entries=%d end=%" PRIu64 "\n",
            xref_list[xref_count - 1].offset, xref_tables[xref_count - 1].count, xref_end_offset);
#endif
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
            validated_xref_count = xref_count;
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
    if(validated == 1 && !pdf_streams_decode_ok(data, length, xref_tables,
                                              xref_list, validated_xref_count,
                                              &damaged_metadata)){
        validated = 0;
#ifdef PDF_TRACE_VALIDATE
        lock_fprintf(stdout, "[PDFVAL] len=%" PRIu64 " REJECTED by stream decode check\n", length);
#endif
    }
    if (validated == 1 && pdf_require_object_syntax &&
        !pdf_nonstream_objects_well_formed(data, length, xref_tables,
                                           validated_xref_count)) {
        validated = 0;
#ifdef PDF_TRACE_VALIDATE
        lock_fprintf(stdout,
                     "[PDFVAL] len=%" PRIu64
                     " REJECTED by indirect-object syntax check\n",
                     length);
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
                if((tail_ptr = memmem(&data[9], validation_cutoff - 8, "%PDF-1", 6)) ||
                (tail_ptr = memmem(&data[9], validation_cutoff - 8, "%PDF-2", 6))){
                    validation_cutoff = tail_ptr - data;
                    goto search_backward;
                }
                if(validation_cutoff < length - 2 &&
                !memcmp(&data[validation_cutoff + 1], "\x0D\x0A", 2)){
                    validation_cutoff += 2;
                    if(check_startxref(data, validation_cutoff) == 0) goto startxref_fail;
                    *promising = damaged_metadata;
                    *validates = !damaged_metadata;
                    *unverified_complete = damaged_metadata;
                    *validates_to = pdf_include_trailing_whitespace(data, length, validation_cutoff);
                    return;
                }
                else if(validation_cutoff < length - 1 &&
                (data[validation_cutoff + 1] == 0x0D ||
                data[validation_cutoff + 1] == 0x0A)){
                    validation_cutoff++;
                    if(check_startxref(data, validation_cutoff) == 0) goto startxref_fail;
                    *promising = damaged_metadata;
                    *validates = !damaged_metadata;
                    *unverified_complete = damaged_metadata;
                    *validates_to = pdf_include_trailing_whitespace(data, length, validation_cutoff);
                    return;
                }
                else{
                    if(check_startxref(data, validation_cutoff) == 0) goto startxref_fail;
                    *promising = damaged_metadata;
                    *validates = !damaged_metadata;
                    *unverified_complete = damaged_metadata;
                    *validates_to = pdf_include_trailing_whitespace(data, length, validation_cutoff);
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
        if(i < length && length - i >= 5 && !memcmp(&data[i], "%%EOF", 5)){
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
                    *promising = damaged_metadata;
                    *validates = !damaged_metadata;
                    *unverified_complete = damaged_metadata;
                    *validates_to = pdf_include_trailing_whitespace(data, length, validation_cutoff);
                    return;
                }
                else if(validation_cutoff < length - 1 &&
                (data[validation_cutoff + 1] == 0x0D ||
                data[validation_cutoff + 1] == 0x0A)){
                    validation_cutoff++;
                    if(check_startxref(data, validation_cutoff) == 0) goto startxref_fail;
                    *promising = damaged_metadata;
                    *validates = !damaged_metadata;
                    *unverified_complete = damaged_metadata;
                    *validates_to = pdf_include_trailing_whitespace(data, length, validation_cutoff);
                    return;
                }
                else{
                    if(check_startxref(data, validation_cutoff) == 0) goto startxref_fail;
                    *promising = damaged_metadata;
                    *validates = !damaged_metadata;
                    *unverified_complete = damaged_metadata;
                    *validates_to = pdf_include_trailing_whitespace(data, length, validation_cutoff);
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

/**
 * @description         Validates a full PDF using its cross-reference tables,
 *                      object structure and supported stream encodings.
 * @param data          Candidate bytes.
 * @param length        Number of bytes available.
 * @param validates     Whether the candidate passes validation.
 * @param validates_to  Inclusive byte offset of the accepted extent.
 * @param promising     Whether an unvalidated candidate remains useful.
 * @param needleidx     Search-spec index.
 * @param blocksize     Carving block size.
 * @param carvehashkey  Candidate state key.
 */
static inline void pdf_file_validate(char *data, uint64_t length, bool *validates,
    uint64_t *validates_to, bool *promising, uint32_t needleidx,
    uint32_t blocksize, void *carvehashkey) {
    bool unverified_complete = false;
    pdf_file_validate_content(data, length, validates, validates_to, promising,
                              needleidx, blocksize, carvehashkey, &unverified_complete);
    if (length && *validates_to >= length) {
        *validates_to = length - 1;
    }
}

// Skip PDF whitespace and comments with interruption checks for partial scans.
static uint64_t pdf_partial_skip_space(const unsigned char *data, uint64_t cursor,
                                       uint64_t limit, bool (*stop)(void)) {
    if (!stop) {
        return pdf_skip_space_and_comments(data, cursor, limit);
    }
    uint32_t work = 0;
    bool comment = false;
    while (cursor < limit) {
        if ((work++ & 1023) == 0 && stop()) {
            return limit;
        }
        unsigned char c = data[cursor];
        if (comment) {
            comment = c != '\r' && c != '\n';
        }
        else if (c == '%') {
            comment = true;
        }
        else if (!pdf_lexical_space(c)) {
            break;
        }
        cursor++;
    }
    return cursor;
}

// Reuse the stream parsers without accumulating output. A malformed block
// leaves the preceding checked blocks available as a partial, not validated,
// result. A short final input can end within a token or marker.
static uint64_t pdf_embedded_stream_prefix(const unsigned char *data,
                                           uint64_t available, uint64_t declared,
                                           uint64_t stream_offset,
                                           uint32_t blocksize, bool is_jpeg,
                                           bool (*stop)(void), bool *interrupted) {
    if (!data || !available || blocksize == 0 || available > SIZE_MAX
        || declared > SIZE_MAX) {
        return 0;
    }
    if (!is_jpeg
        && !xml_has_signature(data, available < blocksize ? available : blocksize)) {
        return 0;
    }
    JpegStreamReassembler jpeg = {0};
    XmlStreamReassembler xml = {0};
    jpeg.state = J_START;
    jpeg.stream_length = declared;
    xml.state = X_TEXT;
    uint64_t good = 0;
    for (uint64_t cursor = 0; cursor < available; cursor++) {
        if (stop && (cursor & 1023) == 0 && stop()) {
            *interrupted = true;
            break;
        }
        if (is_jpeg) {
            if (jpeg.state == J_DONE && !pdf_lexical_space(data[cursor])) {
                break;
            }
            jpeg_feed_byte(&jpeg, data[cursor]);
            if (jpeg.malformed) {
                break;
            }
        }
        else {
            xml_feed_byte(&xml, data[cursor]);
            if (xml.malformed) {
                break;
            }
        }
        if ((!is_jpeg || jpeg.saw_sos)
            && ((stream_offset + cursor + 1) % blocksize == 0
                || cursor + 1 == available)) {
            good = cursor + 1;
        }
    }
    return good;
}

// Scan a partial body independently of its cross-reference table. This is
// progress evidence only; it is not a complete-file validation decision.
static PDFPrefixScan pdf_scan_forward_prefix(const unsigned char *data,
                                             uint64_t length,
                                             uint32_t blocksize,
                                             bool (*stop)(void)) {
    PDFPrefixScan result = { 0 };
    if (!data || length < 8 || length > SIZE_MAX || blocksize == 0
        || memcmp(data, "%PDF-", 5)
        || (data[5] != '1' && data[5] != '2')
        || data[6] != '.' || !isdigit(data[7])) {
        return result;
    }
    uint64_t cursor = 8;
    result.length = cursor;
    unsigned char *stack = NULL;
    size_t capacity = 0;
    while (cursor < length) {
        if (stop && stop()) {
            result.interrupted = true;
            break;
        }
        cursor = pdf_partial_skip_space(data, cursor, length, stop);
        result.stream_length = 0;
        if (length - cursor >= 4 && !memcmp(data + cursor, "xref", 4)) {
            cursor += 4;
            for (;;) {
                cursor = pdf_partial_skip_space(data, cursor, length, stop);
                if (length - cursor >= 7 && !memcmp(data + cursor, "trailer", 7)) {
                    cursor = pdf_partial_skip_space(data, cursor + 7, length, stop);
                    uint64_t end = 0;
                    if (length - cursor < 2 || memcmp(data + cursor, "<<", 2)
                        || !pdf_nonstream_object_end(data, cursor, length, -1,
                                                      &stack, &capacity, &end,
                                                      NULL, stop)) {
                        goto finished;
                    }
                    cursor = end;
                    result.length = cursor;
                    break;
                }
                int64_t first = 0;
                int64_t count = 0;
                size_t end = 0;
                if (!pdf_parse_signed_integer(data, length, cursor, &first, &end)
                    || first < 0 || first > INT_MAX || end >= length
                    || !pdf_lexical_space(data[end])
                    || !pdf_parse_signed_integer(data, length,
                          pdf_partial_skip_space(data, end, length, stop), &count, &end)
                    || count < 0 || count > INT_MAX - first || end >= length
                    || !pdf_lexical_space(data[end])) {
                    goto finished;
                }
                cursor = end;
                for (int64_t index = 0; index < count; index++) {
                    if (stop && stop()) {
                        result.interrupted = true;
                        goto finished;
                    }
                    int64_t offset = 0;
                    int64_t generation = 0;
                    if (!pdf_parse_signed_integer(data, length,
                          pdf_partial_skip_space(data, cursor, length, stop), &offset, &end)
                        || offset < 0 || end >= length || !pdf_lexical_space(data[end])
                        || !pdf_parse_signed_integer(data, length,
                              pdf_partial_skip_space(data, end, length, stop), &generation, &end)
                        || generation < 0 || generation > 65535 || end >= length
                        || !pdf_lexical_space(data[end])) {
                        goto finished;
                    }
                    cursor = pdf_partial_skip_space(data, end, length, stop);
                    if (cursor >= length || (data[cursor] != 'n' && data[cursor] != 'f')
                        || cursor + 1 >= length || !pdf_lexical_space(data[cursor + 1])) {
                        goto finished;
                    }
                    cursor++;
                    result.length = cursor;
                }
            }
            continue;
        }
        if (length - cursor >= 9 && !memcmp(data + cursor, "startxref", 9)) {
            int64_t offset = 0;
            size_t end = 0;
            if (!pdf_parse_signed_integer(data, length,
                  pdf_partial_skip_space(data, cursor + 9, length, stop), &offset, &end)
                || offset < 0) {
                break;
            }
            cursor = end;
            while (cursor < length && pdf_lexical_space(data[cursor])) {
                if (stop && (cursor & 1023) == 0 && stop()) {
                    result.interrupted = true;
                    goto finished;
                }
                cursor++;
            }
            if (length - cursor < 5 || memcmp(data + cursor, "%%EOF", 5)) {
                break;
            }
            cursor += 5;
            result.length = cursor;
            continue;
        }
        int64_t object_number = -1;
        if (!pdf_parse_signed_integer(data, (size_t)length, (size_t)cursor,
                                       &object_number, NULL)
            || object_number < 0 || object_number > INT_MAX) {
            break;
        }
        uint64_t body = 0;
        uint64_t end = 0;
        PDFStreamMetadata metadata = { 0 };
        int header = pdf_indirect_object_header(data, cursor, length,
                                                 (int)object_number, &body, NULL);
        if (header < 0) {
            break;
        }
        // A header cut off by the input boundary is still useful partial
        // progress. A contradictory header must not extend the prefix.
        if (header == 0) {
            result.length = length;
            result.needs_more = true;
            break;
        }
        result.length = body;
        if (!pdf_nonstream_object_end(data, cursor, length,
                                       (int)object_number, &stack,
                                       &capacity, &end, &metadata, stop)) {
            result.needs_more = metadata.incomplete;
            break;
        }
        if (!memcmp(data + end - 6, "endobj", 6)) {
            result.length = end;
            result.complete_length = end;
            result.objects++;
            cursor = end;
            continue;
        }
        uint64_t stream = end;
        if (stream < length && data[stream] == '\r') {
            stream++;
            if (stream < length && data[stream] == '\n') {
                stream++;
            }
        }
        else if (stream < length && data[stream] == '\n') {
            stream++;
        }
        else {
            break;
        }
        uint64_t stream_length = metadata.has_length ? (uint64_t)metadata.length : length - stream;
        result.stream_offset = stream;
        result.stream_length = metadata.has_length ? stream_length : 0;
        result.stream_flate = metadata.flate;
        result.stream_jpeg = metadata.jpeg;
        uint64_t available = stream_length < length - stream
                                 ? stream_length : length - stream;
        bool ended = false;
        result.length = stream;
        if (metadata.flate) {
            z_stream inflater = { 0 };
            if (inflateInit(&inflater) != Z_OK) {
                break;
            }
            unsigned char output[32768];
            uint64_t supplied = 0;
            uint64_t good = 0;
            int status = Z_OK;
            while (supplied < available || inflater.avail_in != 0) {
                if (stop && stop()) {
                    result.interrupted = true;
                    break;
                }
                if (inflater.avail_in == 0) {
                    uint64_t count = blocksize - (stream + supplied) % blocksize;
                    if (count > available - supplied) {
                        count = available - supplied;
                    }
                    inflater.next_in = (Bytef *)(data + stream + supplied);
                    inflater.avail_in = (uInt)count;
                    supplied += count;
                }
                uInt before = inflater.avail_in;
                inflater.next_out = output;
                inflater.avail_out = sizeof(output);
                status = inflate(&inflater, Z_NO_FLUSH);
                if (status != Z_OK && status != Z_STREAM_END) {
                    break;
                }
                if (inflater.avail_in == 0 || status == Z_STREAM_END) {
                    good = supplied - inflater.avail_in;
                }
                if (status == Z_STREAM_END) {
                    ended = true;
                    break;
                }
                if (before == inflater.avail_in && inflater.avail_out == sizeof(output)) {
                    break;
                }
            }
            inflateEnd(&inflater);
            result.length = stream + good;
            result.stream_progress |= good != 0;
            if (!ended || result.interrupted) {
                result.needs_more = !result.interrupted && good == available;
                break;
            }
            stream_length = good;
        }
        else if (metadata.jpeg || (metadata.xml && !metadata.has_filter)) {
            uint64_t good = pdf_embedded_stream_prefix(data + stream, available,
                metadata.has_length ? stream_length : 0, stream, blocksize,
                metadata.jpeg, stop, &result.interrupted);
            result.length = stream + good;
            result.stream_progress |= good != 0;
            if (result.interrupted || !metadata.has_length || good < stream_length) {
                result.needs_more = !result.interrupted && good == available;
                break;
            }
        }
        else if (!metadata.has_length || stream_length > available) {
            result.needs_more = metadata.has_length && stream_length > available;
            break;
        }
        uint64_t tail = pdf_partial_skip_space(data, stream + stream_length, length, stop);
        if (tail > length || length - tail < 9 || memcmp(data + tail, "endstream", 9)) {
            break;
        }
        tail = pdf_partial_skip_space(data, tail + 9, length, stop);
        if (tail > length || length - tail < 6 || memcmp(data + tail, "endobj", 6)) {
            break;
        }
        result.length = tail + 6;
        result.complete_length = result.length;
        result.objects++;
        cursor = result.length;
    }
finished:
    if (stop && stop()) {
        result.interrupted = true;
    }
    free(stack);
    return result;
}

static bool pdf_prefix_checkpoint_requested(void) {
    return atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)
        || atomic_load_explicit(&TAKE_CHECKPOINT_AND_EXIT, memory_order_acquire);
}

static void pdf_partial_prefix_release(PDFPartialPrefix *prefix) {
    if (prefix && atomic_fetch_sub_explicit(&prefix->references, 1,
                                             memory_order_acq_rel) == 1) {
        free(prefix);
    }
}

// Preserve the longest parsed prefix without changing the active blockvector.
static void pdf_preserve_partial_prefix(CarveInfo *candidate) {
    if (!candidate || !candidate->b || scalpel_state.blocksize == 0) {
        return;
    }
    uint64_t length = pdf_candidate_trusted_prefix_length(candidate);
    PDFCarveState *state = carve_get_state(candidate->carvehashkey);
    if (state && state->partial_prefix && length <= state->partial_prefix->length) {
        pdf_free_carve_state((void **)&state);
        return;
    }
    PDFPrefixScan scan = pdf_scan_forward_prefix(
        (const unsigned char *)blockvector_get_data_pointer(candidate->b),
        length, scalpel_state.blocksize, pdf_prefix_checkpoint_requested);
    if ((scan.objects == 0 && !scan.stream_progress) || scan.length == 0
        || (state && state->partial_prefix && scan.length <= state->partial_prefix->length)) {
        pdf_free_carve_state((void **)&state);
        return;
    }
    uint64_t count = CEILDIV(scan.length, scalpel_state.blocksize);
    if (count > blockvector_get_num_blocks(candidate->b)
        || count > (SIZE_MAX - sizeof(PDFPartialPrefix)) / sizeof(int64_t)) {
        pdf_free_carve_state((void **)&state);
        return;
    }
    PDFPartialPrefix *prefix = malloc(sizeof(*prefix) + count * sizeof(int64_t));
    check_memory_allocation(prefix, __LINE__, __FILE__, "PDF partial mapping");
    atomic_init(&prefix->references, 1);
    prefix->length = scan.length;
    prefix->count = count;
    uint64_t image_blocks = CEILDIV(filemirror_filesize(scalpel_state.filemirror),
                                    scalpel_state.blocksize);
    // Keep the checked prefix even if its scan stopped for a checkpoint. Only
    // the compact mapping is copied here, before the caller returns to idle.
    for (uint64_t slot = 0; slot < count; slot++) {
        int64_t actual = blockvector_get_actual_blocknumber(candidate->b, slot);
        if (actual < 0 || (uint64_t)actual >= image_blocks) {
            pdf_partial_prefix_release(prefix);
            pdf_free_carve_state((void **)&state);
            return;
        }
        prefix->actual[slot] = actual;
    }
    if (!state) {
        state = calloc(1, sizeof(*state));
        check_memory_allocation(state, __LINE__, __FILE__, "PDF carve state");
        state->lin_L = -1;
        state->lin_T = -1;
        pdf_xref_search_state_init(&state->xref_search);
    }
    pdf_partial_prefix_release(state->partial_prefix);
    state->partial_prefix = prefix;
    carve_put_state(candidate->carvehashkey, state);
    pdf_free_carve_state((void **)&state);
}

// Match a stream terminator at its declared block-local position. Whitespace
// and the keyword may cross physical block boundaries.
static bool pdf_partial_endstream_at(int64_t actual, uint64_t offset) {
    const char marker[] = "endstream";
    size_t matched = 0;
    uint64_t visited = 0;
    bool started = false;
    for (;;) {
        uint64_t available = 0;
        const char *data = filemirror_actual_block_data_pointer(
            scalpel_state.filemirror, actual, &available);
        if (!data || offset >= available) {
            return false;
        }
        while (offset < available) {
            if ((visited++ & 1023) == 0 && pdf_prefix_checkpoint_requested()) {
                return false;
            }
            unsigned char value = (unsigned char)data[offset++];
            if (!started && pdf_lexical_space(value)) {
                continue;
            }
            started = true;
            if (matched == sizeof(marker) - 1) {
                return pdf_lexical_space(value) || pdf_lexical_delimiter(value);
            }
            if (value != (unsigned char)marker[matched++]) {
                return false;
            }
        }
        if (actual == INT64_MAX) {
            return false;
        }
        actual++;
        offset = 0;
    }
}

// Check a candidate JPEG continuation without copying its bytes. The parser
// borrows the input solely for the existing exact-extent completion check.
static bool pdf_partial_jpeg_complete(const unsigned char *data, size_t length) {
    JpegStreamReassembler jpeg = {0};
    jpeg.state = J_START;
    jpeg.stream_length = length;
    jpeg.fed = length;
    jpeg.output = (unsigned char *)data;
    jpeg.output_len = length;
    for (size_t i = 0; i < length; i++) {
        if ((i & 1023) == 0 && pdf_prefix_checkpoint_requested()) {
            return false;
        }
        jpeg_feed_byte(&jpeg, data[i]);
        if (jpeg.malformed) {
            return false;
        }
    }
    return pdf_jpeg_extent_complete(&jpeg);
}

// Continue a retained body when its final checked stream crosses a gap. A
// declared stream length locates possible tail runs; the body parser must then
// finish that stream and its object. Later unfinished data is retained only if
// its entire prefix parses up to a known coverage, source-reuse, or image bound.
// This search neither replaces the main assembly nor promotes a file to VALIDATED.
static void pdf_extend_partial_prefix(CarveInfo *candidate) {
    if (!candidate || !candidate->b || !scalpel_state.write_promising
        || scalpel_state.blocksize == 0) {
        return;
    }
    PDFCarveState *state = carve_get_state(candidate->carvehashkey);
    if (!state || !state->partial_prefix) {
        pdf_free_carve_state((void **)&state);
        return;
    }
    const uint64_t bsz = scalpel_state.blocksize;
    const uint64_t image_size = filemirror_filesize(scalpel_state.filemirror);
    const uint64_t total = CEILDIV(image_size, bsz);
    const uint64_t maximum = scalpel_state.search_specs[candidate->needleidx].MAXIMUMSIZE;
    const uint64_t source_length = state->partial_search_active
        ? state->partial_search_length : state->partial_prefix->length;
    uint64_t source_count = source_length / bsz;
    unsigned char *data = NULL;
    roaring64_bitmap_t *source_blocks = NULL;
    if (source_length == 0 || source_length % bsz != 0
        || source_length > SIZE_MAX || source_length >= maximum
        || source_count > state->partial_prefix->count || total > INT64_MAX) {
        goto finished;
    }
    data = malloc((size_t)source_length);
    check_memory_allocation(data, __LINE__, __FILE__, "PDF partial search data");
    source_blocks = roaring64_bitmap_create();
    check_memory_allocation(source_blocks, __LINE__, __FILE__, "PDF partial source blocks");
    state->partial_search_active = true;
    state->partial_search_length = source_length;
    for (uint64_t slot = 0; slot < source_count; slot++) {
        if ((slot & 255) == 0 && pdf_prefix_checkpoint_requested()) {
            goto save;
        }
        int64_t actual = state->partial_prefix->actual[slot];
        uint64_t available = 0;
        const char *block = filemirror_actual_block_data_pointer(
            scalpel_state.filemirror, actual, &available);
        if (actual < 0 || !block || available < bsz) {
            goto finished;
        }
        memcpy(data + slot * bsz, block, (size_t)bsz);
        roaring64_bitmap_add(source_blocks, (uint64_t)actual);
    }
    PDFPrefixScan original = pdf_scan_forward_prefix(
        data, source_length, (uint32_t)bsz, pdf_prefix_checkpoint_requested);
    if (original.interrupted) {
        goto save;
    }
    if ((!original.stream_flate && !original.stream_jpeg)
        || original.stream_length == 0 || original.length != source_length
        || original.stream_offset > maximum
        || original.stream_length > maximum - original.stream_offset) {
        goto finished;
    }
    uint64_t stream_end = original.stream_offset + original.stream_length;
    if (stream_end <= source_length) {
        goto finished;
    }
    uint64_t tail_blocks = (stream_end - source_length) / bsz;
    for (; (uint64_t)state->partial_search_next < total; state->partial_search_next++) {
        int64_t end_actual = state->partial_search_next;
        if (pdf_prefix_checkpoint_requested()) {
            goto save;
        }
        if ((uint64_t)end_actual < tail_blocks
            || filemirror_apparent_blocknumber(scalpel_state.filemirror, end_actual) < 0
            || filemirror_actual_block_covered(scalpel_state.filemirror, end_actual)
            || !pdf_partial_endstream_at(end_actual, stream_end % bsz)) {
            if (pdf_prefix_checkpoint_requested()) {
                goto save;
            }
            continue;
        }
        int64_t run_start = end_actual - (int64_t)tail_blocks;
        uint64_t limit = image_size - (uint64_t)run_start * bsz;
        if (limit > maximum - source_length) {
            limit = maximum - source_length;
        }
        if (limit > SIZE_MAX - source_length) {
            limit = SIZE_MAX - source_length;
        }
        uint64_t wanted = tail_blocks * bsz;
        if (wanted > limit || limit - wanted < 2 * bsz) {
            wanted = limit;
        }
        else {
            wanted += 2 * bsz;
        }
        uint64_t copied = 0;
        bool anchor_checked = false;
        while (wanted > copied) {
            bool bounded = false;
            data = realloc(data, (size_t)(source_length + wanted));
            check_memory_allocation(data, __LINE__, __FILE__, "PDF partial continuation");
            while (copied < wanted) {
                if (pdf_prefix_checkpoint_requested()) {
                    goto save;
                }
                int64_t actual = run_start + (int64_t)(copied / bsz);
                if (roaring64_bitmap_contains(source_blocks, (uint64_t)actual)
                    || filemirror_actual_block_covered(scalpel_state.filemirror, actual)) {
                    bounded = true;
                    break;
                }
                if (filemirror_apparent_blocknumber(scalpel_state.filemirror, actual) < 0) {
                    break;
                }
                uint64_t available = 0;
                const char *block = filemirror_actual_block_data_pointer(
                    scalpel_state.filemirror, actual, &available);
                uint64_t take = wanted - copied;
                if (!block || available == 0) {
                    break;
                }
                if (take > available) {
                    take = available;
                }
                memcpy(data + source_length + copied, block, (size_t)take);
                copied += take;
                if (take < bsz) {
                    break;
                }
            }
            PDFPrefixScan scan = pdf_scan_forward_prefix(data, source_length + copied,
                (uint32_t)bsz, pdf_prefix_checkpoint_requested);
            bounded |= copied == image_size - (uint64_t)run_start * bsz;
            uint64_t retained = scan.complete_length;
            if (bounded && !scan.interrupted && scan.length == source_length + copied) {
                retained = scan.length;
            }
            if (scan.complete_length > stream_end && scan.objects > original.objects
                && retained > state->partial_prefix->length) {
                if (original.stream_jpeg && !anchor_checked) {
                    anchor_checked = pdf_partial_jpeg_complete(data + original.stream_offset,
                                                               (size_t)original.stream_length);
                    if (!anchor_checked) {
                        if (pdf_prefix_checkpoint_requested()) {
                            goto save;
                        }
                        break;
                    }
                }
                uint64_t count = CEILDIV(retained, bsz);
                if (count <= (SIZE_MAX - sizeof(PDFPartialPrefix)) / sizeof(int64_t)) {
                    PDFPartialPrefix *best = malloc(sizeof(*best) + count * sizeof(int64_t));
                    check_memory_allocation(best, __LINE__, __FILE__, "PDF continued partial mapping");
                    atomic_init(&best->references, 1);
                    best->length = retained;
                    best->count = count;
                    memcpy(best->actual, state->partial_prefix->actual,
                           (size_t)source_count * sizeof(int64_t));
                    for (uint64_t slot = source_count; slot < count; slot++) {
                        best->actual[slot] = run_start + (int64_t)(slot - source_count);
                    }
                    pdf_partial_prefix_release(state->partial_prefix);
                    state->partial_prefix = best;
                }
            }
            if (scan.interrupted || pdf_prefix_checkpoint_requested()) {
                goto save;
            }
            if (copied < wanted || wanted == limit
                || (!scan.needs_more && scan.length < source_length + copied)) {
                break;
            }
            wanted = wanted > limit / 2 ? limit : wanted * 2;
        }
    }
finished:
    state->partial_search_active = false;
    state->partial_search_length = 0;
    state->partial_search_next = 0;
save:
    free(data);
    roaring64_bitmap_free(source_blocks);
    carve_put_state(candidate->carvehashkey, state);
    pdf_free_carve_state((void **)&state);
}

// Capture initial bytes before the backend trims the candidate for reassembly.
static void pdf_candidate_preserve_prefix(CarveInfo *candidate, bool *validates,
                                           uint64_t *validates_to, bool *promising) {
    if (!*validates && *promising && scalpel_state.write_promising
        && *validates_to < blockvector_get_data_length(candidate->b)) {
        bool complete = false, checked = false, partial = false;
        uint64_t end = 0;
        pdf_file_validate_content(blockvector_get_data_pointer(candidate->b),
            *validates_to + 1, &checked, &end, &partial, candidate->needleidx,
            scalpel_state.blocksize, candidate->carvehashkey, &complete);
        if (complete && end <= *validates_to) {
            // Keep a complete but unverified encrypted/document hypothesis,
            // including in contiguous-only mode. Do not claim its blocks.
            CarveInfo snapshot = *candidate;
            clone_blockvector(candidate->b, &snapshot.b, false);
            blockvector_set_data_length(snapshot.b, end + 1);
            resize_blockvector(snapshot.b, CEILDIV(end + 1, scalpel_state.blocksize));
            inflate_blockvector(snapshot.b);
            snapshot.flavor = PROMISING;
            CarveInfo *preserved = &snapshot;
            write_candidate(&preserved, true);
            candidate->partial_artifact_written |= snapshot.partial_artifact_written;
            free_blockvector(&snapshot.b);
        }
    }
    if (!*validates && *promising && !candidate->deposited && !scalpel_state.no_defrag) {
        pdf_preserve_partial_prefix(candidate);
    }
}

// Publish at most one retained prefix after search, without replacing its result.
static void pdf_write_partial_prefix(CarveInfo *candidate) {
    if (!scalpel_state.write_promising) {
        return;
    }
    PDFCarveState *state = carve_get_state(candidate->carvehashkey);
    PDFPartialPrefix *prefix = state ? state->partial_prefix : NULL;
    if (!prefix) {
        pdf_free_carve_state((void **)&state);
        return;
    }
    BlockVector *partial = NULL;
    init_blockvector(scalpel_state.filemirror, &partial, prefix->count, true);
    uint64_t count = 0;
    uint64_t image_size = filemirror_filesize(scalpel_state.filemirror);
    uint64_t image_blocks = CEILDIV(image_size, scalpel_state.blocksize);
    for (; count < prefix->count; count++) {
        int64_t actual = prefix->actual[count];
        if (actual < 0 || (uint64_t)actual >= image_blocks) {
            break;
        }
        int64_t apparent = filemirror_apparent_blocknumber(scalpel_state.filemirror, actual);
        if (apparent < 0) {
            break;
        }
        blockvector_set_apparent_blocknumber(partial, count, apparent);
    }
    if (count != 0) {
        uint64_t length = count == prefix->count ? prefix->length
                                                : count * (uint64_t)scalpel_state.blocksize;
        uint64_t available = count * (uint64_t)scalpel_state.blocksize;
        if ((uint64_t)prefix->actual[count - 1] == image_blocks - 1
            && image_size % scalpel_state.blocksize != 0) {
            available -= scalpel_state.blocksize - image_size % scalpel_state.blocksize;
        }
        if (length > available) {
            length = available;
        }
        resize_blockvector(partial, count);
        blockvector_set_data_length(partial, available);
        inflate_blockvector(partial);
        // Check the unused bytes of the retained final block without extending
        // the search mapping or changing its exact saved length.
        if (count == prefix->count && length < available) {
            PDFPrefixScan scan = pdf_scan_forward_prefix(
                (const unsigned char *)blockvector_get_data_pointer(partial),
                available, scalpel_state.blocksize, pdf_prefix_checkpoint_requested);
            if (!scan.interrupted && scan.length > length && scan.length <= available) {
                length = scan.length;
            }
        }
        blockvector_set_data_length(partial, length);
        BlockVector *original = candidate->b;
        CarveInfoFlavor flavor = candidate->flavor;
        candidate->b = partial;
        candidate->flavor = PROMISING;
        write_candidate(&candidate, true);
        candidate->b = original;
        candidate->flavor = flavor;
    }
    free_blockvector(&partial);
    pdf_free_carve_state((void **)&state);
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
