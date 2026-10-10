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

// Microsoft Portable Executable (PE) validation and fragmented recovery.
//
// PE images do not have a terminal signature. Their on-disk extent is described by the PE header,
// section table, debug records, COFF symbol data, and attribute certificate table. The validator
// derives that extent, checks the structures reachable through the data directories, and uses the
// image checksum and Authenticode image digest when they are present. The same layout information
// guides fragmented recovery.
//

#ifndef SCALPEL3_EXE_H
#define SCALPEL3_EXE_H

#include "scalpel.h"

#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <zlib.h>

#define EXE_DOS_HEADER_SIZE 64U
#define EXE_COFF_HEADER_SIZE 20U
#define EXE_COFF_SYMBOL_SIZE 18U
#define EXE_COFF_STRING_TABLE_HEADER_SIZE 4U
#define EXE_SECTION_HEADER_SIZE 40U
#define EXE_MAX_SECTIONS 96U
#define EXE_MAX_DIRECTORIES 16U
#define EXE_MAX_PE_HEADER_OFFSET (16U * 1024U * 1024U)
#define EXE_MAX_IMPORT_DESCRIPTORS 65536U
#define EXE_MAX_IMPORT_THUNKS 1048576U
#define EXE_MAX_EXCEPTION_ENTRIES 1048576U
#define EXE_MAX_LOAD_CONFIG_ENTRIES 1048576U
#define EXE_MAX_TLS_CALLBACKS 65536U
#define EXE_MAX_CLR_STREAMS 1024U
#define EXE_MAX_CLR_METHODS 1048576U
#define EXE_MAX_ORDER_ANCHORS 1048576U
#define EXE_MAX_RESOURCE_DEPTH 8U
#define EXE_MAX_RESOURCE_NODES 1048576U
#define EXE_MAX_RESOURCE_EVIDENCE_RECORDS 16384U
#define EXE_MAX_STRING_LENGTH 4096U
#define EXE_WIN_CERTIFICATE_HEADER_SIZE 8U
#define EXE_CHECKSUM_RESIDUES 65535U
#define EXE_REASSEMBLY_POLL_INTERVAL 256U
#define EXE_ORDER_EVIDENCE_DOMINANCE 16U
#define EXE_ORDER_EVIDENCE_MINIMUM 128U
#define EXE_ZERO_COMPOSITION_MAX_DESTINATIONS 2U
#define EXE_ZERO_COMPOSITION_STATE_LIMIT 262144U
#define EXE_ZERO_RESUME_ENTRY_NONE UINT64_MAX
#define EXE_ZERO_ALTERNATIVE_CLASSES 3U
#define EXE_ZERO_ALTERNATIVE_LIMIT_PER_CLASS 256U
#define EXE_ZERO_ALTERNATIVE_OUTPUT_BUDGET_PER_CLASS \
  (UINT64_C(96) * 1024U * 1024U)
#define EXE_CARVE_STATE_MAGIC UINT64_C(0x4558455354415445)
#define EXE_CARVE_STATE_VERSION UINT32_C(8)
#define EXE_MAXIMUM_FILE_SIZE UINT64_C(268435456)

// Bound each worker's gap-search prefix table independently of image size.
#define EXE_GAP_SCAN_CHUNK_WIDTH 4096U
#define EXE_CONFIDENCE_GAP_RUNS 4U
#define EXE_CONFIDENCE_GAP_EDGE_SLACK 4U
#define EXE_CONFIDENCE_GAP_CONTEXT_BLOCKS 64U
#define EXE_CONFIDENCE_GAP_HINTS \
  (EXE_CONFIDENCE_GAP_RUNS \
   * (EXE_CONFIDENCE_GAP_EDGE_SLACK + 1U) \
   * (EXE_CONFIDENCE_GAP_EDGE_SLACK + 1U))
#define EXE_CONFIDENCE_OOO_EDGES 8U
#define EXE_CONFIDENCE_OOO_WINDOW 32U
#define EXE_CONFIDENCE_OOO_EDGE_SLACK 8U
#define EXE_CONFIDENCE_OOO_CANDIDATES \
  (EXE_CONFIDENCE_GAP_HINTS \
   + EXE_CONFIDENCE_OOO_EDGES \
     * (2U * EXE_CONFIDENCE_OOO_EDGE_SLACK + 1U) + 2U)

// Bound each worker's displaced-run checksum index independently of image size.
#define EXE_SOURCE_INDEX_CHUNK_WIDTH 65536U

#define EXE_IMAGE_FILE_EXECUTABLE_IMAGE UINT16_C(0x0002)
#define EXE_IMAGE_FILE_DLL UINT16_C(0x2000)
#define EXE_IMAGE_SCN_MEM_EXECUTE UINT32_C(0x20000000)
#define EXE_WIN_CERT_TYPE_PKCS_SIGNED_DATA UINT16_C(0x0002)
#define EXE_RESOURCE_TYPE_ICON 3U
#define EXE_RESOURCE_TYPE_GROUP_ICON 14U

typedef enum ExeParseResult {
  EXE_PARSE_INVALID = 0,
  EXE_PARSE_PARTIAL = 1,
  EXE_PARSE_COMPLETE = 2
} ExeParseResult;

typedef enum ExeRecoveryResult {
  EXE_RECOVERY_NO_MATCH = 0,
  EXE_RECOVERY_MATCH = 1,
  EXE_RECOVERY_PROMISING_MATCH = 2,
  EXE_RECOVERY_STOPPED = 3
} ExeRecoveryResult;

typedef enum ExeMappingResult {
  EXE_MAPPING_INVALID = 0,
  EXE_MAPPING_COMPLETE = 1,
  EXE_MAPPING_ORDER_PROVEN = 2,
  EXE_MAPPING_CRYPTOGRAPHIC = 3
} ExeMappingResult;

typedef struct ExeDirectory {
  uint32_t rva;
  uint32_t size;
} ExeDirectory;

typedef struct ExeSection {
  char name[9];
  uint32_t virtual_size;
  uint32_t virtual_address;
  uint32_t raw_size;
  uint32_t raw_offset;
  uint32_t characteristics;
} ExeSection;

typedef struct ExeLayout {
  bool header_valid;
  bool pe32_plus;
  bool sections_valid;
  bool directories_valid;
  bool certificate_table_valid;
  bool checksum_present;
  bool checksum_matches;
  bool authenticode_present;
  bool authenticode_matches;
  uint16_t machine;
  uint16_t section_count;
  uint16_t optional_header_size;
  uint16_t characteristics;
  uint32_t pe_offset;
  uint32_t optional_header_offset;
  uint32_t section_table_offset;
  uint32_t checksum_offset;
  uint32_t certificate_directory_offset;
  uint32_t section_alignment;
  uint32_t file_alignment;
  uint32_t size_of_image;
  uint32_t size_of_headers;
  uint32_t address_of_entry_point;
  uint64_t image_base;
  uint32_t stored_checksum;
  uint32_t certificate_offset;
  uint32_t certificate_size;
  uint32_t coff_symbol_offset;
  uint32_t coff_symbol_count;
  uint32_t coff_string_table_size;
  uint32_t directory_count;
  uint64_t image_extent;
  uint64_t coff_symbol_end;
  uint64_t described_extent;
  uint64_t failure_offset;
  ExeDirectory directories[EXE_MAX_DIRECTORIES];
  ExeSection sections[EXE_MAX_SECTIONS];
} ExeLayout;

typedef struct ExeBlockOrderEvidence {
  uint32_t local_references;
  uint32_t target_references;
  uint32_t cross_references;
  uint32_t validated_target_references;
  uint32_t relocation_values;
  uint32_t control_flow_references;
} ExeBlockOrderEvidence;

typedef struct ExeOrderEvidence {
  uint64_t region_offset;
  uint64_t region_length;
  uint32_t metadata_records;
  uint32_t local_references;
  uint32_t target_references;
  uint32_t cross_references;
  uint32_t validated_target_references;
  uint32_t relocation_values;
  uint32_t control_flow_references;
  uint32_t cryptographic_regions;
  uint32_t *anchors;
  uint32_t anchor_count;
  uint32_t anchor_capacity;
  ExeBlockOrderEvidence *blocks;
  uint64_t first_block;
  uint64_t block_count;
} ExeOrderEvidence;

typedef struct ExeRecoveryAccumulator {
  int64_t *mapping;
  int64_t *gap_mapping;
  int64_t *complete_mapping;
  uint64_t total_blocks;
  uint64_t qualified_mappings;
  uint64_t gap_mappings;
  uint64_t complete_mappings;
  uint64_t strongest_order_evidence;
  uint64_t second_order_evidence;
  uint64_t baseline_repair_first;
  uint64_t baseline_repair_last;
  bool ambiguous;
  bool gap_ambiguous;
  bool complete_ambiguous;
  bool require_baseline_repair;
} ExeRecoveryAccumulator;

typedef struct ExeGapHint {
  uint64_t boundary;
  uint64_t gap_blocks;
} ExeGapHint;

typedef struct ExeSourceRunIndex {
  uint32_t *heads;
  uint32_t *next;
  uint16_t *folded_sums;
  uint8_t *valid;
  uint64_t source_first;
  uint64_t source_count;
  uint64_t run_blocks;
} ExeSourceRunIndex;

typedef struct ExeZeroDestination {
  uint64_t first_slot;
  uint64_t block_count;
} ExeZeroDestination;

typedef struct ExeZeroAlternativeRank {
  uint64_t confidence_sum;
  uint64_t scored_blocks;
  uint64_t order_strength;
  uint64_t crossing_references;
  uint64_t reservations;
  uint64_t diversity;
  uint32_t minimum_confidence;
} ExeZeroAlternativeRank;

typedef struct ExeZeroAlternativeSet {
  int64_t *mappings;
  ExeZeroAlternativeRank *ranks;
  uint64_t total_blocks;
  uint32_t capacity_per_class;
  uint32_t counts[EXE_ZERO_ALTERNATIVE_CLASSES];
} ExeZeroAlternativeSet;

typedef enum ExeZeroResumePhase {
  EXE_ZERO_RESUME_NONE = 0,
  EXE_ZERO_RESUME_PAIR = 1,
  EXE_ZERO_RESUME_OOO_MAIN = 2,
  EXE_ZERO_RESUME_OOO_FINAL = 3
} ExeZeroResumePhase;

typedef enum ExeSearchPhase {
  EXE_SEARCH_INITIAL = 0,
  EXE_SEARCH_GAP,
  EXE_SEARCH_COMMON,
  EXE_SEARCH_OOO,
  EXE_SEARCH_COMBINED,
  EXE_SEARCH_DONE
} ExeSearchPhase;

typedef struct ExeRunProgress {
  uint64_t outer;
  uint64_t inner;
  uint64_t entry;
  uint32_t phase;
  uint32_t reserved;
} ExeRunProgress;

typedef enum ExeCoffPhase {
  EXE_COFF_INITIAL = 0,
  EXE_COFF_SEARCH,
  EXE_COFF_COMPLETE,
  EXE_COFF_FAILED
} ExeCoffPhase;

typedef struct ExeCoffProgress {
  uint64_t next_gap;
  uint64_t next_boundary;
  uint32_t string_size;
  uint32_t phase;
} ExeCoffProgress;

typedef struct ExeGapHintScan {
  uint64_t longest_first[EXE_CONFIDENCE_GAP_RUNS];
  uint64_t longest_length[EXE_CONFIDENCE_GAP_RUNS];
  uint64_t next_offset;
  uint64_t run_first;
  uint64_t run_length;
  uint8_t complete;
  uint8_t reserved[7];
} ExeGapHintScan;

typedef struct ExeConfidenceEdges {
  uint64_t offsets[EXE_CONFIDENCE_OOO_EDGES];
  uint64_t scores[EXE_CONFIDENCE_OOO_EDGES];
  uint64_t next_boundary;
  uint64_t left_sum;
  uint64_t right_sum;
  uint32_t count;
  uint8_t initialized;
  uint8_t complete;
  uint8_t reserved[2];
} ExeConfidenceEdges;

// Retain the ranked choices with their next trial positions. A checkpoint
// resumes the same ordering rather than rebuilding a partially consumed list.
typedef struct ExeHintProgress {
  ExeGapHintScan gap_scan;
  ExeConfidenceEdges destination_edges;
  ExeConfidenceEdges source_edges;
  ExeGapHint gaps[EXE_CONFIDENCE_GAP_HINTS];
  uint64_t destinations[EXE_CONFIDENCE_OOO_CANDIDATES];
  uint64_t widths[EXE_CONFIDENCE_OOO_CANDIDATES];
  uint64_t next_destination;
  uint32_t gap_count;
  uint32_t next_gap;
  uint32_t destination_count;
  uint32_t width_count;
  uint32_t next_width;
  uint8_t gaps_ready;
  uint8_t ooo_ready;
  uint8_t ooo_complete;
  uint8_t reserved;
} ExeHintProgress;

typedef struct ExeRelocationConstraint {
  uint64_t offset;
  uint32_t width;
} ExeRelocationConstraint;

// Keep one proposed mapping and the next physical block to examine. Multiple
// physical copies of identical bytes are one choice, not competing contents.
typedef struct ExeRelocationProgress {
  uint64_t next_constraint;
  uint64_t next_actual;
  int64_t choice_actual;
  uint8_t initialized;
  uint8_t complete;
  uint8_t ambiguous;
  uint8_t reserved[5];
} ExeRelocationProgress;

// Persistent PE search state. The flexible array contains all retained
// mappings followed by their ranks, so cloning and checkpoint serialization
// never retain process-local pointers.
typedef struct ExeCarveState {
  uint64_t magic;
  uint32_t version;
  uint32_t capacity_per_class;
  uint64_t allocation_size;
  uint64_t total_blocks;
  uint64_t described_extent;
  int64_t start_block;
  uint64_t view_hash_low;
  uint64_t view_hash_high;
  uint64_t gap_next_width;
  uint64_t gap_next_boundary;
  uint64_t search_width;
  uint64_t search_inner;
  uint64_t combined_source;
  uint64_t combined_boundary;
  ExeRunProgress zero_run;
  ExeRunProgress general_run;
  ExeCoffProgress coff;
  ExeHintProgress hints;
  ExeRelocationProgress relocations;
  uint64_t zero_resume_terminal;
  uint64_t qualified_mappings;
  uint64_t gap_mappings;
  uint64_t complete_mappings;
  uint64_t strongest_order_evidence;
  uint64_t second_order_evidence;
  uint64_t baseline_repair_first;
  uint64_t baseline_repair_last;
  uint32_t alternative_counts[EXE_ZERO_ALTERNATIVE_CLASSES];
  uint32_t search_phase;
  uint32_t search_edge;
  uint32_t combined_pass;
  uint8_t zero_complete;
  uint8_t mapping_published;
  uint8_t ambiguous;
  uint8_t gap_ambiguous;
  uint8_t complete_ambiguous;
  uint8_t require_baseline_repair;
  uint8_t zero_initialized;
  uint8_t gap_complete;
  uint8_t view_initialized;
  uint8_t reserved[7];
  uint8_t storage[];
} ExeCarveState;

typedef struct ExeReassemblyContext {
  ThreadWork *work;
  CarveInfo **candidate;
  char *uuidp;
  char *uuidc;
  const ExeLayout *layout;
  const int64_t *baseline_mapping;
  uint64_t total_blocks;
  uint64_t header_blocks;
  uint64_t apparent_blocks;
  int64_t start;
  uint8_t *trial_data;
  int64_t *mapping;
  int64_t *pair_mapping;
  uint64_t *mapping_sums;
  int64_t *solution_mapping;
  ExeRecoveryAccumulator *accumulator;
  ExeZeroAlternativeSet *alternatives;
  int64_t *published_mapping;
  bool *mapping_published;
  uint64_t *iterations;
  ExeCarveState *state;
  ExeRunProgress *run_progress;
  uint64_t states_visited;
  uint64_t terminal_index;
  ExeRecoveryResult result;
} ExeReassemblyContext;

typedef struct ExeRawRange {
  uint32_t offset;
  uint32_t size;
} ExeRawRange;

typedef enum ExeClrColumnKind {
  EXE_CLR_COLUMN_U16 = 0,
  EXE_CLR_COLUMN_U32,
  EXE_CLR_COLUMN_STRING,
  EXE_CLR_COLUMN_GUID,
  EXE_CLR_COLUMN_BLOB,
  EXE_CLR_COLUMN_TABLE,
  EXE_CLR_COLUMN_LIST,
  EXE_CLR_COLUMN_CODED
} ExeClrColumnKind;

typedef enum ExeClrCodedIndexKind {
  EXE_CLR_CODED_TYPE_DEF_OR_REF = 0,
  EXE_CLR_CODED_HAS_CONSTANT,
  EXE_CLR_CODED_HAS_CUSTOM_ATTRIBUTE,
  EXE_CLR_CODED_HAS_FIELD_MARSHAL,
  EXE_CLR_CODED_HAS_DECL_SECURITY,
  EXE_CLR_CODED_MEMBER_REF_PARENT,
  EXE_CLR_CODED_HAS_SEMANTICS,
  EXE_CLR_CODED_METHOD_DEF_OR_REF,
  EXE_CLR_CODED_MEMBER_FORWARDED,
  EXE_CLR_CODED_IMPLEMENTATION,
  EXE_CLR_CODED_CUSTOM_ATTRIBUTE_TYPE,
  EXE_CLR_CODED_RESOLUTION_SCOPE,
  EXE_CLR_CODED_TYPE_OR_METHOD_DEF
} ExeClrCodedIndexKind;

typedef struct ExeClrColumn {
  ExeClrColumnKind kind;
  uint8_t target;
} ExeClrColumn;

typedef struct ExeClrTableSchema {
  uint8_t column_count;
  ExeClrColumn columns[9];
} ExeClrTableSchema;

typedef struct ExeClrTableLayout {
  uint64_t offset;
  uint32_t row_size;
  uint32_t row_count;
  bool present;
} ExeClrTableLayout;

typedef struct ExeClrHeap {
  uint64_t offset;
  uint32_t size;
  bool present;
} ExeClrHeap;

typedef struct ExeClrReference {
  uint64_t source_offset;
  uint64_t target_offset;
  uint32_t source_size;
  uint32_t target_size;
  bool target_validated;
} ExeClrReference;

typedef struct ExeResourceRecord {
  uint32_t type;
  uint32_t id;
  uint32_t language;
  uint32_t content_size;
  uint32_t validated_header_size;
  uint32_t width;
  uint32_t height;
  uint16_t planes;
  uint16_t bit_count;
  uint64_t descriptor_offset;
  uint64_t content_offset;
  bool icon_valid;
} ExeResourceRecord;

typedef struct ExeResourceCatalog {
  ExeResourceRecord *records;
  ExeOrderEvidence *evidence;
  uint32_t count;
  uint32_t capacity;
} ExeResourceCatalog;

typedef struct ExeBlockSumCache {
  pthread_mutex_t lock;
  FileMirror *filemirror;
  uint32_t blocksize;
  uint64_t block_count;
  _Atomic uint64_t *encoded_sums;
} ExeBlockSumCache;

static ExeBlockSumCache exe_block_sum_cache = {
  .lock = PTHREAD_MUTEX_INITIALIZER,
  .filemirror = NULL,
  .blocksize = 0,
  .block_count = 0,
  .encoded_sums = NULL
};

// Function prototypes.
static inline bool exe_range_available(uint64_t length, uint64_t offset,
                                       uint64_t size);
static inline bool exe_add_u64(uint64_t left, uint64_t right,
                               uint64_t *result);
static inline uint16_t exe_read_le16(const uint8_t *data);
static inline uint32_t exe_read_le32(const uint8_t *data);
static inline uint64_t exe_read_le64(const uint8_t *data);
static inline uint32_t exe_read_be32(const uint8_t *data);
static inline bool exe_power_of_two_u32(uint32_t value);
static inline uint64_t exe_align_up_u64(uint64_t value, uint64_t alignment);
static inline void exe_set_failure(ExeLayout *layout, uint64_t offset);
static inline bool exe_machine_supported(uint16_t machine);
static inline bool exe_ranges_overlap(uint64_t first_offset,
                                      uint64_t first_size,
                                      uint64_t second_offset,
                                      uint64_t second_size);
static inline void exe_order_evidence_initialize(
    ExeOrderEvidence *evidence, uint64_t region_offset,
    uint64_t region_length);
static inline void exe_order_evidence_destroy(ExeOrderEvidence *evidence);
static inline bool exe_parse_headers(const uint8_t *data, uint64_t length,
                                     ExeLayout *layout);
static inline bool exe_resolve_coff_string_table_extent(
    const uint8_t *data, uint64_t length, ExeLayout *layout);
static inline bool exe_validate_coff_symbol_table(
    const uint8_t *data, uint64_t length, ExeLayout *layout,
    ExeOrderEvidence *evidence);
static inline bool exe_copy_gap_mapped_range(
    int64_t start, uint64_t gap_blocks, uint64_t boundary,
    uint64_t logical_offset, uint64_t length, uint8_t *destination,
    bool uncovered_only);
static inline bool exe_gap_mapped_coff_extent(
    const ExeLayout *layout, int64_t start, uint64_t gap_blocks,
    uint64_t boundary, uint64_t maximum_size, uint32_t *string_size);
static inline bool exe_resolve_fragmented_coff_extent(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, ExeLayout *layout, int64_t start,
    uint64_t apparent_blocks, uint64_t header_blocks,
    uint64_t maximum_size, uint64_t *iterations, ExeCarveState *state,
    bool *stopped);
static inline bool exe_rva_to_file_offset(const ExeLayout *layout,
                                          uint32_t rva, uint32_t size,
                                          uint64_t *offset);
static inline bool exe_rva_bytes_available(const ExeLayout *layout,
                                           uint32_t rva, uint64_t *offset,
                                           uint64_t *available);
static inline bool exe_va_to_rva(const ExeLayout *layout, uint64_t va,
                                 uint32_t *rva);
static inline bool exe_rva_is_executable(const ExeLayout *layout,
                                         uint32_t rva);
static inline bool exe_file_range_is_executable(const ExeLayout *layout,
                                                uint64_t offset,
                                                uint64_t length);
static inline void exe_evidence_note_record(ExeOrderEvidence *evidence,
                                            uint64_t offset,
                                            uint64_t size);
static inline void exe_evidence_note_reference(ExeOrderEvidence *evidence,
                                               uint64_t source_offset,
                                               uint64_t source_size,
                                               uint64_t target_offset,
                                               uint64_t target_size);
static inline void exe_evidence_note_validated_reference(
    ExeOrderEvidence *evidence, uint64_t source_offset,
    uint64_t source_size, uint64_t target_offset, uint64_t target_size);
static inline void exe_evidence_note_control_flow(
    ExeOrderEvidence *evidence, uint64_t source_offset,
    uint64_t source_size, uint64_t target_offset, uint64_t target_size);
static inline void exe_evidence_add_anchor(ExeOrderEvidence *evidence,
                                           uint32_t rva);
static inline int exe_compare_u32(const void *left, const void *right);
static inline bool exe_evidence_has_anchor(const ExeOrderEvidence *evidence,
                                           uint32_t rva);
static inline bool exe_order_evidence_sufficient(
    const ExeOrderEvidence *evidence);
static inline bool exe_order_evidence_disconnected_code_range(
    const ExeLayout *layout, const ExeOrderEvidence *evidence,
    uint64_t *first_block, uint64_t *last_block);
static inline bool exe_authenticode_region_covered(
    const ExeLayout *layout, uint64_t offset, uint64_t length);
static inline bool exe_validate_ascii_string(const uint8_t *data,
                                             uint64_t length,
                                             uint64_t offset,
                                             uint64_t limit,
                                             ExeLayout *layout);
static inline bool exe_validate_export_directory(const uint8_t *data,
                                                 uint64_t length,
                                                 ExeLayout *layout);
static inline bool exe_validate_import_directory(const uint8_t *data,
                                                 uint64_t length,
                                                 ExeLayout *layout,
                                                 uint32_t directory_index);
static inline bool exe_validate_relocation_directory(const uint8_t *data,
                                                     uint64_t length,
                                                     ExeLayout *layout);
static inline bool exe_validate_resource_tree(const uint8_t *data,
                                              uint64_t length,
                                              ExeLayout *layout,
                                              uint64_t root_offset,
                                              uint32_t directory_size,
                                              uint32_t relative_offset,
                                              uint32_t depth,
                                              uint32_t resource_type,
                                              uint32_t resource_id,
                                              uint32_t resource_language,
                                              uint32_t *nodes,
                                              ExeResourceCatalog *catalog);
static inline bool exe_validate_resource_directory(const uint8_t *data,
                                                   uint64_t length,
                                                   ExeLayout *layout,
                                                   ExeOrderEvidence *evidence);
static inline void exe_resource_catalog_add(
    ExeResourceCatalog *catalog, uint32_t type, uint32_t id,
    uint32_t language, uint64_t descriptor_offset,
    uint64_t content_offset, uint32_t content_size);
static inline bool exe_validate_icon_resource(
    const uint8_t *data, uint64_t length, uint64_t content_offset,
    uint32_t content_size, ExeResourceRecord *record);
static inline void exe_collect_group_icon_evidence(
    const uint8_t *data, uint64_t length, ExeResourceCatalog *catalog);
static inline void exe_collect_embedded_pe_evidence(
    const uint8_t *data, uint64_t length, uint64_t content_offset,
    uint32_t content_size, ExeOrderEvidence *evidence);
static inline bool exe_validate_debug_directory(const uint8_t *data,
                                                uint64_t length,
                                                ExeLayout *layout);
static inline bool exe_validate_clr_directory(const uint8_t *data,
                                              uint64_t length,
                                              ExeLayout *layout);
static inline bool exe_validate_export_targets(
    const uint8_t *data, uint64_t length, ExeLayout *layout,
    ExeOrderEvidence *evidence);
static inline bool exe_validate_thunk_table(
    const uint8_t *data, uint64_t length, ExeLayout *layout,
    uint32_t lookup_rva, uint32_t iat_rva, bool allow_bound,
    uint64_t lookup_source_offset, uint64_t iat_source_offset,
    ExeOrderEvidence *evidence);
static inline bool exe_validate_import_thunks(
    const uint8_t *data, uint64_t length, ExeLayout *layout,
    uint32_t directory_index, ExeOrderEvidence *evidence);
static inline bool exe_validate_relocation_entries(
    const uint8_t *data, uint64_t length, ExeLayout *layout,
    ExeOrderEvidence *evidence);
static inline bool exe_validate_exception_directory(
    const uint8_t *data, uint64_t length, ExeLayout *layout,
    ExeOrderEvidence *evidence);
static inline bool exe_validate_x64_unwind_info(
    const uint8_t *data, uint64_t length, ExeLayout *layout,
    uint32_t unwind_rva, uint64_t source_offset,
    ExeOrderEvidence *evidence);
static inline bool exe_validate_tls_directory(
    const uint8_t *data, uint64_t length, ExeLayout *layout,
    ExeOrderEvidence *evidence);
static inline bool exe_validate_load_config_directory(
    const uint8_t *data, uint64_t length, ExeLayout *layout,
    ExeOrderEvidence *evidence);
static inline bool exe_validate_load_config_table(
    const uint8_t *data, uint64_t length, ExeLayout *layout,
    uint64_t table_va, uint64_t count, uint32_t stride,
    bool executable_targets, uint64_t source_offset,
    ExeOrderEvidence *evidence);
static inline bool exe_validate_clr_metadata_streams(
    const uint8_t *data, uint64_t length, ExeLayout *layout,
    ExeOrderEvidence *evidence);
static inline const ExeClrTableSchema *exe_clr_table_schema(uint32_t table);
static inline bool exe_clr_coded_index_info(
    ExeClrCodedIndexKind kind, const uint8_t **tables,
    uint32_t *table_count, uint32_t *tag_bits);
static inline bool exe_clr_column_width(
    const ExeClrColumn *column, uint8_t heap_sizes,
    const uint32_t *row_counts, uint32_t *width);
static inline bool exe_clr_build_table_layouts(
    uint64_t table_offset, uint32_t table_size,
    uint64_t table_data_offset, uint8_t heap_sizes, uint64_t valid,
    const uint32_t *row_counts, ExeClrTableLayout *layouts);
static inline bool exe_clr_heap_reference(
    const uint8_t *data, uint64_t length, const ExeClrHeap *heap,
    ExeClrColumnKind kind, uint32_t index,
    uint64_t *target_offset, uint32_t *target_size);
static inline bool exe_clr_table_reference(
    const ExeClrTableLayout *layouts, const uint32_t *row_counts,
    const ExeClrColumn *column, uint32_t value,
    uint64_t *target_offset, uint32_t *target_size);
static inline bool exe_collect_clr_row_evidence(
    const uint8_t *data, uint64_t length, uint32_t table,
    uint64_t row_offset, uint8_t heap_sizes,
    const uint32_t *row_counts, const ExeClrTableLayout *layouts,
    const ExeClrHeap *strings_heap, const ExeClrHeap *guid_heap,
    const ExeClrHeap *blob_heap, ExeOrderEvidence *evidence);
static inline void exe_collect_clr_table_evidence(
    const uint8_t *data, uint64_t length, uint64_t table_offset,
    uint32_t table_size, uint64_t table_data_offset, uint8_t heap_sizes,
    uint64_t valid, const uint32_t *row_counts,
    const ExeClrHeap *strings_heap, const ExeClrHeap *guid_heap,
    const ExeClrHeap *blob_heap, ExeOrderEvidence *evidence);
static inline uint32_t exe_validate_clr_method_body(
    const uint8_t *data, uint64_t length, const ExeLayout *layout,
    uint32_t method_rva);
static inline void exe_collect_clr_method_evidence(
    const uint8_t *data, uint64_t length, ExeLayout *layout,
    uint64_t table_offset, uint32_t table_size, uint64_t table_data_offset,
    uint8_t heap_sizes, uint64_t valid, const uint32_t *row_counts,
    ExeOrderEvidence *evidence);
static inline bool exe_validate_deep_directories(
    const uint8_t *data, uint64_t length, ExeLayout *layout,
    ExeOrderEvidence *evidence);
static inline void exe_collect_control_flow_evidence(
    const uint8_t *data, uint64_t length, const ExeLayout *layout,
    ExeOrderEvidence *evidence);
static inline bool exe_validate_directories(const uint8_t *data,
                                            uint64_t length,
                                            ExeLayout *layout,
                                            ExeOrderEvidence *evidence);
static inline bool exe_validate_certificate_table(const uint8_t *data,
                                                  uint64_t length,
                                                  ExeLayout *layout);
static inline uint32_t exe_compute_checksum(const uint8_t *data,
                                            uint64_t length,
                                            uint32_t checksum_offset);
static inline bool exe_extract_authenticode_digest(
    const uint8_t *certificate, uint64_t certificate_length,
    const EVP_MD **digest_method, const uint8_t **digest,
    uint32_t *digest_length);
static inline int exe_compare_raw_ranges(const void *left, const void *right);
static inline bool exe_compute_authenticode_digest(const uint8_t *data,
                                                   uint64_t length,
                                                   const ExeLayout *layout,
                                                   const EVP_MD *digest_method,
                                                   uint8_t *digest,
                                                   uint32_t *digest_length);
static inline bool exe_validate_authenticode(const uint8_t *data,
                                             uint64_t length,
                                             ExeLayout *layout);
static inline ExeParseResult exe_parse_image(const uint8_t *data,
                                             uint64_t length,
                                             ExeLayout *layout);
static inline ExeParseResult exe_parse_image_with_evidence(
    const uint8_t *data, uint64_t length, ExeLayout *layout,
    ExeOrderEvidence *evidence);
static inline uint64_t exe_raw_word_sum(const uint8_t *data,
                                        uint64_t length,
                                        uint64_t logical_offset,
                                        uint32_t checksum_offset);
static inline uint32_t exe_fold_word_sum(uint64_t sum);
static inline uint32_t exe_checksum_from_raw_sum(uint64_t sum,
                                                 uint64_t length);
static inline bool exe_prepare_block_sum_cache(void);
static inline bool exe_get_full_block_sum(int64_t apparent_block,
                                          uint64_t *sum,
                                          bool uncovered_only);
static inline bool exe_get_slot_sum(int64_t apparent_block,
                                    uint64_t slot,
                                    const ExeLayout *layout,
                                    uint64_t *sum,
                                    bool uncovered_only);
static inline bool exe_mapping_raw_sum(const int64_t *mapping,
                                       uint64_t total_blocks,
                                       const ExeLayout *layout,
                                       uint64_t *slot_sums,
                                       uint64_t *sum,
                                       bool uncovered_only);
static inline bool exe_materialize_mapping(const int64_t *mapping,
                                           uint64_t total_blocks,
                                           const ExeLayout *layout,
                                           uint8_t *data,
                                           bool uncovered_only);
static inline ExeMappingResult exe_mapping_validates(
    const int64_t *mapping, uint64_t total_blocks, const ExeLayout *layout,
    uint8_t *data, uint64_t order_offset, uint64_t order_length,
    ExeOrderEvidence *evidence, bool uncovered_only);
static inline bool exe_order_evidence_repairs_baseline(
    const int64_t *baseline_mapping, uint64_t total_blocks,
    const ExeLayout *layout, uint8_t *data, uint64_t order_offset,
    uint64_t order_length, const ExeOrderEvidence *candidate_evidence);
static inline void exe_accumulate_ordered_mapping(
    ExeRecoveryAccumulator *accumulator, const int64_t *mapping,
    const ExeOrderEvidence *evidence);
static inline bool exe_ordered_mapping_is_decisive(
    const ExeRecoveryAccumulator *accumulator);
static inline void exe_accumulate_complete_mapping(
    ExeRecoveryAccumulator *accumulator, const int64_t *mapping);
static inline void exe_accumulate_gap_mapping(
    ExeRecoveryAccumulator *accumulator, const int64_t *mapping);
static inline bool exe_source_run_index_build(
    ExeSourceRunIndex *index, uint64_t run_blocks, uint64_t source_first,
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, uint64_t *iterations, bool *stopped,
    ExeReassemblyContext *context);
static inline void exe_source_run_index_destroy(ExeSourceRunIndex *index);
static inline void exe_commit_mapping(CarveInfo *candidate,
                                      const int64_t *mapping,
                                      uint64_t total_blocks,
                                      const ExeLayout *layout);
static inline bool exe_write_mapping_hypothesis(
    CarveInfo *candidate, const int64_t *mapping,
    uint64_t total_blocks, const ExeLayout *layout);
static inline void exe_publish_decisive_mapping_hypothesis(
    CarveInfo *candidate, const ExeLayout *layout,
    ExeRecoveryAccumulator *accumulator, int64_t *published_mapping,
    bool *mapping_published);
static inline bool exe_reassembly_poll(ThreadWork *work,
                                       CarveInfo **candidate,
                                       uuid_string_t uuidp,
                                       uuid_string_t uuidc,
                                       uint64_t *iterations);
static inline XXH128_hash_t exe_reassembly_view_hash(void);
static inline void exe_run_progress_reset(ExeRunProgress *progress);
static inline bool exe_run_progress_valid(const ExeRunProgress *progress);
static inline ExeRecoveryResult exe_try_gap(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const ExeLayout *layout,
    const int64_t *baseline_mapping, const uint64_t *baseline_sums,
    uint64_t total_blocks, uint64_t header_blocks,
    uint64_t first_gap_blocks, uint64_t last_gap_blocks,
    uint8_t *trial_data, int64_t *solution_mapping,
    ExeRecoveryAccumulator *accumulator, uint64_t *iterations,
    ExeReassemblyContext *context);
static inline ExeRecoveryResult exe_try_preceding_ooo_hints(
    ExeReassemblyContext *context);
static inline int exe_compare_relocation_constraints(const void *a,
                                                      const void *b);
static inline uint64_t exe_relocation_constraints(
    const uint8_t *data, const ExeLayout *layout,
    ExeRelocationConstraint **constraints);
static inline bool exe_block_matches_relocations(
    const uint8_t *data, uint64_t length, const ExeLayout *layout,
    const ExeRelocationConstraint *constraints, uint64_t count);
static inline ExeRecoveryResult exe_try_relocation_blocks(
    ExeReassemblyContext *context);
static inline bool exe_confidence_gap_hints(
    ExeReassemblyContext *context, uint64_t max_gap);
static inline bool exe_confidence_edges(
    ExeReassemblyContext *context, ExeConfidenceEdges *edges,
    int64_t base, uint64_t first_boundary, uint64_t end, bool rising);
static inline uint32_t exe_apparent_block_confidence(
    int64_t apparent_block, uint32_t needleidx);
static inline void exe_add_u64_candidate(
    uint64_t *values, uint32_t *count, uint32_t capacity,
    uint64_t value);
static inline bool exe_apparent_block_is_zero(int64_t apparent_block);
static inline uint32_t exe_zero_alternative_capacity(
    uint64_t described_extent);
static inline bool exe_carve_state_size(
    uint64_t total_blocks, uint64_t described_extent, size_t *state_size);
static inline bool exe_carve_state_valid(const ExeCarveState *state);
static inline ExeCarveState *exe_carve_state_create(
    uint64_t total_blocks, uint64_t described_extent, int64_t start_block);
static inline int64_t *exe_carve_state_alternative_mappings(
    ExeCarveState *state);
static inline int64_t *exe_carve_state_ordered_mapping(
    ExeCarveState *state);
static inline int64_t *exe_carve_state_gap_mapping(
    ExeCarveState *state);
static inline int64_t *exe_carve_state_complete_mapping(
    ExeCarveState *state);
static inline int64_t *exe_carve_state_published_mapping(
    ExeCarveState *state);
static inline int64_t *exe_carve_state_relocation_mapping(
    ExeCarveState *state);
static inline ExeZeroAlternativeRank *exe_carve_state_alternative_ranks(
    ExeCarveState *state);
static inline bool exe_serialize_carve_state(
    void **state, FILE *fp, StateSerialization mode);
static inline void *exe_clone_carve_state(const void *srcstate);
static inline void exe_free_carve_state(void **state);
static inline void exe_print_carve_state(const void *state);
static inline void exe_carve_state_load(
    const ExeCarveState *state, ExeRecoveryAccumulator *accumulator,
    ExeZeroAlternativeSet *alternatives, int64_t *published_mapping,
    bool *mapping_published);
static inline void exe_carve_state_capture(
    ExeCarveState *state, const ExeRecoveryAccumulator *accumulator,
    const ExeZeroAlternativeSet *alternatives,
    const int64_t *published_mapping, bool mapping_published);
static inline void exe_carve_state_identify_view(ExeCarveState *state);
static inline bool exe_reassembly_context_poll(
    ExeReassemblyContext *context);
static inline void exe_zero_composition_complete_terminal(
    ExeReassemblyContext *context, uint64_t terminal);
static inline bool exe_zero_alternatives_initialize(
    ExeZeroAlternativeSet *set, uint64_t total_blocks,
    uint64_t described_extent);
static inline void exe_zero_alternatives_destroy(
    ExeZeroAlternativeSet *set);
static inline bool exe_zero_alternative_rank_better(
    const ExeZeroAlternativeRank *left,
    const ExeZeroAlternativeRank *right);
static inline void exe_zero_alternatives_retain(
    ExeReassemblyContext *context, const int64_t *mapping,
    const ExeOrderEvidence *evidence, uint32_t destination_count);
static inline const int64_t *exe_zero_alternatives_best(
    const ExeZeroAlternativeSet *set);
static inline void exe_zero_alternatives_write(
    CarveInfo *candidate, const ExeLayout *layout,
    const ExeZeroAlternativeSet *set);
static inline ExeRecoveryResult exe_consider_zero_composition_mapping(
    ExeReassemblyContext *context, const int64_t *mapping,
    uint32_t destination_count);
static inline ExeRecoveryResult exe_try_zero_composition_pair(
    ExeReassemblyContext *context,
    const ExeZeroDestination destinations[2], uint64_t main_last);
static inline void exe_zero_composition_walk(
    ExeReassemblyContext *context, uint64_t logical_slot,
    uint64_t physical_block, ExeZeroDestination destinations[2],
    uint32_t destination_count);
static inline ExeRecoveryResult exe_try_zero_run_composition(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const ExeLayout *layout,
    const int64_t *baseline_mapping, uint64_t total_blocks,
    uint64_t header_blocks, uint8_t *trial_data,
    int64_t *solution_mapping, ExeRecoveryAccumulator *accumulator,
    int64_t *published_mapping, bool *mapping_published,
    uint64_t *iterations, ExeCarveState *state);
static inline ExeRecoveryResult exe_try_ooo_on_mapping(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const ExeLayout *layout,
    const int64_t *base_mapping, const uint64_t *base_sums,
    uint64_t base_sum, uint64_t total_blocks, uint64_t header_blocks,
    uint64_t run_blocks, int64_t main_first, int64_t main_last,
    bool zero_destinations_only, const ExeSourceRunIndex *source_index,
    uint8_t *trial_data,
    int64_t *solution_mapping,
    ExeRecoveryAccumulator *accumulator, int64_t *published_mapping,
    bool *mapping_published, uint64_t *iterations,
    ExeReassemblyContext *context);
static inline ExeRecoveryResult exe_try_gap_ooo(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const ExeLayout *layout,
    const int64_t *baseline_mapping, const uint64_t *baseline_sums,
    uint64_t total_blocks, uint64_t header_blocks, uint64_t gap_blocks,
    uint64_t run_blocks, uint8_t *trial_data, int64_t *solution_mapping,
    ExeRecoveryAccumulator *accumulator, int64_t *published_mapping,
    bool *mapping_published, uint64_t *iterations,
    ExeReassemblyContext *context);
static inline char *exe_header_discovery(char *base, uint64_t offset,
                                         uint64_t remaining, char **matchpos,
                                         uint32_t *matchlen,
                                         uint32_t blocksize);
static inline void exe_file_validate(char *data, uint64_t length,
                                     bool *validates,
                                     uint64_t *validates_to,
                                     bool *promising, uint32_t needleidx,
                                     uint32_t blocksize,
                                     void *carvehashkey);
static inline void exe_reassembly(ThreadWork *work, CarveInfo **candidate,
                                  uuid_string_t uuidp,
                                  uuid_string_t uuidc);

// Return true when the byte range [offset, offset + size) lies within length.
// The subtraction form avoids overflow when offset and size are untrusted.
//
static inline bool exe_range_available(uint64_t length, uint64_t offset,
                                       uint64_t size) {
  return offset <= length && size <= length - offset;
}

// Add two file offsets and report whether the result fits in uint64_t.
//
static inline bool exe_add_u64(uint64_t left, uint64_t right,
                               uint64_t *result) {
  if (!result || left > UINT64_MAX - right) {
    return false;
  }
  *result = left + right;
  return true;
}

// Validate one x64 unwind record and the optional handler or chained runtime
// function record that follows its unwind-code array.
//
static inline bool exe_validate_x64_unwind_info(
    const uint8_t *data, uint64_t length, ExeLayout *layout,
    uint32_t unwind_rva, uint64_t source_offset,
    ExeOrderEvidence *evidence) {
  uint64_t offset;
  uint64_t available;
  if ((unwind_rva & 3U) != 0
      || !exe_rva_bytes_available(layout, unwind_rva, &offset, &available)
      || available < 4 || !exe_range_available(length, offset, available)) {
    return false;
  }
  const uint8_t version = data[offset] & 7U;
  const uint8_t flags = data[offset] >> 3;
  if (version == 0 || version > 3 || (flags & ~UINT8_C(0x1f)) != 0) {
    return false;
  }
  exe_evidence_note_record(evidence, offset, 4);

  // Version 3 has a different payload layout. Its fixed header remains useful
  // structural evidence, but parsing the variable payload as V1/V2 would
  // reject valid APX-enabled images.
  if (version == 3) {
    exe_evidence_note_validated_reference(evidence, source_offset, 4,
                                          offset, 4);
    return true;
  }

  const uint8_t prolog_size = data[offset + 1];
  const uint8_t code_count = data[offset + 2];
  const uint64_t code_bytes = (uint64_t)code_count * 2;
  const uint64_t tail_offset = 4 + exe_align_up_u64(code_bytes, 4);
  if (tail_offset == UINT64_MAX || tail_offset > available) {
    return false;
  }
  if (version == 1) {
    uint32_t slot = 0;
    uint8_t prior_code_offset = UINT8_MAX;
    while (slot < code_count) {
      const uint8_t *code = data + offset + 4 + (uint64_t)slot * 2;
      const uint8_t code_offset = code[0];
      const uint8_t operation = code[1] & 0x0fU;
      const uint8_t info = code[1] >> 4;
      if (code_offset > prolog_size || code_offset > prior_code_offset) {
        return false;
      }
      prior_code_offset = code_offset;
      uint32_t slots = 1;
      switch (operation) {
        case 0: // UWOP_PUSH_NONVOL
        case 2: // UWOP_ALLOC_SMALL
        case 3: // UWOP_SET_FPREG
        case 10: // UWOP_PUSH_MACHFRAME
          if (operation == 10 && info > 1) {
            return false;
          }
          break;
        case 1: // UWOP_ALLOC_LARGE
          if (info == 0) {
            slots = 2;
          }
          else if (info == 1) {
            slots = 3;
          }
          else {
            return false;
          }
          break;
        case 4: // UWOP_SAVE_NONVOL
        case 8: // UWOP_SAVE_XMM128
          slots = 2;
          break;
        case 5: // UWOP_SAVE_NONVOL_FAR
        case 9: // UWOP_SAVE_XMM128_FAR
          slots = 3;
          break;
        default:
          return false;
      }
      if (slots > code_count - slot) {
        return false;
      }
      slot += slots;
    }
  }
  exe_evidence_note_record(evidence, offset + 4, code_bytes);

  const bool has_handler = (flags & 3U) != 0;
  const bool has_chain = (flags & 4U) != 0;
  if (has_handler && has_chain) {
    return false;
  }
  if (has_chain) {
    if (tail_offset + 12 > available) {
      return false;
    }
    const uint8_t *chain = data + offset + tail_offset;
    const uint32_t begin_rva = exe_read_le32(chain);
    const uint32_t end_rva = exe_read_le32(chain + 4);
    const uint32_t chained_unwind_rva = exe_read_le32(chain + 8);
    if (begin_rva >= end_rva || end_rva > layout->size_of_image
        || !exe_rva_is_executable(layout, begin_rva)
        || chained_unwind_rva >= layout->size_of_image) {
      return false;
    }
    exe_evidence_note_record(evidence, offset + tail_offset, 12);
    exe_evidence_add_anchor(evidence, begin_rva);
  }
  else if (has_handler) {
    if (tail_offset + 4 > available) {
      return false;
    }
    const uint32_t handler_rva = exe_read_le32(data + offset + tail_offset);
    if (!exe_rva_is_executable(layout, handler_rva)) {
      return false;
    }
    uint64_t handler_offset;
    if (exe_rva_to_file_offset(layout, handler_rva, 1, &handler_offset)) {
      exe_evidence_note_reference(evidence, offset + tail_offset, 4,
                                  handler_offset, 1);
    }
    exe_evidence_add_anchor(evidence, handler_rva);
  }
  exe_evidence_note_validated_reference(evidence, source_offset, 4,
                                        offset, 4);
  return true;
}

// Validate architecture-specific exception table entries and collect their
// function starts as exact RVA anchors.
//
static inline bool exe_validate_exception_directory(
    const uint8_t *data, uint64_t length, ExeLayout *layout,
    ExeOrderEvidence *evidence) {
  if (layout->directory_count <= 3 || layout->directories[3].size == 0) {
    return true;
  }
  const ExeDirectory *directory = &layout->directories[3];
  uint64_t offset;
  if (!exe_rva_to_file_offset(layout, directory->rva, directory->size,
                              &offset)) {
    return false;
  }

  if (layout->machine == UINT16_C(0x8664)
      || layout->machine == UINT16_C(0x0200)) {
    if (directory->size % 12 != 0
        || directory->size / 12 > EXE_MAX_EXCEPTION_ENTRIES) {
      return false;
    }
    uint32_t prior_begin = 0;
    for (uint32_t i = 0; i < directory->size / 12; i++) {
      const uint64_t entry_offset = offset + (uint64_t)i * 12;
      const uint32_t begin_rva = exe_read_le32(data + entry_offset);
      const uint32_t end_rva = exe_read_le32(data + entry_offset + 4);
      const uint32_t unwind_rva = exe_read_le32(data + entry_offset + 8);
      if (begin_rva >= end_rva || end_rva > layout->size_of_image
          || (i != 0 && begin_rva < prior_begin)
          || !exe_rva_is_executable(layout, begin_rva)
          || !exe_validate_x64_unwind_info(data, length, layout, unwind_rva,
                                           entry_offset + 8, evidence)) {
        return false;
      }
      prior_begin = begin_rva;
      exe_evidence_note_record(evidence, entry_offset, 12);
      uint64_t begin_offset;
      if (exe_rva_to_file_offset(layout, begin_rva, 1, &begin_offset)) {
        exe_evidence_note_reference(evidence, entry_offset, 4, begin_offset,
                                    1);
      }
      exe_evidence_add_anchor(evidence, begin_rva);
    }
    return true;
  }

  if (layout->machine == UINT16_C(0xaa64)
      || layout->machine == UINT16_C(0xa641)
      || layout->machine == UINT16_C(0xa64e)) {
    if (directory->size % 8 != 0
        || directory->size / 8 > EXE_MAX_EXCEPTION_ENTRIES) {
      return false;
    }
    uint32_t prior_begin = 0;
    for (uint32_t i = 0; i < directory->size / 8; i++) {
      const uint64_t entry_offset = offset + (uint64_t)i * 8;
      const uint32_t begin_rva = exe_read_le32(data + entry_offset);
      const uint32_t unwind = exe_read_le32(data + entry_offset + 4);
      const uint32_t flag = unwind & 3U;
      if (begin_rva >= layout->size_of_image
          || (i != 0 && begin_rva < prior_begin)
          || !exe_rva_is_executable(layout, begin_rva)) {
        return false;
      }
      prior_begin = begin_rva;
      exe_evidence_note_record(evidence, entry_offset, 8);
      exe_evidence_add_anchor(evidence, begin_rva);
      uint64_t begin_offset;
      if (exe_rva_to_file_offset(layout, begin_rva, 4, &begin_offset)) {
        exe_evidence_note_reference(evidence, entry_offset, 4, begin_offset,
                                    4);
      }
      if (flag == 0) {
        const uint32_t xdata_rva = unwind & ~UINT32_C(3);
        uint64_t xdata_offset;
        if (!exe_rva_to_file_offset(layout, xdata_rva, 4, &xdata_offset)
            || !exe_range_available(length, xdata_offset, 4)) {
          return false;
        }
        const uint32_t header = exe_read_le32(data + xdata_offset);
        if (((header >> 18) & 3U) != 0) {
          return false;
        }
        uint64_t xdata_size;
        uint32_t epilogs;
        uint32_t unwind_words;
        if ((header >> 22) != 0) {
          xdata_size = 4;
          epilogs = (header >> 22) & 0x1fU;
          unwind_words = (header >> 27) & 0x1fU;
        }
        else {
          if (!exe_range_available(length, xdata_offset, 8)) {
            return false;
          }
          const uint32_t extension = exe_read_le32(data + xdata_offset + 4);
          xdata_size = 8;
          epilogs = extension & 0xffffU;
          unwind_words = (extension >> 16) & 0xffU;
        }
        if ((header & (UINT32_C(1) << 21)) == 0) {
          xdata_size += (uint64_t)epilogs * 4;
        }
        xdata_size += (uint64_t)unwind_words * 4;
        if (header & (UINT32_C(1) << 20)) {
          xdata_size += 4;
        }
        if (!exe_range_available(length, xdata_offset, xdata_size)) {
          return false;
        }
        exe_evidence_note_validated_reference(evidence, entry_offset + 4, 4,
                                              xdata_offset, xdata_size);
      }
    }
  }
  return true;
}

// Validate the TLS template, index, and null-terminated callback array.
//
static inline bool exe_validate_tls_directory(
    const uint8_t *data, uint64_t length, ExeLayout *layout,
    ExeOrderEvidence *evidence) {
  if (layout->directory_count <= 9 || layout->directories[9].size == 0) {
    return true;
  }
  const ExeDirectory *directory = &layout->directories[9];
  const uint32_t pointer_size = layout->pe32_plus ? 8U : 4U;
  const uint32_t minimum_size = layout->pe32_plus ? 40U : 24U;
  uint64_t offset;
  if (directory->size < minimum_size
      || !exe_rva_to_file_offset(layout, directory->rva, minimum_size,
                                 &offset)
      || !exe_range_available(length, offset, minimum_size)) {
    return false;
  }
  exe_evidence_note_record(evidence, offset, minimum_size);
  const uint64_t start_va = layout->pe32_plus
                                ? exe_read_le64(data + offset)
                                : exe_read_le32(data + offset);
  const uint64_t end_va = layout->pe32_plus
                              ? exe_read_le64(data + offset + pointer_size)
                              : exe_read_le32(data + offset + pointer_size);
  const uint64_t index_va = layout->pe32_plus
                                ? exe_read_le64(data + offset + 2 * pointer_size)
                                : exe_read_le32(data + offset + 2 * pointer_size);
  const uint64_t callbacks_va =
      layout->pe32_plus
          ? exe_read_le64(data + offset + 3 * pointer_size)
          : exe_read_le32(data + offset + 3 * pointer_size);

  if ((start_va == 0) != (end_va == 0) || (start_va != 0 && end_va < start_va)) {
    return false;
  }
  if (start_va != 0 && end_va != start_va) {
    uint32_t start_rva;
    uint32_t end_rva;
    uint64_t template_offset;
    if (!exe_va_to_rva(layout, start_va, &start_rva)
        || !exe_va_to_rva(layout, end_va - 1, &end_rva)
        || !exe_rva_to_file_offset(layout, start_rva,
                                   end_rva - start_rva + 1,
                                   &template_offset)) {
      return false;
    }
    exe_evidence_note_reference(evidence, offset, 2 * pointer_size,
                                template_offset, end_rva - start_rva + 1);
  }
  if (index_va != 0) {
    uint32_t index_rva;
    uint64_t index_offset;
    if (!exe_va_to_rva(layout, index_va, &index_rva)) {
      return false;
    }
    if (exe_rva_to_file_offset(layout, index_rva, 4, &index_offset)) {
      exe_evidence_note_reference(evidence, offset + 2 * pointer_size,
                                  pointer_size, index_offset, 4);
    }
  }
  if (callbacks_va == 0) {
    return true;
  }

  uint32_t callbacks_rva;
  uint64_t callbacks_offset;
  uint64_t callbacks_available;
  if (!exe_va_to_rva(layout, callbacks_va, &callbacks_rva)
      || !exe_rva_bytes_available(layout, callbacks_rva, &callbacks_offset,
                                  &callbacks_available)) {
    return false;
  }
  uint64_t callbacks = callbacks_available / pointer_size;
  if (callbacks > EXE_MAX_TLS_CALLBACKS) {
    callbacks = EXE_MAX_TLS_CALLBACKS;
  }
  for (uint64_t i = 0; i < callbacks; i++) {
    const uint64_t entry_offset = callbacks_offset + i * pointer_size;
    const uint64_t callback_va = layout->pe32_plus
                                     ? exe_read_le64(data + entry_offset)
                                     : exe_read_le32(data + entry_offset);
    exe_evidence_note_record(evidence, entry_offset, pointer_size);
    if (callback_va == 0) {
      return true;
    }
    uint32_t callback_rva;
    uint64_t callback_offset;
    if (!exe_va_to_rva(layout, callback_va, &callback_rva)
        || !exe_rva_is_executable(layout, callback_rva)
        || !exe_rva_to_file_offset(layout, callback_rva, 1,
                                   &callback_offset)) {
      return false;
    }
    exe_evidence_note_reference(evidence, entry_offset, pointer_size,
                                callback_offset, 1);
    exe_evidence_add_anchor(evidence, callback_rva);
  }
  return false;
}

// Validate a load-configuration RVA table and every address it contains. CFG,
// SafeSEH, long-jump, EH-continuation, and address-taken IAT tables all use a
// 32-bit RVA as the first field of each entry.
//
static inline bool exe_validate_load_config_table(
    const uint8_t *data, uint64_t length, ExeLayout *layout,
    uint64_t table_va, uint64_t count, uint32_t stride,
    bool executable_targets, uint64_t source_offset,
    ExeOrderEvidence *evidence) {
  if (table_va == 0 || count == 0) {
    return table_va == 0 && count == 0;
  }
  if (count > EXE_MAX_LOAD_CONFIG_ENTRIES || stride < 4 || stride > 32
      || count > UINT32_MAX / stride) {
    return false;
  }

  uint32_t table_rva;
  uint64_t table_offset;
  const uint32_t table_size = (uint32_t)count * stride;
  if (!exe_va_to_rva(layout, table_va, &table_rva)
      || !exe_rva_to_file_offset(layout, table_rva, table_size,
                                 &table_offset)
      || !exe_range_available(length, table_offset, table_size)) {
    return false;
  }
  uint32_t prior_rva = 0;
  for (uint64_t i = 0; i < count; i++) {
    const uint64_t entry_offset = table_offset + i * stride;
    const uint32_t target_rva = exe_read_le32(data + entry_offset);
    const uint32_t target_size = executable_targets
                                     ? 1U
                                     : (layout->pe32_plus ? 8U : 4U);
    uint64_t target_offset;
    if (target_rva >= layout->size_of_image
        || (i != 0 && target_rva < prior_rva)
        || (executable_targets
            && !exe_rva_is_executable(layout, target_rva))
        || !exe_rva_to_file_offset(layout, target_rva, target_size,
                                   &target_offset)
        || !exe_range_available(length, target_offset, target_size)) {
      return false;
    }
    prior_rva = target_rva;
    exe_evidence_note_record(evidence, entry_offset, stride);
    exe_evidence_note_reference(evidence, entry_offset, 4, target_offset,
                                target_size);
    exe_evidence_add_anchor(evidence, target_rva);
  }
  exe_evidence_note_validated_reference(
      evidence, source_offset, layout->pe32_plus ? 8 : 4,
      table_offset, table_size);
  return true;
}

// Validate the versioned PE load-configuration directory and the address
// tables present in the version declared by its Size field.
//
static inline bool exe_validate_load_config_directory(
    const uint8_t *data, uint64_t length, ExeLayout *layout,
    ExeOrderEvidence *evidence) {
  if (layout->directory_count <= 10 || layout->directories[10].size == 0) {
    return true;
  }
  const ExeDirectory *directory = &layout->directories[10];
  uint64_t offset;
  uint64_t available;
  if (directory->size < 4
      || !exe_rva_bytes_available(layout, directory->rva, &offset, &available)
      || available < 4 || !exe_range_available(length, offset, available)) {
    return false;
  }
  const uint32_t structure_size = exe_read_le32(data + offset);
  if (structure_size < 4 || structure_size > available) {
    return false;
  }
  exe_evidence_note_record(evidence, offset, structure_size);

  const uint32_t pointer_size = layout->pe32_plus ? 8U : 4U;
  const uint32_t cookie_field = layout->pe32_plus ? 88U : 60U;
  if (structure_size >= cookie_field + pointer_size) {
    const uint64_t cookie_va = layout->pe32_plus
                                   ? exe_read_le64(data + offset + cookie_field)
                                   : exe_read_le32(data + offset + cookie_field);
    if (cookie_va != 0) {
      uint32_t cookie_rva;
      uint64_t cookie_offset;
      if (!exe_va_to_rva(layout, cookie_va, &cookie_rva)
          || !exe_rva_to_file_offset(layout, cookie_rva, pointer_size,
                                     &cookie_offset)) {
        return false;
      }
      exe_evidence_note_reference(evidence, offset + cookie_field,
                                  pointer_size, cookie_offset, pointer_size);
    }
  }

  // SafeSEH is a 32-bit image table of executable handler RVAs.
  if (!layout->pe32_plus && structure_size >= 72) {
    const uint64_t table_va = exe_read_le32(data + offset + 64);
    const uint64_t count = exe_read_le32(data + offset + 68);
    if (!exe_validate_load_config_table(data, length, layout, table_va, count,
                                        4, true, offset + 64, evidence)) {
      return false;
    }
  }

  const uint32_t guard_check_field = layout->pe32_plus ? 112U : 72U;
  const uint32_t guard_dispatch_field = layout->pe32_plus ? 120U : 76U;
  const uint32_t guard_table_field = layout->pe32_plus ? 128U : 80U;
  const uint32_t guard_count_field = layout->pe32_plus ? 136U : 84U;
  const uint32_t guard_flags_field = layout->pe32_plus ? 144U : 88U;
  uint32_t guard_stride = 4;
  if (structure_size >= guard_flags_field + 4) {
    const uint32_t pointer_fields[] = {guard_check_field,
                                      guard_dispatch_field};
    for (uint32_t i = 0;
         i < sizeof(pointer_fields) / sizeof(pointer_fields[0]); i++) {
      const uint32_t field = pointer_fields[i];
      const uint64_t pointer_va = layout->pe32_plus
                                      ? exe_read_le64(data + offset + field)
                                      : exe_read_le32(data + offset + field);
      if (pointer_va != 0) {
        uint32_t pointer_rva;
        uint64_t pointer_offset;
        if (!exe_va_to_rva(layout, pointer_va, &pointer_rva)
            || !exe_rva_to_file_offset(layout, pointer_rva, pointer_size,
                                       &pointer_offset)) {
          return false;
        }
        exe_evidence_note_reference(evidence, offset + field, pointer_size,
                                    pointer_offset, pointer_size);
        exe_evidence_add_anchor(evidence, pointer_rva);
      }
    }

    const uint64_t table_va = layout->pe32_plus
                                  ? exe_read_le64(data + offset
                                                  + guard_table_field)
                                  : exe_read_le32(data + offset
                                                 + guard_table_field);
    const uint64_t count = layout->pe32_plus
                               ? exe_read_le64(data + offset
                                               + guard_count_field)
                               : exe_read_le32(data + offset
                                              + guard_count_field);
    const uint32_t guard_flags = exe_read_le32(data + offset
                                               + guard_flags_field);
    guard_stride = 4U + ((guard_flags >> 28) & 0x0fU);
    if (!exe_validate_load_config_table(data, length, layout, table_va, count,
                                        guard_stride, true,
                                        offset + guard_table_field,
                                        evidence)) {
      return false;
    }
  }

  const uint32_t iat_table_field = layout->pe32_plus ? 160U : 104U;
  const uint32_t iat_count_field = layout->pe32_plus ? 168U : 108U;
  if (structure_size >= iat_count_field + pointer_size) {
    const uint64_t table_va = layout->pe32_plus
                                  ? exe_read_le64(data + offset
                                                  + iat_table_field)
                                  : exe_read_le32(data + offset
                                                 + iat_table_field);
    const uint64_t count = layout->pe32_plus
                               ? exe_read_le64(data + offset + iat_count_field)
                               : exe_read_le32(data + offset + iat_count_field);
    if (!exe_validate_load_config_table(data, length, layout, table_va, count,
                                        guard_stride, false,
                                        offset + iat_table_field, evidence)) {
      return false;
    }
  }

  const uint32_t longjump_table_field = layout->pe32_plus ? 176U : 112U;
  const uint32_t longjump_count_field = layout->pe32_plus ? 184U : 116U;
  if (structure_size >= longjump_count_field + pointer_size) {
    const uint64_t table_va = layout->pe32_plus
                                  ? exe_read_le64(data + offset
                                                  + longjump_table_field)
                                  : exe_read_le32(data + offset
                                                 + longjump_table_field);
    const uint64_t count = layout->pe32_plus
                               ? exe_read_le64(data + offset
                                               + longjump_count_field)
                               : exe_read_le32(data + offset
                                              + longjump_count_field);
    if (!exe_validate_load_config_table(data, length, layout, table_va, count,
                                        guard_stride, true,
                                        offset + longjump_table_field,
                                        evidence)) {
      return false;
    }
  }

  const uint32_t eh_table_field = layout->pe32_plus ? 264U : 164U;
  const uint32_t eh_count_field = layout->pe32_plus ? 272U : 168U;
  if (structure_size >= eh_count_field + pointer_size) {
    const uint64_t table_va = layout->pe32_plus
                                  ? exe_read_le64(data + offset + eh_table_field)
                                  : exe_read_le32(data + offset + eh_table_field);
    const uint64_t count = layout->pe32_plus
                               ? exe_read_le64(data + offset + eh_count_field)
                               : exe_read_le32(data + offset + eh_count_field);
    if (!exe_validate_load_config_table(data, length, layout, table_va, count,
                                        guard_stride, true,
                                        offset + eh_table_field, evidence)) {
      return false;
    }
  }
  return true;
}

// Describe the physical columns in each standardized ECMA-335 metadata
// table. The target identifies either another metadata table or a coded-index
// family.
//
static inline const ExeClrTableSchema *exe_clr_table_schema(uint32_t table) {
  static const ExeClrTableSchema schemas[] = {
    [0] = {5, {{EXE_CLR_COLUMN_U16, 0},
               {EXE_CLR_COLUMN_STRING, 0},
               {EXE_CLR_COLUMN_GUID, 0},
               {EXE_CLR_COLUMN_GUID, 0},
               {EXE_CLR_COLUMN_GUID, 0}}},
    [1] = {3, {{EXE_CLR_COLUMN_CODED, EXE_CLR_CODED_RESOLUTION_SCOPE},
               {EXE_CLR_COLUMN_STRING, 0},
               {EXE_CLR_COLUMN_STRING, 0}}},
    [2] = {6, {{EXE_CLR_COLUMN_U32, 0},
               {EXE_CLR_COLUMN_STRING, 0},
               {EXE_CLR_COLUMN_STRING, 0},
               {EXE_CLR_COLUMN_CODED, EXE_CLR_CODED_TYPE_DEF_OR_REF},
               {EXE_CLR_COLUMN_LIST, 4},
               {EXE_CLR_COLUMN_LIST, 6}}},
    [3] = {1, {{EXE_CLR_COLUMN_TABLE, 4}}},
    [4] = {3, {{EXE_CLR_COLUMN_U16, 0},
               {EXE_CLR_COLUMN_STRING, 0},
               {EXE_CLR_COLUMN_BLOB, 0}}},
    [5] = {1, {{EXE_CLR_COLUMN_TABLE, 6}}},
    [6] = {6, {{EXE_CLR_COLUMN_U32, 0},
               {EXE_CLR_COLUMN_U16, 0},
               {EXE_CLR_COLUMN_U16, 0},
               {EXE_CLR_COLUMN_STRING, 0},
               {EXE_CLR_COLUMN_BLOB, 0},
               {EXE_CLR_COLUMN_LIST, 8}}},
    [7] = {1, {{EXE_CLR_COLUMN_TABLE, 8}}},
    [8] = {3, {{EXE_CLR_COLUMN_U16, 0},
               {EXE_CLR_COLUMN_U16, 0},
               {EXE_CLR_COLUMN_STRING, 0}}},
    [9] = {2, {{EXE_CLR_COLUMN_TABLE, 2},
               {EXE_CLR_COLUMN_CODED, EXE_CLR_CODED_TYPE_DEF_OR_REF}}},
    [10] = {3, {{EXE_CLR_COLUMN_CODED, EXE_CLR_CODED_MEMBER_REF_PARENT},
                {EXE_CLR_COLUMN_STRING, 0},
                {EXE_CLR_COLUMN_BLOB, 0}}},
    [11] = {3, {{EXE_CLR_COLUMN_U16, 0},
                {EXE_CLR_COLUMN_CODED, EXE_CLR_CODED_HAS_CONSTANT},
                {EXE_CLR_COLUMN_BLOB, 0}}},
    [12] = {3, {{EXE_CLR_COLUMN_CODED,
                 EXE_CLR_CODED_HAS_CUSTOM_ATTRIBUTE},
                {EXE_CLR_COLUMN_CODED,
                 EXE_CLR_CODED_CUSTOM_ATTRIBUTE_TYPE},
                {EXE_CLR_COLUMN_BLOB, 0}}},
    [13] = {2, {{EXE_CLR_COLUMN_CODED, EXE_CLR_CODED_HAS_FIELD_MARSHAL},
                {EXE_CLR_COLUMN_BLOB, 0}}},
    [14] = {3, {{EXE_CLR_COLUMN_U16, 0},
                {EXE_CLR_COLUMN_CODED, EXE_CLR_CODED_HAS_DECL_SECURITY},
                {EXE_CLR_COLUMN_BLOB, 0}}},
    [15] = {3, {{EXE_CLR_COLUMN_U16, 0},
                {EXE_CLR_COLUMN_U32, 0},
                {EXE_CLR_COLUMN_TABLE, 2}}},
    [16] = {2, {{EXE_CLR_COLUMN_U32, 0},
                {EXE_CLR_COLUMN_TABLE, 4}}},
    [17] = {1, {{EXE_CLR_COLUMN_BLOB, 0}}},
    [18] = {2, {{EXE_CLR_COLUMN_TABLE, 2},
                {EXE_CLR_COLUMN_LIST, 20}}},
    [19] = {1, {{EXE_CLR_COLUMN_TABLE, 20}}},
    [20] = {3, {{EXE_CLR_COLUMN_U16, 0},
                {EXE_CLR_COLUMN_STRING, 0},
                {EXE_CLR_COLUMN_CODED, EXE_CLR_CODED_TYPE_DEF_OR_REF}}},
    [21] = {2, {{EXE_CLR_COLUMN_TABLE, 2},
                {EXE_CLR_COLUMN_LIST, 23}}},
    [22] = {1, {{EXE_CLR_COLUMN_TABLE, 23}}},
    [23] = {3, {{EXE_CLR_COLUMN_U16, 0},
                {EXE_CLR_COLUMN_STRING, 0},
                {EXE_CLR_COLUMN_BLOB, 0}}},
    [24] = {3, {{EXE_CLR_COLUMN_U16, 0},
                {EXE_CLR_COLUMN_TABLE, 6},
                {EXE_CLR_COLUMN_CODED, EXE_CLR_CODED_HAS_SEMANTICS}}},
    [25] = {3, {{EXE_CLR_COLUMN_TABLE, 2},
                {EXE_CLR_COLUMN_CODED, EXE_CLR_CODED_METHOD_DEF_OR_REF},
                {EXE_CLR_COLUMN_CODED, EXE_CLR_CODED_METHOD_DEF_OR_REF}}},
    [26] = {1, {{EXE_CLR_COLUMN_STRING, 0}}},
    [27] = {1, {{EXE_CLR_COLUMN_BLOB, 0}}},
    [28] = {4, {{EXE_CLR_COLUMN_U16, 0},
                {EXE_CLR_COLUMN_CODED, EXE_CLR_CODED_MEMBER_FORWARDED},
                {EXE_CLR_COLUMN_STRING, 0},
                {EXE_CLR_COLUMN_TABLE, 26}}},
    [29] = {2, {{EXE_CLR_COLUMN_U32, 0},
                {EXE_CLR_COLUMN_TABLE, 4}}},
    [30] = {2, {{EXE_CLR_COLUMN_U32, 0},
                {EXE_CLR_COLUMN_U32, 0}}},
    [31] = {1, {{EXE_CLR_COLUMN_U32, 0}}},
    [32] = {9, {{EXE_CLR_COLUMN_U32, 0},
                {EXE_CLR_COLUMN_U16, 0},
                {EXE_CLR_COLUMN_U16, 0},
                {EXE_CLR_COLUMN_U16, 0},
                {EXE_CLR_COLUMN_U16, 0},
                {EXE_CLR_COLUMN_U32, 0},
                {EXE_CLR_COLUMN_BLOB, 0},
                {EXE_CLR_COLUMN_STRING, 0},
                {EXE_CLR_COLUMN_STRING, 0}}},
    [33] = {1, {{EXE_CLR_COLUMN_U32, 0}}},
    [34] = {3, {{EXE_CLR_COLUMN_U32, 0},
                {EXE_CLR_COLUMN_U32, 0},
                {EXE_CLR_COLUMN_U32, 0}}},
    [35] = {9, {{EXE_CLR_COLUMN_U16, 0},
                {EXE_CLR_COLUMN_U16, 0},
                {EXE_CLR_COLUMN_U16, 0},
                {EXE_CLR_COLUMN_U16, 0},
                {EXE_CLR_COLUMN_U32, 0},
                {EXE_CLR_COLUMN_BLOB, 0},
                {EXE_CLR_COLUMN_STRING, 0},
                {EXE_CLR_COLUMN_STRING, 0},
                {EXE_CLR_COLUMN_BLOB, 0}}},
    [36] = {2, {{EXE_CLR_COLUMN_U32, 0},
                {EXE_CLR_COLUMN_TABLE, 35}}},
    [37] = {4, {{EXE_CLR_COLUMN_U32, 0},
                {EXE_CLR_COLUMN_U32, 0},
                {EXE_CLR_COLUMN_U32, 0},
                {EXE_CLR_COLUMN_TABLE, 35}}},
    [38] = {3, {{EXE_CLR_COLUMN_U32, 0},
                {EXE_CLR_COLUMN_STRING, 0},
                {EXE_CLR_COLUMN_BLOB, 0}}},
    [39] = {5, {{EXE_CLR_COLUMN_U32, 0},
                {EXE_CLR_COLUMN_U32, 0},
                {EXE_CLR_COLUMN_STRING, 0},
                {EXE_CLR_COLUMN_STRING, 0},
                {EXE_CLR_COLUMN_CODED, EXE_CLR_CODED_IMPLEMENTATION}}},
    [40] = {4, {{EXE_CLR_COLUMN_U32, 0},
                {EXE_CLR_COLUMN_U32, 0},
                {EXE_CLR_COLUMN_STRING, 0},
                {EXE_CLR_COLUMN_CODED, EXE_CLR_CODED_IMPLEMENTATION}}},
    [41] = {2, {{EXE_CLR_COLUMN_TABLE, 2},
                {EXE_CLR_COLUMN_TABLE, 2}}},
    [42] = {4, {{EXE_CLR_COLUMN_U16, 0},
                {EXE_CLR_COLUMN_U16, 0},
                {EXE_CLR_COLUMN_CODED, EXE_CLR_CODED_TYPE_OR_METHOD_DEF},
                {EXE_CLR_COLUMN_STRING, 0}}},
    [43] = {2, {{EXE_CLR_COLUMN_CODED, EXE_CLR_CODED_METHOD_DEF_OR_REF},
                {EXE_CLR_COLUMN_BLOB, 0}}},
    [44] = {2, {{EXE_CLR_COLUMN_TABLE, 42},
                {EXE_CLR_COLUMN_CODED, EXE_CLR_CODED_TYPE_DEF_OR_REF}}}
  };
  return table < sizeof(schemas) / sizeof(schemas[0])
             ? &schemas[table]
             : NULL;
}

// Return the tag width and target-table map for one ECMA-335 coded index.
// UINT8_MAX entries are reserved tag values and never identify a table.
//
static inline bool exe_clr_coded_index_info(
    ExeClrCodedIndexKind kind, const uint8_t **tables,
    uint32_t *table_count, uint32_t *tag_bits) {
  static const uint8_t type_def_or_ref[] = {2, 1, 27};
  static const uint8_t has_constant[] = {4, 8, 23};
  static const uint8_t has_custom_attribute[] = {
    6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35,
    38, 39, 40, 42, 44, 43
  };
  static const uint8_t has_field_marshal[] = {4, 8};
  static const uint8_t has_decl_security[] = {2, 6, 32};
  static const uint8_t member_ref_parent[] = {2, 1, 26, 6, 27};
  static const uint8_t has_semantics[] = {20, 23};
  static const uint8_t method_def_or_ref[] = {6, 10};
  static const uint8_t member_forwarded[] = {4, 6};
  static const uint8_t implementation[] = {38, 35, 39};
  static const uint8_t custom_attribute_type[] = {
    UINT8_MAX, UINT8_MAX, 6, 10, UINT8_MAX
  };
  static const uint8_t resolution_scope[] = {0, 26, 35, 1};
  static const uint8_t type_or_method_def[] = {2, 6};

  if (!tables || !table_count || !tag_bits) {
    return false;
  }
  switch (kind) {
    case EXE_CLR_CODED_TYPE_DEF_OR_REF:
      *tables = type_def_or_ref;
      *table_count = sizeof(type_def_or_ref);
      *tag_bits = 2;
      return true;
    case EXE_CLR_CODED_HAS_CONSTANT:
      *tables = has_constant;
      *table_count = sizeof(has_constant);
      *tag_bits = 2;
      return true;
    case EXE_CLR_CODED_HAS_CUSTOM_ATTRIBUTE:
      *tables = has_custom_attribute;
      *table_count = sizeof(has_custom_attribute);
      *tag_bits = 5;
      return true;
    case EXE_CLR_CODED_HAS_FIELD_MARSHAL:
      *tables = has_field_marshal;
      *table_count = sizeof(has_field_marshal);
      *tag_bits = 1;
      return true;
    case EXE_CLR_CODED_HAS_DECL_SECURITY:
      *tables = has_decl_security;
      *table_count = sizeof(has_decl_security);
      *tag_bits = 2;
      return true;
    case EXE_CLR_CODED_MEMBER_REF_PARENT:
      *tables = member_ref_parent;
      *table_count = sizeof(member_ref_parent);
      *tag_bits = 3;
      return true;
    case EXE_CLR_CODED_HAS_SEMANTICS:
      *tables = has_semantics;
      *table_count = sizeof(has_semantics);
      *tag_bits = 1;
      return true;
    case EXE_CLR_CODED_METHOD_DEF_OR_REF:
      *tables = method_def_or_ref;
      *table_count = sizeof(method_def_or_ref);
      *tag_bits = 1;
      return true;
    case EXE_CLR_CODED_MEMBER_FORWARDED:
      *tables = member_forwarded;
      *table_count = sizeof(member_forwarded);
      *tag_bits = 1;
      return true;
    case EXE_CLR_CODED_IMPLEMENTATION:
      *tables = implementation;
      *table_count = sizeof(implementation);
      *tag_bits = 2;
      return true;
    case EXE_CLR_CODED_CUSTOM_ATTRIBUTE_TYPE:
      *tables = custom_attribute_type;
      *table_count = sizeof(custom_attribute_type);
      *tag_bits = 3;
      return true;
    case EXE_CLR_CODED_RESOLUTION_SCOPE:
      *tables = resolution_scope;
      *table_count = sizeof(resolution_scope);
      *tag_bits = 2;
      return true;
    case EXE_CLR_CODED_TYPE_OR_METHOD_DEF:
      *tables = type_or_method_def;
      *table_count = sizeof(type_or_method_def);
      *tag_bits = 1;
      return true;
    default:
      return false;
  }
}

// Return the physical width of one metadata-table column.
//
static inline bool exe_clr_column_width(
    const ExeClrColumn *column, uint8_t heap_sizes,
    const uint32_t *row_counts, uint32_t *width) {
  if (!column || !row_counts || !width) {
    return false;
  }
  switch (column->kind) {
    case EXE_CLR_COLUMN_U16:
      *width = 2;
      return true;
    case EXE_CLR_COLUMN_U32:
      *width = 4;
      return true;
    case EXE_CLR_COLUMN_STRING:
      *width = (heap_sizes & 1U) != 0 ? 4U : 2U;
      return true;
    case EXE_CLR_COLUMN_GUID:
      *width = (heap_sizes & 2U) != 0 ? 4U : 2U;
      return true;
    case EXE_CLR_COLUMN_BLOB:
      *width = (heap_sizes & 4U) != 0 ? 4U : 2U;
      return true;
    case EXE_CLR_COLUMN_TABLE:
    case EXE_CLR_COLUMN_LIST:
      if (column->target >= 64) {
        return false;
      }
      *width = row_counts[column->target] > UINT16_MAX ? 4U : 2U;
      return true;
    case EXE_CLR_COLUMN_CODED: {
      const uint8_t *tables;
      uint32_t table_count;
      uint32_t tag_bits;
      if (!exe_clr_coded_index_info(
              (ExeClrCodedIndexKind)column->target, &tables,
              &table_count, &tag_bits)) {
        return false;
      }
      uint32_t maximum = 0;
      for (uint32_t i = 0; i < table_count; i++) {
        if (tables[i] != UINT8_MAX && row_counts[tables[i]] > maximum) {
          maximum = row_counts[tables[i]];
        }
      }
      *width = maximum >= (UINT32_C(1) << (16U - tag_bits)) ? 4U : 2U;
      return true;
    }
    default:
      return false;
  }
}

// Locate every standardized metadata table without trusting row data.
// Unknown future tables disable this optional evidence path rather than making
// an otherwise valid managed PE fail validation.
//
static inline bool exe_clr_build_table_layouts(
    uint64_t table_offset, uint32_t table_size,
    uint64_t table_data_offset, uint8_t heap_sizes, uint64_t valid,
    const uint32_t *row_counts, ExeClrTableLayout *layouts) {
  if (!row_counts || !layouts
      || (valid & ~((UINT64_C(1) << 45) - 1)) != 0) {
    return false;
  }
  memset(layouts, 0, 64 * sizeof(*layouts));
  uint64_t cursor = table_data_offset;
  for (uint32_t table = 0; table < 45; table++) {
    if ((valid & (UINT64_C(1) << table)) == 0) {
      continue;
    }
    const ExeClrTableSchema *schema = exe_clr_table_schema(table);
    if (!schema || schema->column_count == 0) {
      return false;
    }
    uint32_t row_size = 0;
    for (uint32_t column = 0; column < schema->column_count; column++) {
      uint32_t width;
      if (!exe_clr_column_width(&schema->columns[column], heap_sizes,
                                row_counts, &width)
          || row_size > UINT32_MAX - width) {
        return false;
      }
      row_size += width;
    }
    const uint64_t bytes = (uint64_t)row_counts[table] * row_size;
    uint64_t absolute_offset;
    if (cursor > table_size || bytes > table_size - cursor
        || !exe_add_u64(table_offset, cursor, &absolute_offset)) {
      return false;
    }
    layouts[table].offset = absolute_offset;
    layouts[table].row_size = row_size;
    layouts[table].row_count = row_counts[table];
    layouts[table].present = true;
    cursor += bytes;
  }
  return cursor <= table_size;
}

// Validate an index into one CLR metadata heap and return the exact byte range
// it identifies. String and blob indexes are self-delimiting; GUID indexes are
// one based and identify fixed-width entries.
//
static inline bool exe_clr_heap_reference(
    const uint8_t *data, uint64_t length, const ExeClrHeap *heap,
    ExeClrColumnKind kind, uint32_t index,
    uint64_t *target_offset, uint32_t *target_size) {
  if (!data || !heap || !heap->present || index == 0
      || index >= heap->size || !target_offset || !target_size
      || !exe_range_available(length, heap->offset, heap->size)) {
    return false;
  }
  uint64_t relative = index;
  uint32_t size = 0;
  if (kind == EXE_CLR_COLUMN_STRING) {
    const uint8_t *start = data + heap->offset + relative;
    const uint8_t *end = (const uint8_t *)memchr(
        start, 0, (size_t)(heap->size - relative));
    if (!end) {
      return false;
    }
    size = (uint32_t)(end - start) + 1U;
  }
  else if (kind == EXE_CLR_COLUMN_GUID) {
    relative = ((uint64_t)index - 1) * 16;
    if (relative > heap->size || 16 > heap->size - relative) {
      return false;
    }
    size = 16;
  }
  else if (kind == EXE_CLR_COLUMN_BLOB) {
    const uint8_t *blob = data + heap->offset + relative;
    const uint64_t available = heap->size - relative;
    uint32_t prefix;
    uint32_t payload;
    if ((blob[0] & UINT8_C(0x80)) == 0) {
      prefix = 1;
      payload = blob[0];
    }
    else if ((blob[0] & UINT8_C(0xc0)) == UINT8_C(0x80)
             && available >= 2) {
      prefix = 2;
      payload = ((uint32_t)(blob[0] & UINT8_C(0x3f)) << 8) | blob[1];
    }
    else if ((blob[0] & UINT8_C(0xe0)) == UINT8_C(0xc0)
             && available >= 4) {
      prefix = 4;
      payload = ((uint32_t)(blob[0] & UINT8_C(0x1f)) << 24)
                | ((uint32_t)blob[1] << 16)
                | ((uint32_t)blob[2] << 8)
                | blob[3];
    }
    else {
      return false;
    }
    if ((uint64_t)prefix + payload > available) {
      return false;
    }
    size = prefix + payload;
  }
  else {
    return false;
  }
  if (!exe_add_u64(heap->offset, relative, target_offset)) {
    return false;
  }
  *target_size = size;
  return true;
}

// Decode a direct or coded metadata-table index. A list endpoint one row past
// the target table is valid but does not identify target bytes.
//
static inline bool exe_clr_table_reference(
    const ExeClrTableLayout *layouts, const uint32_t *row_counts,
    const ExeClrColumn *column, uint32_t value,
    uint64_t *target_offset, uint32_t *target_size) {
  if (!layouts || !row_counts || !column || value == 0
      || !target_offset || !target_size) {
    return false;
  }
  uint32_t table;
  uint32_t row = value;
  if (column->kind == EXE_CLR_COLUMN_CODED) {
    const uint8_t *tables;
    uint32_t table_count;
    uint32_t tag_bits;
    if (!exe_clr_coded_index_info(
            (ExeClrCodedIndexKind)column->target, &tables,
            &table_count, &tag_bits)) {
      return false;
    }
    const uint32_t tag = value & ((UINT32_C(1) << tag_bits) - 1);
    row = value >> tag_bits;
    if (tag >= table_count || tables[tag] == UINT8_MAX || row == 0) {
      return false;
    }
    table = tables[tag];
  }
  else if (column->kind == EXE_CLR_COLUMN_TABLE
           || column->kind == EXE_CLR_COLUMN_LIST) {
    table = column->target;
  }
  else {
    return false;
  }
  if (table >= 64 || row > row_counts[table]
      || !layouts[table].present || layouts[table].row_size == 0) {
    return false;
  }
  const uint64_t relative = (uint64_t)(row - 1) * layouts[table].row_size;
  if (!exe_add_u64(layouts[table].offset, relative, target_offset)) {
    return false;
  }
  *target_size = layouts[table].row_size;
  return true;
}

// Validate every reference in one metadata row before allowing any of its
// relationships to contribute order evidence.
//
static inline bool exe_collect_clr_row_evidence(
    const uint8_t *data, uint64_t length, uint32_t table,
    uint64_t row_offset, uint8_t heap_sizes,
    const uint32_t *row_counts, const ExeClrTableLayout *layouts,
    const ExeClrHeap *strings_heap, const ExeClrHeap *guid_heap,
    const ExeClrHeap *blob_heap, ExeOrderEvidence *evidence) {
  const ExeClrTableSchema *schema = exe_clr_table_schema(table);
  if (!data || !schema || !row_counts || !layouts
      || table >= 64 || !layouts[table].present
      || !exe_range_available(length, row_offset,
                              layouts[table].row_size)) {
    return false;
  }

  ExeClrReference references[9];
  uint32_t reference_count = 0;
  uint32_t cursor = 0;
  for (uint32_t i = 0; i < schema->column_count; i++) {
    const ExeClrColumn *column = &schema->columns[i];
    uint32_t width;
    if (!exe_clr_column_width(column, heap_sizes, row_counts, &width)
        || cursor > layouts[table].row_size
        || width > layouts[table].row_size - cursor) {
      return false;
    }
    const uint64_t source_offset = row_offset + cursor;
    const uint32_t value = width == 2
                               ? exe_read_le16(data + source_offset)
                               : exe_read_le32(data + source_offset);
    cursor += width;
    if (column->kind == EXE_CLR_COLUMN_U16
        || column->kind == EXE_CLR_COLUMN_U32 || value == 0) {
      continue;
    }

    uint64_t target_offset;
    uint32_t target_size;
    bool target_validated = false;
    if (column->kind == EXE_CLR_COLUMN_STRING
        || column->kind == EXE_CLR_COLUMN_GUID
        || column->kind == EXE_CLR_COLUMN_BLOB) {
      const ExeClrHeap *heap = column->kind == EXE_CLR_COLUMN_STRING
                                   ? strings_heap
                                   : column->kind == EXE_CLR_COLUMN_GUID
                                         ? guid_heap
                                         : blob_heap;
      if (!exe_clr_heap_reference(data, length, heap, column->kind, value,
                                  &target_offset, &target_size)) {
        return false;
      }
      target_validated = true;
    }
    else {
      if (column->kind == EXE_CLR_COLUMN_LIST
          && row_counts[column->target] != UINT32_MAX
          && value == row_counts[column->target] + 1U) {
        continue;
      }
      if (!exe_clr_table_reference(layouts, row_counts, column, value,
                                   &target_offset, &target_size)) {
        return false;
      }
    }
    references[reference_count++] = (ExeClrReference) {
      .source_offset = source_offset,
      .target_offset = target_offset,
      .source_size = width,
      .target_size = target_size,
      .target_validated = target_validated
    };
  }
  if (cursor != layouts[table].row_size) {
    return false;
  }

  exe_evidence_note_record(evidence, row_offset, layouts[table].row_size);
  for (uint32_t i = 0; i < reference_count; i++) {
    const ExeClrReference *reference = &references[i];
    if (reference->target_validated) {
      exe_evidence_note_validated_reference(
          evidence, reference->source_offset, reference->source_size,
          reference->target_offset, reference->target_size);
    }
    else {
      exe_evidence_note_reference(
          evidence, reference->source_offset, reference->source_size,
          reference->target_offset, reference->target_size);
    }
  }
  return true;
}

// Collect relationships only from rows intersecting the displaced trial run.
// Every such row is checked once without side effects before its evidence is
// committed, so a malformed row cannot contribute partial evidence.
//
static inline void exe_collect_clr_table_evidence(
    const uint8_t *data, uint64_t length, uint64_t table_offset,
    uint32_t table_size, uint64_t table_data_offset, uint8_t heap_sizes,
    uint64_t valid, const uint32_t *row_counts,
    const ExeClrHeap *strings_heap, const ExeClrHeap *guid_heap,
    const ExeClrHeap *blob_heap, ExeOrderEvidence *evidence) {
  if (!data || !row_counts || !evidence || evidence->region_length == 0
      || evidence->region_offset > UINT64_MAX - evidence->region_length) {
    return;
  }
  ExeClrTableLayout layouts[64];
  if (!exe_clr_build_table_layouts(
          table_offset, table_size, table_data_offset, heap_sizes, valid,
          row_counts, layouts)) {
    return;
  }
  const uint64_t region_end = evidence->region_offset
                              + evidence->region_length;
  for (uint32_t table = 0; table < 45; table++) {
    const ExeClrTableLayout *layout = &layouts[table];
    const uint64_t table_bytes = (uint64_t)layout->row_count
                                 * layout->row_size;
    if (!layout->present || layout->row_count == 0
        || !exe_ranges_overlap(layout->offset, table_bytes,
                               evidence->region_offset,
                               evidence->region_length)) {
      continue;
    }
    const uint64_t overlap_start = layout->offset > evidence->region_offset
                                       ? layout->offset
                                       : evidence->region_offset;
    const uint64_t table_end = layout->offset + table_bytes;
    const uint64_t overlap_end = table_end < region_end
                                     ? table_end
                                     : region_end;
    const uint32_t first_row =
        (uint32_t)((overlap_start - layout->offset) / layout->row_size);
    const uint32_t last_row =
        (uint32_t)((overlap_end - 1 - layout->offset) / layout->row_size);
    if ((uint64_t)last_row - first_row + 1U < 4U) {
      continue;
    }

    bool rows_valid = true;
    for (uint64_t row = first_row; row <= last_row; row++) {
      const uint64_t row_offset = layout->offset
                                  + row * layout->row_size;
      if (!exe_collect_clr_row_evidence(
              data, length, table, row_offset, heap_sizes, row_counts,
              layouts, strings_heap, guid_heap, blob_heap, NULL)) {
        rows_valid = false;
        break;
      }
    }
    if (!rows_valid) {
      continue;
    }
    for (uint64_t row = first_row; row <= last_row; row++) {
      const uint64_t row_offset = layout->offset
                                  + row * layout->row_size;
      (void)exe_collect_clr_row_evidence(
          data, length, table, row_offset, heap_sizes, row_counts,
          layouts, strings_heap, guid_heap, blob_heap, evidence);
    }
  }
}

// Validate one IL method header and every declared extra-data section. The
// returned size covers only the method header because the IL bytecode itself
// is bounded here but not interpreted.
//
static inline uint32_t exe_validate_clr_method_body(
    const uint8_t *data, uint64_t length, const ExeLayout *layout,
    uint32_t method_rva) {
  uint64_t method_offset;
  uint64_t available;
  if (!data || !layout || !exe_rva_is_executable(layout, method_rva)
      || !exe_rva_bytes_available(layout, method_rva, &method_offset,
                                  &available)
      || available == 0
      || !exe_range_available(length, method_offset, available)) {
    return 0;
  }

  const uint8_t first = data[method_offset];
  if ((first & 3U) == 2U) {
    const uint32_t code_size = first >> 2;
    return code_size != 0 && code_size <= available - 1 ? 1U : 0U;
  }
  if (available < 12) {
    return 0;
  }
  const uint16_t flags_and_size = exe_read_le16(data + method_offset);
  if ((flags_and_size & 3U) != 3U) {
    return 0;
  }
  const uint32_t header_size = ((flags_and_size >> 12) & 0x0fU) * 4U;
  const uint32_t code_size = exe_read_le32(data + method_offset + 4);
  const uint32_t local_signature = exe_read_le32(data + method_offset + 8);
  if (header_size < 12 || header_size > available || code_size == 0
      || code_size > available - header_size
      || (local_signature != 0
          && (local_signature >> 24) != UINT32_C(0x11))) {
    return 0;
  }
  if ((flags_and_size & UINT16_C(0x0008)) == 0) {
    return header_size;
  }

  uint64_t cursor = exe_align_up_u64((uint64_t)header_size + code_size, 4);
  if (cursor == UINT64_MAX || cursor > available) {
    return 0;
  }
  bool more_sections = true;
  while (more_sections) {
    if (available - cursor < 4) {
      return 0;
    }
    const uint8_t *section = data + method_offset + cursor;
    const uint8_t kind = section[0];
    const bool fat = (kind & UINT8_C(0x40)) != 0;
    more_sections = (kind & UINT8_C(0x80)) != 0;
    const uint32_t section_size = fat
                                      ? (uint32_t)section[1]
                                            | ((uint32_t)section[2] << 8)
                                            | ((uint32_t)section[3] << 16)
                                      : section[1];
    const uint32_t clause_size = fat ? 24U : 12U;
    if ((kind & UINT8_C(0x3f)) != 1U
        || section_size < 4 || section_size > available - cursor
        || ((section_size - 4) % clause_size) != 0) {
      return 0;
    }

    const uint32_t clauses = (section_size - 4) / clause_size;
    for (uint32_t i = 0; i < clauses; i++) {
      const uint8_t *clause = section + 4 + (uint64_t)i * clause_size;
      const uint32_t flags = fat ? exe_read_le32(clause)
                                 : exe_read_le16(clause);
      const uint32_t try_offset = fat ? exe_read_le32(clause + 4)
                                      : exe_read_le16(clause + 2);
      const uint32_t try_length = fat ? exe_read_le32(clause + 8)
                                      : clause[4];
      const uint32_t handler_offset = fat ? exe_read_le32(clause + 12)
                                          : exe_read_le16(clause + 5);
      const uint32_t handler_length = fat ? exe_read_le32(clause + 16)
                                          : clause[7];
      const uint32_t class_or_filter = fat ? exe_read_le32(clause + 20)
                                           : exe_read_le32(clause + 8);
      if ((flags & ~UINT32_C(0x0f)) != 0 || try_length == 0
          || handler_length == 0 || try_offset > code_size
          || try_length > code_size - try_offset
          || handler_offset > code_size
          || handler_length > code_size - handler_offset
          || ((flags & 1U) != 0 && class_or_filter >= code_size)) {
        return 0;
      }
    }

    cursor += section_size;
    if (more_sections) {
      cursor = exe_align_up_u64(cursor, 4);
      if (cursor == UINT64_MAX || cursor > available) {
        return 0;
      }
    }
  }
  return header_size;
}

// Use MethodDef RVAs to verify method headers at their declared logical
// positions. Unsupported metadata layouts simply provide no order evidence.
//
static inline void exe_collect_clr_method_evidence(
    const uint8_t *data, uint64_t length, ExeLayout *layout,
    uint64_t table_offset, uint32_t table_size, uint64_t table_data_offset,
    uint8_t heap_sizes, uint64_t valid, const uint32_t *row_counts,
    ExeOrderEvidence *evidence) {
  if (!data || !layout || !row_counts || !evidence
      || (valid & (UINT64_C(1) << 6)) == 0 || row_counts[6] == 0
      || row_counts[6] > EXE_MAX_CLR_METHODS) {
    return;
  }

  const uint32_t string_index = (heap_sizes & 1U) != 0 ? 4U : 2U;
  const uint32_t guid_index = (heap_sizes & 2U) != 0 ? 4U : 2U;
  const uint32_t blob_index = (heap_sizes & 4U) != 0 ? 4U : 2U;
  const uint32_t field_index = row_counts[4] > UINT16_MAX ? 4U : 2U;
  const uint32_t method_index = row_counts[6] > UINT16_MAX ? 4U : 2U;
  const uint32_t param_index = row_counts[8] > UINT16_MAX ? 4U : 2U;

  uint32_t maximum = row_counts[0];
  static const uint8_t resolution_tables[] = {1, 26, 35};
  for (uint32_t i = 0;
       i < sizeof(resolution_tables) / sizeof(resolution_tables[0]); i++) {
    if (row_counts[resolution_tables[i]] > maximum) {
      maximum = row_counts[resolution_tables[i]];
    }
  }
  const uint32_t resolution_scope = maximum >= (UINT32_C(1) << 14) ? 4U : 2U;
  maximum = row_counts[1] > row_counts[2] ? row_counts[1] : row_counts[2];
  if (row_counts[27] > maximum) {
    maximum = row_counts[27];
  }
  const uint32_t type_def_or_ref = maximum >= (UINT32_C(1) << 14) ? 4U : 2U;

  const uint32_t row_sizes[6] = {
    2U + string_index + 3U * guid_index,
    resolution_scope + 2U * string_index,
    4U + 2U * string_index + type_def_or_ref + field_index + method_index,
    field_index,
    2U + string_index + blob_index,
    method_index
  };
  uint64_t method_table_offset = table_data_offset;
  for (uint32_t table = 0; table < 6; table++) {
    const uint64_t bytes = (uint64_t)row_counts[table] * row_sizes[table];
    if (method_table_offset > table_size
        || bytes > table_size - method_table_offset) {
      return;
    }
    method_table_offset += bytes;
  }
  const uint32_t method_row_size =
      8U + string_index + blob_index + param_index;
  const uint64_t method_bytes =
      (uint64_t)row_counts[6] * method_row_size;
  if (method_table_offset > table_size
      || method_bytes > table_size - method_table_offset) {
    return;
  }

  for (uint32_t i = 0; i < row_counts[6]; i++) {
    const uint64_t row_offset = table_offset + method_table_offset
                                + (uint64_t)i * method_row_size;
    const uint32_t method_rva = exe_read_le32(data + row_offset);
    if (method_rva == 0) {
      continue;
    }
    uint64_t method_offset;
    if (!exe_rva_to_file_offset(layout, method_rva, 1, &method_offset)) {
      continue;
    }
    const bool source_touches = exe_ranges_overlap(
        row_offset, method_row_size, evidence->region_offset,
        evidence->region_length);
    const bool target_touches = exe_ranges_overlap(
        method_offset, 1, evidence->region_offset, evidence->region_length);
    if (!source_touches && !target_touches) {
      continue;
    }
    const uint32_t header_size = exe_validate_clr_method_body(
        data, length, layout, method_rva);
    if (header_size != 0) {
      exe_evidence_note_record(evidence, method_offset, header_size);
      exe_evidence_note_validated_reference(
          evidence, row_offset, 4, method_offset, header_size);
    }
  }
}

// Validate the CLR metadata root and all declared streams. The tables stream
// is checked far enough to prove that every declared row-count field exists.
//
static inline bool exe_validate_clr_metadata_streams(
    const uint8_t *data, uint64_t length, ExeLayout *layout,
    ExeOrderEvidence *evidence) {
  if (layout->directory_count <= 14 || layout->directories[14].size == 0) {
    return true;
  }
  const ExeDirectory *directory = &layout->directories[14];
  uint64_t clr_offset;
  if (!exe_rva_to_file_offset(layout, directory->rva, 72, &clr_offset)
      || !exe_range_available(length, clr_offset, 72)) {
    return false;
  }
  exe_evidence_note_record(evidence, clr_offset, 72);

  const uint32_t metadata_rva = exe_read_le32(data + clr_offset + 8);
  const uint32_t metadata_size = exe_read_le32(data + clr_offset + 12);
  uint64_t metadata_offset;
  if (metadata_size < 20
      || !exe_rva_to_file_offset(layout, metadata_rva, metadata_size,
                                 &metadata_offset)
      || !exe_range_available(length, metadata_offset, metadata_size)
      || memcmp(data + metadata_offset, "BSJB", 4) != 0) {
    return false;
  }
  exe_evidence_note_record(evidence, metadata_offset, 16);

  const uint32_t version_length = exe_read_le32(data + metadata_offset + 12);
  if (version_length == 0 || version_length > metadata_size - 16) {
    return false;
  }
  const uint64_t stream_count_offset = exe_align_up_u64(
      (uint64_t)16 + version_length, 4);
  if (stream_count_offset == UINT64_MAX
      || stream_count_offset + 4 > metadata_size) {
    return false;
  }
  const uint16_t streams = exe_read_le16(data + metadata_offset
                                         + stream_count_offset + 2);
  if (streams == 0 || streams > EXE_MAX_CLR_STREAMS) {
    return false;
  }
  exe_evidence_note_validated_reference(
      evidence, clr_offset + 8, 8, metadata_offset,
      stream_count_offset + 4);

  uint64_t cursor = stream_count_offset + 4;
  bool tables_stream = false;
  uint64_t tables_offset = 0;
  uint32_t tables_size = 0;
  uint64_t tables_data_offset = 0;
  uint8_t heap_sizes = 0;
  uint64_t valid_tables = 0;
  uint32_t row_counts[64] = {0};
  ExeClrHeap strings_heap = {0};
  ExeClrHeap guid_heap = {0};
  ExeClrHeap blob_heap = {0};
  for (uint32_t stream = 0; stream < streams; stream++) {
    if (cursor + 9 > metadata_size) {
      return false;
    }
    const uint32_t stream_offset = exe_read_le32(data + metadata_offset
                                                 + cursor);
    const uint32_t stream_size = exe_read_le32(data + metadata_offset
                                               + cursor + 4);
    uint64_t name_length = 0;
    while (cursor + 8 + name_length < metadata_size
           && name_length < 128
           && data[metadata_offset + cursor + 8 + name_length] != 0) {
      name_length++;
    }
    if (name_length == 0 || name_length == 128
        || cursor + 8 + name_length >= metadata_size) {
      return false;
    }
    const uint64_t header_size = exe_align_up_u64(9 + name_length, 4);
    if (header_size == UINT64_MAX || cursor + header_size > metadata_size
        || stream_offset > metadata_size
        || stream_size > metadata_size - stream_offset) {
      return false;
    }
    const uint8_t *name = data + metadata_offset + cursor + 8;
    const bool is_tables = (name_length == 2 && memcmp(name, "#~", 2) == 0)
                           || (name_length == 2
                               && memcmp(name, "#-", 2) == 0);
    exe_evidence_note_record(evidence, metadata_offset + cursor, header_size);
    if (is_tables) {
      if (tables_stream || stream_size < 24) {
        return false;
      }
      const uint8_t *table = data + metadata_offset + stream_offset;
      const uint64_t valid = exe_read_le64(table + 8);
      uint32_t tables = 0;
      for (uint32_t bit = 0; bit < 64; bit++) {
        if (valid & (UINT64_C(1) << bit)) {
          tables++;
        }
      }
      if ((uint64_t)24 + (uint64_t)tables * 4 > stream_size) {
        return false;
      }
      uint64_t row_cursor = 24;
      for (uint32_t bit = 0; bit < 64; bit++) {
        if (valid & (UINT64_C(1) << bit)) {
          row_counts[bit] = exe_read_le32(table + row_cursor);
          row_cursor += 4;
        }
      }
      exe_evidence_note_validated_reference(
          evidence, metadata_offset + cursor, 8,
          metadata_offset + stream_offset, row_cursor);
      tables_offset = metadata_offset + stream_offset;
      tables_size = stream_size;
      tables_data_offset = row_cursor;
      heap_sizes = table[6];
      valid_tables = valid;
      tables_stream = true;
    }
    else {
      ExeClrHeap *heap = NULL;
      if (name_length == 8 && memcmp(name, "#Strings", 8) == 0) {
        heap = &strings_heap;
      }
      else if (name_length == 5 && memcmp(name, "#GUID", 5) == 0) {
        heap = &guid_heap;
      }
      else if (name_length == 5 && memcmp(name, "#Blob", 5) == 0) {
        heap = &blob_heap;
      }
      if (heap && !heap->present) {
        heap->offset = metadata_offset + stream_offset;
        heap->size = stream_size;
        heap->present = true;
      }
      exe_evidence_note_reference(evidence, metadata_offset + cursor, 8,
                                  metadata_offset + stream_offset,
                                  stream_size);
    }
    cursor += header_size;
  }
  if (!tables_stream) {
    return false;
  }
  exe_collect_clr_method_evidence(
      data, length, layout, tables_offset, tables_size,
      tables_data_offset, heap_sizes, valid_tables, row_counts, evidence);
  exe_collect_clr_table_evidence(
      data, length, tables_offset, tables_size, tables_data_offset,
      heap_sizes, valid_tables, row_counts, &strings_heap, &guid_heap,
      &blob_heap, evidence);

  // Validate every optional RVA/size pair in the fixed CLR header.
  static const uint32_t directory_fields[] = {24, 32, 40, 48, 56, 64};
  for (uint32_t i = 0;
       i < sizeof(directory_fields) / sizeof(directory_fields[0]); i++) {
    const uint32_t field = directory_fields[i];
    const uint32_t rva = exe_read_le32(data + clr_offset + field);
    const uint32_t size = exe_read_le32(data + clr_offset + field + 4);
    if (rva == 0 || size == 0) {
      if (rva != 0 || size != 0) {
        return false;
      }
      continue;
    }
    uint64_t target_offset;
    if (!exe_rva_to_file_offset(layout, rva, size, &target_offset)
        || !exe_range_available(length, target_offset, size)) {
      return false;
    }
    exe_evidence_note_reference(evidence, clr_offset + field, 8,
                                target_offset, size);
  }
  return true;
}

// Apply the order-sensitive validators after the baseline PE parser has
// established the image layout.
//
static inline bool exe_validate_deep_directories(
    const uint8_t *data, uint64_t length, ExeLayout *layout,
    ExeOrderEvidence *evidence) {
  exe_evidence_add_anchor(evidence, layout->address_of_entry_point);
  return exe_validate_export_targets(data, length, layout, evidence)
         && exe_validate_import_thunks(data, length, layout, 1, evidence)
         && exe_validate_import_thunks(data, length, layout, 13, evidence)
         && exe_validate_relocation_entries(data, length, layout, evidence)
         && exe_validate_exception_directory(data, length, layout, evidence)
         && exe_validate_tls_directory(data, length, layout, evidence)
         && exe_validate_load_config_directory(data, length, layout, evidence)
         && exe_validate_clr_metadata_streams(data, length, layout, evidence);
}

// Collect direct calls and branches that connect a displaced executable region
// to exact function or IAT anchors established by PE metadata.
//
static inline void exe_collect_control_flow_evidence(
    const uint8_t *data, uint64_t length, const ExeLayout *layout,
    ExeOrderEvidence *evidence) {
  if (!data || !layout || !evidence || evidence->region_length == 0
      || evidence->anchor_count == 0) {
    return;
  }
  qsort(evidence->anchors, evidence->anchor_count,
        sizeof(*evidence->anchors), exe_compare_u32);
  uint32_t unique = 0;
  for (uint32_t i = 0; i < evidence->anchor_count; i++) {
    if (unique == 0 || evidence->anchors[i] != evidence->anchors[unique - 1]) {
      evidence->anchors[unique++] = evidence->anchors[i];
    }
  }
  evidence->anchor_count = unique;

  for (uint32_t section_index = 0;
       section_index < layout->section_count; section_index++) {
    const ExeSection *section = &layout->sections[section_index];
    if (!(section->characteristics & EXE_IMAGE_SCN_MEM_EXECUTE)
        || section->raw_size == 0
        || !exe_range_available(length, section->raw_offset,
                                section->raw_size)) {
      continue;
    }

    if (layout->machine == UINT16_C(0x014c)
        || layout->machine == UINT16_C(0x8664)) {
      for (uint64_t i = 0; i + 5 <= section->raw_size; i++) {
        const uint64_t source_offset = (uint64_t)section->raw_offset + i;
        const uint32_t source_rva = section->virtual_address + (uint32_t)i;
        uint32_t target_rva = 0;
        uint32_t instruction_size = 0;
        if (data[source_offset] == UINT8_C(0xe8)
            || data[source_offset] == UINT8_C(0xe9)) {
          const int64_t displacement =
              (int32_t)exe_read_le32(data + source_offset + 1);
          const int64_t target = (int64_t)source_rva + 5 + displacement;
          if (target >= 0 && target <= UINT32_MAX) {
            target_rva = (uint32_t)target;
            instruction_size = 5;
          }
        }
        else if (i + 6 <= section->raw_size
                 && data[source_offset] == UINT8_C(0xff)
                 && (data[source_offset + 1] == UINT8_C(0x15)
                     || data[source_offset + 1] == UINT8_C(0x25))) {
          if (layout->pe32_plus) {
            const int64_t displacement =
                (int32_t)exe_read_le32(data + source_offset + 2);
            const int64_t target = (int64_t)source_rva + 6 + displacement;
            if (target >= 0 && target <= UINT32_MAX) {
              target_rva = (uint32_t)target;
              instruction_size = 6;
            }
          }
          else {
            const uint64_t target_va = exe_read_le32(data + source_offset + 2);
            if (exe_va_to_rva(layout, target_va, &target_rva)) {
              instruction_size = 6;
            }
          }
        }
        if (instruction_size == 0
            || !exe_evidence_has_anchor(evidence, target_rva)) {
          continue;
        }
        uint64_t target_offset;
        if (!exe_rva_to_file_offset(layout, target_rva, 1, &target_offset)) {
          continue;
        }
        if (exe_ranges_overlap(source_offset, instruction_size,
                               evidence->region_offset,
                               evidence->region_length)) {
          exe_evidence_note_control_flow(evidence, source_offset,
                                         instruction_size, target_offset, 1);
        }
      }
    }
    else if (layout->machine == UINT16_C(0xaa64)) {
      const ExeDirectory *iat = layout->directory_count > 12
                                    ? &layout->directories[12]
                                    : NULL;
      const uint64_t iat_end = iat
                                   ? (uint64_t)iat->rva + iat->size
                                   : 0;
      for (uint64_t i = 0; i + 4 <= section->raw_size; i += 4) {
        const uint64_t source_offset = (uint64_t)section->raw_offset + i;
        const uint32_t instruction = exe_read_le32(data + source_offset);
        const uint32_t source_rva = section->virtual_address + (uint32_t)i;
        if ((instruction & UINT32_C(0x7c000000))
            == UINT32_C(0x14000000)) {
          int64_t immediate = instruction & UINT32_C(0x03ffffff);
          if (immediate & INT64_C(0x02000000)) {
            immediate -= INT64_C(0x04000000);
          }
          const int64_t target = (int64_t)source_rva + immediate * 4;
          if (target >= 0 && target <= UINT32_MAX
              && exe_evidence_has_anchor(evidence, (uint32_t)target)) {
            uint64_t target_offset;
            if (exe_rva_to_file_offset(layout, (uint32_t)target, 4,
                                       &target_offset)
                && exe_ranges_overlap(
                    source_offset, 4, evidence->region_offset,
                    evidence->region_length)) {
              exe_evidence_note_control_flow(evidence, source_offset, 4,
                                             target_offset, 4);
            }
          }
        }

        // ARM64 import thunks load an exact IAT entry through X16 before
        // branching through X16. The decoded IAT relationship proves both the
        // thunk's logical address and the identity of its target entry.
        if (iat && iat->rva != 0 && iat->size != 0
            && i + 12 <= section->raw_size) {
          const uint32_t load = exe_read_le32(data + source_offset + 4);
          const uint32_t branch = exe_read_le32(data + source_offset + 8);
          if ((instruction & UINT32_C(0x9f00001f))
                  == UINT32_C(0x90000010)
              && (load & UINT32_C(0xffc003ff))
                  == UINT32_C(0xf9400210)
              && branch == UINT32_C(0xd61f0200)) {
            int64_t page_delta =
                ((instruction >> 29) & UINT32_C(0x3))
                | (((instruction >> 5) & UINT32_C(0x7ffff)) << 2);
            if (page_delta & INT64_C(0x100000)) {
              page_delta -= INT64_C(0x200000);
            }
            const int64_t target =
                (int64_t)(source_rva & UINT32_C(0xfffff000))
                + page_delta * INT64_C(4096)
                + (int64_t)((load >> 10) & UINT32_C(0xfff)) * 8;
            if (target >= 0 && target <= UINT32_MAX
                && (uint64_t)target >= iat->rva
                && (uint64_t)target + sizeof(uint64_t) <= iat_end
                && exe_evidence_has_anchor(evidence, (uint32_t)target)) {
              uint64_t target_offset;
              if (exe_rva_to_file_offset(
                      layout, (uint32_t)target, sizeof(uint64_t),
                      &target_offset)
                  && exe_ranges_overlap(
                      source_offset, 12, evidence->region_offset,
                      evidence->region_length)) {
                exe_evidence_note_control_flow(
                    evidence, source_offset, 12, target_offset,
                    sizeof(uint64_t));
              }
            }
          }
        }
      }
    }
  }
}

// Read little-endian PE integers without imposing alignment requirements.
//
static inline uint16_t exe_read_le16(const uint8_t *data) {
  return (uint16_t)data[0] | (uint16_t)((uint16_t)data[1] << 8);
}

static inline uint32_t exe_read_le32(const uint8_t *data) {
  return (uint32_t)data[0]
         | ((uint32_t)data[1] << 8)
         | ((uint32_t)data[2] << 16)
         | ((uint32_t)data[3] << 24);
}

static inline uint64_t exe_read_le64(const uint8_t *data) {
  return (uint64_t)exe_read_le32(data)
         | ((uint64_t)exe_read_le32(data + 4) << 32);
}

static inline uint32_t exe_read_be32(const uint8_t *data) {
  return ((uint32_t)data[0] << 24)
         | ((uint32_t)data[1] << 16)
         | ((uint32_t)data[2] << 8)
         | (uint32_t)data[3];
}

// Return true when value is a nonzero power of two.
//
static inline bool exe_power_of_two_u32(uint32_t value) {
  return value != 0 && (value & (value - 1)) == 0;
}

// Round value upward to a power-of-two alignment, or return UINT64_MAX on
// invalid input or overflow.
//
static inline uint64_t exe_align_up_u64(uint64_t value, uint64_t alignment) {
  if (alignment == 0 || value > UINT64_MAX - (alignment - 1)) {
    return UINT64_MAX;
  }
  return (value + alignment - 1) & ~(alignment - 1);
}

// Retain the earliest byte at which structural validation failed.
//
static inline void exe_set_failure(ExeLayout *layout, uint64_t offset) {
  if (layout && offset < layout->failure_offset) {
    layout->failure_offset = offset;
  }
}

// Recognize the machine values assigned to PE executable images.
//
static inline bool exe_machine_supported(uint16_t machine) {
  switch (machine) {
    case UINT16_C(0x014c): // I386
    case UINT16_C(0x0160): // R3000 big endian
    case UINT16_C(0x0162): // R3000
    case UINT16_C(0x0166): // R4000
    case UINT16_C(0x0168): // R10000
    case UINT16_C(0x0169): // WCEMIPSV2
    case UINT16_C(0x0184): // Alpha
    case UINT16_C(0x01a2): // SH3
    case UINT16_C(0x01a3): // SH3DSP
    case UINT16_C(0x01a6): // SH4
    case UINT16_C(0x01a8): // SH5
    case UINT16_C(0x01c0): // ARM
    case UINT16_C(0x01c2): // Thumb
    case UINT16_C(0x01c4): // ARMNT
    case UINT16_C(0x01d3): // AM33
    case UINT16_C(0x01f0): // PowerPC
    case UINT16_C(0x01f1): // PowerPCFP
    case UINT16_C(0x0200): // IA64
    case UINT16_C(0x0266): // MIPS16
    case UINT16_C(0x0284): // Alpha64
    case UINT16_C(0x0366): // MIPSFPU
    case UINT16_C(0x0466): // MIPSFPU16
    case UINT16_C(0x5032): // RISC-V 32
    case UINT16_C(0x5064): // RISC-V 64
    case UINT16_C(0x5128): // RISC-V 128
    case UINT16_C(0x6232): // LoongArch 32
    case UINT16_C(0x6264): // LoongArch 64
    case UINT16_C(0x8664): // AMD64
    case UINT16_C(0x9041): // M32R
    case UINT16_C(0xa641): // ARM64EC
    case UINT16_C(0xa64e): // ARM64X
    case UINT16_C(0xaa64): // ARM64
    case UINT16_C(0x0ebc): // EFI byte code
      return true;
    default:
      return false;
  }
}

// Return true when two nonempty byte ranges overlap without allowing either
// end calculation to wrap.
//
static inline bool exe_ranges_overlap(uint64_t first_offset,
                                      uint64_t first_size,
                                      uint64_t second_offset,
                                      uint64_t second_size) {
  if (first_size == 0 || second_size == 0) {
    return false;
  }
  return first_offset <= UINT64_MAX - first_size
         && second_offset <= UINT64_MAX - second_size
         && first_offset < second_offset + second_size
         && second_offset < first_offset + first_size;
}

// Initialize aggregate and per-block evidence for one logical trial region.
// Per-block evidence lets the reassembler reject mappings justified by only a
// small portion of a larger displaced run.
//
static inline void exe_order_evidence_initialize(
    ExeOrderEvidence *evidence, uint64_t region_offset,
    uint64_t region_length) {
  if (!evidence) {
    return;
  }
  memset(evidence, 0, sizeof(*evidence));
  evidence->region_offset = region_offset;
  evidence->region_length = region_length;
  if (region_length == 0 || scalpel_state.blocksize == 0) {
    return;
  }

  evidence->first_block = region_offset / scalpel_state.blocksize;
  const uint64_t final_offset = region_offset + region_length - 1;
  const uint64_t final_block = final_offset / scalpel_state.blocksize;
  evidence->block_count = final_block - evidence->first_block + 1;
  evidence->blocks = (ExeBlockOrderEvidence *)calloc(
      evidence->block_count, sizeof(*evidence->blocks));
  check_memory_allocation(evidence->blocks, __LINE__, __FILE__,
                          "PE block order evidence");
}

// Release storage owned by one order-evidence record.
//
static inline void exe_order_evidence_destroy(ExeOrderEvidence *evidence) {
  if (!evidence) {
    return;
  }
  free(evidence->blocks);
  free(evidence->anchors);
  memset(evidence, 0, sizeof(*evidence));
}

// Record validated structures and references that touch the logical region
// replaced by an out-of-order recovery trial.
//
static inline void exe_evidence_note_record(ExeOrderEvidence *evidence,
                                            uint64_t offset,
                                            uint64_t size) {
  if (!evidence
      || !exe_ranges_overlap(offset, size, evidence->region_offset,
                             evidence->region_length)) {
    return;
  }
  if (evidence->metadata_records != UINT32_MAX) {
    evidence->metadata_records++;
  }
}

static inline void exe_evidence_note_reference(ExeOrderEvidence *evidence,
                                               uint64_t source_offset,
                                               uint64_t source_size,
                                               uint64_t target_offset,
                                               uint64_t target_size) {
  if (!evidence) {
    return;
  }
  const bool source_touches = exe_ranges_overlap(
      source_offset, source_size, evidence->region_offset,
      evidence->region_length);
  const bool target_touches = exe_ranges_overlap(
      target_offset, target_size, evidence->region_offset,
      evidence->region_length);
  if (source_touches && evidence->local_references != UINT32_MAX) {
    evidence->local_references++;
  }
  if (target_touches && evidence->target_references != UINT32_MAX) {
    evidence->target_references++;
  }
  if (source_touches && !target_touches
      && evidence->cross_references != UINT32_MAX) {
    evidence->cross_references++;
  }

  for (uint64_t i = 0; i < evidence->block_count; i++) {
    const uint64_t block_offset =
        (evidence->first_block + i) * scalpel_state.blocksize;
    const bool source_touches_block = exe_ranges_overlap(
        source_offset, source_size, block_offset, scalpel_state.blocksize);
    const bool target_touches_block = exe_ranges_overlap(
        target_offset, target_size, block_offset, scalpel_state.blocksize);
    ExeBlockOrderEvidence *block = &evidence->blocks[i];
    if (source_touches_block && block->local_references != UINT32_MAX) {
      block->local_references++;
    }
    if (!source_touches_block && target_touches_block
        && block->target_references != UINT32_MAX) {
      block->target_references++;
    }
    if (source_touches_block && !target_touches_block
        && block->cross_references != UINT32_MAX) {
      block->cross_references++;
    }
  }
}

// Record an incoming relationship only after the target bytes have passed a
// format-specific parser. A pointer to otherwise unchecked bytes does not
// establish their order.
//
static inline void exe_evidence_note_validated_reference(
    ExeOrderEvidence *evidence, uint64_t source_offset,
    uint64_t source_size, uint64_t target_offset, uint64_t target_size) {
  exe_evidence_note_reference(evidence, source_offset, source_size,
                              target_offset, target_size);
  if (evidence
      && !exe_ranges_overlap(source_offset, source_size,
                             evidence->region_offset,
                             evidence->region_length)
      && exe_ranges_overlap(target_offset, target_size,
                            evidence->region_offset,
                            evidence->region_length)
      && evidence->validated_target_references != UINT32_MAX) {
    evidence->validated_target_references++;
  }
  if (!evidence) {
    return;
  }
  for (uint64_t i = 0; i < evidence->block_count; i++) {
    const uint64_t block_offset =
        (evidence->first_block + i) * scalpel_state.blocksize;
    if (!exe_ranges_overlap(source_offset, source_size, block_offset,
                            scalpel_state.blocksize)
        && exe_ranges_overlap(target_offset, target_size, block_offset,
                              scalpel_state.blocksize)
        && evidence->blocks[i].validated_target_references != UINT32_MAX) {
      evidence->blocks[i].validated_target_references++;
    }
  }
}

// Record a decoded branch or call whose target is a metadata-derived anchor.
//
static inline void exe_evidence_note_control_flow(
    ExeOrderEvidence *evidence, uint64_t source_offset,
    uint64_t source_size, uint64_t target_offset, uint64_t target_size) {
  if (!evidence) {
    return;
  }
  if (evidence->control_flow_references != UINT32_MAX) {
    evidence->control_flow_references++;
  }
  for (uint64_t i = 0; i < evidence->block_count; i++) {
    const uint64_t block_offset =
        (evidence->first_block + i) * scalpel_state.blocksize;
    if (exe_ranges_overlap(source_offset, source_size, block_offset,
                           scalpel_state.blocksize)
        && evidence->blocks[i].control_flow_references != UINT32_MAX) {
      evidence->blocks[i].control_flow_references++;
    }
  }
  exe_evidence_note_reference(evidence, source_offset, source_size,
                              target_offset, target_size);
}

// Retain address-sensitive control-flow targets for candidate-order checks.
// Anchor collection is optional and bounded independently of file contents.
//
static inline void exe_evidence_add_anchor(ExeOrderEvidence *evidence,
                                           uint32_t rva) {
  if (!evidence || rva == 0
      || evidence->anchor_count >= EXE_MAX_ORDER_ANCHORS) {
    return;
  }
  if (evidence->anchor_count == evidence->anchor_capacity) {
    uint32_t new_capacity = evidence->anchor_capacity == 0
                                ? 1024U
                                : evidence->anchor_capacity * 2U;
    if (new_capacity > EXE_MAX_ORDER_ANCHORS
        || new_capacity < evidence->anchor_capacity) {
      new_capacity = EXE_MAX_ORDER_ANCHORS;
    }
    uint32_t *anchors = (uint32_t *)realloc(
        evidence->anchors, (size_t)new_capacity * sizeof(*anchors));
    check_memory_allocation(anchors, __LINE__, __FILE__,
                            "EXE order anchors");
    evidence->anchors = anchors;
    evidence->anchor_capacity = new_capacity;
  }
  evidence->anchors[evidence->anchor_count++] = rva;
}

static inline int exe_compare_u32(const void *left, const void *right) {
  const uint32_t first = *(const uint32_t *)left;
  const uint32_t second = *(const uint32_t *)right;
  return (first > second) - (first < second);
}

static inline bool exe_evidence_has_anchor(const ExeOrderEvidence *evidence,
                                           uint32_t rva) {
  return evidence && evidence->anchors && evidence->anchor_count != 0
         && bsearch(&rva, evidence->anchors, evidence->anchor_count,
                    sizeof(*evidence->anchors), exe_compare_u32) != NULL;
}

// A recovered run needs relationships that cross its boundary. Relationships
// wholly inside a moved run preserve relative order but cannot establish the
// run's position in the file. The exact Authenticode path is handled
// separately and does not use these thresholds.
//
static inline bool exe_order_evidence_sufficient(
    const ExeOrderEvidence *evidence) {
  if (!evidence) {
    return false;
  }
  if (evidence->cryptographic_regions != 0) {
    return true;
  }
  const uint64_t crossing_references =
      (uint64_t)evidence->cross_references
      + evidence->validated_target_references;
  return crossing_references >= 2
         || (crossing_references >= 1
             && (evidence->relocation_values >= 2
                 || evidence->control_flow_references >= 2));
}

// Return true only when every byte in a trial region contributes to the
// Authenticode image digest. Attribute certificates and unhashed file gaps do
// not provide cryptographic ordering evidence.
//
static inline bool exe_authenticode_region_covered(
    const ExeLayout *layout, uint64_t offset, uint64_t length) {
  if (!layout || length == 0 || offset > UINT64_MAX - length
      || layout->certificate_directory_offset == 0) {
    return false;
  }

  const uint64_t end = offset + length;
  uint64_t hashed_end = layout->size_of_headers;
  for (uint32_t i = 0; i < layout->section_count; i++) {
    const uint64_t section_end =
        (uint64_t)layout->sections[i].raw_offset
        + layout->sections[i].raw_size;
    if (section_end > hashed_end) {
      hashed_end = section_end;
    }
  }

  uint64_t cursor = offset;
  while (cursor < end) {
    uint64_t covered_end = cursor;
    if (cursor < layout->checksum_offset) {
      covered_end = layout->checksum_offset;
    }
    else if (cursor >= (uint64_t)layout->checksum_offset + 4
             && cursor < layout->certificate_directory_offset) {
      covered_end = layout->certificate_directory_offset;
    }
    else if (cursor >= (uint64_t)layout->certificate_directory_offset + 8
             && cursor < layout->size_of_headers) {
      covered_end = layout->size_of_headers;
    }

    for (uint32_t i = 0; i < layout->section_count; i++) {
      const uint64_t section_start = layout->sections[i].raw_offset;
      const uint64_t section_end =
          section_start + layout->sections[i].raw_size;
      if (cursor >= section_start && cursor < section_end
          && section_end > covered_end) {
        covered_end = section_end;
      }
    }

    if (layout->certificate_offset > hashed_end
        && cursor >= hashed_end && cursor < layout->certificate_offset
        && layout->certificate_offset > covered_end) {
      covered_end = layout->certificate_offset;
    }
    if (covered_end == cursor) {
      return false;
    }
    cursor = covered_end < end ? covered_end : end;
  }
  return true;
}

// Parse the DOS, COFF, optional, and section headers without reading section contents. This is also
// the false-positive filter used by header discovery.
static inline bool exe_parse_headers(const uint8_t *data, uint64_t length,
                                     ExeLayout *layout) {
  uint64_t pe_end;
  uint64_t optional_end;
  uint64_t section_table_end;
  uint64_t extent;
  uint32_t minimum_optional_size;
  uint32_t directory_offset;
  uint32_t directory_count_offset;

  if (!data || !layout) {
    return false;
  }
  memset(layout, 0, sizeof(*layout));
  layout->failure_offset = UINT64_MAX;

  if (!exe_range_available(length, 0, EXE_DOS_HEADER_SIZE)
      || data[0] != 'M' || data[1] != 'Z') {
    return false;
  }
  layout->pe_offset = exe_read_le32(data + 0x3c);
  if (layout->pe_offset < EXE_DOS_HEADER_SIZE
      || layout->pe_offset > EXE_MAX_PE_HEADER_OFFSET
      || !exe_add_u64(layout->pe_offset, 4 + EXE_COFF_HEADER_SIZE,
                      &pe_end)
      || !exe_range_available(length, layout->pe_offset,
                              4 + EXE_COFF_HEADER_SIZE)) {
    return false;
  }
  if (memcmp(data + layout->pe_offset, "PE\0\0", 4) != 0) {
    return false;
  }

  const uint8_t *coff = data + layout->pe_offset + 4;
  layout->machine = exe_read_le16(coff);
  layout->section_count = exe_read_le16(coff + 2);
  layout->optional_header_size = exe_read_le16(coff + 16);
  layout->characteristics = exe_read_le16(coff + 18);
  if (!exe_machine_supported(layout->machine)
      || layout->section_count == 0
      || layout->section_count > EXE_MAX_SECTIONS
      || !(layout->characteristics & EXE_IMAGE_FILE_EXECUTABLE_IMAGE)) {
    return false;
  }

  layout->optional_header_offset = (uint32_t)pe_end;
  if (!exe_add_u64(layout->optional_header_offset,
                   layout->optional_header_size, &optional_end)
      || !exe_range_available(length, layout->optional_header_offset,
                              layout->optional_header_size)
      || layout->optional_header_size < 2) {
    return false;
  }

  const uint8_t *optional = data + layout->optional_header_offset;
  const uint16_t magic = exe_read_le16(optional);
  if (magic == UINT16_C(0x010b)) {
    layout->pe32_plus = false;
    minimum_optional_size = 96;
    directory_offset = 96;
    directory_count_offset = 92;
  }
  else if (magic == UINT16_C(0x020b)) {
    layout->pe32_plus = true;
    minimum_optional_size = 112;
    directory_offset = 112;
    directory_count_offset = 108;
  }
  else {
    return false;
  }
  if (layout->optional_header_size < minimum_optional_size) {
    return false;
  }

  layout->address_of_entry_point = exe_read_le32(optional + 16);
  layout->image_base = layout->pe32_plus
                           ? exe_read_le64(optional + 24)
                           : exe_read_le32(optional + 28);
  layout->section_alignment = exe_read_le32(optional + 32);
  layout->file_alignment = exe_read_le32(optional + 36);
  layout->size_of_image = exe_read_le32(optional + 56);
  layout->size_of_headers = exe_read_le32(optional + 60);
  layout->checksum_offset = layout->optional_header_offset + 64;
  layout->stored_checksum = exe_read_le32(optional + 64);
  layout->checksum_present = layout->stored_checksum != 0;

  if (!exe_power_of_two_u32(layout->file_alignment)
      || layout->file_alignment > UINT32_C(65536)
      || layout->image_base % UINT32_C(65536) != 0
      || layout->section_alignment == 0
      || layout->section_alignment < layout->file_alignment
      || (layout->section_alignment < UINT32_C(4096)
          && layout->section_alignment != layout->file_alignment)
      || layout->size_of_headers == 0
      || layout->size_of_headers % layout->file_alignment != 0
      || layout->size_of_image == 0) {
    return false;
  }

  layout->section_table_offset = (uint32_t)optional_end;
  if (!exe_add_u64(layout->section_table_offset,
                   (uint64_t)layout->section_count * EXE_SECTION_HEADER_SIZE,
                   &section_table_end)
      || !exe_range_available(length, layout->section_table_offset,
                              (uint64_t)layout->section_count
                                  * EXE_SECTION_HEADER_SIZE)
      || layout->size_of_headers < section_table_end) {
    return false;
  }

  layout->directory_count = exe_read_le32(optional + directory_count_offset);
  const uint32_t directory_capacity =
      (layout->optional_header_size - directory_offset) / 8;
  if (layout->directory_count > directory_capacity) {
    return false;
  }
  if (layout->directory_count > EXE_MAX_DIRECTORIES) {
    layout->directory_count = EXE_MAX_DIRECTORIES;
  }
  for (uint32_t i = 0; i < layout->directory_count; i++) {
    layout->directories[i].rva =
        exe_read_le32(optional + directory_offset + i * 8);
    layout->directories[i].size =
        exe_read_le32(optional + directory_offset + i * 8 + 4);
  }
  if (layout->directory_count > 4) {
    layout->certificate_directory_offset =
        layout->optional_header_offset + directory_offset + 4 * 8;
    layout->certificate_offset = layout->directories[4].rva;
    layout->certificate_size = layout->directories[4].size;
  }

  extent = layout->size_of_headers;
  uint64_t highest_virtual_end = 0;
  uint64_t expected_virtual_address = exe_align_up_u64(
      layout->size_of_headers, layout->section_alignment);
  uint64_t previous_raw_end = layout->size_of_headers;
  for (uint32_t i = 0; i < layout->section_count; i++) {
    const uint8_t *section = data + layout->section_table_offset
                             + (uint64_t)i * EXE_SECTION_HEADER_SIZE;
    ExeSection *parsed = &layout->sections[i];
    memcpy(parsed->name, section, 8);
    parsed->name[8] = 0;
    parsed->virtual_size = exe_read_le32(section + 8);
    parsed->virtual_address = exe_read_le32(section + 12);
    parsed->raw_size = exe_read_le32(section + 16);
    parsed->raw_offset = exe_read_le32(section + 20);
    parsed->characteristics = exe_read_le32(section + 36);

    uint64_t virtual_span = parsed->virtual_size > parsed->raw_size
                                ? parsed->virtual_size
                                : parsed->raw_size;
    uint64_t virtual_end;
    if (parsed->virtual_address != expected_virtual_address
        || parsed->virtual_address % layout->section_alignment != 0
        || !exe_add_u64(parsed->virtual_address, virtual_span, &virtual_end)) {
      return false;
    }
    expected_virtual_address = exe_align_up_u64(
        virtual_end, layout->section_alignment);
    if (expected_virtual_address == UINT64_MAX) {
      return false;
    }
    if (virtual_end > highest_virtual_end) {
      highest_virtual_end = virtual_end;
    }

    if (parsed->raw_size != 0) {
      uint64_t raw_end;
      if (parsed->raw_offset == 0
          || parsed->raw_size % layout->file_alignment != 0
          || parsed->raw_offset < previous_raw_end
          || !exe_add_u64(parsed->raw_offset, parsed->raw_size, &raw_end)) {
        return false;
      }
      if (layout->file_alignment >= 512
          && parsed->raw_offset % layout->file_alignment != 0) {
        return false;
      }
      if (layout->section_alignment < UINT32_C(4096)
          && parsed->raw_offset != parsed->virtual_address) {
        return false;
      }
      previous_raw_end = raw_end;
      if (raw_end > extent) {
        extent = raw_end;
      }
    }
  }

  if (highest_virtual_end > layout->size_of_image
      || expected_virtual_address != layout->size_of_image
      || layout->size_of_image % layout->section_alignment != 0) {
    return false;
  }
  if (layout->address_of_entry_point != 0) {
    bool entry_mapped = false;
    for (uint32_t i = 0; i < layout->section_count; i++) {
      const ExeSection *section = &layout->sections[i];
      const uint64_t span = section->virtual_size > section->raw_size
                                ? section->virtual_size
                                : section->raw_size;
      if (layout->address_of_entry_point >= section->virtual_address
          && (uint64_t)layout->address_of_entry_point
                 < (uint64_t)section->virtual_address + span
          && (section->characteristics & EXE_IMAGE_SCN_MEM_EXECUTE)) {
        entry_mapped = true;
        break;
      }
    }
    if (!entry_mapped && !(layout->characteristics & EXE_IMAGE_FILE_DLL)) {
      return false;
    }
  }

  layout->image_extent = extent;
  layout->described_extent = extent;
  if (layout->certificate_offset != 0 || layout->certificate_size != 0) {
    uint64_t certificate_end;
    if (layout->certificate_offset == 0 || layout->certificate_size == 0
        || layout->certificate_offset % 8 != 0
        || layout->certificate_offset < layout->image_extent
        || !exe_add_u64(layout->certificate_offset,
                        layout->certificate_size, &certificate_end)) {
      return false;
    }
    if (certificate_end > layout->described_extent) {
      layout->described_extent = certificate_end;
    }
  }

  layout->coff_symbol_offset = exe_read_le32(coff + 8);
  layout->coff_symbol_count = exe_read_le32(coff + 12);
  if (layout->coff_symbol_offset != 0 || layout->coff_symbol_count != 0) {
    if (layout->coff_symbol_offset == 0 || layout->coff_symbol_count == 0
        || !exe_add_u64(layout->coff_symbol_offset,
                        (uint64_t)layout->coff_symbol_count
                            * EXE_COFF_SYMBOL_SIZE,
                        &layout->coff_symbol_end)) {
      return false;
    }
    uint64_t string_header_end;
    if (!exe_add_u64(layout->coff_symbol_end,
                     EXE_COFF_STRING_TABLE_HEADER_SIZE,
                     &string_header_end)) {
      return false;
    }
    if (string_header_end > layout->described_extent) {
      layout->described_extent = string_header_end;
    }

    // The string-table length follows the symbol array. Header discovery
    // normally sees enough contiguous bytes to establish the complete extent;
    // fragmented recovery retains the four-byte minimum until a mapping makes
    // the length field available.
    if (exe_range_available(length, layout->coff_symbol_end,
                            EXE_COFF_STRING_TABLE_HEADER_SIZE)) {
      const uint32_t string_size =
          exe_read_le32(data + layout->coff_symbol_end);
      uint64_t string_end;
      if (string_size >= EXE_COFF_STRING_TABLE_HEADER_SIZE
          && exe_add_u64(layout->coff_symbol_end, string_size, &string_end)
          && string_end <= length) {
        ExeLayout candidate_layout = *layout;
        candidate_layout.coff_string_table_size = string_size;
        if (string_end > candidate_layout.described_extent) {
          candidate_layout.described_extent = string_end;
        }
        if (exe_validate_coff_symbol_table(
                data, length, &candidate_layout, NULL)) {
          layout->coff_string_table_size = string_size;
          layout->described_extent = candidate_layout.described_extent;
        }
      }
    }
  }

  layout->header_valid = true;
  layout->sections_valid = true;
  return true;
}

// Resolve the length-prefixed COFF string table that immediately follows the
// symbol array and include it in the recoverable on-disk extent.
static inline bool exe_resolve_coff_string_table_extent(
    const uint8_t *data, uint64_t length, ExeLayout *layout) {
  if (!data || !layout) {
    return false;
  }
  if (layout->coff_symbol_count == 0) {
    return true;
  }
  if (layout->coff_string_table_size != 0) {
    return true;
  }
  if (!exe_range_available(length, layout->coff_symbol_end,
                           EXE_COFF_STRING_TABLE_HEADER_SIZE)) {
    exe_set_failure(layout, layout->coff_symbol_end);
    return false;
  }

  const uint32_t string_size =
      exe_read_le32(data + layout->coff_symbol_end);
  uint64_t string_end;
  if (string_size < EXE_COFF_STRING_TABLE_HEADER_SIZE
      || !exe_add_u64(layout->coff_symbol_end, string_size, &string_end)) {
    exe_set_failure(layout, layout->coff_symbol_end);
    return false;
  }
  ExeLayout candidate_layout = *layout;
  candidate_layout.coff_string_table_size = string_size;
  if (string_end > candidate_layout.described_extent) {
    candidate_layout.described_extent = string_end;
  }
  if (!exe_validate_coff_symbol_table(
          data, length, &candidate_layout, NULL)) {
    exe_set_failure(layout, candidate_layout.failure_offset);
    return false;
  }
  layout->coff_string_table_size = string_size;
  layout->described_extent = candidate_layout.described_extent;
  return true;
}

// Validate the COFF symbol records and every referenced long name. Auxiliary
// records are counted by NumberOfSymbols and are skipped with their owner.
static inline bool exe_validate_coff_symbol_table(
    const uint8_t *data, uint64_t length, ExeLayout *layout,
    ExeOrderEvidence *evidence) {
  if (!data || !layout) {
    return false;
  }
  if (layout->coff_symbol_count == 0) {
    return true;
  }
  if (!exe_range_available(
          length, layout->coff_symbol_offset,
          (uint64_t)layout->coff_symbol_count * EXE_COFF_SYMBOL_SIZE)) {
    exe_set_failure(layout, layout->coff_symbol_offset);
    return false;
  }

  // Validate the fixed-size records before using the string-table extent.
  // This keeps a corrupt length field from obscuring an earlier structural
  // contradiction in the symbol array.
  uint32_t index = 0;
  while (index < layout->coff_symbol_count) {
    const uint64_t entry_offset =
        (uint64_t)layout->coff_symbol_offset
        + (uint64_t)index * EXE_COFF_SYMBOL_SIZE;
    const uint8_t *entry = data + entry_offset;
    const int16_t section_number = (int16_t)exe_read_le16(entry + 12);
    const uint8_t auxiliary_count = entry[17];
    if (section_number < -2
        || section_number > (int16_t)layout->section_count
        || auxiliary_count > layout->coff_symbol_count - index - 1) {
      exe_set_failure(layout, entry_offset);
      return false;
    }

    const uint64_t record_count = (uint64_t)auxiliary_count + 1;
    exe_evidence_note_record(evidence, entry_offset,
                             record_count * EXE_COFF_SYMBOL_SIZE);
    index += (uint32_t)record_count;
  }

  if (layout->coff_string_table_size
          < EXE_COFF_STRING_TABLE_HEADER_SIZE
      || !exe_range_available(length, layout->coff_symbol_end,
                              layout->coff_string_table_size)) {
    const uint64_t failure = layout->coff_symbol_end < length
                                 ? length
                                 : layout->coff_symbol_end;
    exe_set_failure(layout, failure);
    return false;
  }

  index = 0;
  while (index < layout->coff_symbol_count) {
    const uint64_t entry_offset =
        (uint64_t)layout->coff_symbol_offset
        + (uint64_t)index * EXE_COFF_SYMBOL_SIZE;
    const uint8_t *entry = data + entry_offset;
    const uint8_t auxiliary_count = entry[17];
    if (exe_read_le32(entry) == 0) {
      const uint32_t name_offset = exe_read_le32(entry + 4);
      if (name_offset != 0) {
        if (name_offset < EXE_COFF_STRING_TABLE_HEADER_SIZE
            || name_offset >= layout->coff_string_table_size) {
          exe_set_failure(layout, entry_offset + 4);
          return false;
        }
        const uint64_t name_position =
            layout->coff_symbol_end + name_offset;
        const uint64_t name_limit =
            layout->coff_string_table_size - name_offset;
        const uint8_t *terminator =
            memchr(data + name_position, 0, (size_t)name_limit);
        if (!terminator || terminator == data + name_position) {
          exe_set_failure(layout, name_position);
          return false;
        }
        const uint32_t name_size =
            (uint32_t)(terminator - (data + name_position)) + 1;
        exe_evidence_note_validated_reference(
            evidence, entry_offset, EXE_COFF_SYMBOL_SIZE,
            name_position, name_size);
      }
    }
    index += (uint32_t)auxiliary_count + 1;
  }
  return true;
}

// Copy bytes through a one-gap logical mapping without materializing the
// complete PE. This is used only to establish a structurally valid COFF tail
// before the checksum-based recovery search allocates a fixed-size mapping.
static inline bool exe_copy_gap_mapped_range(
    int64_t start, uint64_t gap_blocks, uint64_t boundary,
    uint64_t logical_offset, uint64_t length, uint8_t *destination,
    bool uncovered_only) {
  if (start < 0 || (!destination && length != 0)) {
    return false;
  }

  const uint64_t blocksize = scalpel_state.blocksize;
  const uint64_t apparent_blocks =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  uint64_t copied = 0;
  while (copied < length) {
    const uint64_t offset = logical_offset + copied;
    const uint64_t logical_block = offset / blocksize;
    const uint64_t within_block = offset % blocksize;
    uint64_t apparent = (uint64_t)start + logical_block;
    if (logical_block >= boundary) {
      if (apparent > UINT64_MAX - gap_blocks) {
        return false;
      }
      apparent += gap_blocks;
    }
    if (apparent >= apparent_blocks || apparent > INT64_MAX) {
      return false;
    }

    const int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, (int64_t)apparent);
    if (actual < 0
        || (uncovered_only
            && filemirror_actual_block_covered(scalpel_state.filemirror,
                                               actual))) {
      return false;
    }
    uint64_t available = 0;
    const uint8_t *source =
        (const uint8_t *)filemirror_actual_block_data_pointer(
            scalpel_state.filemirror, actual, &available);
    if (!source || within_block >= available) {
      return false;
    }
    uint64_t chunk = length - copied;
    if (chunk > available - within_block) {
      chunk = available - within_block;
    }
    memcpy(destination + copied, source + within_block, (size_t)chunk);
    copied += chunk;
  }
  return true;
}

// Validate the COFF records and referenced names through one proposed gap
// mapping, returning the exact length-prefixed string-table size.
static inline bool exe_gap_mapped_coff_extent(
    const ExeLayout *layout, int64_t start, uint64_t gap_blocks,
    uint64_t boundary, uint64_t maximum_size, uint32_t *string_size) {
  if (!layout || !string_size || layout->coff_symbol_count == 0) {
    return false;
  }

  uint8_t entry[EXE_COFF_SYMBOL_SIZE];
  uint32_t index = 0;
  while (index < layout->coff_symbol_count) {
    const uint64_t entry_offset =
        (uint64_t)layout->coff_symbol_offset
        + (uint64_t)index * EXE_COFF_SYMBOL_SIZE;
    if (!exe_copy_gap_mapped_range(
            start, gap_blocks, boundary, entry_offset, sizeof(entry), entry,
            true)) {
      return false;
    }
    const int16_t section_number = (int16_t)exe_read_le16(entry + 12);
    const uint8_t auxiliary_count = entry[17];
    if (section_number < -2
        || section_number > (int16_t)layout->section_count
        || auxiliary_count > layout->coff_symbol_count - index - 1) {
      return false;
    }
    index += (uint32_t)auxiliary_count + 1;
  }

  uint8_t encoded_size[EXE_COFF_STRING_TABLE_HEADER_SIZE];
  if (!exe_copy_gap_mapped_range(
          start, gap_blocks, boundary, layout->coff_symbol_end,
          sizeof(encoded_size), encoded_size, true)) {
    return false;
  }
  const uint32_t observed_size = exe_read_le32(encoded_size);
  uint64_t string_end;
  if (observed_size < EXE_COFF_STRING_TABLE_HEADER_SIZE
      || !exe_add_u64(layout->coff_symbol_end, observed_size, &string_end)
      || string_end > maximum_size) {
    return false;
  }

  index = 0;
  while (index < layout->coff_symbol_count) {
    const uint64_t entry_offset =
        (uint64_t)layout->coff_symbol_offset
        + (uint64_t)index * EXE_COFF_SYMBOL_SIZE;
    if (!exe_copy_gap_mapped_range(
            start, gap_blocks, boundary, entry_offset, sizeof(entry), entry,
            true)) {
      return false;
    }
    if (exe_read_le32(entry) == 0) {
      const uint32_t name_offset = exe_read_le32(entry + 4);
      if (name_offset != 0) {
        if (name_offset < EXE_COFF_STRING_TABLE_HEADER_SIZE
            || name_offset >= observed_size) {
          return false;
        }
        uint64_t name_position = layout->coff_symbol_end + name_offset;
        uint64_t name_remaining = observed_size - name_offset;
        bool first = true;
        bool terminated = false;
        while (name_remaining != 0) {
          uint8_t byte;
          if (!exe_copy_gap_mapped_range(
                  start, gap_blocks, boundary, name_position, 1, &byte,
                  true)) {
            return false;
          }
          if (byte == 0) {
            if (first) {
              return false;
            }
            terminated = true;
            break;
          }
          first = false;
          name_position++;
          name_remaining--;
        }
        if (!terminated) {
          return false;
        }
      }
    }
    index += (uint32_t)entry[17] + 1;
  }

  *string_size = observed_size;
  return true;
}

// Resolve a fragmented COFF tail before entering the fixed-extent checksum
// search. Gap positions before the symbol array share one mapping; positions
// that split the symbol or string table are checked individually. The cursor
// and any agreed string-table size survive checkpoints together.
static inline bool exe_resolve_fragmented_coff_extent(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, ExeLayout *layout, int64_t start,
    uint64_t apparent_blocks, uint64_t header_blocks,
    uint64_t maximum_size, uint64_t *iterations, ExeCarveState *state,
    bool *stopped) {
  if (stopped) {
    *stopped = false;
  }
  if (!work || !candidate || !*candidate || !layout || !iterations || !state
      || start < 0 || layout->coff_symbol_count == 0) {
    return false;
  }
  if (layout->coff_string_table_size != 0) {
    return true;
  }

  const uint64_t blocksize = scalpel_state.blocksize;
  const uint64_t minimum_blocks = CEILDIV(
      layout->coff_symbol_end + EXE_COFF_STRING_TABLE_HEADER_SIZE,
      blocksize);
  if ((uint64_t)start >= apparent_blocks
      || minimum_blocks > apparent_blocks - (uint64_t)start) {
    return false;
  }
  const uint64_t max_gap =
      apparent_blocks - (uint64_t)start - minimum_blocks;
  const uint64_t first_symbol_block =
      layout->coff_symbol_offset / blocksize;
  const uint64_t minimum_last_block = minimum_blocks - 1;

  ExeCoffProgress *progress = &state->coff;
  if (progress->phase == EXE_COFF_FAILED) {
    return false;
  }
  if (progress->phase == EXE_COFF_INITIAL) {
    uint32_t baseline_string_size = 0;
    if (exe_gap_mapped_coff_extent(
            layout, start, 0, UINT64_MAX, maximum_size,
            &baseline_string_size)) {
      progress->string_size = baseline_string_size;
      progress->phase = EXE_COFF_COMPLETE;
    }
    else {
      progress->next_gap = 1;
      progress->next_boundary = 0;
      progress->phase = EXE_COFF_SEARCH;
    }
  }

  ExeReassemblyContext context = {
      .work = work, .candidate = candidate, .uuidp = uuidp, .uuidc = uuidc,
      .state = state, .iterations = iterations
  };
  while (progress->phase == EXE_COFF_SEARCH
         && progress->next_gap <= max_gap) {
    const uint64_t boundary = progress->next_boundary == 0
        ? header_blocks : progress->next_boundary;
    uint32_t observed_size = 0;
    if (exe_gap_mapped_coff_extent(
            layout, start, progress->next_gap, boundary, maximum_size,
            &observed_size)) {
      if (progress->string_size == 0) {
        progress->string_size = observed_size;
      }
      else if (progress->string_size != observed_size) {
        progress->phase = EXE_COFF_FAILED;
        return false;
      }
    }

    if (progress->next_boundary == 0) {
      progress->next_boundary = first_symbol_block + 1;
    }
    else {
      progress->next_boundary++;
    }
    if (progress->next_boundary > minimum_last_block) {
      progress->next_gap++;
      progress->next_boundary = 0;
    }
    if (exe_reassembly_context_poll(&context)) {
      if (stopped) {
        *stopped = true;
      }
      return false;
    }
  }
  if (progress->string_size == 0) {
    progress->phase = EXE_COFF_FAILED;
    return false;
  }

  uint64_t string_end;
  if (!exe_add_u64(layout->coff_symbol_end, progress->string_size,
                   &string_end)
      || string_end > maximum_size) {
    progress->phase = EXE_COFF_FAILED;
    return false;
  }
  progress->phase = EXE_COFF_COMPLETE;
  layout->coff_string_table_size = progress->string_size;
  if (string_end > layout->described_extent) {
    layout->described_extent = string_end;
  }
  return true;
}

// Translate an RVA-backed range into its on-disk offset. Header RVAs map
// directly; section RVAs must lie within bytes actually present on disk.
//
static inline bool exe_rva_to_file_offset(const ExeLayout *layout,
                                          uint32_t rva, uint32_t size,
                                          uint64_t *offset) {
  uint64_t end;

  if (!layout || !offset || !exe_add_u64(rva, size, &end)) {
    return false;
  }
  if (rva < layout->size_of_headers && end <= layout->size_of_headers) {
    *offset = rva;
    return true;
  }
  for (uint32_t i = 0; i < layout->section_count; i++) {
    const ExeSection *section = &layout->sections[i];
    if (rva < section->virtual_address) {
      continue;
    }
    const uint64_t delta = (uint64_t)rva - section->virtual_address;
    if (delta <= section->raw_size && size <= section->raw_size - delta) {
      return exe_add_u64(section->raw_offset, delta, offset);
    }
  }
  return false;
}

// Translate an RVA and report how many contiguous on-disk bytes remain in the
// containing header or section.
//
static inline bool exe_rva_bytes_available(const ExeLayout *layout,
                                           uint32_t rva, uint64_t *offset,
                                           uint64_t *available) {
  if (!layout || !offset || !available) {
    return false;
  }
  if (rva < layout->size_of_headers) {
    *offset = rva;
    *available = layout->size_of_headers - rva;
    return true;
  }
  for (uint32_t i = 0; i < layout->section_count; i++) {
    const ExeSection *section = &layout->sections[i];
    if (rva < section->virtual_address) {
      continue;
    }
    const uint64_t delta = (uint64_t)rva - section->virtual_address;
    if (delta < section->raw_size) {
      *offset = (uint64_t)section->raw_offset + delta;
      *available = section->raw_size - delta;
      return true;
    }
  }
  return false;
}

// Convert an image-relative virtual address to an RVA.
//
static inline bool exe_va_to_rva(const ExeLayout *layout, uint64_t va,
                                 uint32_t *rva) {
  if (!layout || !rva || va < layout->image_base
      || va - layout->image_base > UINT32_MAX
      || va - layout->image_base >= layout->size_of_image) {
    return false;
  }
  *rva = (uint32_t)(va - layout->image_base);
  return true;
}

// Return true when an RVA lies in a section the loader marks executable.
//
static inline bool exe_rva_is_executable(const ExeLayout *layout,
                                         uint32_t rva) {
  if (!layout) {
    return false;
  }
  for (uint32_t i = 0; i < layout->section_count; i++) {
    const ExeSection *section = &layout->sections[i];
    const uint64_t span = section->virtual_size > section->raw_size
                              ? section->virtual_size
                              : section->raw_size;
    if (rva >= section->virtual_address
        && (uint64_t)rva < (uint64_t)section->virtual_address + span) {
      return (section->characteristics & EXE_IMAGE_SCN_MEM_EXECUTE) != 0;
    }
  }
  return false;
}

// Return true when a file range overlaps raw bytes from an executable
// section.
//
static inline bool exe_file_range_is_executable(const ExeLayout *layout,
                                                uint64_t offset,
                                                uint64_t length) {
  if (!layout || length == 0) {
    return false;
  }
  for (uint32_t i = 0; i < layout->section_count; i++) {
    const ExeSection *section = &layout->sections[i];
    if ((section->characteristics & EXE_IMAGE_SCN_MEM_EXECUTE) != 0
        && exe_ranges_overlap(offset, length, section->raw_offset,
                              section->raw_size)) {
      return true;
    }
  }
  return false;
}

// Identify executable blocks that metadata addresses but no independently
// validated relationship connects to the rest of the image. An exact
// Authenticode digest supersedes this diagnostic.
//
static inline bool exe_order_evidence_disconnected_code_range(
    const ExeLayout *layout, const ExeOrderEvidence *evidence,
    uint64_t *first_block, uint64_t *last_block) {
  if (!layout || !evidence || !evidence->blocks
      || evidence->block_count == 0 || scalpel_state.blocksize == 0) {
    return false;
  }
  bool found = false;
  for (uint64_t i = 0; i < evidence->block_count; i++) {
    const uint64_t block_offset =
        (evidence->first_block + i) * scalpel_state.blocksize;
    if (block_offset >= layout->described_extent) {
      break;
    }
    uint64_t block_length = layout->described_extent - block_offset;
    if (block_length > scalpel_state.blocksize) {
      block_length = scalpel_state.blocksize;
    }
    const ExeBlockOrderEvidence *block = &evidence->blocks[i];
    if (exe_file_range_is_executable(layout, block_offset, block_length)
        && block->target_references != 0
        && block->cross_references == 0
        && block->validated_target_references == 0
        && block->relocation_values == 0
        && block->control_flow_references == 0) {
      const uint64_t logical_block = evidence->first_block + i;
      if (!found && first_block) {
        *first_block = logical_block;
      }
      if (last_block) {
        *last_block = logical_block + 1;
      }
      found = true;
    }
  }
  return found;
}

static inline uint32_t exe_zero_alternative_capacity(
    uint64_t described_extent) {
  if (described_extent == 0) {
    return 0;
  }
  uint64_t capacity =
      EXE_ZERO_ALTERNATIVE_OUTPUT_BUDGET_PER_CLASS / described_extent;
  if (capacity == 0) {
    capacity = 1;
  }
  if (capacity > EXE_ZERO_ALTERNATIVE_LIMIT_PER_CLASS) {
    capacity = EXE_ZERO_ALTERNATIVE_LIMIT_PER_CLASS;
  }
  return (uint32_t)capacity;
}

static inline bool exe_carve_state_size(
    uint64_t total_blocks, uint64_t described_extent, size_t *state_size) {
  if (!state_size || total_blocks == 0 || described_extent == 0
      || described_extent > EXE_MAXIMUM_FILE_SIZE
      || total_blocks > CEILDIV(described_extent, UINT64_C(512))) {
    return false;
  }
  const uint32_t capacity =
      exe_zero_alternative_capacity(described_extent);
  const uint64_t alternative_count =
      (uint64_t)capacity * EXE_ZERO_ALTERNATIVE_CLASSES;
  const uint64_t mapping_count = alternative_count + 5;
  if (capacity == 0 || total_blocks > SIZE_MAX / sizeof(int64_t)
      || mapping_count > SIZE_MAX / total_blocks) {
    return false;
  }
  const size_t mapping_entries = (size_t)(mapping_count * total_blocks);
  if (mapping_entries > SIZE_MAX / sizeof(int64_t)
      || alternative_count
             > SIZE_MAX / sizeof(ExeZeroAlternativeRank)) {
    return false;
  }
  const size_t mapping_bytes = mapping_entries * sizeof(int64_t);
  const size_t rank_bytes =
      (size_t)alternative_count * sizeof(ExeZeroAlternativeRank);
  const size_t header_bytes = offsetof(ExeCarveState, storage);
  if (mapping_bytes > SIZE_MAX - header_bytes
      || rank_bytes > SIZE_MAX - header_bytes - mapping_bytes) {
    return false;
  }
  *state_size = header_bytes + mapping_bytes + rank_bytes;
  return true;
}

static inline bool exe_carve_state_valid(const ExeCarveState *state) {
  if (!state || state->magic != EXE_CARVE_STATE_MAGIC
      || state->version != EXE_CARVE_STATE_VERSION
      || state->start_block < 0
      || !exe_run_progress_valid(&state->zero_run)
      || !exe_run_progress_valid(&state->general_run)
      || state->coff.phase > EXE_COFF_FAILED
      || (state->coff.phase == EXE_COFF_SEARCH && state->coff.next_gap == 0)
      || state->coff.next_boundary > state->total_blocks
      || state->hints.gap_count > EXE_CONFIDENCE_GAP_HINTS
      || state->hints.next_gap > state->hints.gap_count
      || state->hints.width_count > EXE_CONFIDENCE_OOO_CANDIDATES
      || state->hints.destination_count > EXE_CONFIDENCE_OOO_CANDIDATES
      || state->hints.next_width > state->hints.width_count
      || state->hints.next_destination
             > state->total_blocks + EXE_CONFIDENCE_OOO_CANDIDATES + 2U
      || state->hints.gaps_ready > 1 || state->hints.ooo_ready > 1
      || state->hints.ooo_complete > 1
      || state->hints.gap_scan.complete > 1
      || state->hints.gap_scan.next_offset > INT64_MAX
      || state->hints.destination_edges.count > EXE_CONFIDENCE_OOO_EDGES
      || state->hints.source_edges.count > EXE_CONFIDENCE_OOO_EDGES
      || state->hints.destination_edges.initialized > 1
      || state->hints.source_edges.initialized > 1
      || state->hints.destination_edges.complete > 1
      || state->hints.source_edges.complete > 1
      || state->relocations.initialized > 1
      || state->relocations.complete > 1
      || state->relocations.ambiguous > 1
      || state->relocations.next_constraint > state->described_extent / 2
      || state->relocations.next_actual > INT64_MAX
      || state->relocations.choice_actual < -1
      || (state->coff.string_size != 0
          && state->coff.string_size < EXE_COFF_STRING_TABLE_HEADER_SIZE)
      || (state->coff.phase == EXE_COFF_COMPLETE
          && state->coff.string_size == 0)
      || state->search_phase > EXE_SEARCH_DONE
      || state->search_edge > 1 || state->combined_pass > 1
      || (state->search_phase >= EXE_SEARCH_OOO
          && state->search_phase < EXE_SEARCH_DONE
          && state->search_width == 0)
      || state->general_run.phase == EXE_ZERO_RESUME_PAIR
      || state->zero_resume_terminal > EXE_ZERO_COMPOSITION_STATE_LIMIT
      || state->zero_complete > 1 || state->mapping_published > 1
      || state->ambiguous > 1 || state->gap_ambiguous > 1
      || state->complete_ambiguous > 1
      || state->require_baseline_repair > 1
      || state->zero_initialized > 1
      || state->gap_complete > 1 || state->view_initialized > 1
      || state->gap_next_boundary > state->total_blocks
      || state->combined_boundary > state->total_blocks) {
    return false;
  }
  size_t expected_size = 0;
  if (!exe_carve_state_size(state->total_blocks,
                            state->described_extent, &expected_size)
      || state->allocation_size != expected_size
      || state->capacity_per_class
             != exe_zero_alternative_capacity(state->described_extent)) {
    return false;
  }
  if (scalpel_state.blocksize != 0
      && state->total_blocks
             != CEILDIV(state->described_extent,
                        scalpel_state.blocksize)) {
    return false;
  }
  for (uint32_t class_index = 0;
       class_index < EXE_ZERO_ALTERNATIVE_CLASSES; class_index++) {
    if (state->alternative_counts[class_index]
        > state->capacity_per_class) {
      return false;
    }
  }
  return true;
}

static inline ExeCarveState *exe_carve_state_create(
    uint64_t total_blocks, uint64_t described_extent, int64_t start_block) {
  size_t state_size = 0;
  if (start_block < 0
      || !exe_carve_state_size(total_blocks, described_extent,
                               &state_size)) {
    return NULL;
  }
  ExeCarveState *state = (ExeCarveState *)calloc(1, state_size);
  check_memory_allocation(state, __LINE__, __FILE__,
                          "EXE carve state");
  state->magic = EXE_CARVE_STATE_MAGIC;
  state->version = EXE_CARVE_STATE_VERSION;
  state->capacity_per_class =
      exe_zero_alternative_capacity(described_extent);
  state->allocation_size = state_size;
  state->total_blocks = total_blocks;
  state->described_extent = described_extent;
  state->start_block = start_block;
  exe_run_progress_reset(&state->zero_run);
  exe_run_progress_reset(&state->general_run);
  return state;
}

static inline int64_t *exe_carve_state_alternative_mappings(
    ExeCarveState *state) {
  return state ? (int64_t *)state->storage : NULL;
}

static inline int64_t *exe_carve_state_ordered_mapping(
    ExeCarveState *state) {
  if (!state) {
    return NULL;
  }
  const uint64_t alternatives =
      (uint64_t)state->capacity_per_class
      * EXE_ZERO_ALTERNATIVE_CLASSES;
  return exe_carve_state_alternative_mappings(state)
         + alternatives * state->total_blocks;
}

static inline int64_t *exe_carve_state_gap_mapping(
    ExeCarveState *state) {
  return state ? exe_carve_state_ordered_mapping(state)
                     + state->total_blocks : NULL;
}

static inline int64_t *exe_carve_state_complete_mapping(
    ExeCarveState *state) {
  return state ? exe_carve_state_gap_mapping(state)
                     + state->total_blocks : NULL;
}

static inline int64_t *exe_carve_state_published_mapping(
    ExeCarveState *state) {
  return state ? exe_carve_state_complete_mapping(state)
                     + state->total_blocks : NULL;
}

static inline ExeZeroAlternativeRank *exe_carve_state_alternative_ranks(
    ExeCarveState *state) {
  return state
             ? (ExeZeroAlternativeRank *)(
                   exe_carve_state_relocation_mapping(state)
                   + state->total_blocks)
             : NULL;
}

static inline int64_t *exe_carve_state_relocation_mapping(
    ExeCarveState *state) {
  return state ? exe_carve_state_published_mapping(state)
                     + state->total_blocks : NULL;
}

static inline bool exe_serialize_carve_state(
    void **state, FILE *fp, StateSerialization mode) {
  if (!state || !fp) {
    return false;
  }
  if (mode == SERIALIZE) {
    const ExeCarveState *current = (const ExeCarveState *)*state;
    if (!exe_carve_state_valid(current)
        || fwrite(current, current->allocation_size, 1, fp) != 1) {
      handle_error(SCALPEL_ERROR_CHECKPOINT,
                   "invalid EXE carve state", __LINE__, __FILE__);
    }
    return true;
  }

  ExeCarveState header;
  memset(&header, 0, sizeof(header));
  const size_t header_size = offsetof(ExeCarveState, storage);
  if (fread(&header, header_size, 1, fp) != 1) {
    handle_error(SCALPEL_ERROR_CHECKPOINT,
                 "invalid EXE carve state", __LINE__, __FILE__);
  }
  size_t state_size = 0;
  if (!exe_carve_state_size(header.total_blocks,
                            header.described_extent, &state_size)
      || header.allocation_size != state_size) {
    handle_error(SCALPEL_ERROR_CHECKPOINT,
                 "invalid EXE carve state size", __LINE__, __FILE__);
  }
  ExeCarveState *restored = (ExeCarveState *)malloc(state_size);
  check_memory_allocation(restored, __LINE__, __FILE__,
                          "EXE restored carve state");
  memcpy(restored, &header, header_size);
  if (state_size > header_size
      && fread(restored->storage, state_size - header_size, 1, fp) != 1) {
    free(restored);
    handle_error(SCALPEL_ERROR_CHECKPOINT,
                 "invalid EXE carve state payload", __LINE__, __FILE__);
  }
  if (!exe_carve_state_valid(restored)) {
    free(restored);
    handle_error(SCALPEL_ERROR_CHECKPOINT,
                 "invalid EXE carve state", __LINE__, __FILE__);
  }
  *state = restored;
  return true;
}

static inline void *exe_clone_carve_state(const void *srcstate) {
  const ExeCarveState *source = (const ExeCarveState *)srcstate;
  if (!exe_carve_state_valid(source)) {
    return NULL;
  }
  ExeCarveState *clone = (ExeCarveState *)malloc(source->allocation_size);
  check_memory_allocation(clone, __LINE__, __FILE__,
                          "EXE carve state clone");
  memcpy(clone, source, source->allocation_size);
  return clone;
}

static inline void exe_free_carve_state(void **state) {
  if (state) {
    free(*state);
    *state = NULL;
  }
}

static inline void exe_print_carve_state(const void *state) {
  const ExeCarveState *current = (const ExeCarveState *)state;
  if (!current) {
    fprintf(stdout, "NULL");
    return;
  }
  fprintf(stdout,
          "blocks=%" PRIu64 " extent=%" PRIu64
          " zero_complete=%u terminal=%" PRIu64
          " phase=%u outer=%" PRIu64 " inner=%" PRIu64
          " entry=%" PRIu64
          " gap=%" PRIu64 ":%" PRIu64 " gap_complete=%u"
          " search=%u width=%" PRIu64 " inner=%" PRIu64 " edge=%u"
          " combined=%" PRIu64 ":%u:%" PRIu64
          " run=%u:%" PRIu64 ":%" PRIu64 ":%" PRIu64
          " coff=%u:%" PRIu64 ":%" PRIu64 ":%u"
          " hints=%u/%u:%u/%u:%" PRIu64 ":%u"
          " hint_scan=%" PRIu64 ":%" PRIu64 ":%" PRIu64
          " alternatives=%u/%u/%u",
          current->total_blocks, current->described_extent,
          current->zero_complete, current->zero_resume_terminal,
          current->zero_run.phase, current->zero_run.outer,
          current->zero_run.inner, current->zero_run.entry,
          current->gap_next_width, current->gap_next_boundary,
          current->gap_complete,
          current->search_phase, current->search_width,
          current->search_inner, current->search_edge,
          current->combined_source, current->combined_pass,
          current->combined_boundary,
          current->general_run.phase, current->general_run.outer,
          current->general_run.inner, current->general_run.entry,
          current->coff.phase, current->coff.next_gap,
          current->coff.next_boundary, current->coff.string_size,
          current->hints.next_gap, current->hints.gap_count,
          current->hints.next_width, current->hints.width_count,
          current->hints.next_destination, current->hints.ooo_complete,
          current->hints.gap_scan.next_offset,
          current->hints.destination_edges.next_boundary,
          current->hints.source_edges.next_boundary,
          current->alternative_counts[0],
          current->alternative_counts[1],
          current->alternative_counts[2]);
}

// Return whether an available apparent block is a physical zero block.
static inline bool exe_apparent_block_is_zero(int64_t apparent_block) {
  if (apparent_block < 0) {
    return false;
  }
  const int64_t actual_block = filemirror_actual_blocknumber(
      scalpel_state.filemirror, apparent_block);
  return actual_block >= 0
      && !filemirror_actual_block_covered(scalpel_state.filemirror,
                                          actual_block)
      && filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                         actual_block);
}

static inline void exe_carve_state_load(
    const ExeCarveState *state, ExeRecoveryAccumulator *accumulator,
    ExeZeroAlternativeSet *alternatives, int64_t *published_mapping,
    bool *mapping_published) {
  if (!exe_carve_state_valid(state) || !accumulator
      || !published_mapping || !mapping_published
      || accumulator->total_blocks != state->total_blocks
      || (alternatives
          && (alternatives->total_blocks != state->total_blocks
              || alternatives->capacity_per_class
                     != state->capacity_per_class))) {
    return;
  }
  ExeCarveState *mutable_state = (ExeCarveState *)state;
  const uint64_t alternative_count =
      (uint64_t)state->capacity_per_class
      * EXE_ZERO_ALTERNATIVE_CLASSES;
  if (alternatives) {
    memcpy(alternatives->mappings,
           exe_carve_state_alternative_mappings(mutable_state),
           (size_t)(alternative_count * state->total_blocks)
               * sizeof(*alternatives->mappings));
    memcpy(alternatives->ranks,
           exe_carve_state_alternative_ranks(mutable_state),
           (size_t)alternative_count * sizeof(*alternatives->ranks));
    memcpy(alternatives->counts, state->alternative_counts,
           sizeof(alternatives->counts));
  }

  memcpy(accumulator->mapping,
         exe_carve_state_ordered_mapping(mutable_state),
         state->total_blocks * sizeof(*accumulator->mapping));
  memcpy(accumulator->gap_mapping,
         exe_carve_state_gap_mapping(mutable_state),
         state->total_blocks * sizeof(*accumulator->gap_mapping));
  memcpy(accumulator->complete_mapping,
         exe_carve_state_complete_mapping(mutable_state),
         state->total_blocks * sizeof(*accumulator->complete_mapping));
  memcpy(published_mapping,
         exe_carve_state_published_mapping(mutable_state),
         state->total_blocks * sizeof(*published_mapping));

  accumulator->qualified_mappings = state->qualified_mappings;
  accumulator->gap_mappings = state->gap_mappings;
  accumulator->complete_mappings = state->complete_mappings;
  accumulator->strongest_order_evidence =
      state->strongest_order_evidence;
  accumulator->second_order_evidence = state->second_order_evidence;
  accumulator->baseline_repair_first = state->baseline_repair_first;
  accumulator->baseline_repair_last = state->baseline_repair_last;
  accumulator->ambiguous = state->ambiguous != 0;
  accumulator->gap_ambiguous = state->gap_ambiguous != 0;
  accumulator->complete_ambiguous = state->complete_ambiguous != 0;
  accumulator->require_baseline_repair =
      state->require_baseline_repair != 0;
  *mapping_published = state->mapping_published != 0;
}

static inline void exe_carve_state_capture(
    ExeCarveState *state, const ExeRecoveryAccumulator *accumulator,
    const ExeZeroAlternativeSet *alternatives,
    const int64_t *published_mapping, bool mapping_published) {
  if (!exe_carve_state_valid(state) || !accumulator
      || !published_mapping
      || accumulator->total_blocks != state->total_blocks
      || (alternatives
          && (alternatives->total_blocks != state->total_blocks
              || alternatives->capacity_per_class
                     != state->capacity_per_class))) {
    return;
  }
  const uint64_t alternative_count =
      (uint64_t)state->capacity_per_class
      * EXE_ZERO_ALTERNATIVE_CLASSES;
  if (alternatives) {
    memcpy(exe_carve_state_alternative_mappings(state),
           alternatives->mappings,
           (size_t)(alternative_count * state->total_blocks)
               * sizeof(*alternatives->mappings));
    memcpy(exe_carve_state_alternative_ranks(state), alternatives->ranks,
           (size_t)alternative_count * sizeof(*alternatives->ranks));
    memcpy(state->alternative_counts, alternatives->counts,
           sizeof(state->alternative_counts));
    state->zero_initialized = 1;
  }

  memcpy(exe_carve_state_ordered_mapping(state), accumulator->mapping,
         state->total_blocks * sizeof(*accumulator->mapping));
  memcpy(exe_carve_state_gap_mapping(state), accumulator->gap_mapping,
         state->total_blocks * sizeof(*accumulator->gap_mapping));
  memcpy(exe_carve_state_complete_mapping(state),
         accumulator->complete_mapping,
         state->total_blocks * sizeof(*accumulator->complete_mapping));
  memcpy(exe_carve_state_published_mapping(state), published_mapping,
         state->total_blocks * sizeof(*published_mapping));

  state->qualified_mappings = accumulator->qualified_mappings;
  state->gap_mappings = accumulator->gap_mappings;
  state->complete_mappings = accumulator->complete_mappings;
  state->strongest_order_evidence =
      accumulator->strongest_order_evidence;
  state->second_order_evidence = accumulator->second_order_evidence;
  state->baseline_repair_first = accumulator->baseline_repair_first;
  state->baseline_repair_last = accumulator->baseline_repair_last;
  state->ambiguous = accumulator->ambiguous;
  state->gap_ambiguous = accumulator->gap_ambiguous;
  state->complete_ambiguous = accumulator->complete_ambiguous;
  state->require_baseline_repair = accumulator->require_baseline_repair;
  state->mapping_published = mapping_published;
  exe_carve_state_identify_view(state);
}

// Bind positional search state to the apparent view in which it was obtained.
static inline void exe_carve_state_identify_view(ExeCarveState *state) {
  if (!state->view_initialized) {
    const XXH128_hash_t view_hash = exe_reassembly_view_hash();
    state->view_hash_low = view_hash.low64;
    state->view_hash_high = view_hash.high64;
    state->view_initialized = 1;
  }
}

// Save cursor and evidence together before returning a candidate for a
// checkpoint. COFF extent discovery precedes mapping trials and therefore has
// no recovery accumulator; its cursor and evidence are already in the state.
static inline bool exe_reassembly_context_poll(
    ExeReassemblyContext *context) {
  if (!context || !context->iterations || !context->candidate
      || !*context->candidate) {
    return false;
  }
  (*context->iterations)++;
  if (*context->iterations % EXE_REASSEMBLY_POLL_INTERVAL != 0) {
    return false;
  }
  if (reassembly_check_kill_queue(
          context->work, context->candidate,
          context->uuidp, context->uuidc)) {
    return true;
  }
  if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
    if (context->accumulator) {
      exe_carve_state_capture(
          context->state, context->accumulator, context->alternatives,
          context->published_mapping, *context->mapping_published);
    }
    exe_carve_state_identify_view(context->state);
    carve_put_state((*context->candidate)->carvehashkey, context->state);
    if (reassembly_time_to_checkpoint(
            context->work->id, *context->candidate,
            context->uuidp, context->uuidc)) {
      return true;
    }
  }
  return false;
}

static inline void exe_zero_composition_complete_terminal(
    ExeReassemblyContext *context, uint64_t terminal) {
  if (!context || !context->state
      || context->result != EXE_RECOVERY_NO_MATCH) {
    return;
  }
  context->state->zero_resume_terminal = terminal + 1;
  context->state->zero_run.phase = EXE_ZERO_RESUME_NONE;
  context->state->zero_run.outer = 0;
  context->state->zero_run.inner = 0;
  context->state->zero_run.entry = EXE_ZERO_RESUME_ENTRY_NONE;
}

// Keep a bounded set of reviewable alternatives for each composition class.
// The bound is expressed in potential output bytes so large PE files do not
// consume disproportionate memory or generate unbounded -w output.
static inline bool exe_zero_alternatives_initialize(
    ExeZeroAlternativeSet *set, uint64_t total_blocks,
    uint64_t described_extent) {
  if (!set || total_blocks == 0 || described_extent == 0) {
    return false;
  }
  memset(set, 0, sizeof(*set));

  const uint64_t capacity =
      exe_zero_alternative_capacity(described_extent);
  const uint64_t total_capacity =
      capacity * EXE_ZERO_ALTERNATIVE_CLASSES;
  if (total_blocks > SIZE_MAX / sizeof(int64_t)
      || total_capacity > SIZE_MAX / (total_blocks * sizeof(int64_t))) {
    return false;
  }

  set->mappings = (int64_t *)calloc(
      (size_t)(total_capacity * total_blocks),
      sizeof(*set->mappings));
  set->ranks = (ExeZeroAlternativeRank *)calloc(
      (size_t)total_capacity, sizeof(*set->ranks));
  check_memory_allocation(set->mappings, __LINE__, __FILE__,
                          "EXE zero-run alternatives");
  check_memory_allocation(set->ranks, __LINE__, __FILE__,
                          "EXE zero-run alternative ranks");
  set->total_blocks = total_blocks;
  set->capacity_per_class = (uint32_t)capacity;
  return true;
}

static inline void exe_zero_alternatives_destroy(
    ExeZeroAlternativeSet *set) {
  if (!set) {
    return;
  }
  free(set->ranks);
  free(set->mappings);
  memset(set, 0, sizeof(*set));
}

// Prefer type confidence before format evidence. Random blocks can create
// more accidental control-flow or relocation references than the correct
// mapping, while MoDiCo confidence reflects independent block evidence.
static inline bool exe_zero_alternative_rank_better(
    const ExeZeroAlternativeRank *left,
    const ExeZeroAlternativeRank *right) {
  if (!left || !right) {
    return left != NULL;
  }
  const uint64_t left_average =
      left->confidence_sum * right->scored_blocks;
  const uint64_t right_average =
      right->confidence_sum * left->scored_blocks;
  if (left_average != right_average) {
    return left_average > right_average;
  }
  if (left->minimum_confidence != right->minimum_confidence) {
    return left->minimum_confidence > right->minimum_confidence;
  }
  if (left->order_strength != right->order_strength) {
    return left->order_strength > right->order_strength;
  }
  if (left->crossing_references != right->crossing_references) {
    return left->crossing_references > right->crossing_references;
  }
  if (left->reservations != right->reservations) {
    return left->reservations < right->reservations;
  }
  return left->diversity > right->diversity;
}

// Retain one mapping in the bounded class corresponding to the number of
// displaced destinations. Tied mappings are diversified deterministically so
// a large collision set is not represented only by adjacent scan positions.
static inline void exe_zero_alternatives_retain(
    ExeReassemblyContext *context, const int64_t *mapping,
    const ExeOrderEvidence *evidence, uint32_t destination_count) {
  if (!context || !context->alternatives || !mapping || !evidence
      || !*context->candidate) {
    return;
  }
  ExeZeroAlternativeSet *set = context->alternatives;
  if (!set->mappings || !set->ranks || set->capacity_per_class == 0
      || set->total_blocks != context->total_blocks) {
    return;
  }

  uint32_t class_index = destination_count;
  if (class_index >= EXE_ZERO_ALTERNATIVE_CLASSES) {
    class_index = EXE_ZERO_ALTERNATIVE_CLASSES - 1;
  }
  ExeZeroAlternativeRank rank = {
      .confidence_sum = 0,
      .scored_blocks = 0,
      .order_strength = evidence->cross_references,
      .crossing_references = (uint64_t)evidence->cross_references
                             + evidence->validated_target_references,
      .reservations = 0,
      .diversity = UINT64_C(1469598103934665603),
      .minimum_confidence = UINT32_MAX
  };
  if (evidence->validated_target_references > rank.order_strength) {
    rank.order_strength = evidence->validated_target_references;
  }
  if (evidence->relocation_values > rank.order_strength) {
    rank.order_strength = evidence->relocation_values;
  }
  if (evidence->control_flow_references > rank.order_strength) {
    rank.order_strength = evidence->control_flow_references;
  }

  for (uint64_t slot = 0; slot < context->total_blocks; slot++) {
    rank.diversity ^= (uint64_t)mapping[slot];
    rank.diversity *= UINT64_C(1099511628211);
    if (mapping[slot] == context->baseline_mapping[slot]
        || !exe_apparent_block_is_zero(
               context->baseline_mapping[slot])) {
      continue;
    }
    const int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, mapping[slot]);
    if (actual < 0) {
      continue;
    }
    const BlockValidationDecision confidence = filemirror_get_blocktype(
        scalpel_state.filemirror, actual,
        (*context->candidate)->needleidx);
    rank.confidence_sum += (uint32_t)confidence;
    rank.scored_blocks++;
    if ((uint32_t)confidence < rank.minimum_confidence) {
      rank.minimum_confidence = (uint32_t)confidence;
    }
    if (scalpel_state.reservations) {
      const int64_t reservations = filemirror_actual_block_reserved(
          scalpel_state.filemirror, actual);
      if (reservations > 0) {
        rank.reservations += (uint64_t)reservations;
      }
    }
  }
  if (rank.scored_blocks == 0) {
    rank.scored_blocks = 1;
    rank.minimum_confidence = BLOCK_CONFIDENCE_INVALID;
  }

  const uint64_t class_offset =
      (uint64_t)class_index * set->capacity_per_class;
  uint32_t count = set->counts[class_index];
  for (uint32_t index = 0; index < count; index++) {
    const uint64_t entry = class_offset + index;
    const int64_t *retained =
        set->mappings + entry * set->total_blocks;
    if (memcmp(retained, mapping,
               set->total_blocks * sizeof(*mapping)) == 0) {
      if (exe_zero_alternative_rank_better(&rank, &set->ranks[entry])) {
        set->ranks[entry] = rank;
      }
      return;
    }
  }

  uint32_t selected = count;
  if (count == set->capacity_per_class) {
    selected = 0;
    for (uint32_t index = 1; index < count; index++) {
      const uint64_t current = class_offset + index;
      const uint64_t weakest = class_offset + selected;
      if (exe_zero_alternative_rank_better(
              &set->ranks[weakest], &set->ranks[current])) {
        selected = index;
      }
    }
    if (!exe_zero_alternative_rank_better(
            &rank, &set->ranks[class_offset + selected])) {
      return;
    }
  }
  else {
    set->counts[class_index]++;
  }

  const uint64_t entry = class_offset + selected;
  memcpy(set->mappings + entry * set->total_blocks, mapping,
         set->total_blocks * sizeof(*mapping));
  set->ranks[entry] = rank;
}

static inline const int64_t *exe_zero_alternatives_best(
    const ExeZeroAlternativeSet *set) {
  if (!set || !set->mappings || !set->ranks
      || set->capacity_per_class == 0) {
    return NULL;
  }
  uint64_t best = UINT64_MAX;
  for (uint32_t class_index = 0;
       class_index < EXE_ZERO_ALTERNATIVE_CLASSES; class_index++) {
    const uint64_t class_offset =
        (uint64_t)class_index * set->capacity_per_class;
    for (uint32_t index = 0; index < set->counts[class_index]; index++) {
      const uint64_t entry = class_offset + index;
      if (best == UINT64_MAX
          || exe_zero_alternative_rank_better(
                 &set->ranks[entry], &set->ranks[best])) {
        best = entry;
      }
    }
  }
  return best == UINT64_MAX
             ? NULL
             : set->mappings + best * set->total_blocks;
}

static inline void exe_zero_alternatives_write(
    CarveInfo *candidate, const ExeLayout *layout,
    const ExeZeroAlternativeSet *set) {
  if (!scalpel_state.write_promising || !candidate || !layout || !set
      || !set->mappings || set->capacity_per_class == 0) {
    return;
  }
  for (uint32_t class_index = 0;
       class_index < EXE_ZERO_ALTERNATIVE_CLASSES; class_index++) {
    const uint64_t class_offset =
        (uint64_t)class_index * set->capacity_per_class;
    for (uint32_t index = 0; index < set->counts[class_index]; index++) {
      const uint64_t entry = class_offset + index;
      exe_write_mapping_hypothesis(
          candidate, set->mappings + entry * set->total_blocks,
          set->total_blocks, layout);
    }
  }
}

// Retain a checksum-correct, parser-complete mapping using the same proof
// policy as the ordinary PE searches.
static inline ExeRecoveryResult exe_consider_zero_composition_mapping(
    ExeReassemblyContext *context, const int64_t *mapping,
    uint32_t destination_count) {
  if (!context || !mapping || context->result != EXE_RECOVERY_NO_MATCH) {
    return context ? context->result : EXE_RECOVERY_NO_MATCH;
  }

  uint64_t first_changed = UINT64_MAX;
  uint64_t last_changed = 0;
  for (uint64_t slot = 0; slot < context->total_blocks; slot++) {
    if (mapping[slot] != context->baseline_mapping[slot]) {
      if (first_changed == UINT64_MAX) {
        first_changed = slot;
      }
      last_changed = slot;
    }
  }
  if (first_changed == UINT64_MAX) {
    return EXE_RECOVERY_NO_MATCH;
  }

  uint64_t raw_sum = 0;
  if (!exe_mapping_raw_sum(mapping, context->total_blocks,
                           context->layout, context->mapping_sums,
                           &raw_sum, true)) {
    return EXE_RECOVERY_NO_MATCH;
  }
  if (context->layout->checksum_present
      && exe_checksum_from_raw_sum(raw_sum,
                                   context->layout->described_extent)
             != context->layout->stored_checksum) {
    return EXE_RECOVERY_NO_MATCH;
  }

  const uint64_t order_offset = first_changed * scalpel_state.blocksize;
  uint64_t order_end = (last_changed + 1) * scalpel_state.blocksize;
  if (order_end > context->layout->described_extent) {
    order_end = context->layout->described_extent;
  }
  ExeOrderEvidence evidence;
  const ExeMappingResult mapping_result = exe_mapping_validates(
      mapping, context->total_blocks, context->layout,
      context->trial_data, order_offset, order_end - order_offset,
      &evidence, true);

  if (mapping_result == EXE_MAPPING_CRYPTOGRAPHIC) {
    memcpy(context->solution_mapping, mapping,
           context->total_blocks * sizeof(*context->solution_mapping));
    context->result = EXE_RECOVERY_MATCH;
  }
  else if (mapping_result == EXE_MAPPING_ORDER_PROVEN) {
    exe_zero_alternatives_retain(
        context, mapping, &evidence, destination_count);
    exe_accumulate_ordered_mapping(context->accumulator, mapping,
                                   &evidence);
  }
  else if (mapping_result == EXE_MAPPING_COMPLETE) {
    exe_zero_alternatives_retain(
        context, mapping, &evidence, destination_count);
    exe_accumulate_complete_mapping(context->accumulator, mapping);
  }
  exe_order_evidence_destroy(&evidence);
  return context->result;
}

// Solve two zero-filled displaced runs together. The PE checksum reduces the
// pair search to matching 16-bit residues; complete PE parsing and ordering
// evidence remain the acceptance gates.
static inline ExeRecoveryResult exe_try_zero_composition_pair(
    ExeReassemblyContext *context,
    const ExeZeroDestination destinations[2], uint64_t main_last) {
  if (!context || !destinations || !context->layout->checksum_present
      || context->layout->stored_checksum
             < context->layout->described_extent
      || context->layout->stored_checksum
             - context->layout->described_extent > UINT16_MAX
      || main_last > INT64_MAX) {
    return EXE_RECOVERY_NO_MATCH;
  }

  ExeZeroDestination first = destinations[0];
  ExeZeroDestination second = destinations[1];
  const uint64_t final_length = context->layout->described_extent
                                - (context->total_blocks - 1)
                                      * scalpel_state.blocksize;
  const bool second_has_partial = final_length != scalpel_state.blocksize
      && second.first_slot + second.block_count == context->total_blocks;
  if (second_has_partial) {
    const ExeZeroDestination swap = first;
    first = second;
    second = swap;
  }
  if (final_length != scalpel_state.blocksize
      && second.first_slot + second.block_count == context->total_blocks) {
    return EXE_RECOVERY_NO_MATCH;
  }
  if (first.block_count == 0 || second.block_count == 0
      || first.first_slot >= context->total_blocks
      || second.first_slot >= context->total_blocks
      || first.block_count
             > context->total_blocks - first.first_slot
      || second.block_count
             > context->total_blocks - second.first_slot) {
    return EXE_RECOVERY_NO_MATCH;
  }

  uint64_t base_sum = 0;
  if (!exe_mapping_raw_sum(
          context->mapping, context->total_blocks, context->layout,
          context->mapping_sums, &base_sum, true)) {
    return EXE_RECOVERY_NO_MATCH;
  }
  uint64_t removed_sum = 0;
  for (uint64_t offset = 0; offset < first.block_count; offset++) {
    removed_sum += context->mapping_sums[first.first_slot + offset];
  }
  for (uint64_t offset = 0; offset < second.block_count; offset++) {
    removed_sum += context->mapping_sums[second.first_slot + offset];
  }
  if (removed_sum > base_sum) {
    return EXE_RECOVERY_NO_MATCH;
  }
  const uint64_t retained_sum = base_sum - removed_sum;
  const uint64_t apparent_blocks = context->apparent_blocks;
  if (first.block_count > apparent_blocks
      || second.block_count > apparent_blocks) {
    return EXE_RECOVERY_NO_MATCH;
  }
  const uint64_t first_sources = apparent_blocks - first.block_count + 1;
  const uint64_t second_sources = apparent_blocks - second.block_count + 1;
  const uint32_t target_fold = (uint32_t)(
      context->layout->stored_checksum
      - context->layout->described_extent);
  const uint32_t target_residue = target_fold % EXE_CHECKSUM_RESIDUES;
  uint64_t second_chunk_first = 0;
  if (context->state->zero_run.phase == EXE_ZERO_RESUME_PAIR) {
    second_chunk_first = context->state->zero_run.outer;
    if (second_chunk_first >= second_sources) {
      second_chunk_first = 0;
    }
  }

  while (second_chunk_first < second_sources
         && context->result == EXE_RECOVERY_NO_MATCH) {
    const bool resume_chunk =
        context->state->zero_run.phase == EXE_ZERO_RESUME_PAIR
        && context->state->zero_run.outer == second_chunk_first;
    uint64_t first_source = resume_chunk
        ? context->state->zero_run.inner : 0;
    if (first_source > first_sources) {
      first_source = 0;
      context->state->zero_run.entry = EXE_ZERO_RESUME_ENTRY_NONE;
    }
    context->state->zero_run.phase = EXE_ZERO_RESUME_PAIR;
    context->state->zero_run.outer = second_chunk_first;
    context->state->zero_run.inner = first_source;
    if (!resume_chunk) {
      context->state->zero_run.entry = EXE_ZERO_RESUME_ENTRY_NONE;
    }
    ExeSourceRunIndex second_index = {0};
    bool stopped = false;
    if (!exe_source_run_index_build(
            &second_index, second.block_count, second_chunk_first,
            context->work, context->candidate, context->uuidp,
            context->uuidc, context->iterations, &stopped, context)) {
      exe_source_run_index_destroy(&second_index);
      if (stopped) {
        context->result = EXE_RECOVERY_STOPPED;
      }
      break;
    }
    const uint64_t next_second_chunk =
        second_index.source_first + second_index.source_count;

    for (;
         first_source < first_sources
         && context->result == EXE_RECOVERY_NO_MATCH;
         first_source++) {
      const uint64_t first_last = first_source + first.block_count - 1;
      if (first_source > INT64_MAX || first_last > INT64_MAX
          || (first_source <= main_last
              && first_last >= (uint64_t)context->start)) {
        context->state->zero_run.inner = first_source + 1;
        context->state->zero_run.entry = EXE_ZERO_RESUME_ENTRY_NONE;
        if (exe_reassembly_context_poll(context)) {
          context->result = EXE_RECOVERY_STOPPED;
        }
        continue;
      }

      uint64_t first_sum = 0;
      bool first_valid = true;
      for (uint64_t offset = 0; offset < first.block_count; offset++) {
        uint64_t block_sum = 0;
        if (!exe_get_slot_sum(
                (int64_t)(first_source + offset),
                first.first_slot + offset, context->layout,
                &block_sum, true)) {
          first_valid = false;
          break;
        }
        first_sum += block_sum;
      }
      if (!first_valid) {
        context->state->zero_run.inner = first_source + 1;
        context->state->zero_run.entry = EXE_ZERO_RESUME_ENTRY_NONE;
        if (exe_reassembly_context_poll(context)) {
          context->result = EXE_RECOVERY_STOPPED;
        }
        continue;
      }

      const uint64_t partial_sum = retained_sum + first_sum;
      const uint32_t partial_residue =
          exe_fold_word_sum(partial_sum) % EXE_CHECKSUM_RESIDUES;
      const uint32_t required_residue =
          (target_residue + EXE_CHECKSUM_RESIDUES - partial_residue)
          % EXE_CHECKSUM_RESIDUES;
      uint32_t entry = second_index.heads[required_residue];
      if (resume_chunk
          && context->state->zero_run.inner == first_source
          && context->state->zero_run.entry
                 != EXE_ZERO_RESUME_ENTRY_NONE) {
        const uint64_t saved_entry = context->state->zero_run.entry;
        if (saved_entry < second_index.source_count
            && second_index.valid[saved_entry]
            && second_index.folded_sums[saved_entry]
                   % EXE_CHECKSUM_RESIDUES == required_residue) {
          entry = (uint32_t)saved_entry;
        }
      }
      context->state->zero_run.inner = first_source;
      context->state->zero_run.entry = entry == UINT32_MAX
          ? EXE_ZERO_RESUME_ENTRY_NONE : entry;

      while (entry != UINT32_MAX
             && context->result == EXE_RECOVERY_NO_MATCH) {
        const uint32_t next_entry = second_index.next[entry];
        const uint64_t second_source =
            second_index.source_first + entry;
        const uint64_t second_last =
            second_source + second.block_count - 1;
        const bool sources_overlap =
            first_source <= second_last && second_source <= first_last;
        if (second_source <= INT64_MAX && second_last <= INT64_MAX
            && (second_source > main_last
                || second_last < (uint64_t)context->start)
            && !sources_overlap
            && exe_checksum_from_raw_sum(
                   partial_sum + second_index.folded_sums[entry],
                   context->layout->described_extent)
                   == context->layout->stored_checksum) {
          memcpy(context->pair_mapping, context->mapping,
                 context->total_blocks * sizeof(*context->pair_mapping));
          for (uint64_t offset = 0; offset < first.block_count; offset++) {
            context->pair_mapping[first.first_slot + offset] =
                (int64_t)(first_source + offset);
          }
          for (uint64_t offset = 0; offset < second.block_count; offset++) {
            context->pair_mapping[second.first_slot + offset] =
                (int64_t)(second_source + offset);
          }

          uint64_t candidate_sum = 0;
          if (exe_mapping_raw_sum(
                  context->pair_mapping, context->total_blocks,
                  context->layout, context->mapping_sums,
                  &candidate_sum, true)
              && exe_checksum_from_raw_sum(
                     candidate_sum, context->layout->described_extent)
                     == context->layout->stored_checksum) {
            exe_consider_zero_composition_mapping(
                context, context->pair_mapping, 2);
          }
        }
        if (context->result == EXE_RECOVERY_NO_MATCH) {
          context->state->zero_run.inner =
              next_entry == UINT32_MAX ? first_source + 1 : first_source;
          context->state->zero_run.entry =
              next_entry == UINT32_MAX
                  ? EXE_ZERO_RESUME_ENTRY_NONE : next_entry;
          if (exe_reassembly_context_poll(context)) {
            context->result = EXE_RECOVERY_STOPPED;
          }
        }
        entry = next_entry;
      }

      if (context->result == EXE_RECOVERY_NO_MATCH) {
        context->state->zero_run.inner = first_source + 1;
        context->state->zero_run.entry = EXE_ZERO_RESUME_ENTRY_NONE;
        if (exe_reassembly_context_poll(context)) {
          context->result = EXE_RECOVERY_STOPPED;
        }
      }
    }
    exe_source_run_index_destroy(&second_index);
    second_chunk_first = next_second_chunk;
    if (context->result == EXE_RECOVERY_NO_MATCH) {
      context->state->zero_run.outer = second_chunk_first;
      context->state->zero_run.inner = 0;
      context->state->zero_run.entry = EXE_ZERO_RESUME_ENTRY_NONE;
    }
  }
  if (context->result != EXE_RECOVERY_STOPPED) {
    context->state->zero_run.phase = EXE_ZERO_RESUME_NONE;
    context->state->zero_run.outer = 0;
    context->state->zero_run.inner = 0;
    context->state->zero_run.entry = EXE_ZERO_RESUME_ENTRY_NONE;
  }
  return context->result;
}

// Enumerate the roles of physical zero runs in the sequential PE corridor.
// A run may be legitimate file data, an inserted physical gap, or a displaced
// logical run whose source must be recovered elsewhere.
static inline void exe_zero_composition_walk(
    ExeReassemblyContext *context, uint64_t logical_slot,
    uint64_t physical_block, ExeZeroDestination destinations[2],
    uint32_t destination_count) {
  if (!context || context->result != EXE_RECOVERY_NO_MATCH
      || context->states_visited >= EXE_ZERO_COMPOSITION_STATE_LIMIT) {
    return;
  }
  context->states_visited++;
  if (exe_reassembly_context_poll(context)) {
    context->result = EXE_RECOVERY_STOPPED;
    return;
  }
  if (logical_slot == context->total_blocks) {
    const uint64_t terminal = context->terminal_index++;
    if (terminal < context->state->zero_resume_terminal) {
      return;
    }
    if (terminal > context->state->zero_resume_terminal) {
      context->state->zero_resume_terminal = terminal;
      context->state->zero_run.phase = EXE_ZERO_RESUME_NONE;
      context->state->zero_run.outer = 0;
      context->state->zero_run.inner = 0;
      context->state->zero_run.entry = EXE_ZERO_RESUME_ENTRY_NONE;
    }
    if (destination_count == 0) {
      exe_consider_zero_composition_mapping(
          context, context->mapping, 0);
      exe_zero_composition_complete_terminal(context, terminal);
      return;
    }
    if (!context->layout->checksum_present || physical_block == 0) {
      exe_zero_composition_complete_terminal(context, terminal);
      return;
    }

    uint64_t base_sum = 0;
    if (!exe_mapping_raw_sum(
            context->mapping, context->total_blocks, context->layout,
            context->mapping_sums, &base_sum, true)) {
      exe_zero_composition_complete_terminal(context, terminal);
      return;
    }
    if (destination_count == 1) {
      const ExeRecoveryResult result = exe_try_ooo_on_mapping(
          context->work, context->candidate, context->uuidp,
          context->uuidc, context->layout, context->mapping,
          context->mapping_sums, base_sum, context->total_blocks,
          context->header_blocks, destinations[0].block_count,
          context->start, (int64_t)(physical_block - 1), true, NULL,
          context->trial_data, context->solution_mapping,
          context->accumulator, context->published_mapping,
          context->mapping_published, context->iterations, context);
      if (result != EXE_RECOVERY_NO_MATCH) {
        context->result = result;
      }
      exe_zero_composition_complete_terminal(context, terminal);
      return;
    }
    exe_try_zero_composition_pair(
        context, destinations, physical_block - 1);
    exe_zero_composition_complete_terminal(context, terminal);
    return;
  }
  if (physical_block >= context->apparent_blocks
      || physical_block > INT64_MAX) {
    return;
  }

  const int64_t actual_block = filemirror_actual_blocknumber(
      scalpel_state.filemirror, (int64_t)physical_block);
  if (actual_block < 0
      || filemirror_actual_block_covered(scalpel_state.filemirror,
                                         actual_block)) {
    return;
  }
  if (!exe_apparent_block_is_zero((int64_t)physical_block)) {
    context->mapping[logical_slot] = (int64_t)physical_block;
    exe_zero_composition_walk(
        context, logical_slot + 1, physical_block + 1,
        destinations, destination_count);
    return;
  }

  uint64_t run_length = 1;
  while (run_length < context->apparent_blocks - physical_block
         && exe_apparent_block_is_zero(
                (int64_t)(physical_block + run_length))) {
    run_length++;
    if ((run_length & UINT64_C(0xff)) == 0
        && exe_reassembly_context_poll(context)) {
      context->result = EXE_RECOVERY_STOPPED;
      return;
    }
  }

  // First treat the complete run as an inserted gap. This prioritizes the
  // common case without excluding the file-data and displaced-run roles.
  exe_zero_composition_walk(
      context, logical_slot, physical_block + run_length,
      destinations, destination_count);
  if (context->result != EXE_RECOVERY_NO_MATCH) {
    return;
  }

  uint64_t mapped_run = run_length;
  if (mapped_run > context->total_blocks - logical_slot) {
    mapped_run = context->total_blocks - logical_slot;
  }
  if (destination_count < EXE_ZERO_COMPOSITION_MAX_DESTINATIONS) {
    for (uint64_t offset = 0; offset < mapped_run; offset++) {
      context->mapping[logical_slot + offset] =
          (int64_t)(physical_block + offset);
    }
    destinations[destination_count].first_slot = logical_slot;
    destinations[destination_count].block_count = mapped_run;
    exe_zero_composition_walk(
        context, logical_slot + mapped_run,
        physical_block + mapped_run, destinations,
        destination_count + 1);
    if (context->result != EXE_RECOVERY_NO_MATCH) {
      return;
    }
  }

  for (uint64_t offset = 0; offset < mapped_run; offset++) {
    context->mapping[logical_slot + offset] =
        (int64_t)(physical_block + offset);
  }
  exe_zero_composition_walk(
      context, logical_slot + mapped_run, physical_block + mapped_run,
      destinations, destination_count);
}

// Resolve repeated zero-filled gaps and up to two displaced zero-filled runs
// before entering the exhaustive one-event searches.
static inline ExeRecoveryResult exe_try_zero_run_composition(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const ExeLayout *layout,
    const int64_t *baseline_mapping, uint64_t total_blocks,
    uint64_t header_blocks, uint8_t *trial_data,
    int64_t *solution_mapping, ExeRecoveryAccumulator *accumulator,
    int64_t *published_mapping, bool *mapping_published,
    uint64_t *iterations, ExeCarveState *state) {
  if (!work || !candidate || !*candidate || !layout || !baseline_mapping
      || !trial_data || !solution_mapping || !accumulator
      || !published_mapping || !mapping_published || !iterations
      || !exe_carve_state_valid(state)
      || header_blocks == 0 || header_blocks >= total_blocks
      || baseline_mapping[0] < 0) {
    return EXE_RECOVERY_NO_MATCH;
  }

  const uint64_t apparent_blocks =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  const int64_t start = baseline_mapping[0];
  if ((uint64_t)start >= apparent_blocks
      || total_blocks > apparent_blocks - (uint64_t)start) {
    return EXE_RECOVERY_NO_MATCH;
  }

  uint32_t zero_runs = 0;
  bool in_zero_run = false;
  for (uint64_t slot = header_blocks; slot < total_blocks; slot++) {
    const bool zero = exe_apparent_block_is_zero(start + (int64_t)slot);
    if (zero && !in_zero_run) {
      zero_runs++;
    }
    in_zero_run = zero;
  }
  if (zero_runs < 2) {
    return EXE_RECOVERY_NO_MATCH;
  }

  int64_t *mapping = (int64_t *)malloc(
      total_blocks * sizeof(*mapping));
  int64_t *pair_mapping = (int64_t *)malloc(
      total_blocks * sizeof(*pair_mapping));
  uint64_t *mapping_sums = (uint64_t *)malloc(
      total_blocks * sizeof(*mapping_sums));
  check_memory_allocation(mapping, __LINE__, __FILE__,
                          "EXE zero-composition mapping");
  check_memory_allocation(pair_mapping, __LINE__, __FILE__,
                          "EXE zero-composition pair mapping");
  check_memory_allocation(mapping_sums, __LINE__, __FILE__,
                          "EXE zero-composition sums");
  memcpy(mapping, baseline_mapping,
         total_blocks * sizeof(*mapping));

  ExeZeroAlternativeSet alternatives;
  if (!exe_zero_alternatives_initialize(
          &alternatives, total_blocks, layout->described_extent)) {
    free(mapping_sums);
    free(pair_mapping);
    free(mapping);
    return EXE_RECOVERY_NO_MATCH;
  }
  if (state->zero_initialized) {
    exe_carve_state_load(state, accumulator, &alternatives,
                         published_mapping, mapping_published);
  }
  if (state->zero_complete) {
    exe_zero_alternatives_destroy(&alternatives);
    free(mapping_sums);
    free(pair_mapping);
    free(mapping);
    return EXE_RECOVERY_NO_MATCH;
  }

  ExeZeroDestination destinations[2] = {{0, 0}, {0, 0}};
  ExeReassemblyContext context = {
      .work = work,
      .candidate = candidate,
      .uuidp = uuidp,
      .uuidc = uuidc,
      .layout = layout,
      .baseline_mapping = baseline_mapping,
      .total_blocks = total_blocks,
      .header_blocks = header_blocks,
      .apparent_blocks = apparent_blocks,
      .start = start,
      .trial_data = trial_data,
      .mapping = mapping,
      .pair_mapping = pair_mapping,
      .mapping_sums = mapping_sums,
      .solution_mapping = solution_mapping,
      .accumulator = accumulator,
      .alternatives = &alternatives,
      .published_mapping = published_mapping,
      .mapping_published = mapping_published,
      .iterations = iterations,
      .state = state,
      .run_progress = &state->zero_run,
      .states_visited = 0,
      .terminal_index = 0,
      .result = EXE_RECOVERY_NO_MATCH
  };
  exe_zero_composition_walk(
      &context, header_blocks,
      (uint64_t)start + header_blocks, destinations, 0);

  if (context.result == EXE_RECOVERY_NO_MATCH
      && exe_ordered_mapping_is_decisive(accumulator)) {
    memcpy(solution_mapping, accumulator->mapping,
           total_blocks * sizeof(*solution_mapping));
    context.result = EXE_RECOVERY_MATCH;
  }
  else if (context.result == EXE_RECOVERY_NO_MATCH
           && accumulator->qualified_mappings == 0
           && accumulator->complete_mappings == 1
           && !accumulator->complete_ambiguous) {
    memcpy(solution_mapping, accumulator->complete_mapping,
           total_blocks * sizeof(*solution_mapping));
    context.result = EXE_RECOVERY_MATCH;
  }
  else if (context.result == EXE_RECOVERY_NO_MATCH
           && exe_zero_alternatives_best(&alternatives)) {
    const int64_t *best = exe_zero_alternatives_best(&alternatives);
    memcpy(solution_mapping, best,
           total_blocks * sizeof(*solution_mapping));
    memcpy(published_mapping, best,
           total_blocks * sizeof(*published_mapping));
    *mapping_published = true;
    exe_zero_alternatives_write(*candidate, layout, &alternatives);
    context.result = EXE_RECOVERY_PROMISING_MATCH;
  }
  else if (context.result == EXE_RECOVERY_NO_MATCH
           && *mapping_published) {
    memcpy(solution_mapping, published_mapping,
           total_blocks * sizeof(*solution_mapping));
    context.result = EXE_RECOVERY_PROMISING_MATCH;
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(
        stdout,
        "PE zero-run composition: start=%" PRId64
        " runs=%u states=%" PRIu64 " result=%u.\n",
        start, zero_runs, context.states_visited, context.result);
  }
  if (context.result != EXE_RECOVERY_STOPPED) {
    state->zero_complete = 1;
    state->zero_run.phase = EXE_ZERO_RESUME_NONE;
    state->zero_run.outer = 0;
    state->zero_run.inner = 0;
    state->zero_run.entry = EXE_ZERO_RESUME_ENTRY_NONE;
    exe_carve_state_capture(
        state, accumulator, &alternatives, published_mapping,
        *mapping_published);
    carve_put_state((*candidate)->carvehashkey, state);
  }
  exe_zero_alternatives_destroy(&alternatives);
  free(mapping_sums);
  free(pair_mapping);
  free(mapping);
  return context.result;
}

// Try removing one contiguous physical gap from an otherwise sequential PE.
// A bounded source prefix table makes every boundary test O(1) without making
// per-worker scratch storage proportional to the remaining image size.
static inline ExeRecoveryResult exe_try_gap(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const ExeLayout *layout,
    const int64_t *baseline_mapping, const uint64_t *baseline_sums,
    uint64_t total_blocks, uint64_t header_blocks,
    uint64_t first_gap_blocks, uint64_t last_gap_blocks,
    uint8_t *trial_data, int64_t *solution_mapping,
    ExeRecoveryAccumulator *accumulator, uint64_t *iterations,
    ExeReassemblyContext *context) {
  if (!accumulator || header_blocks == 0 || header_blocks >= total_blocks
      || first_gap_blocks == 0 || first_gap_blocks > last_gap_blocks
      || last_gap_blocks > UINT64_MAX - total_blocks) {
    return EXE_RECOVERY_NO_MATCH;
  }
  ExeCarveState *state = context ? context->state : NULL;
  if (state && state->gap_complete) {
    return EXE_RECOVERY_NO_MATCH;
  }
  uint64_t *prefix = (uint64_t *)calloc(total_blocks + 1,
                                        sizeof(*prefix));
  check_memory_allocation(prefix, __LINE__, __FILE__, "EXE gap prefix");

  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    prefix[slot + 1] = prefix[slot] + baseline_sums[slot];
  }

  ExeRecoveryResult result = EXE_RECOVERY_NO_MATCH;
  const uint64_t final_length = layout->described_extent
                                - (total_blocks - 1)
                                      * scalpel_state.blocksize;
  const bool final_block_is_full = final_length == scalpel_state.blocksize;
  uint64_t chunk_first = first_gap_blocks;
  if (state) {
    if (state->gap_next_width >= first_gap_blocks
        && state->gap_next_width <= last_gap_blocks + 1) {
      chunk_first = state->gap_next_width;
    }
    else {
      state->gap_next_width = chunk_first;
      state->gap_next_boundary = header_blocks;
    }
  }
  while (result == EXE_RECOVERY_NO_MATCH
         && chunk_first <= last_gap_blocks) {
    uint64_t chunk_last = last_gap_blocks;
    if (last_gap_blocks - chunk_first >= EXE_GAP_SCAN_CHUNK_WIDTH) {
      chunk_last = chunk_first + EXE_GAP_SCAN_CHUNK_WIDTH - 1;
    }
    const uint64_t source_base = chunk_first + header_blocks;
    const uint64_t source_end = chunk_last + total_blocks;
    const uint64_t source_slots = source_end - source_base;
    uint64_t *source_prefix = (uint64_t *)calloc(
        source_slots + 1, sizeof(*source_prefix));
    uint64_t *source_invalid = (uint64_t *)calloc(
        source_slots + 1, sizeof(*source_invalid));
    check_memory_allocation(source_prefix, __LINE__, __FILE__,
                            "EXE source block prefix");
    check_memory_allocation(source_invalid, __LINE__, __FILE__,
                            "EXE source block validity");

    for (uint64_t offset = 0; offset < source_slots; offset++) {
      uint64_t block_sum = 0;
      const bool valid = exe_get_full_block_sum(
          baseline_mapping[0] + (int64_t)source_base + (int64_t)offset,
          &block_sum, true);
      source_prefix[offset + 1] = source_prefix[offset]
                                  + (valid ? block_sum : 0);
      source_invalid[offset + 1] = source_invalid[offset]
                                   + (valid ? 0 : 1);
      const bool must_stop = context
          ? exe_reassembly_context_poll(context)
          : exe_reassembly_poll(work, candidate, uuidp, uuidc, iterations);
      if (must_stop) {
        result = EXE_RECOVERY_STOPPED;
        break;
      }
    }

    for (uint64_t gap_blocks = chunk_first;
         result == EXE_RECOVERY_NO_MATCH && gap_blocks <= chunk_last;
         gap_blocks++) {
      uint64_t partial_sum = 0;
      bool partial_valid = true;
      uint64_t full_end = gap_blocks + total_blocks;
      if (!final_block_is_full) {
        full_end--;
        partial_valid = exe_get_slot_sum(
            baseline_mapping[0] + (int64_t)gap_blocks
                + (int64_t)total_blocks - 1,
            total_blocks - 1, layout, &partial_sum, true);
      }
      full_end -= source_base;

      uint64_t first_boundary = header_blocks;
      if (state && state->gap_next_width == gap_blocks
          && state->gap_next_boundary >= header_blocks
          && state->gap_next_boundary < total_blocks) {
        first_boundary = state->gap_next_boundary;
      }
      for (uint64_t boundary = first_boundary; boundary < total_blocks;
           boundary++) {
        const uint64_t full_first = gap_blocks + boundary - source_base;
        if (partial_valid
            && source_invalid[full_end] == source_invalid[full_first]) {
          const uint64_t suffix_sum = source_prefix[full_end]
                                      - source_prefix[full_first]
                                      + partial_sum;
          const uint64_t raw_sum = prefix[boundary] + suffix_sum;
          if (!layout->checksum_present
              || exe_checksum_from_raw_sum(raw_sum,
                                           layout->described_extent)
                     == layout->stored_checksum) {
            for (uint64_t slot = 0; slot < total_blocks; slot++) {
              solution_mapping[slot] = baseline_mapping[0] + (int64_t)slot;
              if (slot >= boundary) {
                solution_mapping[slot] += (int64_t)gap_blocks;
              }
            }
            const uint64_t proof_first = boundary - 1;
            uint64_t proof_last = boundary + 1;
            if (proof_last > total_blocks) {
              proof_last = total_blocks;
            }
            const uint64_t order_offset = proof_first
                                          * scalpel_state.blocksize;
            uint64_t order_length = (proof_last - proof_first)
                                    * scalpel_state.blocksize;
            if (order_length > layout->described_extent - order_offset) {
              order_length = layout->described_extent - order_offset;
            }
            ExeOrderEvidence evidence;
            const ExeMappingResult mapping_result = exe_mapping_validates(
                solution_mapping, total_blocks, layout, trial_data,
                order_offset, order_length, &evidence, true);
            if (mapping_result != EXE_MAPPING_INVALID
                && scalpel_state.mode_verbose) {
              lock_fprintf(
                  stdout,
                  "PE gap evidence: start=%" PRId64 " gap=%" PRIu64
                  " boundary=%" PRIu64 " result=%u"
                  " records=%u cross=%u targets=%u reloc=%u control=%u.\n",
                  baseline_mapping[0], gap_blocks, boundary, mapping_result,
                  evidence.metadata_records, evidence.cross_references,
                  evidence.validated_target_references,
                  evidence.relocation_values,
                  evidence.control_flow_references);
            }
            if (mapping_result == EXE_MAPPING_CRYPTOGRAPHIC) {
              result = EXE_RECOVERY_MATCH;
            }
            else if (mapping_result == EXE_MAPPING_ORDER_PROVEN) {
              if (!layout->checksum_present) {
                // A checksumless PE can admit multiple structurally coherent
                // mappings. Preserve each supported alternative for review;
                // none is promoted to VALIDATED by this path.
                if (scalpel_state.write_promising) {
                  exe_write_mapping_hypothesis(
                      *candidate, solution_mapping, total_blocks, layout);
                }
              }
              const bool repairs_baseline =
                  exe_order_evidence_repairs_baseline(
                      baseline_mapping, total_blocks, layout, trial_data,
                      order_offset, order_length, &evidence);
              const bool repairs_required_region =
                  !accumulator->require_baseline_repair
                  || boundary <= accumulator->baseline_repair_first;
              if (repairs_baseline && repairs_required_region) {
                exe_accumulate_gap_mapping(accumulator, solution_mapping);
                exe_accumulate_ordered_mapping(accumulator,
                                               solution_mapping, &evidence);
              }
            }
            else if (mapping_result == EXE_MAPPING_COMPLETE) {
              exe_accumulate_gap_mapping(accumulator, solution_mapping);
              exe_accumulate_complete_mapping(accumulator,
                                              solution_mapping);
            }
            exe_order_evidence_destroy(&evidence);
            if (result == EXE_RECOVERY_MATCH) {
              break;
            }
          }
        }
        if (state) {
          state->gap_next_width = boundary + 1 == total_blocks
              ? gap_blocks + 1 : gap_blocks;
          state->gap_next_boundary = boundary + 1 == total_blocks
              ? header_blocks : boundary + 1;
        }
        const bool must_stop = context
            ? exe_reassembly_context_poll(context)
            : exe_reassembly_poll(work, candidate, uuidp, uuidc, iterations);
        if (must_stop) {
          result = EXE_RECOVERY_STOPPED;
          break;
        }
      }
    }

    free(source_invalid);
    free(source_prefix);
    if (chunk_last == last_gap_blocks) {
      break;
    }
    chunk_first = chunk_last + 1;
  }

  if (state && result == EXE_RECOVERY_NO_MATCH) {
    state->gap_complete = 1;
    exe_carve_state_capture(
        state, accumulator, NULL, context->published_mapping,
        *context->mapping_published);
    carve_put_state((*candidate)->carvehashkey, state);
  }
  free(prefix);
  return result;
}

// Derive likely gap boundaries from long runs that independent block
// classification considers especially weak. Edge variants account for
// legitimate low-confidence file blocks adjacent to a foreign run. These are
// search hints only; complete PE validation still decides every mapping.
static inline bool exe_confidence_gap_hints(
    ExeReassemblyContext *context, uint64_t max_gap) {
  ExeHintProgress *progress = &context->state->hints;
  ExeGapHintScan *scan = &progress->gap_scan;
  const int64_t start = context->start;
  const uint64_t header_blocks = context->header_blocks;
  const uint64_t total_blocks = context->total_blocks;
  const uint32_t needleidx = (*context->candidate)->needleidx;
  ExeGapHint *hints = progress->gaps;
  if (progress->gaps_ready) {
    return true;
  }
  if (start < 0 || header_blocks >= total_blocks || max_gap == 0
      || total_blocks > UINT64_MAX - max_gap) {
    progress->gaps_ready = 1;
    return true;
  }

  FileMirror *filemirror = scalpel_state.filemirror;
  const uint64_t apparent_blocks = filemirror_apparent_blocks(filemirror);
  const uint64_t scan_blocks = total_blocks + max_gap;
  uint64_t *longest_first = scan->longest_first;
  uint64_t *longest_length = scan->longest_length;
  if (scan->next_offset < header_blocks) {
    scan->next_offset = header_blocks;
  }

  while (!scan->complete && scan->next_offset <= scan_blocks) {
    const uint64_t offset = scan->next_offset;
    bool low_confidence = false;

    if (offset < scan_blocks
        && (uint64_t)start <= UINT64_MAX - offset) {
      const uint64_t apparent = (uint64_t)start + offset;

      if (apparent < apparent_blocks) {
        const int64_t actual = filemirror_actual_blocknumber(
            filemirror, (int64_t)apparent);

        if (actual >= 0) {
          const BlockValidationDecision confidence =
              filemirror_get_blocktype(filemirror, actual, needleidx);

          low_confidence =
              confidence <= BLOCK_CONFIDENCE_LOW + 1;
        }
      }
    }

    if (low_confidence) {
      if (scan->run_length == 0) {
        // An inserted gap must begin before the baseline file extent ends.
        // Once started, keep scanning until the file data resumes.
        if (offset >= total_blocks) {
          scan->complete = 1;
          goto gap_confidence_advance;
        }
        scan->run_first = offset;
      }
      scan->run_length++;
      goto gap_confidence_advance;
    }
    if (scan->run_length == 0) {
      if (offset >= total_blocks) {
        scan->complete = 1;
      }
      goto gap_confidence_advance;
    }

    for (uint32_t index = 0; index < EXE_CONFIDENCE_GAP_RUNS;
         index++) {
      if (scan->run_length <= longest_length[index]) {
        continue;
      }
      for (uint32_t move = EXE_CONFIDENCE_GAP_RUNS - 1;
           move > index; move--) {
        longest_first[move] = longest_first[move - 1];
        longest_length[move] = longest_length[move - 1];
      }
      longest_first[index] = scan->run_first;
      longest_length[index] = scan->run_length;
      break;
    }
    scan->run_length = 0;
    if (offset >= total_blocks) {
      scan->complete = 1;
    }
    gap_confidence_advance:
    scan->next_offset = offset + 1;
    if (exe_reassembly_context_poll(context)) {
      return false;
    }
  }

  uint32_t count = 0;
  for (uint32_t index = 0; index < EXE_CONFIDENCE_GAP_RUNS;
       index++) {
    const uint64_t first = longest_first[index];
    const uint64_t length = longest_length[index];

    if (length == 0) {
      break;
    }
    for (uint32_t removed = 0;
         removed <= 2U * EXE_CONFIDENCE_GAP_EDGE_SLACK;
         removed++) {
      for (uint32_t left = 0; left <= removed; left++) {
        const uint32_t right = removed - left;
        bool duplicate = false;

        if (left > EXE_CONFIDENCE_GAP_EDGE_SLACK
            || right > EXE_CONFIDENCE_GAP_EDGE_SLACK
            || length <= removed || first > UINT64_MAX - left) {
          continue;
        }
        const ExeGapHint hint = {
            .boundary = first + left,
            .gap_blocks = length - removed
        };
        if (hint.boundary < header_blocks
            || hint.boundary >= total_blocks
            || hint.gap_blocks > max_gap) {
          continue;
        }
        for (uint32_t prior = 0; prior < count; prior++) {
          if (hints[prior].boundary == hint.boundary
              && hints[prior].gap_blocks == hint.gap_blocks) {
            duplicate = true;
            break;
          }
        }
        if (!duplicate && count < EXE_CONFIDENCE_GAP_HINTS) {
          hints[count++] = hint;
        }
      }
    }
  }
  progress->gap_count = count;
  progress->gaps_ready = 1;
  return true;
}

// Evaluate one classifier-proposed physical gap without scanning unrelated
// widths or boundaries. The same parser, checksum, Authenticode, and ordering
// requirements used by the exhaustive gap search govern acceptance.
static inline ExeRecoveryResult exe_try_gap_hint(
    CarveInfo *candidate, const ExeLayout *layout,
    const int64_t *baseline_mapping,
    uint64_t total_blocks, const ExeGapHint *hint, uint8_t *trial_data,
    int64_t *trial_mapping, ExeRecoveryAccumulator *accumulator) {
  if (!candidate || !layout || !baseline_mapping || !hint || !trial_data
      || !trial_mapping || !accumulator || hint->boundary == 0
      || hint->boundary >= total_blocks || hint->gap_blocks == 0
      || hint->gap_blocks > INT64_MAX) {
    return EXE_RECOVERY_NO_MATCH;
  }

  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    trial_mapping[slot] = baseline_mapping[slot];
    if (slot >= hint->boundary) {
      if (trial_mapping[slot]
          > INT64_MAX - (int64_t)hint->gap_blocks) {
        return EXE_RECOVERY_NO_MATCH;
      }
      trial_mapping[slot] += (int64_t)hint->gap_blocks;
    }
  }

  const uint64_t proof_first =
      hint->boundary > EXE_CONFIDENCE_GAP_CONTEXT_BLOCKS
          ? hint->boundary - EXE_CONFIDENCE_GAP_CONTEXT_BLOCKS
          : 0;
  uint64_t proof_last = hint->boundary;
  if (proof_last <= UINT64_MAX - EXE_CONFIDENCE_GAP_CONTEXT_BLOCKS) {
    proof_last += EXE_CONFIDENCE_GAP_CONTEXT_BLOCKS;
  }
  else {
    proof_last = UINT64_MAX;
  }
  if (proof_last > total_blocks) {
    proof_last = total_blocks;
  }
  const uint64_t order_offset = proof_first * scalpel_state.blocksize;
  uint64_t order_length =
      (proof_last - proof_first) * scalpel_state.blocksize;
  if (order_length > layout->described_extent - order_offset) {
    order_length = layout->described_extent - order_offset;
  }

  ExeOrderEvidence evidence;
  const ExeMappingResult mapping_result = exe_mapping_validates(
      trial_mapping, total_blocks, layout, trial_data, order_offset,
      order_length, &evidence, true);
  if (scalpel_state.mode_verbose) {
    lock_fprintf(
        stdout,
        "PE confidence gap hint: boundary=%" PRIu64
        " gap=%" PRIu64 " result=%u records=%u cross=%u"
        " targets=%u reloc=%u control=%u.\n",
        hint->boundary, hint->gap_blocks, mapping_result,
        evidence.metadata_records, evidence.cross_references,
        evidence.validated_target_references, evidence.relocation_values,
        evidence.control_flow_references);
  }
  if (mapping_result == EXE_MAPPING_CRYPTOGRAPHIC) {
    exe_order_evidence_destroy(&evidence);
    return EXE_RECOVERY_MATCH;
  }
  if (mapping_result == EXE_MAPPING_ORDER_PROVEN) {
    const bool repairs_baseline = exe_order_evidence_repairs_baseline(
        baseline_mapping, total_blocks, layout, trial_data, order_offset,
        order_length, &evidence);
    const bool repairs_required_region =
        !accumulator->require_baseline_repair
        || hint->boundary <= accumulator->baseline_repair_first;

    if (repairs_baseline && repairs_required_region) {
      exe_accumulate_gap_mapping(accumulator, trial_mapping);
      exe_accumulate_ordered_mapping(accumulator, trial_mapping, &evidence);
      if (scalpel_state.write_promising) {
        exe_write_mapping_hypothesis(candidate, trial_mapping,
                                     total_blocks, layout);
      }
    }
  }
  else if (mapping_result == EXE_MAPPING_COMPLETE) {
    exe_accumulate_gap_mapping(accumulator, trial_mapping);
    exe_accumulate_complete_mapping(accumulator, trial_mapping);
  }
  exe_order_evidence_destroy(&evidence);
  return EXE_RECOVERY_NO_MATCH;
}

static inline uint32_t exe_apparent_block_confidence(
    int64_t apparent_block, uint32_t needleidx) {
  if (apparent_block < 0) {
    return 0;
  }
  const int64_t actual = filemirror_actual_blocknumber(
      scalpel_state.filemirror, apparent_block);
  if (actual < 0) {
    return 0;
  }
  const BlockValidationDecision confidence = filemirror_get_blocktype(
      scalpel_state.filemirror, actual, needleidx);
  return confidence < BLOCK_CONFIDENCE_INVALID
      ? 0U : (uint32_t)confidence;
}

static inline void exe_add_u64_candidate(
    uint64_t *values, uint32_t *count, uint32_t capacity,
    uint64_t value) {
  if (!values || !count || *count >= capacity) {
    return;
  }
  for (uint32_t index = 0; index < *count; index++) {
    if (values[index] == value) {
      return;
    }
  }
  values[(*count)++] = value;
}

// Rank rising or falling confidence transitions using adjacent sliding windows.
// Retain both window sums and ranked edges so checkpoints resume at the next
// boundary without rereading the preceding part of the image.
static inline bool exe_confidence_edges(
    ExeReassemblyContext *context, ExeConfidenceEdges *edges,
    int64_t base, uint64_t first_boundary, uint64_t end, bool rising) {
  if (edges->complete) {
    return true;
  }
  const uint32_t needleidx = (*context->candidate)->needleidx;
  const uint64_t window = EXE_CONFIDENCE_OOO_WINDOW;
  if (base < 0 || first_boundary < window || end <= window
      || first_boundary >= end - window) {
    edges->complete = 1;
    return true;
  }
  if (!edges->initialized) {
    edges->next_boundary = first_boundary;
    for (uint64_t offset = first_boundary - window;
         offset < first_boundary; offset++) {
      edges->left_sum += exe_apparent_block_confidence(
          base + (int64_t)offset, needleidx);
    }
    for (uint64_t offset = first_boundary;
         offset < first_boundary + window; offset++) {
      edges->right_sum += exe_apparent_block_confidence(
          base + (int64_t)offset, needleidx);
    }
    edges->initialized = 1;
  }

  while (edges->next_boundary < end - window) {
    const uint64_t boundary = edges->next_boundary;
    const uint64_t higher = rising ? edges->right_sum : edges->left_sum;
    const uint64_t lower = rising ? edges->left_sum : edges->right_sum;
    if (higher > lower) {
      const uint64_t score = higher - lower;
      int32_t nearby = -1;
      for (uint32_t index = 0; index < edges->count; index++) {
        const uint64_t distance = edges->offsets[index] > boundary
            ? edges->offsets[index] - boundary : boundary - edges->offsets[index];
        if (distance <= window / 2U) {
          nearby = (int32_t)index;
          break;
        }
      }
      if (nearby >= 0) {
        const uint32_t index = (uint32_t)nearby;
        if (score <= edges->scores[index]) {
          goto confidence_edge_advance;
        }
        for (uint32_t move = index; move + 1 < edges->count; move++) {
          edges->offsets[move] = edges->offsets[move + 1];
          edges->scores[move] = edges->scores[move + 1];
        }
        edges->count--;
      }

      uint32_t insert = 0;
      while (insert < edges->count && edges->scores[insert] >= score) {
        insert++;
      }
      if (insert < EXE_CONFIDENCE_OOO_EDGES) {
        uint32_t limit = edges->count;
        if (limit < EXE_CONFIDENCE_OOO_EDGES) {
          edges->count++;
        }
        else {
          limit = EXE_CONFIDENCE_OOO_EDGES - 1U;
        }
        for (uint32_t move = limit; move > insert; move--) {
          edges->offsets[move] = edges->offsets[move - 1];
          edges->scores[move] = edges->scores[move - 1];
        }
        edges->offsets[insert] = boundary;
        edges->scores[insert] = score;
      }
    }

    confidence_edge_advance: ;
    const uint32_t center_confidence = exe_apparent_block_confidence(
        base + (int64_t)boundary, needleidx);
    edges->left_sum += center_confidence;
    edges->left_sum -= exe_apparent_block_confidence(
        base + (int64_t)(boundary - window), needleidx);
    edges->right_sum += exe_apparent_block_confidence(
        base + (int64_t)(boundary + window), needleidx);
    edges->right_sum -= center_confidence;
    edges->next_boundary++;
    if (exe_reassembly_context_poll(context)) {
      return false;
    }
  }
  edges->complete = 1;
  return true;
}

// Sort relocation targets by their logical byte position, then pointer width.
static inline int exe_compare_relocation_constraints(const void *a,
                                                      const void *b) {
  const ExeRelocationConstraint *left = a;
  const ExeRelocationConstraint *right = b;
  if (left->offset != right->offset) {
    return left->offset < right->offset ? -1 : 1;
  }
  return (left->width > right->width) - (left->width < right->width);
}

// Collect full-width pointer relocations from an intact table. Targets in the
// table itself and pointers spanning carving blocks do not guide this search.
// Other recovery paths remain available when these constraints are absent.
static inline uint64_t exe_relocation_constraints(
    const uint8_t *data, const ExeLayout *layout,
    ExeRelocationConstraint **constraints) {
  *constraints = NULL;
  if (!data || !layout || layout->directory_count <= 5
      || scalpel_state.blocksize == 0) {
    return 0;
  }
  const ExeDirectory *directory = &layout->directories[5];
  uint64_t table_offset;
  ExeLayout checked = *layout;
  if (directory->size == 0
      || !exe_rva_to_file_offset(layout, directory->rva, directory->size,
                                 &table_offset)
      || !exe_range_available(layout->described_extent, table_offset,
                               directory->size)
      || !exe_validate_relocation_directory(data, layout->described_extent,
                                             &checked)) {
    return 0;
  }
  uint64_t count = 0;
  uint64_t capacity = 0;
  uint64_t cursor = 0;
  while (cursor < directory->size) {
    const uint32_t page = exe_read_le32(data + table_offset + cursor);
    const uint32_t size = exe_read_le32(data + table_offset + cursor + 4);
    for (uint32_t offset = 8; offset < size; offset += 2) {
      const uint16_t entry = exe_read_le16(
          data + table_offset + cursor + offset);
      const uint32_t type = entry >> 12;
      const uint32_t width = type == 3 ? 4 : type == 10 ? 8 : 0;
      if (type == 4) {
        offset += 2;
      }
      const uint32_t rva = page + (entry & UINT16_C(0x0fff));
      uint64_t target;
      if (width == 0 || rva < page
          || !exe_rva_to_file_offset(layout, rva, width, &target)
          || !exe_range_available(layout->described_extent, target, width)
          || target / scalpel_state.blocksize
                 != (target + width - 1) / scalpel_state.blocksize
          || exe_ranges_overlap(
                 (target / scalpel_state.blocksize) * scalpel_state.blocksize,
                 scalpel_state.blocksize, table_offset, directory->size)) {
        continue;
      }
      if (count == capacity) {
        capacity = capacity == 0 ? 256 : capacity * 2;
        if (capacity > SIZE_MAX / sizeof(**constraints)) {
          free(*constraints);
          *constraints = NULL;
          return 0;
        }
        *constraints = realloc(*constraints, capacity * sizeof(**constraints));
        check_memory_allocation(*constraints, __LINE__, __FILE__,
                                 "PE relocation constraints");
      }
      (*constraints)[count++] = (ExeRelocationConstraint){target, width};
    }
    cursor += size;
  }
  if (count > 1) {
    qsort(*constraints, (size_t)count, sizeof(**constraints),
          exe_compare_relocation_constraints);
  }
  uint64_t unique = 0;
  for (uint64_t i = 0; i < count; i++) {
    const ExeRelocationConstraint current = (*constraints)[i];
    if (unique != 0) {
      const ExeRelocationConstraint previous = (*constraints)[unique - 1];
      if (current.offset == previous.offset && current.width == previous.width) {
        continue;
      }
      if (current.offset < previous.offset + previous.width) {
        free(*constraints);
        *constraints = NULL;
        return 0;
      }
    }
    (*constraints)[unique++] = current;
  }
  return unique;
}

// These pointer values propose block placements, not file validity. A null or
// external pointer is legal PE content but provides no in-image ordering clue.
static inline bool exe_block_matches_relocations(
    const uint8_t *data, uint64_t length, const ExeLayout *layout,
    const ExeRelocationConstraint *constraints, uint64_t count) {
  if (!data || count == 0 || scalpel_state.blocksize == 0) {
    return false;
  }
  for (uint64_t i = 0; i < count; i++) {
    const uint64_t offset = constraints[i].offset % scalpel_state.blocksize;
    const uint32_t width = constraints[i].width;
    if (!exe_range_available(length, offset, width)) {
      return false;
    }
    const uint64_t value = width == 4 ? exe_read_le32(data + offset)
                                    : exe_read_le64(data + offset);
    uint32_t rva;
    if (value == 0 || !exe_va_to_rva(layout, value, &rva)) {
      return false;
    }
  }
  return true;
}

// Search independently constrained slots without requiring a PE checksum or a
// particular gap layout. Only unique block contents are retained. The combined
// mapping must improve the normal ordering evidence and still parse completely;
// without cryptographic evidence it is published only as PROMISING.
static inline ExeRecoveryResult exe_try_relocation_blocks(
    ExeReassemblyContext *context) {
  ExeCarveState *state = context->state;
  ExeRelocationProgress *progress = &state->relocations;
  const ExeLayout *layout = context->layout;
  if (progress->complete) {
    return EXE_RECOVERY_NO_MATCH;
  }
  if (!exe_materialize_mapping(context->baseline_mapping, context->total_blocks,
                                layout, context->trial_data, false)) {
    progress->complete = 1;
    return EXE_RECOVERY_NO_MATCH;
  }
  ExeRelocationConstraint *constraints = NULL;
  const uint64_t count = exe_relocation_constraints(
      context->trial_data, layout, &constraints);
  int64_t *mapping = exe_carve_state_relocation_mapping(state);
  FileMirror *mirror = scalpel_state.filemirror;
  const uint64_t blocksize = scalpel_state.blocksize;
  const uint64_t image_blocks = CEILDIV(filemirror_filesize(mirror), blocksize);
  ExeRecoveryResult result = EXE_RECOVERY_NO_MATCH;
  if (!progress->initialized) {
    for (uint64_t slot = 0; slot < context->total_blocks; slot++) {
      mapping[slot] = filemirror_actual_blocknumber(
          mirror, context->baseline_mapping[slot]);
    }
    progress->choice_actual = -1;
    progress->initialized = 1;
  }
  while (progress->next_constraint < count) {
    const uint64_t first = progress->next_constraint;
    const uint64_t slot = constraints[first].offset / blocksize;
    uint64_t end = first + 1;
    while (end < count && constraints[end].offset / blocksize == slot) {
      end++;
    }
    const uint64_t logical_offset = slot * blocksize;
    const uint64_t length = layout->described_extent - logical_offset < blocksize
        ? layout->described_extent - logical_offset : blocksize;
    if (slot < context->header_blocks || end - first < 2
        || exe_block_matches_relocations(context->trial_data + logical_offset,
              length, layout, constraints + first, end - first)) {
      goto relocation_slot_complete;
    }
    while (progress->next_actual < image_blocks && !progress->ambiguous) {
      const int64_t actual = (int64_t)progress->next_actual++;
      if (!filemirror_actual_block_covered(mirror, actual)) {
        uint64_t available = 0;
        const uint8_t *data = (const uint8_t *)filemirror_actual_block_data_pointer(
            mirror, actual, &available);
        if (available >= length
            && exe_block_matches_relocations(data, available, layout,
                                               constraints + first, end - first)
            && filemirror_apparent_blocknumber(mirror, actual) >= 0) {
          bool used = false;
          for (uint64_t other = 0; other < context->total_blocks; other++) {
            if (other != slot && mapping[other] == actual) {
              used = true;
              break;
            }
          }
          if (!used && progress->choice_actual < 0) {
            progress->choice_actual = actual;
          }
          else if (!used) {
            if (filemirror_actual_block_covered(
                    mirror, progress->choice_actual)) {
              progress->choice_actual = actual;
              goto relocation_block_complete;
            }
            uint64_t previous_length = 0;
            const uint8_t *previous =
                (const uint8_t *)filemirror_actual_block_data_pointer(
                    mirror, progress->choice_actual, &previous_length);
            if (!previous || previous_length < length
                || memcmp(previous, data, (size_t)length) != 0) {
              progress->ambiguous = 1;
            }
          }
        }
      }
      relocation_block_complete: ;
      if (exe_reassembly_context_poll(context)) {
        result = EXE_RECOVERY_STOPPED;
        goto relocation_done;
      }
    }
    if (!progress->ambiguous && progress->choice_actual >= 0) {
      mapping[slot] = progress->choice_actual;
    }

    relocation_slot_complete: ;
    progress->next_constraint = end;
    progress->next_actual = 0;
    progress->choice_actual = -1;
    progress->ambiguous = 0;
    if (exe_reassembly_context_poll(context)) {
      result = EXE_RECOVERY_STOPPED;
      goto relocation_done;
    }
  }
  progress->complete = 1;
  uint64_t first_changed = context->total_blocks;
  uint64_t last_changed = 0;
  for (uint64_t slot = 0; slot < context->total_blocks; slot++) {
    context->solution_mapping[slot] =
        filemirror_apparent_blocknumber(mirror, mapping[slot]);
    if (context->solution_mapping[slot] < 0) {
      goto relocation_done;
    }
    if (context->solution_mapping[slot] != context->baseline_mapping[slot]) {
      if (first_changed == context->total_blocks) {
        first_changed = slot;
      }
      last_changed = slot + 1;
    }
  }
  const bool covers_repair_range =
      !context->accumulator->require_baseline_repair
      || (first_changed <= context->accumulator->baseline_repair_first
          && last_changed >= context->accumulator->baseline_repair_last);
  if (last_changed != 0) {
    const uint64_t offset = first_changed * blocksize;
    const uint64_t end = last_changed == context->total_blocks
        ? layout->described_extent : last_changed * blocksize;
    ExeOrderEvidence evidence;
    const ExeMappingResult proof = exe_mapping_validates(
        context->solution_mapping, context->total_blocks, layout,
        context->trial_data, offset, end - offset, &evidence, true);
    if (proof == EXE_MAPPING_CRYPTOGRAPHIC
        || (proof == EXE_MAPPING_ORDER_PROVEN
             && !exe_order_evidence_disconnected_code_range(
                    layout, &evidence, NULL, NULL)
             && exe_order_evidence_repairs_baseline(
                    context->baseline_mapping, context->total_blocks, layout,
                    context->trial_data, offset, end - offset, &evidence))) {
      if (covers_repair_range) {
        result = proof == EXE_MAPPING_CRYPTOGRAPHIC
            ? EXE_RECOVERY_MATCH : EXE_RECOVERY_PROMISING_MATCH;
      }
      else if (scalpel_state.write_promising
               && context->candidate && *context->candidate) {
        // Retain an independently improved region without treating unrelated
        // uncertain bytes as resolved. The other searches must still run.
        exe_write_mapping_hypothesis(*context->candidate,
            context->solution_mapping, context->total_blocks, layout);
      }
    }
    exe_order_evidence_destroy(&evidence);
  }

  relocation_done: ;
  free(constraints);
  return result;
}

// A checksumless PE cannot use the checksum-residue OOO index. This bounded
// path models a common physical layout in which one displaced run lies
// immediately before the header-bearing run. Confidence transitions propose
// only boundaries; normal PE parsing and ordering evidence still determine
// which mappings are retained.
static inline ExeRecoveryResult exe_try_preceding_ooo_hints(
    ExeReassemblyContext *context) {
  if (!context || !context->state) {
    return EXE_RECOVERY_NO_MATCH;
  }
  ExeHintProgress *progress = &context->state->hints;
  if (progress->ooo_complete) {
    return EXE_RECOVERY_NO_MATCH;
  }
  uint64_t *destinations = progress->destinations;
  uint64_t *widths = progress->widths;
  CarveInfo **candidate = context->candidate;
  const ExeLayout *layout = context->layout;
  const int64_t *baseline_mapping = context->baseline_mapping;
  const uint64_t total_blocks = context->total_blocks;
  const uint64_t header_blocks = context->header_blocks;
  const int64_t start = context->start;
  const ExeGapHint *gap_hints = progress->gaps;
  const uint32_t gap_hint_count = progress->gap_count;
  uint8_t *trial_data = context->trial_data;
  int64_t *solution_mapping = context->solution_mapping;
  ExeRecoveryAccumulator *accumulator = context->accumulator;
  uint64_t *edge_offsets = progress->destination_edges.offsets;
  uint64_t *edge_scores = progress->destination_edges.scores;
  uint64_t *source_edge_offsets = progress->source_edges.offsets;
  uint64_t *source_edge_scores = progress->source_edges.scores;
  uint32_t destination_count = progress->destination_count;
  uint32_t width_count = progress->width_count;
  uint32_t edge_count = 0;
  uint32_t source_edge_count = 0;
  const uint64_t max_run = total_blocks - header_blocks;

  if (!context->work || !candidate || !*candidate || !layout || !baseline_mapping
      || !trial_data || !solution_mapping || !accumulator || !context->iterations
      || start <= 0 || header_blocks >= total_blocks || max_run == 0
      || layout->checksum_present) {
    return EXE_RECOVERY_NO_MATCH;
  }

  if (!progress->ooo_ready) {
    const uint64_t start_offset = (uint64_t)start;
    const uint64_t source_scan_first = start_offset > max_run
        ? start_offset - max_run : 0;
    const uint64_t destination_first = header_blocks > EXE_CONFIDENCE_OOO_WINDOW
        ? header_blocks : EXE_CONFIDENCE_OOO_WINDOW;
    if (!exe_confidence_edges(context, &progress->destination_edges,
                              start, destination_first, total_blocks, false)
        || !exe_confidence_edges(context, &progress->source_edges, 0,
              source_scan_first + EXE_CONFIDENCE_OOO_WINDOW, start_offset, true)) {
      return EXE_RECOVERY_STOPPED;
    }
    edge_count = progress->destination_edges.count;
    source_edge_count = progress->source_edges.count;


    for (uint32_t index = 0; index < source_edge_count; index++) {
      const uint64_t center = source_edge_offsets[index];
      if (center < start_offset && scalpel_state.mode_verbose) {
        lock_fprintf(stdout,
            "PE preceding source edge: boundary=%"PRIu64
            " width=%"PRIu64" score=%"PRIu64".\n",
            center, start_offset - center, source_edge_scores[index]);
      }
      for (int32_t delta = -(int32_t)EXE_CONFIDENCE_OOO_EDGE_SLACK;
           delta <= (int32_t)EXE_CONFIDENCE_OOO_EDGE_SLACK; delta++) {
        if ((delta < 0 && center < (uint64_t)(-delta))
            || (delta > 0 && center > UINT64_MAX - (uint64_t)delta)) {
          continue;
        }
        const uint64_t boundary = delta < 0
            ? center - (uint64_t)(-delta) : center + (uint64_t)delta;
        if (boundary >= source_scan_first && boundary < start_offset) {
          const uint64_t width = start_offset - boundary;
          if (width <= max_run) {
            exe_add_u64_candidate(widths, &width_count,
                EXE_CONFIDENCE_OOO_CANDIDATES, width);
          }
        }
      }
    }
    for (uint32_t index = 0; index < gap_hint_count; index++) {
      const uint64_t center = gap_hints[index].boundary;
      for (int32_t delta = -(int32_t)EXE_CONFIDENCE_OOO_EDGE_SLACK;
           delta <= (int32_t)EXE_CONFIDENCE_OOO_EDGE_SLACK; delta++) {
        if ((delta < 0 && center < (uint64_t)(-delta))
            || (delta > 0 && center > UINT64_MAX - (uint64_t)delta)) {
          continue;
        }
        const uint64_t boundary = delta < 0
            ? center - (uint64_t)(-delta) : center + (uint64_t)delta;
        if (boundary < header_blocks || boundary >= total_blocks) {
          continue;
        }
        exe_add_u64_candidate(destinations, &destination_count,
            EXE_CONFIDENCE_OOO_CANDIDATES, boundary);
        if (total_blocks - boundary <= max_run) {
          exe_add_u64_candidate(widths, &width_count,
              EXE_CONFIDENCE_OOO_CANDIDATES, total_blocks - boundary);
        }
      }
    }
    for (uint32_t index = 0; index < edge_count; index++) {
      const uint64_t center = edge_offsets[index];
      if (scalpel_state.mode_verbose) {
        lock_fprintf(stdout,
            "PE preceding destination edge: start=%"PRId64
            " boundary=%"PRIu64" score=%"PRIu64".\n",
            start, center, edge_scores[index]);
      }
      for (int32_t delta = -(int32_t)EXE_CONFIDENCE_OOO_EDGE_SLACK;
           delta <= (int32_t)EXE_CONFIDENCE_OOO_EDGE_SLACK; delta++) {
        if ((delta < 0 && center < (uint64_t)(-delta))
            || (delta > 0 && center > UINT64_MAX - (uint64_t)delta)) {
          continue;
        }
        const uint64_t boundary = delta < 0
            ? center - (uint64_t)(-delta) : center + (uint64_t)delta;
        if (boundary < header_blocks || boundary >= total_blocks) {
          continue;
        }
        exe_add_u64_candidate(destinations, &destination_count,
            EXE_CONFIDENCE_OOO_CANDIDATES, boundary);
        if (total_blocks - boundary <= max_run) {
          exe_add_u64_candidate(widths, &width_count,
              EXE_CONFIDENCE_OOO_CANDIDATES, total_blocks - boundary);
        }
      }
    }
    if ((uint64_t)start <= max_run) {
      exe_add_u64_candidate(widths, &width_count,
          EXE_CONFIDENCE_OOO_CANDIDATES, (uint64_t)start);
    }
    progress->destination_count = destination_count;
    progress->width_count = width_count;
    progress->ooo_ready = 1;
  }

  const uint64_t complete_destination_width =
      (uint64_t)start <= max_run ? (uint64_t)start : 0;

  int64_t *trial_mapping = (int64_t *)malloc(
      total_blocks * sizeof(*trial_mapping));
  check_memory_allocation(trial_mapping, __LINE__, __FILE__,
      "PE preceding OOO trial mapping");
  ExeRecoveryResult result = EXE_RECOVERY_NO_MATCH;

  for (uint32_t width_index = progress->next_width;
       result == EXE_RECOVERY_NO_MATCH && width_index < width_count;
       width_index++) {
    const uint64_t run_blocks = widths[width_index];
    if (run_blocks == 0 || run_blocks > max_run
        || run_blocks > (uint64_t)start) {
      progress->next_width = width_index + 1;
      progress->next_destination = 0;
      continue;
    }
    const int64_t source_first = start - (int64_t)run_blocks;
    const uint64_t local_blocks = total_blocks - run_blocks;

    const uint64_t complete_destination_count =
        run_blocks == complete_destination_width
            ? local_blocks - header_blocks + 1 : 0;
    const uint64_t destination_iterations =
        1U + destination_count + complete_destination_count;

    for (uint64_t destination_index = progress->next_destination;
         result == EXE_RECOVERY_NO_MATCH
             && destination_index < destination_iterations;
         destination_index++) {
      uint64_t destination;
      if (destination_index == 0) {
        destination = local_blocks;
      }
      else if (destination_index <= destination_count) {
        destination = destinations[destination_index - 1];
      }
      else {
        destination =
            header_blocks + destination_index - destination_count - 1;
      }
      if (destination < header_blocks || destination > local_blocks) {
        goto preceding_hint_advance;
      }

      if (destination_index > destination_count) {
        bool already_tested = false;
        for (uint32_t index = 0; index < destination_count; index++) {
          if (destinations[index] == destination) {
            already_tested = true;
            break;
          }
        }
        if (already_tested) {
          goto preceding_hint_advance;
        }
      }
      else if (destination_index > 0 && destination == local_blocks) {
        goto preceding_hint_advance;
      }

      for (uint64_t slot = 0; slot < total_blocks; slot++) {
        if (slot < destination) {
          trial_mapping[slot] = baseline_mapping[slot];
        }
        else if (slot < destination + run_blocks) {
          trial_mapping[slot] = source_first
              + (int64_t)(slot - destination);
        }
        else {
          trial_mapping[slot] = baseline_mapping[slot - run_blocks];
        }
      }

      const uint64_t order_offset = destination * scalpel_state.blocksize;
      uint64_t order_length = run_blocks * scalpel_state.blocksize;
      if (order_length > layout->described_extent - order_offset) {
        order_length = layout->described_extent - order_offset;
      }
      ExeOrderEvidence evidence;
      const ExeMappingResult mapping_result = exe_mapping_validates(
          trial_mapping, total_blocks, layout, trial_data, order_offset,
          order_length, &evidence, true);
      if (mapping_result == EXE_MAPPING_CRYPTOGRAPHIC) {
        memcpy(solution_mapping, trial_mapping,
            total_blocks * sizeof(*solution_mapping));
        result = EXE_RECOVERY_MATCH;
      }
      else if (mapping_result == EXE_MAPPING_ORDER_PROVEN) {
        const bool repairs_baseline = exe_order_evidence_repairs_baseline(
            baseline_mapping, total_blocks, layout, trial_data,
            order_offset, order_length, &evidence);
        const bool repairs_required_region =
            !accumulator->require_baseline_repair
            || (destination <= accumulator->baseline_repair_first
                && destination + run_blocks
                       >= accumulator->baseline_repair_last);
        if (repairs_baseline && repairs_required_region) {
          if (scalpel_state.mode_verbose) {
            lock_fprintf(stdout,
                "PE preceding OOO evidence: start=%"PRId64
                " source=%"PRId64" run=%"PRIu64
                " destination=%"PRIu64" records=%u cross=%u"
                " targets=%u reloc=%u control=%u.\n",
                start, source_first, run_blocks, destination,
                evidence.metadata_records, evidence.cross_references,
                evidence.validated_target_references,
                evidence.relocation_values,
                evidence.control_flow_references);
          }
          exe_accumulate_ordered_mapping(accumulator, trial_mapping,
              &evidence);
          if (scalpel_state.write_promising) {
            exe_write_mapping_hypothesis(*candidate, trial_mapping,
                total_blocks, layout);
          }
        }
      }
      else if (mapping_result == EXE_MAPPING_COMPLETE) {
        exe_accumulate_complete_mapping(accumulator, trial_mapping);
        if (scalpel_state.write_promising) {
          exe_write_mapping_hypothesis(*candidate, trial_mapping,
              total_blocks, layout);
        }
      }
      exe_order_evidence_destroy(&evidence);

      preceding_hint_advance:
      if (result == EXE_RECOVERY_NO_MATCH) {
        progress->next_destination = destination_index + 1;
        if (progress->next_destination == destination_iterations) {
          progress->next_width = width_index + 1;
          progress->next_destination = 0;
        }
        if (exe_reassembly_context_poll(context)) {
          result = EXE_RECOVERY_STOPPED;
        }
      }
    }
  }

  if (result == EXE_RECOVERY_NO_MATCH) {
    progress->ooo_complete = 1;
  }

  free(trial_mapping);
  return result;
}

// Preserve each new decisive unsigned mapping as a promising hypothesis while
// the complete search continues. The caller-owned copy prevents duplicate
// output when later search widths retain the same strongest mapping.
static inline void exe_publish_decisive_mapping_hypothesis(
    CarveInfo *candidate, const ExeLayout *layout,
    ExeRecoveryAccumulator *accumulator, int64_t *published_mapping,
    bool *mapping_published) {
  if (!scalpel_state.write_promising || !candidate || !layout
      || !accumulator || !published_mapping || !mapping_published
      || !exe_ordered_mapping_is_decisive(accumulator)) {
    return;
  }
  if (*mapping_published
      && memcmp(published_mapping, accumulator->mapping,
                accumulator->total_blocks * sizeof(*published_mapping))
             == 0) {
    return;
  }
  if (exe_write_mapping_hypothesis(candidate, accumulator->mapping,
                                   accumulator->total_blocks, layout)) {
    memcpy(published_mapping, accumulator->mapping,
           accumulator->total_blocks * sizeof(*published_mapping));
    *mapping_published = true;
  }
}

// Build one checksum-residue index for a bounded window of viable physical
// runs. Callers advance through consecutive windows so image size does not
// determine per-worker memory use.
static inline bool exe_source_run_index_build(
    ExeSourceRunIndex *index, uint64_t run_blocks, uint64_t source_first,
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, uint64_t *iterations, bool *stopped,
    ExeReassemblyContext *context) {
  if (stopped) {
    *stopped = false;
  }
  if (!index || !work || !candidate || !*candidate || !iterations
      || run_blocks == 0) {
    return false;
  }

  memset(index, 0, sizeof(*index));
  const uint64_t apparent_blocks =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  if (run_blocks > apparent_blocks) {
    return false;
  }
  const uint64_t total_sources = apparent_blocks - run_blocks + 1;
  if (source_first >= total_sources) {
    return false;
  }
  index->source_first = source_first;
  index->source_count = total_sources - source_first;
  if (index->source_count > EXE_SOURCE_INDEX_CHUNK_WIDTH) {
    index->source_count = EXE_SOURCE_INDEX_CHUNK_WIDTH;
  }
  index->run_blocks = run_blocks;

  index->heads = (uint32_t *)malloc(EXE_CHECKSUM_RESIDUES
                                     * sizeof(*index->heads));
  index->next = (uint32_t *)malloc((size_t)index->source_count
                                   * sizeof(*index->next));
  index->folded_sums = (uint16_t *)malloc(
      (size_t)index->source_count * sizeof(*index->folded_sums));
  index->valid = (uint8_t *)calloc(
      (size_t)index->source_count, sizeof(*index->valid));
  check_memory_allocation(index->heads, __LINE__, __FILE__,
                          "EXE source checksum heads");
  check_memory_allocation(index->next, __LINE__, __FILE__,
                          "EXE source checksum links");
  check_memory_allocation(index->folded_sums, __LINE__, __FILE__,
                          "EXE source folded checksums");
  check_memory_allocation(index->valid, __LINE__, __FILE__,
                          "EXE source run validity");
  memset(index->heads, 0xff,
         EXE_CHECKSUM_RESIDUES * sizeof(*index->heads));
  memset(index->next, 0xff,
         (size_t)index->source_count * sizeof(*index->next));

  uint64_t source_sum = 0;
  uint64_t invalid_blocks = 0;
  for (uint64_t offset = 0; offset < run_blocks; offset++) {
    uint64_t block_sum = 0;
    if (exe_get_full_block_sum((int64_t)(source_first + offset),
                               &block_sum, true)) {
      source_sum += block_sum;
    }
    else {
      invalid_blocks++;
    }
  }

  for (uint32_t entry = 0; entry < index->source_count; entry++) {
    if (invalid_blocks == 0) {
      const uint32_t folded = exe_fold_word_sum(source_sum);
      const uint32_t residue = folded % EXE_CHECKSUM_RESIDUES;
      index->folded_sums[entry] = (uint16_t)folded;
      index->valid[entry] = 1;
      index->next[entry] = index->heads[residue];
      index->heads[residue] = entry;
    }
    const bool must_stop = context
        ? exe_reassembly_context_poll(context)
        : exe_reassembly_poll(work, candidate, uuidp, uuidc, iterations);
    if (must_stop) {
      if (stopped) {
        *stopped = true;
      }
      return false;
    }
    if ((uint64_t)entry + 1 < index->source_count) {
      uint64_t departing_sum = 0;
      const uint64_t source = source_first + entry;
      if (exe_get_full_block_sum((int64_t)source, &departing_sum, true)) {
        source_sum -= departing_sum;
      }
      else {
        invalid_blocks--;
      }
      uint64_t arriving_sum = 0;
      if (exe_get_full_block_sum(
              (int64_t)(source + run_blocks), &arriving_sum, true)) {
        source_sum += arriving_sum;
      }
      else {
        invalid_blocks++;
      }
    }
  }
  return true;
}

static inline void exe_source_run_index_destroy(ExeSourceRunIndex *index) {
  if (!index) {
    return;
  }
  free(index->folded_sums);
  free(index->next);
  free(index->heads);
  free(index->valid);
  memset(index, 0, sizeof(*index));
}

// Replace one logical run with a physically contiguous run elsewhere in the
// image. Source runs are indexed by checksum residue so each destination can
// directly examine only checksum-compatible sources. A combined search reuses
// the same source index across every candidate gap boundary.
static inline ExeRecoveryResult exe_try_ooo_on_mapping(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const ExeLayout *layout,
    const int64_t *base_mapping, const uint64_t *base_sums,
    uint64_t base_sum, uint64_t total_blocks, uint64_t header_blocks,
    uint64_t run_blocks, int64_t main_first, int64_t main_last,
    bool zero_destinations_only, const ExeSourceRunIndex *source_index,
    uint8_t *trial_data,
    int64_t *solution_mapping,
    ExeRecoveryAccumulator *accumulator, int64_t *published_mapping,
    bool *mapping_published, uint64_t *iterations,
    ExeReassemblyContext *context) {
  ExeRunProgress *progress = context ? context->run_progress : NULL;
  if (!accumulator || (context && !progress)
      || header_blocks > total_blocks || run_blocks == 0
      || run_blocks > total_blocks - header_blocks
      || layout->stored_checksum < layout->described_extent
      || layout->stored_checksum - layout->described_extent > UINT16_MAX) {
    return EXE_RECOVERY_NO_MATCH;
  }

  if (!source_index) {
    const uint64_t apparent_blocks =
        filemirror_apparent_blocks(scalpel_state.filemirror);
    if (run_blocks > apparent_blocks) {
      return EXE_RECOVERY_NO_MATCH;
    }
    const uint64_t total_sources = apparent_blocks - run_blocks + 1;
    uint64_t source_first = 0;
    if (context
        && (progress->phase
                == EXE_ZERO_RESUME_OOO_MAIN
            || progress->phase
                == EXE_ZERO_RESUME_OOO_FINAL)) {
      source_first = progress->outer;
      if (source_first >= total_sources) {
        source_first = 0;
      }
    }
    while (source_first < total_sources) {
      const bool resume_chunk =
          context
          && progress->outer == source_first
          && (progress->phase
                  == EXE_ZERO_RESUME_OOO_MAIN
              || progress->phase
                  == EXE_ZERO_RESUME_OOO_FINAL);
      if (context && !resume_chunk) {
        progress->phase = EXE_ZERO_RESUME_OOO_MAIN;
        progress->outer = source_first;
        progress->inner = header_blocks;
        progress->entry =
            EXE_ZERO_RESUME_ENTRY_NONE;
      }
      ExeSourceRunIndex chunk = {0};
      bool stopped = false;
      if (!exe_source_run_index_build(&chunk, run_blocks, source_first, work,
                                      candidate, uuidp, uuidc, iterations,
                                      &stopped, context)) {
        exe_source_run_index_destroy(&chunk);
        return stopped ? EXE_RECOVERY_STOPPED : EXE_RECOVERY_NO_MATCH;
      }
      const uint64_t next_source = chunk.source_first + chunk.source_count;
      const ExeRecoveryResult chunk_result = exe_try_ooo_on_mapping(
          work, candidate, uuidp, uuidc, layout, base_mapping, base_sums,
          base_sum, total_blocks, header_blocks, run_blocks, main_first,
          main_last, zero_destinations_only, &chunk, trial_data,
          solution_mapping, accumulator, published_mapping,
          mapping_published, iterations, context);
      exe_source_run_index_destroy(&chunk);
      if (chunk_result != EXE_RECOVERY_NO_MATCH) {
        return chunk_result;
      }
      source_first = next_source;
      if (context) {
        progress->phase = EXE_ZERO_RESUME_OOO_MAIN;
        progress->outer = source_first;
        progress->inner = header_blocks;
        progress->entry =
            EXE_ZERO_RESUME_ENTRY_NONE;
      }
    }
    if (context) {
      progress->phase = EXE_ZERO_RESUME_NONE;
      progress->outer = 0;
      progress->inner = 0;
      progress->entry = EXE_ZERO_RESUME_ENTRY_NONE;
    }
    return EXE_RECOVERY_NO_MATCH;
  }
  if (!source_index->heads || !source_index->next
      || !source_index->folded_sums || !source_index->valid
      || source_index->run_blocks != run_blocks) {
    return EXE_RECOVERY_NO_MATCH;
  }

  uint64_t *removed_sums = (uint64_t *)calloc(total_blocks,
                                               sizeof(*removed_sums));
  int64_t *trial_mapping = (int64_t *)malloc(total_blocks
                                              * sizeof(*trial_mapping));
  check_memory_allocation(removed_sums, __LINE__, __FILE__,
                          "EXE removed block sums");
  check_memory_allocation(trial_mapping, __LINE__, __FILE__,
                          "EXE trial mapping");

  const uint64_t blocksize = scalpel_state.blocksize;
  uint64_t final_length = layout->described_extent % blocksize;
  if (final_length == 0) {
    final_length = blocksize;
  }
  const uint32_t target_fold =
      (uint32_t)(layout->stored_checksum - layout->described_extent);
  const uint32_t target_residue = target_fold % EXE_CHECKSUM_RESIDUES;
  const uint64_t final_destination = total_blocks - run_blocks;
  bool final_destination_is_eligible = true;
  ExeRecoveryResult result = EXE_RECOVERY_NO_MATCH;

  if (zero_destinations_only) {
    for (uint64_t offset = 0; offset < run_blocks; offset++) {
      const int64_t actual = filemirror_actual_blocknumber(
          scalpel_state.filemirror,
          base_mapping[final_destination + offset]);
      if (actual < 0
          || !filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                              actual)) {
        final_destination_is_eligible = false;
        break;
      }
    }
  }
  uint64_t final_destination_sum = 0;
  for (uint64_t offset = 0; offset < run_blocks; offset++) {
    final_destination_sum += base_sums[final_destination + offset];
  }
  removed_sums[final_destination] = final_destination_sum;

  const bool resume_final =
      context
      && progress->phase == EXE_ZERO_RESUME_OOO_FINAL
      && progress->outer
             == source_index->source_first;
  uint64_t destination_start = header_blocks;
  if (context && !resume_final
      && progress->phase == EXE_ZERO_RESUME_OOO_MAIN
      && progress->outer
             == source_index->source_first) {
    destination_start = progress->inner;
    if (destination_start < header_blocks
        || destination_start > final_destination + 1) {
      destination_start = header_blocks;
    }
  }

  uint64_t destination_sum = 0;
  for (uint64_t slot = destination_start;
       slot < destination_start + run_blocks
           && slot < total_blocks;
       slot++) {
    destination_sum += base_sums[slot];
  }
  if (context && !resume_final) {
    const bool resume_main =
        progress->phase == EXE_ZERO_RESUME_OOO_MAIN
        && progress->outer
               == source_index->source_first
        && progress->inner == destination_start;
    progress->phase = EXE_ZERO_RESUME_OOO_MAIN;
    progress->outer = source_index->source_first;
    progress->inner = destination_start;
    if (!resume_main) {
      progress->entry =
          EXE_ZERO_RESUME_ENTRY_NONE;
    }
  }
  for (uint64_t destination = destination_start;
       !resume_final && result == EXE_RECOVERY_NO_MATCH
           && destination <= final_destination;
       destination++) {
    removed_sums[destination] = destination_sum;
    bool destination_is_eligible = true;
    if (zero_destinations_only) {
      for (uint64_t offset = 0; offset < run_blocks; offset++) {
        const int64_t actual = filemirror_actual_blocknumber(
            scalpel_state.filemirror,
            base_mapping[destination + offset]);
        if (actual < 0
            || !filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                                actual)) {
          destination_is_eligible = false;
          break;
        }
      }
    }
    const bool has_partial_final_block =
        final_length != blocksize
        && destination + run_blocks == total_blocks;
    if (destination_is_eligible && !has_partial_final_block) {
      const uint64_t retained_sum = base_sum - destination_sum;
      const uint32_t retained_residue =
          exe_fold_word_sum(retained_sum) % EXE_CHECKSUM_RESIDUES;
      const uint32_t required_residue =
          (target_residue + EXE_CHECKSUM_RESIDUES - retained_residue)
          % EXE_CHECKSUM_RESIDUES;
      uint32_t entry = source_index->heads[required_residue];
      if (context
          && progress->phase
                 == EXE_ZERO_RESUME_OOO_MAIN
          && progress->outer
                 == source_index->source_first
          && progress->inner == destination
          && progress->entry
                 != EXE_ZERO_RESUME_ENTRY_NONE) {
        const uint64_t saved_entry =
            progress->entry;
        if (saved_entry < source_index->source_count
            && source_index->valid[saved_entry]
            && source_index->folded_sums[saved_entry]
                   % EXE_CHECKSUM_RESIDUES == required_residue) {
          entry = (uint32_t)saved_entry;
        }
      }
      if (context) {
        progress->inner = destination;
        progress->entry = entry == UINT32_MAX
            ? EXE_ZERO_RESUME_ENTRY_NONE : entry;
      }
      while (entry != UINT32_MAX
             && result == EXE_RECOVERY_NO_MATCH) {
        const uint32_t next_entry = source_index->next[entry];
        const int64_t source =
            (int64_t)(source_index->source_first + entry);
        const int64_t source_first = source;
        const int64_t source_last =
            source_first + (int64_t)run_blocks - 1;
        const uint64_t source_sum = source_index->folded_sums[entry];
        const uint64_t candidate_sum =
            retained_sum + source_sum;
        if (!(source_first <= main_last && source_last >= main_first)
            && exe_checksum_from_raw_sum(
                   candidate_sum, layout->described_extent)
                   == layout->stored_checksum) {
          memcpy(trial_mapping, base_mapping,
                 total_blocks * sizeof(*trial_mapping));
          for (uint64_t offset = 0; offset < run_blocks; offset++) {
            trial_mapping[destination + offset] =
                source_first + (int64_t)offset;
          }
          const uint64_t order_offset = destination * blocksize;
          uint64_t order_length = run_blocks * blocksize;
          if (order_length > layout->described_extent - order_offset) {
            order_length = layout->described_extent - order_offset;
          }
          ExeOrderEvidence evidence;
          const ExeMappingResult mapping_result = exe_mapping_validates(
              trial_mapping, total_blocks, layout, trial_data,
              order_offset, order_length, &evidence, true);
          if (mapping_result == EXE_MAPPING_CRYPTOGRAPHIC) {
            memcpy(solution_mapping, trial_mapping,
                   total_blocks * sizeof(*solution_mapping));
            result = EXE_RECOVERY_MATCH;
          }
          else if (mapping_result == EXE_MAPPING_ORDER_PROVEN) {
            const bool repairs_baseline =
                exe_order_evidence_repairs_baseline(
                    base_mapping, total_blocks, layout, trial_data,
                    order_offset, order_length, &evidence);
            const bool repairs_required_region =
                !accumulator->require_baseline_repair
                || (destination <= accumulator->baseline_repair_first
                    && destination + run_blocks
                           >= accumulator->baseline_repair_last);
            const bool eligible =
                repairs_baseline && repairs_required_region;
            if (eligible && scalpel_state.mode_verbose) {
              lock_fprintf(
                  stdout,
                  "PE OOO evidence: start=%" PRId64 " run=%" PRIu64
                  " source=%" PRId64 " destination=%" PRIu64
                  " records=%u cross=%u targets=%u reloc=%u control=%u.\n",
                  main_first, run_blocks, source, destination,
                  evidence.metadata_records, evidence.cross_references,
                  evidence.validated_target_references,
                  evidence.relocation_values,
                  evidence.control_flow_references);
            }
            if (eligible) {
              if (context && context->alternatives) {
                exe_zero_alternatives_retain(
                    context, trial_mapping, &evidence, 1);
              }
              else if (layout->certificate_size == 0
                       && scalpel_state.write_promising) {
                exe_write_mapping_hypothesis(
                    *candidate, trial_mapping, total_blocks, layout);
              }
              exe_accumulate_ordered_mapping(
                  accumulator, trial_mapping, &evidence);
              if (!context || !context->alternatives) {
                exe_publish_decisive_mapping_hypothesis(
                    *candidate, layout, accumulator, published_mapping,
                    mapping_published);
              }
            }
          }
          else if (mapping_result == EXE_MAPPING_COMPLETE) {
            if (context && context->alternatives) {
              exe_zero_alternatives_retain(
                  context, trial_mapping, &evidence, 1);
            }
            exe_accumulate_complete_mapping(accumulator, trial_mapping);
          }
          exe_order_evidence_destroy(&evidence);
        }

        if (result == EXE_RECOVERY_NO_MATCH) {
          if (context) {
            progress->inner =
                next_entry == UINT32_MAX
                    ? destination + 1 : destination;
            progress->entry =
                next_entry == UINT32_MAX
                    ? EXE_ZERO_RESUME_ENTRY_NONE : next_entry;
          }
          const bool must_stop = context
              ? exe_reassembly_context_poll(context)
              : exe_reassembly_poll(
                    work, candidate, uuidp, uuidc, iterations);
          if (must_stop) {
            result = EXE_RECOVERY_STOPPED;
          }
        }
        entry = next_entry;
      }
    }
    if (result == EXE_RECOVERY_STOPPED) {
      break;
    }
    if (destination < final_destination) {
      destination_sum -= base_sums[destination];
      destination_sum += base_sums[destination + run_blocks];
    }
    if (context) {
      progress->inner = destination + 1;
      progress->entry =
          EXE_ZERO_RESUME_ENTRY_NONE;
    }
    if (result == EXE_RECOVERY_NO_MATCH) {
      const bool must_stop = context
          ? exe_reassembly_context_poll(context)
          : exe_reassembly_poll(
                work, candidate, uuidp, uuidc, iterations);
      if (must_stop) {
        result = EXE_RECOVERY_STOPPED;
        break;
      }
    }
  }

  // A run ending at a short final block needs a position-specific source sum,
  // so it is checked separately from the full-block residue index.
  if (result == EXE_RECOVERY_NO_MATCH && final_length != blocksize
      && final_destination_is_eligible) {
    const uint64_t destination = final_destination;
    uint64_t first_source = source_index->source_first;
    const uint64_t last_source = first_source + source_index->source_count - 1;
    if (resume_final) {
      first_source = progress->inner;
      if (first_source < source_index->source_first
          || first_source > last_source + 1) {
        first_source = source_index->source_first;
      }
    }
    if (context) {
      progress->phase = EXE_ZERO_RESUME_OOO_FINAL;
      progress->outer = source_index->source_first;
      progress->inner = first_source;
      progress->entry = EXE_ZERO_RESUME_ENTRY_NONE;
    }
    for (uint64_t source = first_source; source <= last_source; source++) {
      const int64_t source_first = (int64_t)source;
      const int64_t source_last =
          source_first + (int64_t)run_blocks - 1;
      if (source_first <= main_last && source_last >= main_first) {
        if (context) {
          progress->inner = source + 1;
        }
        const bool must_stop = context
            ? exe_reassembly_context_poll(context)
            : exe_reassembly_poll(
                  work, candidate, uuidp, uuidc, iterations);
        if (must_stop) {
          result = EXE_RECOVERY_STOPPED;
          break;
        }
        continue;
      }
      uint64_t source_sum = 0;
      bool source_valid = true;
      for (uint64_t offset = 0; offset < run_blocks; offset++) {
        uint64_t block_sum = 0;
        if (!exe_get_slot_sum(source_first + (int64_t)offset,
                              destination + offset, layout, &block_sum,
                              true)) {
          source_valid = false;
          break;
        }
        source_sum += block_sum;
      }
      const uint64_t candidate_sum =
          base_sum - removed_sums[destination] + source_sum;
      if (source_valid
          && exe_checksum_from_raw_sum(candidate_sum,
                                       layout->described_extent)
                 == layout->stored_checksum) {
        memcpy(trial_mapping, base_mapping,
               total_blocks * sizeof(*trial_mapping));
        for (uint64_t offset = 0; offset < run_blocks; offset++) {
          trial_mapping[destination + offset] =
              source_first + (int64_t)offset;
        }
        const uint64_t order_offset = destination * blocksize;
        uint64_t order_length = run_blocks * blocksize;
        if (order_length > layout->described_extent - order_offset) {
          order_length = layout->described_extent - order_offset;
        }
        ExeOrderEvidence evidence;
        const ExeMappingResult mapping_result = exe_mapping_validates(
            trial_mapping, total_blocks, layout, trial_data, order_offset,
            order_length, &evidence, true);
        if (mapping_result == EXE_MAPPING_CRYPTOGRAPHIC) {
          memcpy(solution_mapping, trial_mapping,
                 total_blocks * sizeof(*solution_mapping));
          result = EXE_RECOVERY_MATCH;
        }
        else if (mapping_result == EXE_MAPPING_ORDER_PROVEN) {
          const bool repairs_baseline =
              exe_order_evidence_repairs_baseline(
                  base_mapping, total_blocks, layout, trial_data,
                  order_offset, order_length, &evidence);
          const bool repairs_required_region =
              !accumulator->require_baseline_repair
              || (destination <= accumulator->baseline_repair_first
                  && destination + run_blocks
                         >= accumulator->baseline_repair_last);
          const bool eligible =
              repairs_baseline && repairs_required_region;
          if (eligible && scalpel_state.mode_verbose) {
            lock_fprintf(
                stdout,
                "PE OOO evidence: start=%" PRId64 " run=%" PRIu64
                " source=%" PRIu64 " destination=%" PRIu64
                " records=%u cross=%u targets=%u reloc=%u control=%u.\n",
                main_first, run_blocks, source, destination,
                evidence.metadata_records, evidence.cross_references,
                evidence.validated_target_references,
                evidence.relocation_values,
                evidence.control_flow_references);
          }
          if (eligible) {
            if (context && context->alternatives) {
              exe_zero_alternatives_retain(
                  context, trial_mapping, &evidence, 1);
            }
            else if (layout->certificate_size == 0
                     && scalpel_state.write_promising) {
              exe_write_mapping_hypothesis(
                  *candidate, trial_mapping, total_blocks, layout);
            }
            exe_accumulate_ordered_mapping(accumulator, trial_mapping,
                                           &evidence);
            if (!context || !context->alternatives) {
              exe_publish_decisive_mapping_hypothesis(
                  *candidate, layout, accumulator, published_mapping,
                  mapping_published);
            }
          }
        }
        else if (mapping_result == EXE_MAPPING_COMPLETE) {
          if (context && context->alternatives) {
            exe_zero_alternatives_retain(
                context, trial_mapping, &evidence, 1);
          }
          exe_accumulate_complete_mapping(accumulator, trial_mapping);
        }
        exe_order_evidence_destroy(&evidence);
        if (result == EXE_RECOVERY_MATCH) {
          break;
        }
      }
      if (context) {
        progress->inner = source + 1;
      }
      const bool must_stop = context
          ? exe_reassembly_context_poll(context)
          : exe_reassembly_poll(
                work, candidate, uuidp, uuidc, iterations);
      if (must_stop) {
        result = EXE_RECOVERY_STOPPED;
        break;
      }
    }
  }

  if (context && result != EXE_RECOVERY_STOPPED) {
    progress->phase = EXE_ZERO_RESUME_NONE;
    progress->outer = 0;
    progress->inner = 0;
    progress->entry = EXE_ZERO_RESUME_ENTRY_NONE;
  }

  free(trial_mapping);
  free(removed_sums);
  return result;
}

// Construct a mapping with one physical gap and then ask the OOO solver to
// replace one logical run in that mapping.
//
static inline ExeRecoveryResult exe_try_gap_ooo(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const ExeLayout *layout,
    const int64_t *baseline_mapping, const uint64_t *baseline_sums,
    uint64_t total_blocks, uint64_t header_blocks, uint64_t gap_blocks,
    uint64_t run_blocks, uint8_t *trial_data, int64_t *solution_mapping,
    ExeRecoveryAccumulator *accumulator, int64_t *published_mapping,
    bool *mapping_published, uint64_t *iterations,
    ExeReassemblyContext *context) {
  ExeCarveState *state = context ? context->state : NULL;
  uint64_t *prefix = (uint64_t *)calloc(total_blocks + 1,
                                        sizeof(*prefix));
  uint64_t *suffix = (uint64_t *)calloc(total_blocks + 1,
                                        sizeof(*suffix));
  uint64_t *shifted_sums = (uint64_t *)calloc(total_blocks,
                                               sizeof(*shifted_sums));
  uint32_t *suffix_invalid = (uint32_t *)calloc(total_blocks + 1,
                                                 sizeof(*suffix_invalid));
  uint64_t *gap_sums = (uint64_t *)malloc(total_blocks
                                           * sizeof(*gap_sums));
  int64_t *gap_mapping = (int64_t *)malloc(total_blocks
                                            * sizeof(*gap_mapping));
  check_memory_allocation(prefix, __LINE__, __FILE__,
                          "EXE combined gap prefix");
  check_memory_allocation(suffix, __LINE__, __FILE__,
                          "EXE combined gap suffix");
  check_memory_allocation(shifted_sums, __LINE__, __FILE__,
                          "EXE combined shifted sums");
  check_memory_allocation(suffix_invalid, __LINE__, __FILE__,
                          "EXE combined shifted validity");
  check_memory_allocation(gap_sums, __LINE__, __FILE__,
                          "EXE combined gap sums");
  check_memory_allocation(gap_mapping, __LINE__, __FILE__,
                          "EXE combined gap mapping");

  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    prefix[slot + 1] = prefix[slot] + baseline_sums[slot];
    if (!exe_get_slot_sum(baseline_mapping[0] + (int64_t)slot
                              + (int64_t)gap_blocks,
                          slot, layout, &shifted_sums[slot], true)) {
      suffix_invalid[slot] = 1;
    }
  }
  for (uint64_t slot = total_blocks; slot > 0; slot--) {
    suffix[slot - 1] = suffix[slot] + shifted_sums[slot - 1];
    suffix_invalid[slot - 1] += suffix_invalid[slot];
  }

  const int64_t main_first = baseline_mapping[0];
  const int64_t main_last = main_first + (int64_t)total_blocks
                            + (int64_t)gap_blocks - 1;
  ExeRecoveryResult result = EXE_RECOVERY_NO_MATCH;
  const uint64_t apparent_blocks =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  if (run_blocks <= apparent_blocks) {
    const uint64_t total_sources = apparent_blocks - run_blocks + 1;
    uint64_t source_first = state ? state->combined_source : 0;
    while (source_first < total_sources
           && result == EXE_RECOVERY_NO_MATCH) {
      ExeSourceRunIndex source_index = {0};
      bool stopped = false;
      if (!exe_source_run_index_build(&source_index, run_blocks, source_first,
                                      work, candidate, uuidp, uuidc,
                                      iterations, &stopped, context)) {
        result = stopped ? EXE_RECOVERY_STOPPED : EXE_RECOVERY_NO_MATCH;
        exe_source_run_index_destroy(&source_index);
        break;
      }
      const uint64_t next_source =
          source_index.source_first + source_index.source_count;
      const uint32_t first_pass = state ? state->combined_pass : 0;
      for (uint32_t pass = first_pass;
           result == EXE_RECOVERY_NO_MATCH && pass < 2; pass++) {
        const bool zero_destinations_only = pass == 0;
        uint64_t first_boundary = header_blocks;
        if (state && state->combined_pass == pass
            && state->combined_boundary >= header_blocks) {
          first_boundary = state->combined_boundary;
        }
        for (uint64_t boundary = first_boundary; boundary < total_blocks;
             boundary++) {
          if (state) {
            state->combined_source = source_first;
            state->combined_pass = pass;
            state->combined_boundary = boundary;
          }
          if (suffix_invalid[boundary] == 0) {
            for (uint64_t slot = 0; slot < total_blocks; slot++) {
              if (slot < boundary) {
                gap_mapping[slot] = baseline_mapping[slot];
                gap_sums[slot] = baseline_sums[slot];
              }
              else {
                gap_mapping[slot] = baseline_mapping[0] + (int64_t)slot
                                    + (int64_t)gap_blocks;
                gap_sums[slot] = shifted_sums[slot];
              }
            }
            const uint64_t gap_sum = prefix[boundary] + suffix[boundary];
            result = exe_try_ooo_on_mapping(
                work, candidate, uuidp, uuidc, layout, gap_mapping, gap_sums,
                gap_sum, total_blocks, header_blocks, run_blocks, main_first,
                main_last, zero_destinations_only, &source_index, trial_data,
                solution_mapping, accumulator, published_mapping,
                mapping_published, iterations, context);
            if (result != EXE_RECOVERY_NO_MATCH) {
              break;
            }
          }
          if (state) {
            state->combined_boundary = boundary + 1;
          }
          const bool must_stop = context
              ? exe_reassembly_context_poll(context)
              : exe_reassembly_poll(work, candidate, uuidp, uuidc, iterations);
          if (must_stop) {
            result = EXE_RECOVERY_STOPPED;
            break;
          }
        }
        if (state && result == EXE_RECOVERY_NO_MATCH) {
          state->combined_pass = pass + 1;
          state->combined_boundary = header_blocks;
        }
      }
      exe_source_run_index_destroy(&source_index);
      if (result == EXE_RECOVERY_NO_MATCH) {
        source_first = next_source;
        if (state) {
          state->combined_source = source_first;
          state->combined_pass = 0;
          state->combined_boundary = header_blocks;
        }
      }
    }
  }

  if (state && result != EXE_RECOVERY_STOPPED) {
    state->combined_source = 0;
    state->combined_pass = 0;
    state->combined_boundary = header_blocks;
    exe_run_progress_reset(context->run_progress);
  }
  free(gap_mapping);
  free(gap_sums);
  free(suffix_invalid);
  free(shifted_sums);
  free(suffix);
  free(prefix);
  return result;
}

// Validate a printable, nonempty, NUL-terminated PE name at offset.
//
static inline bool exe_validate_ascii_string(const uint8_t *data,
                                             uint64_t length,
                                             uint64_t offset,
                                             uint64_t limit,
                                             ExeLayout *layout) {
  if (!data || offset >= length) {
    exe_set_failure(layout, offset);
    return false;
  }
  if (limit > EXE_MAX_STRING_LENGTH) {
    limit = EXE_MAX_STRING_LENGTH;
  }
  if (limit > length - offset) {
    limit = length - offset;
  }
  if (limit == 0) {
    exe_set_failure(layout, offset);
    return false;
  }
  for (uint64_t i = 0; i < limit; i++) {
    const uint8_t value = data[offset + i];
    if (value == 0) {
      return i != 0;
    }
    if (value < 0x20 || value > 0x7e) {
      exe_set_failure(layout, offset + i);
      return false;
    }
  }
  exe_set_failure(layout, offset + limit - 1);
  return false;
}

// Validate the export directory, its address tables, and exported names.
//
static inline bool exe_validate_export_directory(const uint8_t *data,
                                                 uint64_t length,
                                                 ExeLayout *layout) {
  if (layout->directory_count <= 0 || layout->directories[0].size == 0) {
    return true;
  }
  const ExeDirectory *directory = &layout->directories[0];
  uint64_t offset;
  if (directory->size < 40
      || !exe_rva_to_file_offset(layout, directory->rva, 40, &offset)
      || !exe_range_available(length, offset, 40)) {
    exe_set_failure(layout, directory->rva);
    return false;
  }
  const uint32_t name_rva = exe_read_le32(data + offset + 12);
  const uint32_t functions = exe_read_le32(data + offset + 20);
  const uint32_t names = exe_read_le32(data + offset + 24);
  const uint32_t function_table_rva = exe_read_le32(data + offset + 28);
  const uint32_t name_table_rva = exe_read_le32(data + offset + 32);
  const uint32_t ordinal_table_rva = exe_read_le32(data + offset + 36);
  uint64_t table_offset;

  if (functions > UINT32_C(16777216) || names > functions) {
    exe_set_failure(layout, offset + 20);
    return false;
  }
  if (name_rva != 0) {
    if (!exe_rva_to_file_offset(layout, name_rva, 1, &table_offset)
        || !exe_validate_ascii_string(data, length, table_offset,
                                      EXE_MAX_STRING_LENGTH, layout)) {
      return false;
    }
  }
  if (functions != 0
      && (!exe_rva_to_file_offset(layout, function_table_rva,
                                  functions * 4U, &table_offset)
          || !exe_range_available(length, table_offset,
                                  (uint64_t)functions * 4U))) {
    exe_set_failure(layout, function_table_rva);
    return false;
  }
  if (names != 0) {
    uint64_t names_offset;
    uint64_t ordinals_offset;
    if (!exe_rva_to_file_offset(layout, name_table_rva, names * 4U,
                                &names_offset)
        || !exe_rva_to_file_offset(layout, ordinal_table_rva, names * 2U,
                                   &ordinals_offset)
        || !exe_range_available(length, names_offset,
                                (uint64_t)names * 4U)
        || !exe_range_available(length, ordinals_offset,
                                (uint64_t)names * 2U)) {
      exe_set_failure(layout, name_table_rva);
      return false;
    }
    for (uint32_t i = 0; i < names; i++) {
      const uint16_t ordinal = exe_read_le16(data + ordinals_offset + i * 2U);
      const uint32_t export_name_rva =
          exe_read_le32(data + names_offset + i * 4U);
      uint64_t export_name_offset;
      if (ordinal >= functions
          || !exe_rva_to_file_offset(layout, export_name_rva, 1,
                                     &export_name_offset)
          || !exe_validate_ascii_string(data, length, export_name_offset,
                                        EXE_MAX_STRING_LENGTH, layout)) {
        return false;
      }
    }
  }
  return true;
}

// Validate normal or delayed import descriptors and their library names.
// directory_index is 1 for imports and 13 for delayed imports.
//
static inline bool exe_validate_import_directory(const uint8_t *data,
                                                 uint64_t length,
                                                 ExeLayout *layout,
                                                 uint32_t directory_index) {
  if (layout->directory_count <= directory_index
      || layout->directories[directory_index].size == 0) {
    return true;
  }
  const ExeDirectory *directory = &layout->directories[directory_index];
  const uint32_t descriptor_size = directory_index == 1 ? 20U : 32U;
  uint64_t offset;
  if (!exe_rva_to_file_offset(layout, directory->rva, directory->size,
                              &offset)
      || !exe_range_available(length, offset, directory->size)
      || directory->size < descriptor_size) {
    exe_set_failure(layout, directory->rva);
    return false;
  }
  uint32_t descriptors = directory->size / descriptor_size;
  if (descriptors > EXE_MAX_IMPORT_DESCRIPTORS) {
    descriptors = EXE_MAX_IMPORT_DESCRIPTORS;
  }
  bool terminated = false;
  for (uint32_t i = 0; i < descriptors; i++) {
    const uint8_t *entry = data + offset + (uint64_t)i * descriptor_size;
    bool zero = true;
    for (uint32_t j = 0; j < descriptor_size; j++) {
      if (entry[j] != 0) {
        zero = false;
        break;
      }
    }
    if (zero) {
      terminated = true;
      break;
    }
    const uint32_t name_rva =
        directory_index == 1 ? exe_read_le32(entry + 12)
                             : exe_read_le32(entry + 4);
    uint64_t name_offset;
    if (name_rva == 0
        || !exe_rva_to_file_offset(layout, name_rva, 1, &name_offset)
        || !exe_validate_ascii_string(data, length, name_offset,
                                      EXE_MAX_STRING_LENGTH, layout)) {
      return false;
    }
  }
  if (!terminated && directory_index == 1) {
    exe_set_failure(layout, offset + directory->size - 1);
    return false;
  }
  return true;
}

// Walk every base-relocation block and validate its bounded even-sized layout.
//
static inline bool exe_validate_relocation_directory(const uint8_t *data,
                                                     uint64_t length,
                                                     ExeLayout *layout) {
  if (layout->directory_count <= 5 || layout->directories[5].size == 0) {
    return true;
  }
  const ExeDirectory *directory = &layout->directories[5];
  uint64_t offset;
  if (!exe_rva_to_file_offset(layout, directory->rva, directory->size,
                              &offset)
      || !exe_range_available(length, offset, directory->size)) {
    exe_set_failure(layout, directory->rva);
    return false;
  }
  uint64_t cursor = 0;
  while (cursor < directory->size) {
    if (directory->size - cursor < 8) {
      exe_set_failure(layout, offset + cursor);
      return false;
    }
    const uint32_t page_rva = exe_read_le32(data + offset + cursor);
    const uint32_t block_size = exe_read_le32(data + offset + cursor + 4);
    if (page_rva >= layout->size_of_image || block_size < 8
        || (block_size & 1U) != 0 || block_size > directory->size - cursor) {
      exe_set_failure(layout, offset + cursor);
      return false;
    }
    cursor += block_size;
  }
  return true;
}

// Retain the bounded subset of resource leaves used for cross-resource order
// checks. Resource validation itself does not depend on this catalog.
//
static inline void exe_resource_catalog_add(
    ExeResourceCatalog *catalog, uint32_t type, uint32_t id,
    uint32_t language, uint64_t descriptor_offset,
    uint64_t content_offset, uint32_t content_size) {
  if (!catalog || !catalog->evidence
      || (type != EXE_RESOURCE_TYPE_ICON
          && type != EXE_RESOURCE_TYPE_GROUP_ICON)
      || catalog->count >= EXE_MAX_RESOURCE_EVIDENCE_RECORDS) {
    return;
  }
  if (catalog->count == catalog->capacity) {
    uint32_t capacity = catalog->capacity == 0
                            ? 256U
                            : catalog->capacity * 2U;
    if (capacity > EXE_MAX_RESOURCE_EVIDENCE_RECORDS
        || capacity < catalog->capacity) {
      capacity = EXE_MAX_RESOURCE_EVIDENCE_RECORDS;
    }
    ExeResourceRecord *records = (ExeResourceRecord *)realloc(
        catalog->records, (size_t)capacity * sizeof(*records));
    check_memory_allocation(records, __LINE__, __FILE__,
                            "EXE resource evidence catalog");
    catalog->records = records;
    catalog->capacity = capacity;
  }
  ExeResourceRecord *record = &catalog->records[catalog->count++];
  memset(record, 0, sizeof(*record));
  record->type = type;
  record->id = id;
  record->language = language;
  record->descriptor_offset = descriptor_offset;
  record->content_offset = content_offset;
  record->content_size = content_size;
}

// Validate the self-describing portion of an RT_ICON payload. PNG CRCs cover
// the complete payload; DIB evidence is limited to its header and palette.
//
static inline bool exe_validate_icon_resource(
    const uint8_t *data, uint64_t length, uint64_t content_offset,
    uint32_t content_size, ExeResourceRecord *record) {
  static const uint8_t png_signature[8] = {
    0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a
  };
  if (!data || !record
      || !exe_range_available(length, content_offset, content_size)) {
    return false;
  }
  const uint8_t *content = data + content_offset;
  if (content_size >= sizeof(png_signature)
      && memcmp(content, png_signature, sizeof(png_signature)) == 0) {
    uint64_t cursor = sizeof(png_signature);
    bool have_header = false;
    while (cursor <= content_size && content_size - cursor >= 12) {
      const uint32_t chunk_length = exe_read_be32(content + cursor);
      if ((uint64_t)chunk_length + 12 > content_size - cursor) {
        return false;
      }
      const uint8_t *chunk_type = content + cursor + 4;
      const uint8_t *chunk_data = chunk_type + 4;
      const uint32_t expected_crc =
          exe_read_be32(chunk_data + chunk_length);
      uLong observed_crc = crc32(0L, Z_NULL, 0);
      observed_crc = crc32(observed_crc, chunk_type, chunk_length + 4U);
      if ((uint32_t)observed_crc != expected_crc) {
        return false;
      }
      if (!have_header) {
        if (memcmp(chunk_type, "IHDR", 4) != 0 || chunk_length != 13) {
          return false;
        }
        record->width = exe_read_be32(chunk_data);
        record->height = exe_read_be32(chunk_data + 4);
        const uint8_t bit_depth = chunk_data[8];
        const uint8_t color_type = chunk_data[9];
        const uint8_t channels = color_type == 0 ? 1
                                 : color_type == 2 ? 3
                                 : color_type == 3 ? 1
                                 : color_type == 4 ? 2
                                 : color_type == 6 ? 4
                                                   : 0;
        if (record->width == 0 || record->height == 0 || channels == 0) {
          return false;
        }
        record->planes = 1;
        record->bit_count = (uint16_t)bit_depth * channels;
        have_header = true;
      }
      cursor += (uint64_t)chunk_length + 12;
      if (memcmp(chunk_type, "IEND", 4) == 0) {
        if (chunk_length != 0 || cursor != content_size || !have_header) {
          return false;
        }
        record->validated_header_size = content_size;
        return true;
      }
    }
    return false;
  }

  if (content_size < 12) {
    return false;
  }
  const uint32_t header_size = exe_read_le32(content);
  uint32_t width;
  uint32_t doubled_height;
  uint16_t planes;
  uint16_t bit_count;
  uint64_t palette_entries = 0;
  uint64_t palette_entry_size;
  if (header_size == 12) {
    width = exe_read_le16(content + 4);
    doubled_height = exe_read_le16(content + 6);
    planes = exe_read_le16(content + 8);
    bit_count = exe_read_le16(content + 10);
    palette_entry_size = 3;
  }
  else if ((header_size == 40 || header_size == 52 || header_size == 56
            || header_size == 108 || header_size == 124)
           && header_size <= content_size) {
    const int32_t signed_width = (int32_t)exe_read_le32(content + 4);
    const int32_t signed_height = (int32_t)exe_read_le32(content + 8);
    if (signed_width <= 0 || signed_height <= 0
        || exe_read_le32(content + 16) != 0) {
      return false;
    }
    width = (uint32_t)signed_width;
    doubled_height = (uint32_t)signed_height;
    planes = exe_read_le16(content + 12);
    bit_count = exe_read_le16(content + 14);
    palette_entries = exe_read_le32(content + 32);
    palette_entry_size = 4;
  }
  else {
    return false;
  }
  if (width == 0 || doubled_height == 0 || (doubled_height & 1U) != 0
      || planes != 1
      || (bit_count != 1 && bit_count != 4 && bit_count != 8
          && bit_count != 16 && bit_count != 24 && bit_count != 32)) {
    return false;
  }
  if (palette_entries == 0 && bit_count <= 8) {
    palette_entries = UINT64_C(1) << bit_count;
  }
  if (bit_count <= 8 && palette_entries > (UINT64_C(1) << bit_count)) {
    return false;
  }

  const uint64_t height = doubled_height / 2;
  const uint64_t xor_stride =
      (((uint64_t)width * bit_count + 31) / 32) * 4;
  const uint64_t and_stride = (((uint64_t)width + 31) / 32) * 4;
  const uint64_t validated_header =
      header_size + palette_entries * palette_entry_size;
  const uint64_t expected_size =
      validated_header + xor_stride * height + and_stride * height;
  if (validated_header > UINT32_MAX || expected_size != content_size) {
    return false;
  }
  record->validated_header_size = (uint32_t)validated_header;
  record->width = width;
  record->height = (uint32_t)height;
  record->planes = planes;
  record->bit_count = bit_count;
  return true;
}

// A signed PE embedded in a resource can cryptographically prove the order of
// a displaced run even when the outer image has no remaining signature.
//
static inline void exe_collect_embedded_pe_evidence(
    const uint8_t *data, uint64_t length, uint64_t content_offset,
    uint32_t content_size, ExeOrderEvidence *evidence) {
  if (!data || !evidence || content_size < EXE_DOS_HEADER_SIZE
      || !exe_range_available(length, content_offset, content_size)
      || data[content_offset] != 'M' || data[content_offset + 1] != 'Z'
      || evidence->region_offset < content_offset
      || evidence->region_length > content_size
      || evidence->region_offset - content_offset
             > content_size - evidence->region_length) {
    return;
  }
  ExeLayout nested;
  if (!exe_parse_headers(data + content_offset, content_size, &nested)
      || nested.described_extent > content_size
      || !exe_validate_certificate_table(data + content_offset,
                                         nested.described_extent, &nested)
      || !exe_validate_authenticode(data + content_offset,
                                    nested.described_extent, &nested)
      || !nested.authenticode_matches
      || !exe_authenticode_region_covered(
          &nested, evidence->region_offset - content_offset,
          evidence->region_length)) {
    return;
  }
  if (evidence->cryptographic_regions != UINT32_MAX) {
    evidence->cryptographic_regions++;
  }
}

// Cross-check group-icon entries against their referenced RT_ICON payloads.
// The resource descriptor and group entry independently anchor each validated
// icon header at its logical file position.
//
static inline void exe_collect_group_icon_evidence(
    const uint8_t *data, uint64_t length, ExeResourceCatalog *catalog) {
  if (!data || !catalog || !catalog->evidence) {
    return;
  }
  for (uint32_t i = 0; i < catalog->count; i++) {
    ExeResourceRecord *record = &catalog->records[i];
    if (record->type == EXE_RESOURCE_TYPE_ICON) {
      record->icon_valid = exe_validate_icon_resource(
          data, length, record->content_offset, record->content_size,
          record);
      if (record->icon_valid) {
        exe_evidence_note_record(catalog->evidence,
                                 record->content_offset,
                                 record->validated_header_size);
        exe_evidence_note_validated_reference(
            catalog->evidence, record->descriptor_offset, 16,
            record->content_offset, record->validated_header_size);
      }
    }
  }

  for (uint32_t i = 0; i < catalog->count; i++) {
    const ExeResourceRecord *group = &catalog->records[i];
    if (group->type != EXE_RESOURCE_TYPE_GROUP_ICON
        || group->content_size < 6
        || !exe_range_available(length, group->content_offset,
                                group->content_size)) {
      continue;
    }
    const uint8_t *content = data + group->content_offset;
    const uint16_t count = exe_read_le16(content + 4);
    if (exe_read_le16(content) != 0 || exe_read_le16(content + 2) != 1
        || count == 0 || (uint64_t)count * 14 + 6 != group->content_size) {
      continue;
    }
    exe_evidence_note_record(catalog->evidence, group->content_offset,
                             group->content_size);
    exe_evidence_note_validated_reference(
        catalog->evidence, group->descriptor_offset, 16,
        group->content_offset, group->content_size);

    for (uint16_t index = 0; index < count; index++) {
      const uint64_t entry_offset =
          group->content_offset + 6 + (uint64_t)index * 14;
      const uint8_t *entry = data + entry_offset;
      const uint32_t width = entry[0] == 0 ? 256U : entry[0];
      const uint32_t height = entry[1] == 0 ? 256U : entry[1];
      const uint16_t planes = exe_read_le16(entry + 4);
      const uint16_t bit_count = exe_read_le16(entry + 6);
      const uint32_t bytes = exe_read_le32(entry + 8);
      const uint32_t icon_id = exe_read_le16(entry + 12);
      if (entry[3] != 0) {
        continue;
      }
      for (uint32_t icon_index = 0; icon_index < catalog->count;
           icon_index++) {
        const ExeResourceRecord *icon = &catalog->records[icon_index];
        if (icon->type == EXE_RESOURCE_TYPE_ICON && icon->icon_valid
            && icon->id == icon_id
            && icon->language == group->language
            && icon->content_size == bytes && icon->width == width
            && icon->height == height
            && (planes == 0 || icon->planes == planes)
            && (bit_count == 0 || icon->bit_count == bit_count)) {
          exe_evidence_note_validated_reference(
              catalog->evidence, entry_offset, 14, icon->content_offset,
              icon->validated_header_size);
          break;
        }
      }
    }
  }
}

// Recursively validate one resource directory. Depth and node limits bound
// cyclic or adversarial trees before following their child offsets.
//
static inline bool exe_validate_resource_tree(
    const uint8_t *data, uint64_t length, ExeLayout *layout,
    uint64_t root_offset, uint32_t directory_size,
    uint32_t relative_offset, uint32_t depth, uint32_t resource_type,
    uint32_t resource_id, uint32_t resource_language, uint32_t *nodes,
    ExeResourceCatalog *catalog) {
  const uint64_t directory_offset = root_offset + relative_offset;
  if (depth > EXE_MAX_RESOURCE_DEPTH || !nodes
      || *nodes >= EXE_MAX_RESOURCE_NODES
      || relative_offset > directory_size
      || directory_size - relative_offset < 16
      || !exe_range_available(length, directory_offset, 16)) {
    exe_set_failure(layout, directory_offset);
    return false;
  }
  (*nodes)++;
  const uint8_t *directory = data + directory_offset;
  const uint32_t entries = (uint32_t)exe_read_le16(directory + 12)
                           + exe_read_le16(directory + 14);
  const uint64_t table_size = 16 + (uint64_t)entries * 8;
  if (table_size > directory_size - relative_offset
      || !exe_range_available(length, directory_offset, table_size)) {
    exe_set_failure(layout, directory_offset);
    return false;
  }
  exe_evidence_note_record(catalog ? catalog->evidence : NULL,
                           directory_offset, table_size);

  for (uint32_t i = 0; i < entries; i++) {
    const uint64_t entry_offset = directory_offset + 16 + (uint64_t)i * 8;
    const uint8_t *entry = data + entry_offset;
    const uint32_t name = exe_read_le32(entry);
    const uint32_t entry_id =
        (name & UINT32_C(0x80000000)) != 0 ? UINT32_MAX : name;
    const uint32_t target = exe_read_le32(entry + 4);
    if (name & UINT32_C(0x80000000)) {
      const uint32_t name_offset = name & UINT32_C(0x7fffffff);
      if (name_offset > directory_size || directory_size - name_offset < 2) {
        exe_set_failure(layout, root_offset + name_offset);
        return false;
      }
      const uint16_t characters =
          exe_read_le16(data + root_offset + name_offset);
      const uint64_t name_size = (uint64_t)characters * 2 + 2;
      if (name_size > directory_size - name_offset) {
        exe_set_failure(layout, root_offset + name_offset);
        return false;
      }
      exe_evidence_note_record(catalog ? catalog->evidence : NULL,
                               root_offset + name_offset, name_size);
      exe_evidence_note_validated_reference(
          catalog ? catalog->evidence : NULL, entry_offset, 8,
          root_offset + name_offset, name_size);
    }

    uint32_t child_type = resource_type;
    uint32_t child_id = resource_id;
    uint32_t child_language = resource_language;
    if (depth == 0) {
      child_type = entry_id;
    }
    else if (depth == 1) {
      child_id = entry_id;
    }
    else if (depth == 2) {
      child_language = entry_id;
    }

    const uint32_t target_offset = target & UINT32_C(0x7fffffff);
    if (target & UINT32_C(0x80000000)) {
      if (!exe_validate_resource_tree(
              data, length, layout, root_offset, directory_size,
              target_offset, depth + 1, child_type, child_id,
              child_language, nodes, catalog)) {
        return false;
      }
      exe_evidence_note_validated_reference(
          catalog ? catalog->evidence : NULL, entry_offset, 8,
          root_offset + target_offset, 16);
    }
    else {
      const uint64_t descriptor_offset = root_offset + target_offset;
      if (target_offset > directory_size || directory_size - target_offset < 16
          || !exe_range_available(length, descriptor_offset, 16)) {
        exe_set_failure(layout, descriptor_offset);
        return false;
      }
      exe_evidence_note_record(catalog ? catalog->evidence : NULL,
                               descriptor_offset, 16);
      const uint8_t *data_entry = data + descriptor_offset;
      const uint32_t content_rva = exe_read_le32(data_entry);
      const uint32_t content_size = exe_read_le32(data_entry + 4);
      uint64_t content_offset = 0;
      if (content_size != 0
          && (!exe_rva_to_file_offset(layout, content_rva, content_size,
                                      &content_offset)
              || !exe_range_available(length, content_offset,
                                      content_size))) {
        exe_set_failure(layout, content_rva);
        return false;
      }
      exe_evidence_note_validated_reference(
          catalog ? catalog->evidence : NULL, entry_offset, 8,
          descriptor_offset, 16);
      if (content_size != 0) {
        exe_resource_catalog_add(catalog, child_type, child_id,
                                 child_language, descriptor_offset,
                                 content_offset, content_size);
        exe_collect_embedded_pe_evidence(
            data, length, content_offset, content_size,
            catalog ? catalog->evidence : NULL);
      }
    }
  }
  return true;
}

// Locate and validate the complete PE resource tree.
//
static inline bool exe_validate_resource_directory(
    const uint8_t *data, uint64_t length, ExeLayout *layout,
    ExeOrderEvidence *evidence) {
  if (layout->directory_count <= 2 || layout->directories[2].size == 0) {
    return true;
  }
  const ExeDirectory *directory = &layout->directories[2];
  uint64_t offset;
  uint32_t nodes = 0;
  if (!exe_rva_to_file_offset(layout, directory->rva, directory->size,
                              &offset)
      || !exe_range_available(length, offset, directory->size)) {
    exe_set_failure(layout, directory->rva);
    return false;
  }
  ExeResourceCatalog catalog;
  memset(&catalog, 0, sizeof(catalog));
  catalog.evidence = evidence;
  const bool valid = exe_validate_resource_tree(
      data, length, layout, offset, directory->size, 0, 0, UINT32_MAX,
      UINT32_MAX, UINT32_MAX, &nodes, &catalog);
  if (valid) {
    exe_collect_group_icon_evidence(data, length, &catalog);
  }
  free(catalog.records);
  return valid;
}

// Validate debug-directory entries and include externally stored debug data
// in the described on-disk extent.
//
static inline bool exe_validate_debug_directory(const uint8_t *data,
                                                uint64_t length,
                                                ExeLayout *layout) {
  if (layout->directory_count <= 6 || layout->directories[6].size == 0) {
    return true;
  }
  const ExeDirectory *directory = &layout->directories[6];
  uint64_t offset;
  if (directory->size % 28 != 0
      || !exe_rva_to_file_offset(layout, directory->rva, directory->size,
                                 &offset)
      || !exe_range_available(length, offset, directory->size)) {
    exe_set_failure(layout, directory->rva);
    return false;
  }
  for (uint32_t i = 0; i < directory->size / 28; i++) {
    const uint8_t *entry = data + offset + (uint64_t)i * 28;
    const uint32_t data_size = exe_read_le32(entry + 16);
    const uint32_t data_rva = exe_read_le32(entry + 20);
    const uint32_t data_offset = exe_read_le32(entry + 24);
    if (data_size == 0) {
      continue;
    }
    if (data_offset == 0
        || !exe_range_available(length, data_offset, data_size)) {
      exe_set_failure(layout, data_offset);
      return false;
    }
    uint64_t data_end;
    if (!exe_add_u64(data_offset, data_size, &data_end)) {
      return false;
    }
    if (data_end > layout->described_extent) {
      layout->described_extent = data_end;
    }
    if (data_rva != 0) {
      uint64_t mapped_offset;
      if (!exe_rva_to_file_offset(layout, data_rva, data_size,
                                  &mapped_offset)) {
        exe_set_failure(layout, data_rva);
        return false;
      }
    }
  }
  return true;
}

// Validate the CLR header and the signature and bounds of its metadata root.
//
static inline bool exe_validate_clr_directory(const uint8_t *data,
                                              uint64_t length,
                                              ExeLayout *layout) {
  if (layout->directory_count <= 14 || layout->directories[14].size == 0) {
    return true;
  }
  const ExeDirectory *directory = &layout->directories[14];
  uint64_t offset;
  if (directory->size < 72
      || !exe_rva_to_file_offset(layout, directory->rva, 72, &offset)
      || !exe_range_available(length, offset, 72)
      || exe_read_le32(data + offset) < 72) {
    exe_set_failure(layout, directory->rva);
    return false;
  }
  const uint32_t metadata_rva = exe_read_le32(data + offset + 8);
  const uint32_t metadata_size = exe_read_le32(data + offset + 12);
  uint64_t metadata_offset;
  if (metadata_size < 16
      || !exe_rva_to_file_offset(layout, metadata_rva, metadata_size,
                                 &metadata_offset)
      || !exe_range_available(length, metadata_offset, metadata_size)
      || memcmp(data + metadata_offset, "BSJB", 4) != 0) {
    exe_set_failure(layout, metadata_rva);
    return false;
  }
  return true;
}

// Validate every export address, including forwarded exports, and retain
// executable entry points as control-flow anchors.
//
static inline bool exe_validate_export_targets(
    const uint8_t *data, uint64_t length, ExeLayout *layout,
    ExeOrderEvidence *evidence) {
  if (layout->directory_count <= 0 || layout->directories[0].size == 0) {
    return true;
  }
  const ExeDirectory *directory = &layout->directories[0];
  uint64_t offset;
  if (!exe_rva_to_file_offset(layout, directory->rva, 40, &offset)
      || !exe_range_available(length, offset, 40)) {
    return false;
  }
  exe_evidence_note_record(evidence, offset, 40);

  const uint32_t module_name_rva = exe_read_le32(data + offset + 12);
  const uint32_t functions = exe_read_le32(data + offset + 20);
  const uint32_t names = exe_read_le32(data + offset + 24);
  const uint32_t function_table_rva = exe_read_le32(data + offset + 28);
  const uint32_t name_table_rva = exe_read_le32(data + offset + 32);
  const uint32_t ordinal_table_rva = exe_read_le32(data + offset + 36);
  if (module_name_rva != 0) {
    uint64_t module_name_offset;
    if (!exe_rva_to_file_offset(layout, module_name_rva, 1,
                                &module_name_offset)
        || !exe_validate_ascii_string(data, length, module_name_offset,
                                      EXE_MAX_STRING_LENGTH, layout)) {
      return false;
    }
    exe_evidence_note_validated_reference(evidence, offset + 12, 4,
                                          module_name_offset, 1);
  }

  uint64_t function_table_offset = 0;
  if (functions != 0
      && (!exe_rva_to_file_offset(layout, function_table_rva,
                                  functions * 4U,
                                  &function_table_offset)
          || !exe_range_available(length, function_table_offset,
                                  (uint64_t)functions * 4U))) {
    return false;
  }

  const uint64_t forwarder_end = (uint64_t)directory->rva + directory->size;
  for (uint32_t i = 0; i < functions; i++) {
    const uint64_t entry_offset = function_table_offset + (uint64_t)i * 4;
    const uint32_t target_rva = exe_read_le32(data + entry_offset);
    exe_evidence_note_record(evidence, entry_offset, 4);
    if (target_rva == 0) {
      continue;
    }
    uint64_t target_offset;
    if (target_rva >= directory->rva && target_rva < forwarder_end) {
      if (!exe_rva_to_file_offset(layout, target_rva, 1, &target_offset)
          || !exe_validate_ascii_string(data, length, target_offset,
                                        EXE_MAX_STRING_LENGTH, layout)) {
        return false;
      }
      exe_evidence_note_validated_reference(evidence, entry_offset, 4,
                                            target_offset, 1);
      continue;
    }
    if (target_rva >= layout->size_of_image) {
      return false;
    }
    if (exe_rva_to_file_offset(layout, target_rva, 1, &target_offset)) {
      exe_evidence_note_reference(evidence, entry_offset, 4, target_offset, 1);
    }
    if (exe_rva_is_executable(layout, target_rva)) {
      exe_evidence_add_anchor(evidence, target_rva);
    }
  }

  if (names != 0) {
    uint64_t names_offset;
    uint64_t ordinals_offset;
    if (!exe_rva_to_file_offset(layout, name_table_rva, names * 4U,
                                &names_offset)
        || !exe_rva_to_file_offset(layout, ordinal_table_rva, names * 2U,
                                   &ordinals_offset)) {
      return false;
    }
    for (uint32_t i = 0; i < names; i++) {
      const uint32_t name_rva = exe_read_le32(data + names_offset
                                              + (uint64_t)i * 4);
      uint64_t name_offset;
      if (!exe_rva_to_file_offset(layout, name_rva, 1, &name_offset)
          || !exe_validate_ascii_string(data, length, name_offset,
                                        EXE_MAX_STRING_LENGTH, layout)) {
        return false;
      }
      exe_evidence_note_validated_reference(
          evidence, names_offset + (uint64_t)i * 4, 4, name_offset, 1);
      exe_evidence_note_record(evidence, ordinals_offset + (uint64_t)i * 2,
                               2);
    }
  }
  return true;
}

// Validate one import lookup table and its corresponding IAT. Bound images
// may store resolved virtual addresses in an IAT used in place of the lookup
// table; those entries remain bounded and terminated but have no name RVA.
//
static inline bool exe_validate_thunk_table(
    const uint8_t *data, uint64_t length, ExeLayout *layout,
    uint32_t lookup_rva, uint32_t iat_rva, bool allow_bound,
    uint64_t lookup_source_offset, uint64_t iat_source_offset,
    ExeOrderEvidence *evidence) {
  const uint32_t pointer_size = layout->pe32_plus ? 8U : 4U;
  uint64_t lookup_offset;
  uint64_t lookup_available;
  if (lookup_rva == 0
      || !exe_rva_bytes_available(layout, lookup_rva, &lookup_offset,
                                  &lookup_available)
      || lookup_available < pointer_size
      || !exe_range_available(length, lookup_offset, lookup_available)) {
    return false;
  }
  uint64_t iat_offset = 0;
  uint64_t iat_available = 0;
  if (iat_rva != 0
      && (!exe_rva_bytes_available(layout, iat_rva, &iat_offset,
                                   &iat_available)
          || iat_available < pointer_size
          || !exe_range_available(length, iat_offset, iat_available))) {
    return false;
  }
  uint64_t entries = lookup_available / pointer_size;
  if (entries > EXE_MAX_IMPORT_THUNKS) {
    entries = EXE_MAX_IMPORT_THUNKS;
  }
  bool terminated = false;
  uint64_t table_size = 0;
  for (uint64_t i = 0; i < entries; i++) {
    const uint64_t entry_offset = lookup_offset + i * pointer_size;
    const uint64_t value = layout->pe32_plus
                               ? exe_read_le64(data + entry_offset)
                               : exe_read_le32(data + entry_offset);
    exe_evidence_note_record(evidence, entry_offset, pointer_size);
    if (value == 0) {
      terminated = true;
      table_size = (i + 1) * pointer_size;
      if (iat_rva != 0 && (i + 1) * pointer_size > iat_available) {
        return false;
      }
      break;
    }

    const uint64_t ordinal_flag = layout->pe32_plus
                                      ? UINT64_C(0x8000000000000000)
                                      : UINT64_C(0x80000000);
    if (value & ordinal_flag) {
      if ((value & ~(ordinal_flag | UINT64_C(0xffff))) != 0) {
        return false;
      }
    }
    else {
      if (value > UINT32_MAX) {
        if (allow_bound) {
          continue;
        }
        return false;
      }
      uint64_t name_offset;
      if (!exe_rva_to_file_offset(layout, (uint32_t)value, 3,
                                  &name_offset)
          || !exe_range_available(length, name_offset, 3)
          || !exe_validate_ascii_string(data, length, name_offset + 2,
                                        EXE_MAX_STRING_LENGTH, layout)) {
        if (allow_bound) {
          continue;
        }
        return false;
      }
      exe_evidence_note_validated_reference(
          evidence, entry_offset, pointer_size, name_offset, 3);
    }
    if (iat_rva != 0 && (i + 1) * pointer_size > iat_available) {
      return false;
    }
    if (iat_rva != 0) {
      exe_evidence_add_anchor(evidence,
                              iat_rva + (uint32_t)(i * pointer_size));
    }
  }
  if (!terminated) {
    return false;
  }
  exe_evidence_note_validated_reference(
      evidence, lookup_source_offset, 4, lookup_offset, table_size);
  if (iat_rva != 0
      && (iat_rva != lookup_rva
          || iat_source_offset != lookup_source_offset)) {
    exe_evidence_note_reference(evidence, iat_source_offset, 4,
                                iat_offset, table_size);
  }
  return true;
}

// Validate normal and delayed import thunk arrays after their descriptors and
// library names have passed the basic directory checks.
//
static inline bool exe_validate_import_thunks(
    const uint8_t *data, uint64_t length, ExeLayout *layout,
    uint32_t directory_index, ExeOrderEvidence *evidence) {
  if (layout->directory_count <= directory_index
      || layout->directories[directory_index].size == 0) {
    return true;
  }
  const ExeDirectory *directory = &layout->directories[directory_index];
  const uint32_t descriptor_size = directory_index == 1 ? 20U : 32U;
  uint64_t offset;
  if (!exe_rva_to_file_offset(layout, directory->rva, directory->size,
                              &offset)) {
    return false;
  }
  uint32_t descriptors = directory->size / descriptor_size;
  if (descriptors > EXE_MAX_IMPORT_DESCRIPTORS) {
    descriptors = EXE_MAX_IMPORT_DESCRIPTORS;
  }
  for (uint32_t i = 0; i < descriptors; i++) {
    const uint64_t descriptor_offset = offset + (uint64_t)i * descriptor_size;
    const uint8_t *entry = data + descriptor_offset;
    bool zero = true;
    for (uint32_t j = 0; j < descriptor_size; j++) {
      if (entry[j] != 0) {
        zero = false;
        break;
      }
    }
    if (zero) {
      return true;
    }
    exe_evidence_note_record(evidence, descriptor_offset, descriptor_size);

    uint32_t lookup_rva;
    uint32_t iat_rva;
    uint32_t name_rva;
    uint64_t lookup_source_offset;
    uint64_t iat_source_offset;
    uint64_t name_source_offset;
    bool allow_bound = false;
    if (directory_index == 1) {
      const uint32_t original_thunk = exe_read_le32(entry);
      const uint32_t timestamp = exe_read_le32(entry + 4);
      iat_rva = exe_read_le32(entry + 16);
      lookup_rva = original_thunk != 0 ? original_thunk : iat_rva;
      name_rva = exe_read_le32(entry + 12);
      lookup_source_offset = descriptor_offset
                             + (original_thunk != 0 ? 0 : 16);
      iat_source_offset = descriptor_offset + 16;
      name_source_offset = descriptor_offset + 12;
      allow_bound = original_thunk == 0 && timestamp != 0;
    }
    else {
      const uint32_t attributes = exe_read_le32(entry);
      uint64_t lookup_value = exe_read_le32(entry + 16);
      uint64_t iat_value = exe_read_le32(entry + 12);
      uint64_t name_value = exe_read_le32(entry + 4);
      if ((attributes & 1U) == 0) {
        uint32_t converted;
        if (!exe_va_to_rva(layout, lookup_value, &converted)) {
          return false;
        }
        lookup_value = converted;
        if (!exe_va_to_rva(layout, iat_value, &converted)) {
          return false;
        }
        iat_value = converted;
        if (!exe_va_to_rva(layout, name_value, &converted)) {
          return false;
        }
        name_value = converted;
      }
      if (lookup_value > UINT32_MAX || iat_value > UINT32_MAX
          || name_value > UINT32_MAX) {
        return false;
      }
      lookup_rva = (uint32_t)lookup_value;
      iat_rva = (uint32_t)iat_value;
      name_rva = (uint32_t)name_value;
      lookup_source_offset = descriptor_offset + 16;
      iat_source_offset = descriptor_offset + 12;
      name_source_offset = descriptor_offset + 4;
    }
    uint64_t name_offset;
    if (name_rva == 0
        || !exe_rva_to_file_offset(layout, name_rva, 1, &name_offset)
        || !exe_validate_ascii_string(data, length, name_offset,
                                      EXE_MAX_STRING_LENGTH, layout)) {
      return false;
    }
    exe_evidence_note_validated_reference(
        evidence, name_source_offset, 4, name_offset, 1);
    if (!exe_validate_thunk_table(data, length, layout, lookup_rva, iat_rva,
                                  allow_bound, lookup_source_offset,
                                  iat_source_offset, evidence)) {
      return false;
    }
  }
  return directory_index != 1;
}

// Validate the target of every relocation entry and use relocated in-image
// pointer values as order-sensitive evidence when they fall in a trial run.
//
static inline bool exe_validate_relocation_entries(
    const uint8_t *data, uint64_t length, ExeLayout *layout,
    ExeOrderEvidence *evidence) {
  if (layout->directory_count <= 5 || layout->directories[5].size == 0) {
    return true;
  }
  const ExeDirectory *directory = &layout->directories[5];
  uint64_t offset;
  if (!exe_rva_to_file_offset(layout, directory->rva, directory->size,
                              &offset)) {
    return false;
  }
  uint64_t cursor = 0;
  while (cursor < directory->size) {
    const uint32_t page_rva = exe_read_le32(data + offset + cursor);
    const uint32_t block_size = exe_read_le32(data + offset + cursor + 4);
    exe_evidence_note_record(evidence, offset + cursor, block_size);
    const uint32_t entries = (block_size - 8) / 2;
    for (uint32_t i = 0; i < entries; i++) {
      const uint64_t entry_offset = offset + cursor + 8 + (uint64_t)i * 2;
      const uint16_t encoded = exe_read_le16(data + entry_offset);
      const uint32_t type = encoded >> 12;
      if (type == 0) {
        continue;
      }
      const uint32_t target_rva = page_rva + (encoded & UINT16_C(0x0fff));
      if (target_rva < page_rva || target_rva >= layout->size_of_image) {
        return false;
      }
      uint32_t width = 1;
      if (type == 1 || type == 2 || type == 4) {
        width = 2;
      }
      else if (type == 3) {
        width = 4;
      }
      else if (type == 10) {
        width = 8;
      }
      if (type == 4 && i + 1 >= entries) {
        return false;
      }
      uint64_t target_offset;
      if (exe_rva_to_file_offset(layout, target_rva, width, &target_offset)
          && exe_range_available(length, target_offset, width)) {
        bool points_inside_image = false;
        uint32_t referenced_rva = 0;
        uint64_t pointer_value = 0;
        if (type == 3) {
          pointer_value = exe_read_le32(data + target_offset);
        }
        else if (type == 10) {
          pointer_value = exe_read_le64(data + target_offset);
        }
        // A null pointer supplies no ordering evidence, including when the
        // preferred image base is zero. The relocation still identifies bytes
        // whose placement needs independent support.
        if (type == 3 || type == 10) {
          points_inside_image = pointer_value != 0
              && exe_va_to_rva(layout, pointer_value, &referenced_rva);
          if (!points_inside_image) {
            exe_evidence_note_reference(
                evidence, entry_offset, 2, target_offset, width);
          }
        }
        if (points_inside_image) {
          exe_evidence_note_validated_reference(
              evidence, entry_offset, 2, target_offset, width);
          if (evidence
              && exe_ranges_overlap(target_offset, width,
                                    evidence->region_offset,
                                    evidence->region_length)
              && evidence->relocation_values != UINT32_MAX) {
            evidence->relocation_values++;
            for (uint64_t block_index = 0;
                 block_index < evidence->block_count; block_index++) {
              const uint64_t block_offset =
                  (evidence->first_block + block_index)
                  * scalpel_state.blocksize;
              if (exe_ranges_overlap(target_offset, width, block_offset,
                                     scalpel_state.blocksize)
                  && evidence->blocks[block_index].relocation_values
                         != UINT32_MAX) {
                evidence->blocks[block_index].relocation_values++;
              }
            }
          }
          if (exe_rva_is_executable(layout, referenced_rva)) {
            exe_evidence_add_anchor(evidence, referenced_rva);
          }
        }
      }
      if (type == 4) {
        i++;
      }
    }
    cursor += block_size;
  }
  return true;
}

// First bound every populated RVA directory, then apply deeper validators to
// formats whose internal structure provides useful evidence.
//
static inline bool exe_validate_directories(const uint8_t *data,
                                            uint64_t length,
                                            ExeLayout *layout,
                                            ExeOrderEvidence *evidence) {
  for (uint32_t i = 0; i < layout->directory_count; i++) {
    const ExeDirectory *directory = &layout->directories[i];
    if (i == 4 || directory->size == 0) {
      continue;
    }
    if (directory->rva == 0) {
      exe_set_failure(layout, layout->optional_header_offset);
      return false;
    }
    uint64_t offset;
    if (!exe_rva_to_file_offset(layout, directory->rva, directory->size,
                                &offset)
        || !exe_range_available(length, offset, directory->size)) {
      exe_set_failure(layout, directory->rva);
      return false;
    }
  }
  if (!exe_validate_export_directory(data, length, layout)
      || !exe_validate_import_directory(data, length, layout, 1)
      || !exe_validate_resource_directory(data, length, layout, evidence)
      || !exe_validate_relocation_directory(data, length, layout)
      || !exe_validate_debug_directory(data, length, layout)
      || !exe_validate_import_directory(data, length, layout, 13)
      || !exe_validate_clr_directory(data, length, layout)) {
    return false;
  }
  layout->directories_valid = true;
  return true;
}

// Validate each aligned WIN_CERTIFICATE record in the security directory.
// Cryptographic image verification is performed separately.
//
static inline bool exe_validate_certificate_table(const uint8_t *data,
                                                  uint64_t length,
                                                  ExeLayout *layout) {
  if (layout->certificate_size == 0) {
    layout->certificate_table_valid = true;
    return true;
  }
  if (!exe_range_available(length, layout->certificate_offset,
                           layout->certificate_size)) {
    exe_set_failure(layout, layout->certificate_offset);
    return false;
  }
  uint64_t cursor = 0;
  while (cursor < layout->certificate_size) {
    if (layout->certificate_size - cursor < EXE_WIN_CERTIFICATE_HEADER_SIZE) {
      exe_set_failure(layout, layout->certificate_offset + cursor);
      return false;
    }
    const uint8_t *entry = data + layout->certificate_offset + cursor;
    const uint32_t entry_length = exe_read_le32(entry);
    const uint16_t revision = exe_read_le16(entry + 4);
    const uint16_t type = exe_read_le16(entry + 6);
    if (entry_length < EXE_WIN_CERTIFICATE_HEADER_SIZE
        || entry_length > layout->certificate_size - cursor
        || (revision != UINT16_C(0x0100)
            && revision != UINT16_C(0x0200))
        || type == 0) {
      exe_set_failure(layout, layout->certificate_offset + cursor);
      return false;
    }
    const uint64_t next = exe_align_up_u64(cursor + entry_length, 8);
    if (next == UINT64_MAX || next > layout->certificate_size) {
      exe_set_failure(layout, layout->certificate_offset + cursor);
      return false;
    }
    cursor = next;
  }
  layout->certificate_table_valid = cursor == layout->certificate_size;
  return layout->certificate_table_valid;
}

// Compute the checksum used by the PE CheckSum field. The two words occupied by the stored checksum
// are treated as zero, then the file length is added after the folded word sum.
static inline uint32_t exe_compute_checksum(const uint8_t *data,
                                            uint64_t length,
                                            uint32_t checksum_offset) {
  uint64_t sum = 0;
  uint64_t offset = 0;
  while (offset + 1 < length) {
    if (offset != checksum_offset && offset != (uint64_t)checksum_offset + 2) {
      sum += exe_read_le16(data + offset);
      sum = (sum & UINT64_C(0xffff)) + (sum >> 16);
    }
    offset += 2;
  }
  if (offset < length) {
    sum += data[offset];
  }
  sum = (sum & UINT64_C(0xffff)) + (sum >> 16);
  sum += sum >> 16;
  sum = (sum & UINT64_C(0xffff)) + length;
  return (uint32_t)sum;
}

// Extract the image-digest algorithm and expected digest from the
// SpcIndirectDataContent embedded in one Authenticode PKCS#7 entry.
static inline bool exe_extract_authenticode_digest(
    const uint8_t *certificate, uint64_t certificate_length,
    const EVP_MD **digest_method, const uint8_t **digest,
    uint32_t *digest_length) {
  if (!certificate || certificate_length > LONG_MAX || !digest_method
      || !digest || !digest_length) {
    return false;
  }
  const unsigned char *cursor = certificate;
  PKCS7 *pkcs7 = d2i_PKCS7(NULL, &cursor, (long)certificate_length);
  if (!pkcs7 || !PKCS7_type_is_signed(pkcs7) || !pkcs7->d.sign
      || !pkcs7->d.sign->contents || !pkcs7->d.sign->contents->d.other
      || pkcs7->d.sign->contents->d.other->type != V_ASN1_SEQUENCE
      || !pkcs7->d.sign->contents->d.other->value.sequence) {
    PKCS7_free(pkcs7);
    return false;
  }

  const ASN1_STRING *content =
      pkcs7->d.sign->contents->d.other->value.sequence;
  const unsigned char *outer = ASN1_STRING_get0_data(content);
  const unsigned char *outer_end = outer + ASN1_STRING_length(content);
  long object_length = 0;
  int tag = 0;
  int object_class = 0;
  int flags = ASN1_get_object(&outer, &object_length, &tag, &object_class,
                              (long)(outer_end - outer));
  if ((flags & 0x80) || tag != V_ASN1_SEQUENCE
      || object_length < 0 || object_length > outer_end - outer) {
    PKCS7_free(pkcs7);
    return false;
  }
  const unsigned char *sequence_end = outer + object_length;

  const unsigned char *first = outer;
  long first_length = 0;
  flags = ASN1_get_object(&first, &first_length, &tag, &object_class,
                          (long)(sequence_end - first));
  if ((flags & 0x80) || first_length < 0
      || first_length > sequence_end - first) {
    PKCS7_free(pkcs7);
    return false;
  }
  outer = first + first_length;
  if (outer >= sequence_end) {
    PKCS7_free(pkcs7);
    return false;
  }

  const unsigned char *digest_info_cursor = outer;
  X509_SIG *digest_info = d2i_X509_SIG(
      NULL, &digest_info_cursor, (long)(sequence_end - outer));
  if (!digest_info) {
    PKCS7_free(pkcs7);
    return false;
  }
  const X509_ALGOR *algorithm = NULL;
  const ASN1_OCTET_STRING *digest_string = NULL;
  X509_SIG_get0(digest_info, &algorithm, &digest_string);
  const ASN1_OBJECT *algorithm_object = NULL;
  X509_ALGOR_get0(&algorithm_object, NULL, NULL, algorithm);
  const EVP_MD *method = algorithm_object
                             ? EVP_get_digestbynid(OBJ_obj2nid(algorithm_object))
                             : NULL;
  const int extracted_length = digest_string
                                   ? ASN1_STRING_length(digest_string) : 0;
  const unsigned char *digest_data = digest_string
                                        ? ASN1_STRING_get0_data(digest_string)
                                        : NULL;
  if (!method || !digest_data || extracted_length <= 0
      || extracted_length > EVP_MAX_MD_SIZE
      || extracted_length != EVP_MD_get_size(method)) {
    X509_SIG_free(digest_info);
    PKCS7_free(pkcs7);
    return false;
  }

  static _Thread_local uint8_t extracted[EVP_MAX_MD_SIZE];
  memcpy(extracted, digest_data, (size_t)extracted_length);
  *digest_method = method;
  *digest = extracted;
  *digest_length = (uint32_t)extracted_length;
  X509_SIG_free(digest_info);
  PKCS7_free(pkcs7);
  return true;
}

// Order section ranges by their on-disk offsets for Authenticode hashing.
//
static inline int exe_compare_raw_ranges(const void *left, const void *right) {
  const ExeRawRange *a = left;
  const ExeRawRange *b = right;
  if (a->offset < b->offset) {
    return -1;
  }
  if (a->offset > b->offset) {
    return 1;
  }
  if (a->size < b->size) {
    return -1;
  }
  if (a->size > b->size) {
    return 1;
  }
  return 0;
}

// Reproduce the Authenticode image hash, excluding the checksum, security
// directory entry, and attribute certificate table as required by PE signing.
//
static inline bool exe_compute_authenticode_digest(const uint8_t *data,
                                                   uint64_t length,
                                                   const ExeLayout *layout,
                                                   const EVP_MD *digest_method,
                                                   uint8_t *digest,
                                                   uint32_t *digest_length) {
  if (!data || !layout || !digest_method || !digest || !digest_length
      || layout->certificate_directory_offset == 0
      || layout->checksum_offset + 4 > layout->certificate_directory_offset
      || layout->certificate_directory_offset + 8 > layout->size_of_headers
      || !exe_range_available(length, 0, layout->size_of_headers)) {
    return false;
  }

  EVP_MD_CTX *context = EVP_MD_CTX_new();
  if (!context || EVP_DigestInit_ex(context, digest_method, NULL) != 1
      || EVP_DigestUpdate(context, data, layout->checksum_offset) != 1
      || EVP_DigestUpdate(context, data + layout->checksum_offset + 4,
                          layout->certificate_directory_offset
                              - layout->checksum_offset - 4) != 1
      || EVP_DigestUpdate(context,
                          data + layout->certificate_directory_offset + 8,
                          layout->size_of_headers
                              - layout->certificate_directory_offset - 8)
             != 1) {
    EVP_MD_CTX_free(context);
    return false;
  }

  ExeRawRange ranges[EXE_MAX_SECTIONS];
  uint32_t range_count = 0;
  for (uint32_t i = 0; i < layout->section_count; i++) {
    if (layout->sections[i].raw_size != 0) {
      ranges[range_count].offset = layout->sections[i].raw_offset;
      ranges[range_count].size = layout->sections[i].raw_size;
      range_count++;
    }
  }
  qsort(ranges, range_count, sizeof(ranges[0]), exe_compare_raw_ranges);
  uint64_t hashed_end = layout->size_of_headers;
  for (uint32_t i = 0; i < range_count; i++) {
    if (!exe_range_available(length, ranges[i].offset, ranges[i].size)
        || EVP_DigestUpdate(context, data + ranges[i].offset,
                            ranges[i].size) != 1) {
      EVP_MD_CTX_free(context);
      return false;
    }
    const uint64_t range_end = (uint64_t)ranges[i].offset + ranges[i].size;
    if (range_end > hashed_end) {
      hashed_end = range_end;
    }
  }

  // Current Windows signing tools include a pre-certificate overlay in the image digest. This is
  // common in self-contained executables whose payload follows the mapped sections.
  if (layout->certificate_offset > hashed_end
      && EVP_DigestUpdate(context, data + hashed_end,
                          layout->certificate_offset - hashed_end) != 1) {
    EVP_MD_CTX_free(context);
    return false;
  }

  unsigned int output_length = 0;
  const bool success = EVP_DigestFinal_ex(context, digest, &output_length) == 1;
  EVP_MD_CTX_free(context);
  if (!success) {
    return false;
  }
  *digest_length = output_length;
  return true;
}

// Compare every recognizable embedded Authenticode image digest with the
// reconstructed image. Unrecognized certificate types remain structural data.
//
static inline bool exe_validate_authenticode(const uint8_t *data,
                                             uint64_t length,
                                             ExeLayout *layout) {
  if (layout->certificate_size == 0) {
    return true;
  }
  uint64_t cursor = 0;
  bool found = false;
  while (cursor < layout->certificate_size) {
    const uint8_t *entry = data + layout->certificate_offset + cursor;
    const uint32_t entry_length = exe_read_le32(entry);
    const uint16_t type = exe_read_le16(entry + 6);
    if (type == EXE_WIN_CERT_TYPE_PKCS_SIGNED_DATA
        && entry_length > EXE_WIN_CERTIFICATE_HEADER_SIZE) {
      const EVP_MD *method = NULL;
      const uint8_t *expected = NULL;
      uint32_t expected_length = 0;
      if (exe_extract_authenticode_digest(
              entry + EXE_WIN_CERTIFICATE_HEADER_SIZE,
              entry_length - EXE_WIN_CERTIFICATE_HEADER_SIZE,
              &method, &expected, &expected_length)) {
        uint8_t observed[EVP_MAX_MD_SIZE];
        uint32_t observed_length = 0;
        found = true;
        if (exe_compute_authenticode_digest(data, length, layout, method,
                                            observed, &observed_length)
            && observed_length == expected_length
            && CRYPTO_memcmp(observed, expected, expected_length) == 0) {
          layout->authenticode_present = true;
          layout->authenticode_matches = true;
          return true;
        }
      }
    }
    cursor = exe_align_up_u64(cursor + entry_length, 8);
  }
  layout->authenticode_present = found;
  layout->authenticode_matches = false;
  return !found;
}

// Validate a complete PE image. A structurally coherent truncated or
// fragmented image is PARTIAL; contradictory header data is INVALID.
//
static inline ExeParseResult exe_parse_image_with_evidence(
    const uint8_t *data, uint64_t length, ExeLayout *layout,
    ExeOrderEvidence *evidence) {
  if (!exe_parse_headers(data, length, layout)) {
    return EXE_PARSE_INVALID;
  }
  if (layout->described_extent == 0) {
    return EXE_PARSE_INVALID;
  }
  if (!exe_resolve_coff_string_table_extent(data, length, layout)) {
    return EXE_PARSE_PARTIAL;
  }
  if (length < layout->described_extent) {
    exe_set_failure(layout, length);
    return EXE_PARSE_PARTIAL;
  }
  if (!exe_validate_coff_symbol_table(data, length, layout, evidence)
      || !exe_validate_directories(data, length, layout, evidence)
      || !exe_validate_certificate_table(data, length, layout)
      || !exe_validate_deep_directories(data, length, layout, evidence)) {
    return EXE_PARSE_PARTIAL;
  }

  if (layout->checksum_present) {
    layout->checksum_matches =
        exe_compute_checksum(data, layout->described_extent,
                             layout->checksum_offset)
        == layout->stored_checksum;
    if (!layout->checksum_matches) {
      exe_set_failure(layout, layout->size_of_headers);
      return EXE_PARSE_PARTIAL;
    }
  }
  if (!exe_validate_authenticode(data, layout->described_extent, layout)) {
    exe_set_failure(layout, layout->size_of_headers);
    return EXE_PARSE_PARTIAL;
  }
  exe_collect_control_flow_evidence(data, layout->described_extent, layout,
                                    evidence);
  layout->failure_offset = layout->described_extent;
  return EXE_PARSE_COMPLETE;
}

static inline ExeParseResult exe_parse_image(const uint8_t *data,
                                             uint64_t length,
                                             ExeLayout *layout) {
  return exe_parse_image_with_evidence(data, length, layout, NULL);
}

// Return the unfolded sum of little-endian 16-bit words used by the PE
// checksum. The checksum field is omitted when it falls in this byte range.
static inline uint64_t exe_raw_word_sum(const uint8_t *data,
                                        uint64_t length,
                                        uint64_t logical_offset,
                                        uint32_t checksum_offset) {
  uint64_t sum = 0;
  uint64_t offset = 0;

  while (offset + 1 < length) {
    const uint64_t file_offset = logical_offset + offset;
    if (file_offset != checksum_offset
        && file_offset != (uint64_t)checksum_offset + 2) {
      sum += exe_read_le16(data + offset);
    }
    offset += 2;
  }
  if (offset < length) {
    sum += data[offset];
  }
  return sum;
}

// Fold an unfolded PE word sum with end-around carry.
//
static inline uint32_t exe_fold_word_sum(uint64_t sum) {
  while (sum >> 16) {
    sum = (sum & UINT64_C(0xffff)) + (sum >> 16);
  }
  return (uint32_t)sum;
}

// Convert an unfolded word sum into the stored PE checksum by adding the
// complete file length after carry folding.
//
static inline uint32_t exe_checksum_from_raw_sum(uint64_t sum,
                                                 uint64_t length) {
  sum = exe_fold_word_sum(sum);
  sum += sum >> 16;
  sum = (sum & UINT64_C(0xffff)) + length;
  return (uint32_t)sum;
}

// Full-block word sums are independent of a candidate's logical placement.
// Cache them by actual block number so every PE worker shares the same table
// and blockmap coverage changes do not invalidate completed entries.
static inline bool exe_prepare_block_sum_cache(void) {
  FileMirror *filemirror = scalpel_state.filemirror;
  const uint32_t blocksize = scalpel_state.blocksize;
  if (!filemirror || blocksize == 0 || blocksize % 2 != 0) {
    return false;
  }

  MUTEX_ERROR_CHECK(pthread_mutex_lock(&exe_block_sum_cache.lock),
                    __LINE__, __FILE__);
  if (exe_block_sum_cache.filemirror != filemirror
      || exe_block_sum_cache.blocksize != blocksize) {
    free(exe_block_sum_cache.encoded_sums);
    exe_block_sum_cache.encoded_sums = NULL;
    exe_block_sum_cache.filemirror = filemirror;
    exe_block_sum_cache.blocksize = blocksize;
    exe_block_sum_cache.block_count =
        CEILDIV(filemirror_filesize(filemirror), blocksize);
    if (exe_block_sum_cache.block_count != 0) {
      exe_block_sum_cache.encoded_sums = (_Atomic uint64_t *)calloc(
          exe_block_sum_cache.block_count,
          sizeof(*exe_block_sum_cache.encoded_sums));
      check_memory_allocation(exe_block_sum_cache.encoded_sums, __LINE__,
                              __FILE__, "EXE block checksum cache");
    }
  }
  const bool ready = exe_block_sum_cache.encoded_sums != NULL;
  MUTEX_ERROR_CHECK(pthread_mutex_unlock(&exe_block_sum_cache.lock),
                    __LINE__, __FILE__);
  return ready;
}

// Return the cached checksum contribution for one complete block. Selection
// scans require an uncovered block; baseline diagnostics can read an existing
// mapping regardless of concurrent coverage changes.
//
static inline bool exe_get_full_block_sum(int64_t apparent_block,
                                          uint64_t *sum,
                                          bool uncovered_only) {
  if (!sum || apparent_block < 0) {
    return false;
  }
  const int64_t actual_block = filemirror_actual_blocknumber(
      scalpel_state.filemirror, apparent_block);
  if (actual_block < 0
      || (uint64_t)actual_block >= exe_block_sum_cache.block_count
      || (uncovered_only
          && filemirror_actual_block_covered(scalpel_state.filemirror,
                                             actual_block))) {
    return false;
  }

  _Atomic uint64_t *entry =
      &exe_block_sum_cache.encoded_sums[actual_block];
  uint64_t encoded = atomic_load_explicit(entry, memory_order_acquire);
  if (encoded != 0) {
    *sum = encoded - 1;
    return true;
  }

  uint64_t length = 0;
  const uint8_t *data = (const uint8_t *)filemirror_actual_block_data_pointer(
      scalpel_state.filemirror, actual_block, &length);
  if (!data || length != scalpel_state.blocksize) {
    return false;
  }
  const uint64_t observed = exe_raw_word_sum(data, length, 0, UINT32_MAX);
  uint64_t expected = 0;
  encoded = observed + 1;
  if (!atomic_compare_exchange_strong_explicit(
          entry, &expected, encoded, memory_order_release,
          memory_order_acquire)) {
    encoded = expected;
  }
  *sum = encoded - 1;
  return true;
}

// Return one block's checksum contribution at a specific logical slot. The
// partial final block and checksum-containing block require direct reads.
//
static inline bool exe_get_slot_sum(int64_t apparent_block,
                                    uint64_t slot,
                                    const ExeLayout *layout,
                                    uint64_t *sum,
                                    bool uncovered_only) {
  if (!layout || !sum || apparent_block < 0) {
    return false;
  }
  const uint64_t blocksize = scalpel_state.blocksize;
  const uint64_t logical_offset = slot * blocksize;
  if (logical_offset >= layout->described_extent) {
    return false;
  }
  uint64_t length = layout->described_extent - logical_offset;
  if (length > blocksize) {
    length = blocksize;
  }

  const bool contains_checksum =
      layout->checksum_offset >= logical_offset
      && layout->checksum_offset < logical_offset + length;
  if (length == blocksize && !contains_checksum) {
    return exe_get_full_block_sum(apparent_block, sum, uncovered_only);
  }

  const int64_t actual_block = filemirror_actual_blocknumber(
      scalpel_state.filemirror, apparent_block);
  if (actual_block < 0
      || (uncovered_only
          && filemirror_actual_block_covered(scalpel_state.filemirror,
                                             actual_block))) {
    return false;
  }
  uint64_t available = 0;
  const uint8_t *data = (const uint8_t *)filemirror_actual_block_data_pointer(
      scalpel_state.filemirror, actual_block, &available);
  if (!data || available < length) {
    return false;
  }
  *sum = exe_raw_word_sum(data, length, logical_offset,
                          layout->checksum_offset);
  return true;
}

// Sum every block in a proposed PE mapping and optionally retain the
// per-logical-slot contributions for incremental recovery searches.
//
static inline bool exe_mapping_raw_sum(const int64_t *mapping,
                                       uint64_t total_blocks,
                                       const ExeLayout *layout,
                                       uint64_t *slot_sums,
                                       uint64_t *sum,
                                       bool uncovered_only) {
  if (!mapping || !layout || !sum) {
    return false;
  }
  uint64_t total = 0;
  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    uint64_t block_sum = 0;
    if (!exe_get_slot_sum(mapping[slot], slot, layout, &block_sum,
                          uncovered_only)) {
      return false;
    }
    if (slot_sums) {
      slot_sums[slot] = block_sum;
    }
    total += block_sum;
  }
  *sum = total;
  return true;
}

// Materialize the described PE extent from a logical-to-apparent block map.
//
static inline bool exe_materialize_mapping(const int64_t *mapping,
                                           uint64_t total_blocks,
                                           const ExeLayout *layout,
                                           uint8_t *data,
                                           bool uncovered_only) {
  if (!mapping || !layout || !data) {
    return false;
  }
  const uint64_t blocksize = scalpel_state.blocksize;
  uint64_t copied = 0;
  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    const int64_t actual_block = filemirror_actual_blocknumber(
        scalpel_state.filemirror, mapping[slot]);
    if (actual_block < 0
        || (uncovered_only
            && filemirror_actual_block_covered(scalpel_state.filemirror,
                                               actual_block))) {
      return false;
    }
    uint64_t available = 0;
    const uint8_t *source =
        (const uint8_t *)filemirror_actual_block_data_pointer(
            scalpel_state.filemirror, actual_block, &available);
    uint64_t length = layout->described_extent - copied;
    if (length > blocksize) {
      length = blocksize;
    }
    if (!source || available < length) {
      return false;
    }
    memcpy(data + copied, source, (size_t)length);
    copied += length;
  }
  return copied == layout->described_extent;
}

// Parse a materialized mapping and classify the strongest available proof of
// its logical block order. Embedded PE headers are allowed in resources and
// other data; they do not establish or disprove ownership of a source run.
//
static inline ExeMappingResult exe_mapping_validates(
    const int64_t *mapping, uint64_t total_blocks, const ExeLayout *layout,
    uint8_t *data, uint64_t order_offset, uint64_t order_length,
    ExeOrderEvidence *evidence, bool uncovered_only) {
  if (evidence) {
    exe_order_evidence_initialize(evidence, order_offset, order_length);
  }
  if (!exe_materialize_mapping(mapping, total_blocks, layout, data,
                               uncovered_only)) {
    return EXE_MAPPING_INVALID;
  }
  ExeLayout observed;
  if (exe_parse_image_with_evidence(data, layout->described_extent, &observed,
                                    evidence)
      != EXE_PARSE_COMPLETE
      || observed.described_extent != layout->described_extent) {
    return EXE_MAPPING_INVALID;
  }
  if ((observed.authenticode_matches
       && (order_length == 0
           || exe_authenticode_region_covered(
               &observed, order_offset, order_length)))
      || (evidence && evidence->cryptographic_regions != 0)) {
    return EXE_MAPPING_CRYPTOGRAPHIC;
  }
  if (order_length == 0) {
    return EXE_MAPPING_COMPLETE;
  }
  if (exe_order_evidence_sufficient(evidence)) {
    return EXE_MAPPING_ORDER_PROVEN;
  }
  return EXE_MAPPING_COMPLETE;
}

// Structural evidence justifies replacing a logical region only when the
// unchanged baseline lacks sufficient evidence or the replacement is no
// weaker in every order-sensitive category and strictly stronger in at least
// one. This prevents unrelated evidence elsewhere in the run from vetoing a
// genuine repair without allowing a candidate to discard useful baseline
// structure.
//
static inline bool exe_order_evidence_repairs_baseline(
    const int64_t *baseline_mapping, uint64_t total_blocks,
    const ExeLayout *layout, uint8_t *data, uint64_t order_offset,
    uint64_t order_length, const ExeOrderEvidence *candidate_evidence) {
  ExeOrderEvidence baseline_evidence;
  const ExeMappingResult baseline_result = exe_mapping_validates(
      baseline_mapping, total_blocks, layout, data, order_offset,
      order_length, &baseline_evidence, false);

  // A fragmented baseline normally fails its checksum before control-flow
  // relationships are collected. Those relationships still prove that an
  // unchanged executable region is already in its proper logical position.
  if (baseline_result == EXE_MAPPING_INVALID
      && baseline_evidence.anchor_count != 0) {
    ExeLayout baseline_layout;
    if (exe_parse_headers(data, layout->described_extent, &baseline_layout)
        && baseline_layout.described_extent == layout->described_extent) {
      exe_collect_control_flow_evidence(
          data, layout->described_extent, &baseline_layout,
          &baseline_evidence);
    }
  }
  bool repairs_baseline =
      !exe_order_evidence_sufficient(&baseline_evidence);
  if (!repairs_baseline && candidate_evidence) {
    const uint64_t candidate_crossing =
        (uint64_t)candidate_evidence->cross_references
        + candidate_evidence->validated_target_references;
    const uint64_t baseline_crossing =
        (uint64_t)baseline_evidence.cross_references
        + baseline_evidence.validated_target_references;
    const bool no_weaker =
        candidate_crossing >= baseline_crossing
        && candidate_evidence->relocation_values
               >= baseline_evidence.relocation_values
        && candidate_evidence->control_flow_references
               >= baseline_evidence.control_flow_references;
    const bool strictly_stronger =
        candidate_crossing > baseline_crossing
        || candidate_evidence->relocation_values
               > baseline_evidence.relocation_values
        || candidate_evidence->control_flow_references
               > baseline_evidence.control_flow_references;
    repairs_baseline = no_weaker && strictly_stronger;
  }
  exe_order_evidence_destroy(&baseline_evidence);
  return repairs_baseline;
}

// Retain the strongest unsigned mapping and the strongest competing evidence.
// The strongest evidence category avoids counting the same reference through
// multiple related structural tests.
//
static inline void exe_accumulate_ordered_mapping(
    ExeRecoveryAccumulator *accumulator, const int64_t *mapping,
    const ExeOrderEvidence *evidence) {
  if (!accumulator || !accumulator->mapping || !mapping
      || !evidence || accumulator->total_blocks == 0) {
    return;
  }
  uint64_t strength = evidence->cross_references;
  if (evidence->validated_target_references > strength) {
    strength = evidence->validated_target_references;
  }
  if (evidence->relocation_values > strength) {
    strength = evidence->relocation_values;
  }
  if (evidence->control_flow_references > strength) {
    strength = evidence->control_flow_references;
  }
  if (accumulator->qualified_mappings == 0) {
    memcpy(accumulator->mapping, mapping,
           accumulator->total_blocks * sizeof(*mapping));
    accumulator->qualified_mappings = 1;
    accumulator->strongest_order_evidence = strength;
    accumulator->second_order_evidence = 0;
    accumulator->ambiguous = false;
    return;
  }
  if (memcmp(accumulator->mapping, mapping,
             accumulator->total_blocks * sizeof(*mapping)) == 0) {
    if (strength > accumulator->strongest_order_evidence) {
      accumulator->strongest_order_evidence = strength;
      accumulator->ambiguous =
          !exe_ordered_mapping_is_decisive(accumulator);
    }
    return;
  }
  if (accumulator->qualified_mappings != UINT64_MAX) {
    accumulator->qualified_mappings++;
  }
  if (strength > accumulator->strongest_order_evidence) {
    if (accumulator->strongest_order_evidence
        > accumulator->second_order_evidence) {
      accumulator->second_order_evidence =
          accumulator->strongest_order_evidence;
    }
    memcpy(accumulator->mapping, mapping,
           accumulator->total_blocks * sizeof(*mapping));
    accumulator->strongest_order_evidence = strength;
  }
  else if (strength > accumulator->second_order_evidence) {
    accumulator->second_order_evidence = strength;
  }
  accumulator->ambiguous = !exe_ordered_mapping_is_decisive(accumulator);
}

// Accept competing unsigned mappings only when one has an overwhelming margin
// of independent cross-boundary evidence. Close alternatives remain ambiguous.
//
static inline bool exe_ordered_mapping_is_decisive(
    const ExeRecoveryAccumulator *accumulator) {
  if (!accumulator || accumulator->qualified_mappings == 0) {
    return false;
  }
  if (accumulator->qualified_mappings == 1) {
    return true;
  }
  return accumulator->second_order_evidence != 0
         && accumulator->strongest_order_evidence
                >= EXE_ORDER_EVIDENCE_MINIMUM
         && accumulator->second_order_evidence
                <= UINT64_MAX / EXE_ORDER_EVIDENCE_DOMINANCE
         && accumulator->strongest_order_evidence
                >= accumulator->second_order_evidence
                       * EXE_ORDER_EVIDENCE_DOMINANCE;
}

// Retain parser-complete mappings that lack independent ordering proof. A
// lower-tier mapping is usable only when the complete search finds exactly
// one distinct possibility and no structurally ordered mapping.
//
static inline void exe_accumulate_complete_mapping(
    ExeRecoveryAccumulator *accumulator, const int64_t *mapping) {
  if (!accumulator || !accumulator->complete_mapping || !mapping
      || accumulator->total_blocks == 0) {
    return;
  }
  if (accumulator->complete_mappings == 0) {
    memcpy(accumulator->complete_mapping, mapping,
           accumulator->total_blocks * sizeof(*mapping));
    accumulator->complete_mappings = 1;
    accumulator->complete_ambiguous = false;
    return;
  }
  if (memcmp(accumulator->complete_mapping, mapping,
             accumulator->total_blocks * sizeof(*mapping)) == 0) {
    return;
  }
  if (accumulator->complete_mappings != UINT64_MAX) {
    accumulator->complete_mappings++;
  }
  accumulator->complete_ambiguous = true;
}

// Track parser-complete mappings formed by one physical gap independently
// from mappings that reorder blocks. Physical order is useful evidence when
// the PE contains no internal references through the reconstructed seam.
//
static inline void exe_accumulate_gap_mapping(
    ExeRecoveryAccumulator *accumulator, const int64_t *mapping) {
  if (!accumulator || !accumulator->gap_mapping || !mapping
      || accumulator->total_blocks == 0) {
    return;
  }
  if (accumulator->gap_mappings == 0) {
    memcpy(accumulator->gap_mapping, mapping,
           accumulator->total_blocks * sizeof(*mapping));
    accumulator->gap_mappings = 1;
    accumulator->gap_ambiguous = false;
    return;
  }
  if (memcmp(accumulator->gap_mapping, mapping,
             accumulator->total_blocks * sizeof(*mapping)) == 0) {
    return;
  }
  if (accumulator->gap_mappings != UINT64_MAX) {
    accumulator->gap_mappings++;
  }
  accumulator->gap_ambiguous = true;
}

// Install an exact recovered mapping in the candidate blockvector.
//
static inline void exe_commit_mapping(CarveInfo *candidate,
                                      const int64_t *mapping,
                                      uint64_t total_blocks,
                                      const ExeLayout *layout) {
  resize_blockvector(candidate->b, total_blocks);
  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    blockvector_set_apparent_blocknumber(candidate->b, slot, mapping[slot]);
  }
  normalize_blockvector(candidate->b);
  blockvector_set_data_length(candidate->b, layout->described_extent);
  inflate_blockvector(candidate->b);
  candidate->best_validates_to = layout->described_extent - 1;
  candidate->no_initial_block_extension = false;
}

// Publish a complete PE mapping without ending the active search. This preserves a strong result
// while a later fragmentation model is still allowed to challenge it.
//
static inline bool exe_write_mapping_hypothesis(
    CarveInfo *candidate, const int64_t *mapping,
    uint64_t total_blocks, const ExeLayout *layout) {
  if (!candidate || !candidate->b || !mapping || !layout) {
    return false;
  }

  BlockVector *parent_blockvector = candidate->b;
  BlockVector *hypothesis = NULL;
  const CarveInfoFlavor parent_flavor = candidate->flavor;
  const uint64_t parent_validates_to = candidate->best_validates_to;
  const bool parent_no_initial_extension =
      candidate->no_initial_block_extension;

  clone_blockvector(parent_blockvector, &hypothesis, true);
  candidate->b = hypothesis;
  exe_commit_mapping(candidate, mapping, total_blocks, layout);
  candidate->flavor = PROMISING;
  CarveInfo *preserved_candidate = candidate;
  write_candidate(&preserved_candidate, true);
  free_blockvector(&candidate->b);
  candidate->b = parent_blockvector;
  candidate->flavor = parent_flavor;
  candidate->best_validates_to = parent_validates_to;
  candidate->no_initial_block_extension = parent_no_initial_extension;
  return true;
}

// Initialize or validate the cursor shared by indexed displaced-run searches.
static inline void exe_run_progress_reset(ExeRunProgress *progress) {
  *progress = (ExeRunProgress){.entry = EXE_ZERO_RESUME_ENTRY_NONE};
}

static inline bool exe_run_progress_valid(const ExeRunProgress *progress) {
  return progress->phase <= EXE_ZERO_RESUME_OOO_FINAL
      && (progress->entry == EXE_ZERO_RESUME_ENTRY_NONE
          || (progress->entry < EXE_SOURCE_INDEX_CHUNK_WIDTH
              && (progress->phase == EXE_ZERO_RESUME_PAIR
                  || progress->phase == EXE_ZERO_RESUME_OOO_MAIN)));
}

// Identify the apparent-to-actual mapping used by saved positional cursors.
// Only block numbers are read; the image data is not hashed. The apparent
// mapping is immutable while reassembly threads are active.
static inline XXH128_hash_t exe_reassembly_view_hash(void) {
  XXH3_state_t hash;
  XXH3_128bits_reset(&hash);
  const uint64_t count =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  int64_t blocks[256];
  for (uint64_t first = 0; first < count;) {
    uint64_t length = count - first;
    if (length > sizeof(blocks) / sizeof(blocks[0])) {
      length = sizeof(blocks) / sizeof(blocks[0]);
    }
    for (uint64_t offset = 0; offset < length; offset++) {
      blocks[offset] = filemirror_actual_blocknumber(
          scalpel_state.filemirror, (int64_t)(first + offset));
    }
    XXH3_128bits_update(&hash, blocks, (size_t)length * sizeof(blocks[0]));
    first += length;
  }
  return XXH3_128bits_digest(&hash);
}

// Periodically honor kill and checkpoint requests during whole-image scans.
// The checkpoint helper owns requeuing when it reports that work must stop.
//
static inline bool exe_reassembly_poll(ThreadWork *work,
                                       CarveInfo **candidate,
                                       uuid_string_t uuidp,
                                       uuid_string_t uuidc,
                                       uint64_t *iterations) {
  (*iterations)++;
  if (*iterations % EXE_REASSEMBLY_POLL_INTERVAL != 0) {
    return false;
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

// Search for MZ signatures and report only those followed by coherent PE
// headers, reducing candidates produced by incidental DOS signatures.
//
static inline char *exe_header_discovery(char *base, uint64_t offset,
                                         uint64_t remaining, char **matchpos,
                                         uint32_t *matchlen,
                                         uint32_t blocksize) {
  (void)blocksize;
  if (!base || !matchpos || !matchlen) {
    return NULL;
  }
  *matchpos = NULL;
  *matchlen = 2;
  if (remaining < EXE_DOS_HEADER_SIZE) {
    return NULL;
  }

  char signature[2] = {'M', 'Z'};
  size_t table[UCHAR_MAX + 1];
  init_bm_table(signature, table, sizeof(signature), true);
  char *region = base + offset;
  char *candidate = find_binary_string(signature, sizeof(signature), region,
                                       remaining, table, true);
  while (candidate) {
    const uint64_t consumed = (uint64_t)(candidate - region);
    ExeLayout layout;
    if (exe_parse_headers((const uint8_t *)candidate,
                          remaining - consumed, &layout)) {
      *matchpos = candidate;
      return NULL;
    }
    if (consumed + 1 >= remaining) {
      break;
    }
    candidate = find_binary_string(signature, sizeof(signature), candidate + 1,
                                   remaining - consumed - 1, table, true);
  }
  return NULL;
}

// Classify a candidate as complete, structurally promising, or invalid and
// report the strongest inclusive byte offset supported by the parser. During
// fragmented recovery, only Authenticode can independently authenticate a
// complete PE mapping; structurally complete unsigned files remain promising.
//
static inline void exe_file_validate(char *data, uint64_t length,
                                     bool *validates,
                                     uint64_t *validates_to,
                                     bool *promising, uint32_t needleidx,
                                     uint32_t blocksize,
                                     void *carvehashkey) {
  (void)needleidx;
  (void)blocksize;
  (void)carvehashkey;
  if (!validates || !validates_to || !promising) {
    return;
  }
  *validates = false;
  *validates_to = 0;
  *promising = false;

  ExeLayout layout;
  const ExeParseResult result = exe_parse_image((const uint8_t *)data,
                                                length, &layout);
  if (result == EXE_PARSE_INVALID) {
    return;
  }
  *promising = true;
  if (layout.failure_offset == UINT64_MAX || layout.failure_offset == 0) {
    *validates_to = EXE_DOS_HEADER_SIZE - 1;
  }
  else {
    *validates_to = layout.failure_offset - 1;
  }
  if (layout.size_of_headers > 0 && layout.size_of_headers <= length
      && *validates_to < layout.size_of_headers - 1) {
    *validates_to = layout.size_of_headers - 1;
  }
  if (result == EXE_PARSE_COMPLETE) {
    *validates_to = layout.described_extent - 1;
    if (scalpel_state.no_defrag || layout.authenticode_matches) {
      *validates = true;
      *promising = false;
    }
  }
}

// Recover a PE by resolving repeated zero-filled damage first, then searching
// the general one-gap, one-displaced-run, and combined models. PE checksums
// filter candidates. Displaced runs require cryptographic proof from
// Authenticode or a unique mapping supported by independent structural
// ordering evidence.
//
static inline void exe_reassembly(ThreadWork *work, CarveInfo **candidate,
                                  uuid_string_t uuidp,
                                  uuid_string_t uuidc) {
  if (!work || !candidate || !*candidate || !(*candidate)->b) {
    return;
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout,
                 "Reassembly thread #%d starting PE candidate %p UUIDs\n"
                 "%s / %s.\n",
                 work->id, (*candidate)->b, uuidp, uuidc);
  }

  normalize_blockvector((*candidate)->b);
  if (blockvector_get_num_blocks((*candidate)->b) == 0
      || blockvector_get_apparent_blocknumber((*candidate)->b, 0) < 0) {
    destroy_candidate(candidate);
    return;
  }
  inflate_blockvector((*candidate)->b);

  ExeLayout layout;
  if (!exe_parse_headers(
          (const uint8_t *)blockvector_get_data_pointer((*candidate)->b),
          blockvector_get_data_length((*candidate)->b), &layout)
      || layout.described_extent == 0
      || !exe_prepare_block_sum_cache()) {
    if (scalpel_state.write_promising) {
      (*candidate)->flavor = PROMISING;
      write_candidate(candidate, false);
    }
    else {
      destroy_candidate(candidate);
    }
    return;
  }

  const uint64_t maximum_size =
      scalpel_state.search_specs[(*candidate)->needleidx].MAXIMUMSIZE;
  const uint64_t blocksize = scalpel_state.blocksize;
  uint64_t header_blocks = CEILDIV(layout.size_of_headers, blocksize);
  if (header_blocks == 0) {
    header_blocks = 1;
  }

  const int64_t start =
      blockvector_get_apparent_blocknumber((*candidate)->b, 0);
  const uint64_t apparent_blocks =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  ExeCarveState *state = (ExeCarveState *)carve_get_state(
      (*candidate)->carvehashkey);
  bool same_view = true;
  if (exe_carve_state_valid(state) && state->view_initialized) {
    const XXH128_hash_t view_hash = exe_reassembly_view_hash();
    same_view = state->view_hash_low == view_hash.low64
        && state->view_hash_high == view_hash.high64;
  }
  if (!exe_carve_state_valid(state) || !same_view
      || state->start_block != start
      || (layout.coff_string_table_size != 0
          && state->coff.string_size != 0
          && layout.coff_string_table_size != state->coff.string_size)) {
    exe_free_carve_state((void **)&state);
  }
  uint64_t iterations = 0;
  bool extent_resolution_stopped = false;
  if (layout.coff_symbol_count != 0
      && layout.coff_string_table_size == 0) {
    const uint64_t minimum_blocks = CEILDIV(layout.described_extent, blocksize);
    if (!state && layout.described_extent <= maximum_size
        && start >= 0 && (uint64_t)start < apparent_blocks
        && minimum_blocks <= apparent_blocks - (uint64_t)start) {
      state = exe_carve_state_create(
          minimum_blocks, layout.described_extent, start);
    }
    if (!state || !exe_resolve_fragmented_coff_extent(
            work, candidate, uuidp, uuidc, &layout, start, apparent_blocks,
            header_blocks, maximum_size, &iterations, state,
            &extent_resolution_stopped)) {
      exe_free_carve_state((void **)&state);
      if (extent_resolution_stopped) {
        return;
      }
      if (scalpel_state.write_promising) {
        (*candidate)->flavor = PROMISING;
        write_candidate(candidate, false);
      }
      else {
        destroy_candidate(candidate);
      }
      return;
    }
  }

  const uint64_t total_blocks = CEILDIV(layout.described_extent, blocksize);
  if (layout.described_extent > maximum_size
      || header_blocks >= total_blocks) {
    exe_free_carve_state((void **)&state);
    if (scalpel_state.write_promising) {
      (*candidate)->flavor = PROMISING;
      write_candidate(candidate, false);
    }
    else {
      destroy_candidate(candidate);
    }
    return;
  }
  if (start < 0 || (uint64_t)start >= apparent_blocks
      || total_blocks > apparent_blocks - (uint64_t)start) {
    exe_free_carve_state((void **)&state);
    if (scalpel_state.write_promising) {
      (*candidate)->flavor = PROMISING;
      write_candidate(candidate, false);
    }
    else {
      destroy_candidate(candidate);
    }
    return;
  }

  if (!state
      || state->total_blocks != total_blocks
      || state->described_extent != layout.described_extent) {
    // Resolving the string table can enlarge the mapping arrays. Preserve
    // the completed extent search while allocating them for the full file.
    const ExeCoffProgress coff = state ? state->coff : (ExeCoffProgress){0};
    exe_free_carve_state((void **)&state);
    state = exe_carve_state_create(
        total_blocks, layout.described_extent, start);
    if (state) {
      state->coff = coff;
    }
  }
  if (!state) {
    if (scalpel_state.write_promising) {
      (*candidate)->flavor = PROMISING;
      write_candidate(candidate, false);
    }
    else {
      destroy_candidate(candidate);
    }
    return;
  }

  int64_t *baseline_mapping = (int64_t *)malloc(
      total_blocks * sizeof(*baseline_mapping));
  int64_t *solution_mapping = (int64_t *)malloc(
      total_blocks * sizeof(*solution_mapping));
  int64_t *ordered_mapping = (int64_t *)calloc(
      total_blocks, sizeof(*ordered_mapping));
  int64_t *gap_mapping = (int64_t *)calloc(
      total_blocks, sizeof(*gap_mapping));
  int64_t *complete_mapping = (int64_t *)calloc(
      total_blocks, sizeof(*complete_mapping));
  int64_t *published_mapping = (int64_t *)calloc(
      total_blocks, sizeof(*published_mapping));
  uint64_t *baseline_sums = (uint64_t *)malloc(
      total_blocks * sizeof(*baseline_sums));
  uint8_t *trial_data = (uint8_t *)malloc((size_t)layout.described_extent);
  check_memory_allocation(baseline_mapping, __LINE__, __FILE__,
                          "EXE baseline mapping");
  check_memory_allocation(solution_mapping, __LINE__, __FILE__,
                          "EXE solution mapping");
  check_memory_allocation(ordered_mapping, __LINE__, __FILE__,
                          "EXE evidenced mapping");
  check_memory_allocation(gap_mapping, __LINE__, __FILE__,
                          "EXE gap mapping");
  check_memory_allocation(complete_mapping, __LINE__, __FILE__,
                          "EXE complete mapping");
  check_memory_allocation(published_mapping, __LINE__, __FILE__,
                          "EXE published mapping");
  check_memory_allocation(baseline_sums, __LINE__, __FILE__,
                          "EXE baseline sums");
  check_memory_allocation(trial_data, __LINE__, __FILE__,
                          "EXE trial data");

  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    baseline_mapping[slot] = start + (int64_t)slot;
  }
  uint64_t baseline_sum = 0;
  ExeRecoveryResult result = EXE_RECOVERY_NO_MATCH;
  ExeRecoveryAccumulator accumulator = {
      .mapping = ordered_mapping,
      .gap_mapping = gap_mapping,
      .complete_mapping = complete_mapping,
      .total_blocks = total_blocks,
      .qualified_mappings = 0,
      .gap_mappings = 0,
      .complete_mappings = 0,
      .strongest_order_evidence = 0,
      .second_order_evidence = 0,
      .ambiguous = false,
      .gap_ambiguous = false,
      .complete_ambiguous = false,
      .require_baseline_repair = false
  };
  const bool baseline_ready = exe_mapping_raw_sum(
      baseline_mapping, total_blocks, &layout, baseline_sums, &baseline_sum,
      false);
  const bool baseline_checksum_matches =
      baseline_ready
      && (!layout.checksum_present
          || exe_checksum_from_raw_sum(baseline_sum,
                                       layout.described_extent)
                 == layout.stored_checksum);
  const bool baseline_materialized =
      baseline_checksum_matches
      && exe_materialize_mapping(baseline_mapping, total_blocks, &layout,
                                 trial_data, false);
  ExeParseResult baseline_parse_result = EXE_PARSE_INVALID;
  bool baseline_complete = false;
  bool baseline_authenticated = false;
  if (baseline_materialized) {
    ExeOrderEvidence baseline_evidence;
    exe_order_evidence_initialize(&baseline_evidence, 0,
                                  layout.described_extent);
    ExeLayout observed;
    baseline_parse_result = exe_parse_image_with_evidence(
        trial_data, layout.described_extent, &observed, &baseline_evidence);
    if (baseline_parse_result == EXE_PARSE_COMPLETE
        && observed.described_extent == layout.described_extent) {
      baseline_complete = true;
      baseline_authenticated = observed.authenticode_matches;
      const bool disconnected_code =
          exe_order_evidence_disconnected_code_range(
              &observed, &baseline_evidence,
              &accumulator.baseline_repair_first,
              &accumulator.baseline_repair_last);
      accumulator.require_baseline_repair = disconnected_code;
      if ((observed.authenticode_matches || !disconnected_code)
          && exe_materialize_mapping(baseline_mapping, total_blocks, &layout,
                                     trial_data, true)) {
        memcpy(solution_mapping, baseline_mapping,
               total_blocks * sizeof(*solution_mapping));
        result = EXE_RECOVERY_MATCH;
      }
      else if (scalpel_state.mode_verbose) {
        lock_fprintf(
            stdout,
            "PE baseline at block %" PRId64
            " has disconnected executable data; checking displaced "
            "alternatives.\n",
            start);
      }
    }
    exe_order_evidence_destroy(&baseline_evidence);
  }
  if (scalpel_state.mode_verbose) {
    lock_fprintf(
        stdout,
        "PE baseline diagnostic: start=%" PRId64
        " ready=%u checksum=%u materialized=%u parse=%u complete=%u.\n",
        start, baseline_ready, baseline_checksum_matches,
        baseline_materialized, baseline_parse_result, baseline_complete);
  }
  bool mapping_published = false;
  const bool resume_general = state->search_phase != EXE_SEARCH_INITIAL;
  if (resume_general || state->hints.gaps_ready
      || state->hints.gap_scan.next_offset != 0) {
    exe_carve_state_load(state, &accumulator, NULL,
                         published_mapping, &mapping_published);
  }
  ExeReassemblyContext context = {
      .work = work,
      .candidate = candidate,
      .uuidp = uuidp,
      .uuidc = uuidc,
      .accumulator = &accumulator,
      .published_mapping = published_mapping,
      .mapping_published = &mapping_published,
      .iterations = &iterations,
      .state = state,
      .run_progress = &state->general_run,
      .layout = &layout,
      .baseline_mapping = baseline_mapping,
      .total_blocks = total_blocks,
      .header_blocks = header_blocks,
      .start = start,
      .trial_data = trial_data,
      .solution_mapping = solution_mapping
  };
  const uint64_t max_gap = apparent_blocks - (uint64_t)start - total_blocks;
  const uint64_t max_run = total_blocks - header_blocks;
  const uint64_t max_width = max_gap > max_run ? max_gap : max_run;
  const bool can_reorder = true;

  // Relocations can expose displaced bytes even when another reference reaches
  // the same block. Keep an otherwise usable baseline if no stronger repair
  // is found; a matching Authenticode digest needs no speculative repair.
  if (baseline_complete && !baseline_authenticated && !resume_general) {
    const ExeRecoveryResult baseline_result = result;
    result = exe_try_relocation_blocks(&context);
    if (result == EXE_RECOVERY_PROMISING_MATCH
        && baseline_result == EXE_RECOVERY_MATCH
        && scalpel_state.write_promising) {
      // Structural improvement is not cryptographic proof. Retain the usable
      // original as well, rather than replacing a possibly legitimate null.
      exe_write_mapping_hypothesis(
          *context.candidate, baseline_mapping, total_blocks, &layout);
    }
    if (result == EXE_RECOVERY_NO_MATCH) {
      result = baseline_result;
      if (result == EXE_RECOVERY_MATCH) {
        memcpy(solution_mapping, baseline_mapping,
               total_blocks * sizeof(*solution_mapping));
      }
    }
  }

  // Try independently indicated gaps before the combinatorial searches.
  // A checksum or Authenticode match returns immediately; unsigned structural
  // matches remain PROMISING and therefore cannot reserve blocks globally.
  if (baseline_ready && !baseline_complete && max_gap != 0 && !resume_general) {
    ExeHintProgress *progress = &state->hints;
    ExeGapHint *hints = progress->gaps;
    if (!exe_confidence_gap_hints(&context, max_gap)) {
      result = EXE_RECOVERY_STOPPED;
    }
    const uint32_t hinted_count = progress->gap_count;

    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout,
                   "PE confidence gap search produced %u hints.\n",
                   hinted_count);
    }

    for (uint32_t index = progress->next_gap;
         result == EXE_RECOVERY_NO_MATCH && index < hinted_count;
         index++) {
      if (scalpel_state.mode_verbose) {
        lock_fprintf(stdout,
                     "PE confidence gap search testing hint %u/%u:"
                     " boundary=%" PRIu64 " gap=%" PRIu64 ".\n",
                     index + 1, hinted_count, hints[index].boundary,
                     hints[index].gap_blocks);
      }
      result = exe_try_gap_hint(
          *candidate, &layout, baseline_mapping, total_blocks, &hints[index],
          trial_data, solution_mapping, &accumulator);
      if (result == EXE_RECOVERY_NO_MATCH) {
        progress->next_gap = index + 1;
        if (exe_reassembly_context_poll(&context)) {
          result = EXE_RECOVERY_STOPPED;
        }
      }
    }
    if (result == EXE_RECOVERY_NO_MATCH && !layout.checksum_present) {
      result = exe_try_preceding_ooo_hints(&context);
    }
    if (result == EXE_RECOVERY_NO_MATCH
        && accumulator.qualified_mappings != 0) {
      memcpy(solution_mapping, accumulator.mapping,
             total_blocks * sizeof(*solution_mapping));
      result = EXE_RECOVERY_PROMISING_MATCH;
    }
    else if (result == EXE_RECOVERY_NO_MATCH
             && accumulator.qualified_mappings == 0
             && accumulator.gap_mappings == 1
             && !accumulator.gap_ambiguous) {
      memcpy(solution_mapping, accumulator.gap_mapping,
             total_blocks * sizeof(*solution_mapping));
      result = EXE_RECOVERY_PROMISING_MATCH;
    }
  }

  // Whole zero runs provide an efficient, exact model for repeated inserted
  // gaps and up to two displaced runs. Complete parsing still determines
  // acceptance, and the exhaustive single-event searches remain available
  // when the zero-run model does not explain the damage.
  if (baseline_ready && result == EXE_RECOVERY_NO_MATCH
      && !baseline_complete && !resume_general) {
    result = exe_try_zero_run_composition(
        work, candidate, uuidp, uuidc, &layout, baseline_mapping,
        total_blocks, header_blocks, trial_data, solution_mapping,
        &accumulator, published_mapping, &mapping_published, &iterations,
        state);
  }
  if (result == EXE_RECOVERY_NO_MATCH
      && state->search_phase == EXE_SEARCH_INITIAL) {
    state->search_phase = EXE_SEARCH_GAP;
  }

  // Complete the simpler one-gap model before considering displaced runs.
  // A unique parser-complete gap mapping preserves physical order and avoids
  // an exhaustive OOO search when no internal relationship crosses the seam.
  if (state->search_phase == EXE_SEARCH_GAP) {
    if (baseline_ready && result == EXE_RECOVERY_NO_MATCH
        && !baseline_complete && max_gap != 0) {
      result = exe_try_gap(
          work, candidate, uuidp, uuidc, &layout, baseline_mapping,
          baseline_sums, total_blocks, header_blocks, 1, max_gap,
          trial_data, solution_mapping, &accumulator, &iterations, &context);
    }
    if (result == EXE_RECOVERY_NO_MATCH
        && accumulator.qualified_mappings == 1 && !accumulator.ambiguous) {
      memcpy(solution_mapping, accumulator.mapping,
             total_blocks * sizeof(*solution_mapping));
      result = EXE_RECOVERY_MATCH;
    }
    else if (result == EXE_RECOVERY_NO_MATCH
             && accumulator.qualified_mappings == 0
             && accumulator.gap_mappings == 1
             && !accumulator.gap_ambiguous) {
      memcpy(solution_mapping, accumulator.gap_mapping,
             total_blocks * sizeof(*solution_mapping));
      result = EXE_RECOVERY_MATCH;
    }
    if (result == EXE_RECOVERY_NO_MATCH) {
      state->search_phase = EXE_SEARCH_COMMON;
      state->search_width = 0;
      state->search_inner = 0;
    }
  }

  // Prioritize common small combinations before either exhaustive search.
  // These probes do not constrain recovery because the complete pure-OOO and
  // combined searches below still visit every supported width.
  static const uint64_t common_gap_widths[] = {1, 2, 4, 8, 16};
  static const uint64_t common_run_widths[] = {2, 1, 4, 8, 16};
  if (baseline_ready && can_reorder && max_gap != 0 && max_run != 0
      && state->search_phase == EXE_SEARCH_COMMON) {
    for (uint64_t gap_index = state->search_width;
         result == EXE_RECOVERY_NO_MATCH
         && gap_index < sizeof(common_gap_widths)
                            / sizeof(common_gap_widths[0]);
         gap_index++) {
      const uint64_t gap_blocks = common_gap_widths[gap_index];

      if (gap_blocks > max_gap) {
        continue;
      }
      for (uint64_t run_index = state->search_inner;
           result == EXE_RECOVERY_NO_MATCH
           && run_index < sizeof(common_run_widths)
                              / sizeof(common_run_widths[0]);
           run_index++) {
        const uint64_t run_blocks = common_run_widths[run_index];

        if (run_blocks > max_run) {
          continue;
        }
        state->search_width = gap_index;
        state->search_inner = run_index;
        result = exe_try_gap_ooo(
            work, candidate, uuidp, uuidc, &layout, baseline_mapping,
            baseline_sums, total_blocks, header_blocks, gap_blocks,
            run_blocks, trial_data, solution_mapping, &accumulator,
            published_mapping, &mapping_published, &iterations, &context);
        if (result == EXE_RECOVERY_NO_MATCH) {
          state->search_inner = run_index + 1;
        }
      }
      if (result == EXE_RECOVERY_NO_MATCH) {
        state->search_width = gap_index + 1;
        state->search_inner = 0;
      }
    }
  }
  if (result == EXE_RECOVERY_NO_MATCH
      && state->search_phase == EXE_SEARCH_COMMON) {
    state->search_phase = EXE_SEARCH_OOO;
    state->search_width = 1;
  }

  // Complete the simpler displaced-run model before combining independent
  // perturbations. This avoids paying for every possible gap boundary when a
  // pure OOO repair already explains the candidate.
  for (uint64_t width = state->search_width;
       baseline_ready && result == EXE_RECOVERY_NO_MATCH
       && state->search_phase == EXE_SEARCH_OOO
       && can_reorder && width <= max_run; width++) {
    if (scalpel_state.mode_verbose && (width == 1 || width % 64 == 0)) {
      lock_fprintf(stdout,
                   "PE reassembly thread #%d testing OOO width "
                   "%" PRIu64 ".\n",
                   work->id, width);
    }

    result = exe_try_ooo_on_mapping(
        work, candidate, uuidp, uuidc, &layout, baseline_mapping,
        baseline_sums, baseline_sum, total_blocks, header_blocks, width,
        start, start + (int64_t)total_blocks - 1, false, NULL, trial_data,
        solution_mapping, &accumulator, published_mapping,
        &mapping_published, &iterations, &context);

    // Do not expand a published unsigned pure-OOO result into the more complex
    // gap model. The publication gate has already required a unique mapping
    // with sufficient ordering evidence, but it remains PROMISING because no
    // unsigned search can provide cryptographic validation. Signed images
    // continue until their Authenticode digest identifies the exact mapping.
    if (result == EXE_RECOVERY_NO_MATCH && layout.certificate_size == 0
        && mapping_published) {
      memcpy(solution_mapping, published_mapping,
             total_blocks * sizeof(*solution_mapping));
      result = EXE_RECOVERY_PROMISING_MATCH;
    }
    if (result == EXE_RECOVERY_NO_MATCH) {
      state->search_width = width + 1;
      if (exe_reassembly_context_poll(&context)) {
        result = EXE_RECOVERY_STOPPED;
      }
    }
  }
  if (result == EXE_RECOVERY_NO_MATCH
      && state->search_phase == EXE_SEARCH_OOO) {
    state->search_phase = EXE_SEARCH_COMBINED;
    state->search_width = 1;
    state->search_inner = 1;
    state->search_edge = 0;
  }

  // Visit combined repairs in increasing perturbation width. Each pair is
  // visited once, with smaller perturbations considered first.
  for (uint64_t width = state->search_width;
       baseline_ready && result == EXE_RECOVERY_NO_MATCH
       && state->search_phase == EXE_SEARCH_COMBINED
       && width <= max_width; width++) {
    if (scalpel_state.mode_verbose && (width == 1 || width % 64 == 0)) {
      lock_fprintf(stdout,
                   "PE reassembly thread #%d testing combined width "
                   "%" PRIu64 ".\n",
                   work->id, width);
    }

    // Test the new outer edge of the (gap width, run width) search square.
    // Each pair is visited once, with smaller perturbations considered first.
    if (can_reorder && width <= max_run && state->search_edge == 0) {
      uint64_t gap_limit = width - 1;
      if (gap_limit > max_gap) {
        gap_limit = max_gap;
      }
      for (uint64_t gap_blocks = state->search_inner;
           result == EXE_RECOVERY_NO_MATCH && gap_blocks <= gap_limit;
           gap_blocks++) {
        result = exe_try_gap_ooo(
            work, candidate, uuidp, uuidc, &layout, baseline_mapping,
            baseline_sums, total_blocks, header_blocks, gap_blocks, width,
            trial_data, solution_mapping, &accumulator, published_mapping,
            &mapping_published, &iterations, &context);
        if (result == EXE_RECOVERY_NO_MATCH) {
          state->search_inner = gap_blocks + 1;
        }
      }
    }
    if (result == EXE_RECOVERY_NO_MATCH && state->search_edge == 0) {
      state->search_edge = 1;
      state->search_inner = 1;
    }
    if (result == EXE_RECOVERY_NO_MATCH && can_reorder
        && width <= max_gap) {
      uint64_t run_limit = width;
      if (run_limit > max_run) {
        run_limit = max_run;
      }
      for (uint64_t run_blocks = state->search_inner;
           result == EXE_RECOVERY_NO_MATCH && run_blocks <= run_limit;
           run_blocks++) {
        result = exe_try_gap_ooo(
            work, candidate, uuidp, uuidc, &layout, baseline_mapping,
            baseline_sums, total_blocks, header_blocks, width, run_blocks,
            trial_data, solution_mapping, &accumulator, published_mapping,
            &mapping_published, &iterations, &context);
        if (result == EXE_RECOVERY_NO_MATCH) {
          state->search_inner = run_blocks + 1;
        }
      }
    }

    // A published unsigned mapping remains PROMISING, but searching larger
    // perturbations cannot strengthen it into a validated result. Complete
    // every model at this width, then retain the last mapping that was
    // decisive enough to publish. Signed images continue until their
    // Authenticode digest identifies the exact mapping.
    if (result == EXE_RECOVERY_NO_MATCH && layout.certificate_size == 0
        && mapping_published) {
      memcpy(solution_mapping, published_mapping,
             total_blocks * sizeof(*solution_mapping));
      result = EXE_RECOVERY_PROMISING_MATCH;
    }
    if (result == EXE_RECOVERY_NO_MATCH) {
      state->search_width = width + 1;
      state->search_inner = 1;
      state->search_edge = 0;
      if (exe_reassembly_context_poll(&context)) {
        result = EXE_RECOVERY_STOPPED;
      }
    }
  }
  if (result == EXE_RECOVERY_NO_MATCH
      && state->search_phase == EXE_SEARCH_COMBINED) {
    state->search_phase = EXE_SEARCH_DONE;
  }

  if (result == EXE_RECOVERY_NO_MATCH
      && exe_ordered_mapping_is_decisive(&accumulator)) {
    memcpy(solution_mapping, accumulator.mapping,
           total_blocks * sizeof(*solution_mapping));
    result = EXE_RECOVERY_MATCH;
  }
  else if (result == EXE_RECOVERY_NO_MATCH
           && accumulator.qualified_mappings == 0
           && accumulator.gap_mappings == 1
           && !accumulator.gap_ambiguous) {
    memcpy(solution_mapping, accumulator.gap_mapping,
           total_blocks * sizeof(*solution_mapping));
    result = EXE_RECOVERY_MATCH;
  }
  else if (result == EXE_RECOVERY_NO_MATCH
           && accumulator.qualified_mappings == 0
           && accumulator.complete_mappings == 1
           && !accumulator.complete_ambiguous) {
    memcpy(solution_mapping, accumulator.complete_mapping,
           total_blocks * sizeof(*solution_mapping));
    result = EXE_RECOVERY_MATCH;
  }

  if (result == EXE_RECOVERY_MATCH) {
    uint64_t changed_blocks = 0;
    uint64_t first_changed = UINT64_MAX;
    for (uint64_t slot = 0; slot < total_blocks; slot++) {
      if (solution_mapping[slot] != baseline_mapping[slot]) {
        if (first_changed == UINT64_MAX) {
          first_changed = slot;
        }
        changed_blocks++;
      }
    }
    if (scalpel_state.mode_verbose) {
      lock_fprintf(
          stdout,
          "PE selected mapping: start=%" PRId64 " changed=%" PRIu64
          " first=%" PRIu64 " source=%" PRId64
          " qualified=%" PRIu64 " evidence=%" PRIu64 "/%" PRIu64
          " ambiguous=%u.\n",
          start, changed_blocks, first_changed,
          first_changed == UINT64_MAX ? -1 : solution_mapping[first_changed],
          accumulator.qualified_mappings,
          accumulator.strongest_order_evidence,
          accumulator.second_order_evidence, accumulator.ambiguous);
    }
    exe_commit_mapping(*candidate, solution_mapping, total_blocks, &layout);
    if (scalpel_state.mode_verbose) {
      ExeLayout committed_layout;
      const ExeParseResult committed_result = exe_parse_image(
          (const uint8_t *)blockvector_get_data_pointer((*candidate)->b),
          blockvector_get_data_length((*candidate)->b), &committed_layout);
      lock_fprintf(
          stdout,
          "PE committed mapping: start=%" PRId64 " parse=%u actual=%" PRId64
          ".\n",
          start, committed_result,
          first_changed == UINT64_MAX
              ? -1
              : blockvector_get_actual_blocknumber((*candidate)->b,
                                                   first_changed));
    }
    uint64_t validates_to = 0;
    if (reassembly_check_validation(work->id, *candidate, &validates_to,
                                    uuidp, uuidc)) {
      lock_fprintf(stdout,
                   "\nThread #%d VALIDATED PE candidate %p UUIDs\n"
                   "%s / %s.\n",
                   work->id, (*candidate)->b, uuidp, uuidc);
      write_candidate(candidate, false);
    }
    else if (scalpel_state.write_promising) {
      (*candidate)->flavor = PROMISING;
      write_candidate(candidate, false);
    }
    else {
      destroy_candidate(candidate);
    }
  }
  else if (result == EXE_RECOVERY_PROMISING_MATCH) {
    exe_commit_mapping(*candidate, solution_mapping, total_blocks, &layout);
    (*candidate)->flavor = PROMISING;
    write_candidate(candidate, false);
  }
  else if (result == EXE_RECOVERY_NO_MATCH) {
    if (scalpel_state.write_promising) {
      (*candidate)->flavor = PROMISING;
      write_candidate(candidate, false);
    }
    else {
      destroy_candidate(candidate);
    }
  }

  free(trial_data);
  free(baseline_sums);
  free(published_mapping);
  free(complete_mapping);
  free(gap_mapping);
  free(ordered_mapping);
  free(solution_mapping);
  free(baseline_mapping);
  exe_free_carve_state((void **)&state);
}

#endif
