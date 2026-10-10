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

#if !defined(SCALPEL_ZIP_H)
#define SCALPEL_ZIP_H

#include "scalpel.h"

#include <archive.h>
#include <archive_entry.h>
#include <bzlib.h>
#include <inttypes.h>
#include <limits.h>
#include <lzma.h>
#include <openssl/evp.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>
#include <zstd.h>

#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

#define ZIP_LOCAL_HEADER_SIGNATURE             UINT32_C(0x04034b50)
#define ZIP_SINGLE_SEGMENT_MARKER              UINT32_C(0x30304b50)
#define ZIP_DATA_DESCRIPTOR_SIGNATURE          UINT32_C(0x08074b50)
#define ZIP_CENTRAL_HEADER_SIGNATURE           UINT32_C(0x02014b50)
#define ZIP_DIGITAL_SIGNATURE                  UINT32_C(0x05054b50)
#define ZIP64_EOCD_SIGNATURE                   UINT32_C(0x06064b50)
#define ZIP64_EOCD_LOCATOR_SIGNATURE           UINT32_C(0x07064b50)
#define ZIP_EOCD_SIGNATURE                     UINT32_C(0x06054b50)
#define ZIP_LOCAL_HEADER_SIZE                  UINT64_C(30)
#define ZIP_CENTRAL_HEADER_SIZE                UINT64_C(46)
#define ZIP_EOCD_SIZE                          UINT64_C(22)
#define ZIP64_EOCD_MINIMUM_SIZE                UINT64_C(56)
#define ZIP64_EOCD_LOCATOR_SIZE                UINT64_C(20)
#define ZIP_EXTRA_ID_ZIP64                     UINT16_C(0x0001)
#define ZIP_EXTRA_ID_UNICODE_PATH              UINT16_C(0x7075)
#define ZIP_EXTRA_ID_AES                       UINT16_C(0x9901)
#define ZIP_FLAG_ENCRYPTED                     UINT16_C(0x0001)
#define ZIP_FLAG_LZMA_EOPM                     UINT16_C(0x0002)
#define ZIP_FLAG_DATA_DESCRIPTOR               UINT16_C(0x0008)
#define ZIP_METHOD_STORED                      UINT16_C(0)
#define ZIP_METHOD_SHRINK                      UINT16_C(1)
#define ZIP_METHOD_IMPLODE                     UINT16_C(6)
#define ZIP_METHOD_DEFLATE                     UINT16_C(8)
#define ZIP_METHOD_DEFLATE64                   UINT16_C(9)
#define ZIP_METHOD_BZIP2                       UINT16_C(12)
#define ZIP_METHOD_LZMA                        UINT16_C(14)
#define ZIP_METHOD_ZSTD                        UINT16_C(93)
#define ZIP_METHOD_XZ                          UINT16_C(95)
#define ZIP_METHOD_AES                         UINT16_C(99)
#define ZIP_UINT16_SENTINEL                    UINT16_C(0xffff)
#define ZIP_UINT32_SENTINEL                    UINT32_C(0xffffffff)
#define ZIP_VERIFY_BUFFER_SIZE                 (64u * 1024u)
#define ZIP_ZSTD_INPUT_SIZE                    (4u * 1024u)
#define ZIP_HELPER_INITIAL_RUN_LIMIT           UINT64_C(8)
#define ZIP_DEFLATE_TARGET_REWIND_BLOCKS        UINT64_C(16)
#define ZIP_DEFLATE_GAP_PROBE_COUNT             (ZIP_DEFLATE_TARGET_REWIND_BLOCKS + 1)
#define ZIP_ZERO_GAP_RUN_LIMIT                  UINT64_C(20)
#define ZIP_SOURCE_CONFIDENCE_SAMPLE_BLOCKS    UINT64_C(8)
#define ZIP_SOURCE_CONFIDENCE_TIERS             8u
#define ZIP_MAPPED_SLOT_DUPLICATE               INT64_C(-3)
#define ZIP_SWAP_SLOT_PER_BLOCK                INT64_C(-2)
#define ZIP_SWAP_SLOT_UNMAPPED                 INT64_C(-1)
#define ZIP_REASSEMBLY_BUFFER_COPIES           UINT64_C(7)
#define ZIP_REASSEMBLY_BLOCK_OVERHEAD          UINT64_C(128)
#define ZIP_REASSEMBLY_MEMORY_DIVISOR          UINT64_C(4)
#define ZIP_REASSEMBLY_FALLBACK_BUDGET         (UINT64_C(512) * 1024 * 1024)
#define ZIP_REASSEMBLY_WAIT_NANOSECONDS        10000000L
#define ZIP_STORED_CRC_INDEX_BUDGET            (UINT64_C(2) * 1024 * 1024)
#define ZIP_ENCRYPTED_ROTATION_WINDOW_BLOCKS   UINT64_C(32)
#define ZIP_ENCRYPTED_ROTATION_REFINE_BLOCKS   UINT64_C(64)
#define ZIP_ENCRYPTED_ROTATION_HYPOTHESIS_LIMIT 4u
#define ZIP_LEGACY_HUFFMAN_SYMBOLS              288u
#define ZIP_LEGACY_HUFFMAN_NODES                (ZIP_LEGACY_HUFFMAN_SYMBOLS * 2u + 1u)
#define ZIP_LEGACY_HUFFMAN_BITS                 16u
#define ZIP_LEGACY_WINDOW_SIZE                  (64u * 1024u)
#define ZIP_SHRINK_DICTIONARY_SIZE              (1u << 13)
#define ZIP_APK_SIGNING_MAGIC                   "APK Sig Block 42"
#define ZIP_APK_SIGNING_MAGIC_SIZE              UINT64_C(16)
#define ZIP_APK_SIGNING_FOOTER_SIZE             UINT64_C(24)
#define ZIP_APK_V2_BLOCK_ID                     UINT32_C(0x7109871a)
#define ZIP_APK_V3_BLOCK_ID                     UINT32_C(0xf05368c0)
#define ZIP_APK_V31_BLOCK_ID                    UINT32_C(0x1b93ad61)
#define ZIP_APK_CHUNK_SIZE                      (UINT64_C(1024) * 1024)
#define ZIP_APK_FAST_RUN_LIMIT                  UINT64_C(2)
#define ZIP_CARVE_STATE_MAGIC                   UINT64_C(0x5a49505343414e31)
#define ZIP_CARVE_STATE_VERSION                 UINT64_C(2)
#define ZIP_SCAN_VALID                         UINT64_C(1)
#define ZIP_SCAN_ENTRY_VALID                   UINT64_C(2)
#define ZIP_SCAN_STRUCTURE                     UINT64_C(4)

typedef struct ZipEntry {
  const uint8_t *name;
  const uint8_t *unicode_name;
  uint64_t local_offset;
  uint64_t observed_local_offset;
  uint64_t compressed_size;
  uint64_t uncompressed_size;
  uint64_t data_offset;
  uint64_t observed_data_offset;
  uint64_t range_end;
  uint32_t crc32;
  uint32_t unicode_name_crc32;
  uint16_t flags;
  uint16_t method;
  uint16_t name_length;
  uint16_t unicode_name_length;
  bool encrypted;
  bool zip64_sizes;
  bool geometry_known;
} ZipEntry;

typedef struct ZipLayout {
  ZipEntry *entries;
  uint64_t entry_count;
  uint64_t physical_gap_slot;
  uint64_t physical_gap_blocks;
  uint64_t central_offset;
  uint64_t observed_central_offset;
  uint64_t central_size;
  uint64_t archive_size;
  uint64_t observed_archive_size;
  uint64_t eocd_offset;
  uint64_t leading_bytes;
  bool zip64;
  bool encrypted;
  bool office_document;
  bool office_spreadsheet;
  bool office_presentation;
  bool displaced_structure;
} ZipLayout;

typedef struct ZipRange {
  uint64_t start;
  uint64_t end;
} ZipRange;

typedef struct ZipStoredCrcSource {
  uint64_t source;
  uint32_t contribution;
} ZipStoredCrcSource;

typedef struct ZipStateEntry {
  uint64_t local_offset;
  uint64_t observed_local_offset;
  uint64_t compressed_size;
  uint64_t uncompressed_size;
  uint64_t data_offset;
  uint64_t range_end;
  uint32_t crc32;
  uint32_t name_crc32;
  uint16_t flags;
  uint16_t method;
  bool encrypted;
  bool geometry_known;
} ZipStateEntry;

typedef enum ZipSeamVariant {
  ZIP_SEAM_NONE = 0,
  ZIP_SEAM_RIGHT_CONTIGUOUS = 1,
  ZIP_SEAM_LEFT_CONTIGUOUS = 2,
  ZIP_SEAM_UNMODIFIED = 3
} ZipSeamVariant;

typedef enum ZipStoredRepairResult {
  ZIP_STORED_REPAIR_NONE = 0,
  ZIP_STORED_REPAIR_SOLVED = 1,
  ZIP_STORED_REPAIR_STOPPED = 2
} ZipStoredRepairResult;

typedef enum ZipGapRepairResult {
  ZIP_GAP_REPAIR_NONE = 0,
  ZIP_GAP_REPAIR_APPLIED = 1,
  ZIP_GAP_REPAIR_STOPPED = 2
} ZipGapRepairResult;

typedef enum ZipMemoryReservationResult {
  ZIP_MEMORY_ACQUIRED = 0,
  ZIP_MEMORY_UNAVAILABLE = 1,
  ZIP_MEMORY_STOPPED = 2
} ZipMemoryReservationResult;

typedef enum ZipInitializationResult {
  ZIP_INITIALIZATION_NO_MATCH = 0,
  ZIP_INITIALIZATION_MATCHED = 1,
  ZIP_INITIALIZATION_RESOURCE_LIMIT = 2,
  ZIP_INITIALIZATION_STOPPED = 3
} ZipInitializationResult;

typedef enum ZipInflateFeedResult {
  ZIP_INFLATE_NEEDS_INPUT = 0,
  ZIP_INFLATE_ENDED = 1,
  ZIP_INFLATE_FAILED = 2
} ZipInflateFeedResult;

typedef struct ZipDeflatePrefix {
  z_stream stream;
  uLong crc;
  uint64_t patch_start;
  uint64_t patch_end;
  bool initialized;
} ZipDeflatePrefix;

typedef struct ZipApkDigestInfo {
  const EVP_MD *digest;
  uint8_t expected_digest[EVP_MAX_MD_SIZE];
  uint64_t signing_block_start;
  uint64_t central_offset;
  uint64_t eocd_offset;
  uint64_t archive_size;
  uint32_t digest_length;
} ZipApkDigestInfo;

typedef struct ZipApkDigestContext {
  ZipApkDigestInfo info;
  EVP_MD_CTX *chunk_context;
  EVP_MD_CTX *top_context;
  uint8_t *chunk_digests;
  uint8_t *chunk_scratch;
  uint64_t section_chunk_first[3];
  uint64_t section_chunk_count[3];
  uint64_t total_chunks;
  bool initialized;
} ZipApkDigestContext;

typedef enum ZipApkDigestProbeResult {
  ZIP_APK_DIGEST_UNAVAILABLE = 0,
  ZIP_APK_DIGEST_MISMATCH = 1,
  ZIP_APK_DIGEST_MATCH = 2
} ZipApkDigestProbeResult;

typedef struct ZipMappedBlock {
  int64_t actual;
  int64_t slot;
} ZipMappedBlock;

typedef struct ZipMappedBlockIndex {
  ZipMappedBlock *entries;
  uint64_t capacity;
} ZipMappedBlockIndex;

typedef struct ZipDestinationScore {
  uint64_t slot;
  uint64_t confidence_sum;
  int minimum_confidence;
  int left_confidence;
  int right_confidence;
} ZipDestinationScore;

typedef struct ZipLegacyBitReader {
  const uint8_t *data;
  uint64_t size;
  uint64_t next_byte;
  uint64_t bits_read;
  uint64_t buffer;
  uint8_t buffered_bits;
} ZipLegacyBitReader;

typedef struct ZipLegacyHuffmanNode {
  int16_t child[2];
  int16_t symbol;
} ZipLegacyHuffmanNode;

typedef struct ZipLegacyHuffman {
  ZipLegacyHuffmanNode nodes[ZIP_LEGACY_HUFFMAN_NODES];
  uint16_t node_count;
} ZipLegacyHuffman;

typedef struct ZipLegacyOutput {
  uint8_t window[ZIP_LEGACY_WINDOW_SIZE];
  uint64_t expected;
  uint64_t produced;
  uint32_t crc;
} ZipLegacyOutput;

typedef enum ZipRepairPhase {
  ZIP_REPAIR_PHASE_NONE = 0,
  ZIP_REPAIR_PHASE_STORED_PAIR = 1,
  ZIP_REPAIR_PHASE_STORED_ADJACENT = 2,
  ZIP_REPAIR_PHASE_TWO_RUN_FIRST = 3,
  ZIP_REPAIR_PHASE_TWO_RUN_SECOND = 4,
  ZIP_REPAIR_PHASE_ZSTD_ANCHORED = 5,
  ZIP_REPAIR_PHASE_DELAYED = 6,
  ZIP_REPAIR_PHASE_STORED_GAP_OOO = 7,
  ZIP_REPAIR_PHASE_STAGED_GAP = 8,
  ZIP_REPAIR_PHASE_ZERO_INSERTIONS = 9,
  ZIP_REPAIR_PHASE_ENCRYPTED_ROTATION = 10,
  ZIP_REPAIR_PHASE_DELAYED_ADJACENT = 11,
  ZIP_REPAIR_PHASE_ENCRYPTED_VALIDATE = 12
} ZipRepairPhase;

// Cursor state for exact repair loops that may span a checkpoint. The phase
// determines which cursors are active; completed trials are never repeated
// after restore.
typedef struct ZipRepairResume {
  uint64_t destination;
  uint64_t first_destination;
  uint64_t run_length;
  uint64_t source;
  uint64_t second_destination;
  uint64_t second_run_length;
  uint64_t source_rank;
  uint64_t footer_index;
  uint64_t best_destination;
  uint64_t best_run_length;
  uint64_t best_failure;
  uint64_t best_output;
  int64_t best_source;
  int64_t best_swap_slot;
  int64_t best_confidence_gain;
  uint8_t phase;
} ZipRepairResume;

// Completed partial improvements are retained even when another source scores
// better. A checkpoint may make that source unavailable without invalidating
// the other trials against the unchanged candidate.
typedef struct ZipScanOutcome {
  uint64_t source;
  uint64_t run_length;
  uint64_t failure;
  uint64_t entry;
  uint64_t output;
  uint64_t flags;
} ZipScanOutcome;

typedef struct ZipNormalScanState {
  uint64_t signature;
  uint64_t image_blocks;
  uint64_t plan_signature;
  uint64_t pending_source;
  uint64_t selected_source;
  uint64_t selected_run;
  uint64_t outcome_count;
  roaring64_bitmap_t *completed;
  roaring64_bitmap_t *pruned;
  ZipScanOutcome *outcomes;
  uint64_t outcome_capacity;
} ZipNormalScanState;

typedef struct ZipGapProbe {
  uint64_t destination;
  uint64_t failure;
  uint64_t output;
  int64_t source;
  int64_t swap;
  int64_t confidence;
  uint64_t flags;
} ZipGapProbe;

// Retain earlier decoder results needed to rank a delayed-error plateau.
typedef struct ZipDelayedScanState {
  uint64_t signature;
  uint64_t next_delay;
  uint64_t finished;
  uint64_t exact;
  ZipRepairResume best;
  ZipGapProbe probes[ZIP_DEFLATE_GAP_PROBE_COUNT];
} ZipDelayedScanState;

// Validation of the ranked encrypted layouts can yield independently of the
// earlier confidence scan. Only decoder scratch is rebuilt after restore.
typedef struct ZipEncryptedScanState {
  uint64_t signature;
  uint64_t best_split;
  int64_t best_score;
  uint64_t best_header_gain;
  uint64_t hypothesis_count;
  uint64_t next_hypothesis;
  uint64_t valid_count;
  uint64_t hypothesis_splits[ZIP_ENCRYPTED_ROTATION_HYPOTHESIS_LIMIT];
  int64_t hypothesis_scores[ZIP_ENCRYPTED_ROTATION_HYPOTHESIS_LIMIT];
  uint64_t valid_splits[ZIP_ENCRYPTED_ROTATION_HYPOTHESIS_LIMIT];
  int64_t valid_sources[ZIP_ENCRYPTED_ROTATION_HYPOTHESIS_LIMIT];
  int64_t valid_swaps[ZIP_ENCRYPTED_ROTATION_HYPOTHESIS_LIMIT];
  int64_t valid_scores[ZIP_ENCRYPTED_ROTATION_HYPOTHESIS_LIMIT];
} ZipEncryptedScanState;

typedef struct ZipCarveState {
  uint64_t archive_size;
  uint64_t observed_archive_size;
  uint64_t physical_gap_slot;
  uint64_t physical_gap_blocks;
  uint64_t gap_base_observed_archive_size;
  uint64_t gap_base_physical_gap_slot;
  uint64_t gap_base_physical_gap_blocks;
  uint64_t gap_base_failure_offset;
  uint64_t gap_base_failure_entry;
  uint64_t gap_base_header_actual;
  uint64_t gap_base_metadata_source_first;
  uint64_t gap_base_metadata_destination_first;
  uint64_t gap_base_metadata_blocks;
  uint64_t gap_tried_bytes;
  uint64_t entry_count;
  uint64_t central_offset;
  uint64_t eocd_offset;
  uint64_t failure_offset;
  uint64_t failure_entry;
  uint64_t destination_slot;
  uint64_t clone_destination_rank;
  uint64_t clone_destination_stride;
  uint64_t run_length;
  uint64_t preferred_run_length;
  uint64_t preferred_destination_slot;
  uint64_t seam_boundary_slot;
  uint64_t structure_resume_destination;
  uint64_t structure_destination_last;
  uint64_t structure_failure_offset;
  uint64_t structure_failure_entry;
  uint64_t structure_retry_destination;
  uint64_t structure_retry_next_destination;
  uint64_t structure_retry_first_destination;
  uint64_t apk_digest_entry;
  uint32_t scan_shares;
  int64_t seam_left_actual;
  int64_t seam_right_actual;
  int64_t scan_rank;
  uint8_t seam_variant;
  bool initialized;
  bool had_physical_gap;
  bool broad_scan;
  bool broad_wrapped;
  bool structure_pending;
  bool stored_structure_trial;
  bool clone_scan_initialized;
  bool preferred_run_active;
  bool structure_retry_active;
  bool structure_retry_pending;
  bool gap_base_mapping_available;
  bool gap_base_initialized;
  bool gap_base_structure_pending;
  bool gap_repair_applied;
  bool gap_hypothesis_isolated;
  bool apk_digest_fast_active;
  bool apk_digest_fast_complete;
  bool enclosed_by_cfbf;
  ZipRepairResume repair_resume;
  ZipNormalScanState *normal_scan;
  ZipDelayedScanState *delayed_scan;
  ZipEncryptedScanState *encrypted_scan;
  ZipStateEntry entries[];
} ZipCarveState;

static _Atomic uint64_t zip_reassembly_memory_reserved = 0;
static _Atomic uint64_t zip_reassembly_memory_budget_cached = 0;

static inline void zip_normal_scan_clear(ZipCarveState *state);
static inline bool zip_auxiliary_states_valid(const ZipCarveState *state);
static inline uint64_t zip_normal_scan_signature(
    CarveInfo *candidate, const ZipCarveState *state,
    const uint8_t *baseline, uint64_t output, uint64_t run_last);
static inline ZipNormalScanState *zip_normal_scan_prepare(
    ZipCarveState *state, uint64_t signature, uint64_t image_blocks);
static inline void zip_normal_scan_complete_source(ZipNormalScanState *scan);
static inline void zip_normal_scan_record(
    ZipNormalScanState *scan, uint64_t source, uint64_t run_length,
    uint64_t failure, uint64_t entry, uint64_t output, uint64_t flags);
static inline bool zip_normal_scan_select(
    CarveInfo *candidate, ZipCarveState *state, ZipMappedBlockIndex *index,
    uint64_t baseline_output, ZipScanOutcome *best, int64_t *swap_slot);
static inline bool zip_normal_scan_valid(const ZipNormalScanState *scan);
static inline bool zip_normal_scan_codec(
    ZipNormalScanState **scan, FILE *fp, StateSerialization mode);

static inline uint16_t zip_read_le16(const uint8_t *data);
static inline uint32_t zip_read_le32(const uint8_t *data);
static inline uint64_t zip_read_le64(const uint8_t *data);
static inline bool zip_has_archive_header(const uint8_t *data,
                                          uint64_t length);
static inline char *zip_footer_discovery(char *base,
                                         uint64_t offset,
                                         uint64_t remaining,
                                         char **matchpos,
                                         uint32_t *matchlen,
                                         uint32_t blocksize);
static inline bool zip_range_available(uint64_t length, uint64_t offset,
                                       uint64_t wanted);
static inline bool zip_name_equals(const ZipEntry *entry, const char *name);
static inline uint32_t zip_crc32(const uint8_t *data, uint64_t length);
static inline void zip_write_le32(uint8_t *data, uint32_t value);
static inline bool zip_apk_take_length_prefixed(
    const uint8_t *data,
    uint64_t length,
    uint64_t *offset,
    const uint8_t **value,
    uint64_t *value_length);
static inline const EVP_MD *zip_apk_digest_algorithm(
    uint32_t signature_algorithm);
static inline bool zip_apk_extract_scheme_digest(
    const uint8_t *data,
    uint64_t length,
    ZipApkDigestInfo *info);
static inline bool zip_apk_digest_identify(
    const uint8_t *data,
    uint64_t length,
    uint64_t central_offset,
    uint64_t eocd_offset,
    ZipApkDigestInfo *info);
static inline bool zip_apk_digest_calculate_chunk(
    ZipApkDigestContext *context,
    const uint8_t *baseline,
    uint64_t chunk_start,
    uint64_t chunk_length,
    uint64_t destination_start,
    uint64_t destination_length,
    int64_t source_actual,
    int64_t swap_slot,
    uint8_t *digest);
static inline bool zip_apk_digest_calculate_top(
    ZipApkDigestContext *context,
    uint64_t replacement_first,
    uint64_t replacement_count,
    const uint8_t *replacement_digests,
    uint8_t *digest);
static inline bool zip_apk_digest_context_initialize(
    const uint8_t *baseline,
    const ZipApkDigestInfo *info,
    ZipApkDigestContext *context);
static inline void zip_apk_digest_context_clear(
    ZipApkDigestContext *context);
static inline ZipApkDigestProbeResult zip_apk_digest_probe(
    ZipApkDigestContext *context,
    const uint8_t *baseline,
    uint64_t destination_slot,
    uint64_t run_length,
    int64_t source_actual,
    int64_t swap_slot);
static inline void zip_layout_clear(ZipLayout *layout);
static int zip_compare_ranges(const void *left, const void *right);
static int zip_compare_stored_crc_sources(const void *left,
                                          const void *right);
static inline bool zip_parse_zip64_extra(const uint8_t *extra,
                                         uint16_t extra_length,
                                         bool need_uncompressed,
                                         bool need_compressed,
                                         bool need_offset,
                                         bool need_disk,
                                         uint64_t *uncompressed,
                                         uint64_t *compressed,
                                         uint64_t *offset,
                                         uint32_t *disk);
static inline bool zip_find_unicode_path_extra(
    const uint8_t *extra,
    uint16_t extra_length,
    const uint8_t **unicode_name,
    uint16_t *unicode_name_length,
    uint32_t *name_crc32);
static inline bool zip_entry_name_matches_local(
    const ZipEntry *entry,
    const uint8_t *local_name,
    uint16_t local_name_length,
    const uint8_t *local_extra,
    uint16_t local_extra_length);
static inline bool zip_copy_inserted_buffer_bytes(
    const uint8_t *data,
    uint64_t length,
    uint64_t logical_offset,
    uint64_t wanted,
    uint64_t gap_offset,
    uint64_t inserted_bytes,
    uint8_t *destination);
static inline bool zip_local_header_matches_buffer_gap(
    const uint8_t *data,
    uint64_t length,
    uint64_t inserted_bytes,
    uint32_t blocksize,
    const ZipEntry *entry,
    uint16_t *name_length,
    uint16_t *extra_length,
    uint64_t *data_delta,
    uint64_t *gap_offset);
static inline bool zip_extra_has_aes(const uint8_t *extra,
                                     uint16_t extra_length);
static inline bool zip_parse_zip64_record(const uint8_t *data,
                                          uint64_t length,
                                          uint64_t record,
                                          uint64_t locator,
                                          uint64_t *entry_count,
                                          uint64_t *central_size,
                                          uint64_t *central_offset);
static inline bool zip_parse_zip64_eocd(const uint8_t *data,
                                        uint64_t length,
                                        uint64_t eocd_offset,
                                        uint64_t *entry_count,
                                        uint64_t *central_size,
                                        uint64_t *central_offset,
                                        uint64_t *logical_record,
                                        uint64_t *observed_record);
static inline bool zip_parse_eocd(const uint8_t *data,
                                  uint64_t length,
                                  uint64_t eocd_offset,
                                  ZipLayout *layout);
static inline bool zip_parse_central_directory(const uint8_t *data,
                                               uint64_t length,
                                               ZipLayout *layout,
                                               uint64_t *failure_offset);
static inline bool zip_parse_data_descriptor(const uint8_t *data,
                                             uint64_t limit,
                                             uint64_t offset,
                                             const ZipEntry *entry,
                                             uint64_t *descriptor_end);
static inline bool zip_parse_local_headers(const uint8_t *data,
                                           uint64_t length,
                                           uint32_t blocksize,
                                           ZipLayout *layout,
                                           uint64_t *failure_offset);
static inline bool zip_validate_unreferenced_prefix(
    const uint8_t *data,
    uint64_t prefix_end,
    uint64_t *failure_offset);
static inline void zip_classify_office_layout(ZipLayout *layout);
static inline bool zip_method_directly_verifiable(uint16_t method);
static inline void zip_legacy_bits_initialize(ZipLegacyBitReader *reader,
                                              const uint8_t *data,
                                              uint64_t size);
static inline bool zip_legacy_bits_read(ZipLegacyBitReader *reader,
                                        uint8_t count,
                                        uint32_t *value);
static inline bool zip_legacy_bits_align(ZipLegacyBitReader *reader);
static inline uint64_t zip_legacy_bits_consumed(
    const ZipLegacyBitReader *reader);
static inline bool zip_legacy_huffman_build(ZipLegacyHuffman *decoder,
                                            const uint8_t *lengths,
                                            uint16_t symbol_count,
                                            uint8_t maximum_bits,
                                            bool require_complete,
                                            bool invert_bits);
static inline bool zip_legacy_huffman_decode(
    const ZipLegacyHuffman *decoder,
    ZipLegacyBitReader *reader,
    uint16_t *symbol);
static inline void zip_legacy_output_initialize(ZipLegacyOutput *output,
                                                uint64_t expected);
static inline bool zip_legacy_output_byte(ZipLegacyOutput *output,
                                          uint8_t value);
static inline bool zip_legacy_output_copy(ZipLegacyOutput *output,
                                          uint32_t distance,
                                          uint32_t length,
                                          bool zero_prefix);
static inline uint32_t zip_legacy_output_crc(ZipLegacyOutput *output);
static inline bool zip_legacy_failure(const ZipEntry *entry,
                                      uint64_t input_progress,
                                      uint64_t output_progress_value,
                                      uint64_t *failure_offset,
                                      uint64_t *output_progress);
static inline bool zip_implode_read_tree(ZipLegacyBitReader *reader,
                                         uint16_t symbol_count,
                                         ZipLegacyHuffman *decoder);
static inline bool zip_deflate64_read_dynamic_tables(
    ZipLegacyBitReader *reader,
    ZipLegacyHuffman *literal_decoder,
    ZipLegacyHuffman *distance_decoder);
static inline bool zip_verify_shrink_entry(const uint8_t *data,
                                           const ZipEntry *entry,
                                           uint64_t *failure_offset,
                                           uint64_t *output_progress);
static inline bool zip_verify_implode_entry(const uint8_t *data,
                                            const ZipEntry *entry,
                                            uint64_t *failure_offset,
                                            uint64_t *output_progress);
static inline bool zip_verify_deflate_entry(const uint8_t *data,
                                            const ZipEntry *entry,
                                            uint64_t *failure_offset,
                                            uint64_t *output_progress);
static inline ZipInflateFeedResult zip_deflate_feed(
    z_stream *stream,
    const uint8_t *data,
    uint64_t length,
    uLong *crc,
    uint64_t *consumed);
static inline bool zip_deflate_prefix_initialize(
    const uint8_t *data,
    const ZipStateEntry *entry,
    uint64_t patch_start,
    uint64_t patch_end,
    ZipDeflatePrefix *prefix);
static inline void zip_deflate_prefix_clear(ZipDeflatePrefix *prefix);
static inline bool zip_deflate_prefix_probe(
    const ZipDeflatePrefix *prefix,
    const uint8_t *baseline,
    const ZipStateEntry *entry,
    int64_t source_actual,
    uint64_t source_offset,
    bool *valid,
    uint64_t *failure_offset,
    uint64_t *output_progress);
static inline bool zip_verify_deflate64_entry(const uint8_t *data,
                                              const ZipEntry *entry,
                                              uint64_t *failure_offset,
                                              uint64_t *output_progress);
static inline bool zip_verify_bzip2_entry(const uint8_t *data,
                                          const ZipEntry *entry,
                                          uint64_t *failure_offset,
                                          uint64_t *output_progress);
static inline bool zip_verify_lzma_entry(const uint8_t *data,
                                         const ZipEntry *entry,
                                         uint64_t *failure_offset,
                                         uint64_t *output_progress);
static inline bool zip_verify_zstd_entry(const uint8_t *data,
                                         const ZipEntry *entry,
                                         uint64_t *failure_offset,
                                         uint64_t *output_progress);
static inline bool zip_verify_xz_entry(const uint8_t *data,
                                       const ZipEntry *entry,
                                       uint64_t *failure_offset,
                                       uint64_t *output_progress);
static inline bool zip_verify_supported_entry(const uint8_t *data,
                                              const ZipEntry *entry,
                                              bool *supported,
                                              uint64_t *failure_offset,
                                              uint64_t *output_progress);
static inline bool zip_verify_entry_data(const uint8_t *data,
                                         const ZipLayout *layout,
                                         bool *needs_libarchive,
                                         uint64_t *failure_offset,
                                         uint64_t *failure_entry);
static inline bool zip_verify_with_libarchive(const uint8_t *data,
                                              const ZipLayout *layout);
static inline bool zip_find_layout(const uint8_t *data,
                                   uint64_t length,
                                   uint32_t blocksize,
                                   ZipLayout *layout,
                                   uint64_t *failure_offset,
                                   uint64_t *failure_entry,
                                   bool *content_valid);
static inline void zip_set_partial(uint64_t failure_offset,
                                   uint32_t blocksize,
                                   uint64_t *validates_to);
static inline bool zip_state_size(uint64_t entry_count,
                                  uint64_t gap_tried_bytes,
                                  size_t *size);
static inline ZipCarveState *zip_state_from_layout(const ZipLayout *layout,
                                                   uint64_t failure_offset,
                                                   uint64_t failure_entry,
                                                   bool track_gap_hypotheses);
static inline uint8_t *zip_state_gap_tried(ZipCarveState *state);
static inline bool zip_state_enable_gap_tracking(ZipCarveState **state);
static inline bool zip_auxiliary_states_valid(const ZipCarveState *state) {
  if (!state || scalpel_state.blocksize == 0
      || state->repair_resume.phase > ZIP_REPAIR_PHASE_ENCRYPTED_VALIDATE) {
    return false;
  }
  const uint64_t blocks = state->archive_size / scalpel_state.blocksize
      + (state->archive_size % scalpel_state.blocksize != 0);
  const ZipDelayedScanState *delayed = state->delayed_scan;
  if (delayed) {
    if (delayed->next_delay > blocks || delayed->finished > 1
        || delayed->exact > 1 || delayed->best.best_destination > blocks
        || delayed->best.best_run_length > blocks
        || delayed->best.best_run_length
               > blocks - delayed->best.best_destination
        || (delayed->exact && !delayed->finished)) {
      return false;
    }
    for (size_t i = 0; i < ZIP_DEFLATE_GAP_PROBE_COUNT; i++) {
      const ZipGapProbe *probe = &delayed->probes[i];
      if (probe->flags > 7 || (!(probe->flags & 1) && probe->flags != 0)
          || ((probe->flags & 1)
              && (probe->destination >= blocks || probe->source < 0))) {
        return false;
      }
    }
  }
  const ZipEncryptedScanState *encrypted = state->encrypted_scan;
  if (state->repair_resume.phase == ZIP_REPAIR_PHASE_ENCRYPTED_VALIDATE
      && (!encrypted || encrypted->hypothesis_count == 0)) {
    return false;
  }
  if (encrypted) {
    if (encrypted->hypothesis_count > ZIP_ENCRYPTED_ROTATION_HYPOTHESIS_LIMIT
        || encrypted->next_hypothesis > encrypted->hypothesis_count
        || encrypted->valid_count > encrypted->next_hypothesis
        || encrypted->best_split >= blocks) {
      return false;
    }
    for (size_t i = 0; i < encrypted->hypothesis_count; i++) {
      if (encrypted->hypothesis_splits[i] == 0
          || encrypted->hypothesis_splits[i] >= blocks) {
        return false;
      }
    }
    for (size_t i = 0; i < encrypted->valid_count; i++) {
      if (encrypted->valid_splits[i] == 0
          || encrypted->valid_splits[i] >= blocks
          || encrypted->valid_sources[i] < 0) {
        return false;
      }
    }
  }
  return true;
}

static inline bool zip_serialize_carve_state(void **state,
                                             FILE *fp,
                                             StateSerialization mode);
static inline void *zip_clone_carve_state(const void *srcstate);
static inline void zip_free_carve_state(void **state);
static inline void zip_print_carve_state(const void *state);
static inline bool zip_state_entry_verify(const uint8_t *data,
                                          uint64_t data_length,
                                          const ZipStateEntry *entry,
                                          uint64_t *failure_offset,
                                          uint64_t *output_progress);
static inline bool zip_state_entry_verify_with_libarchive(
    const uint8_t *data,
    uint64_t data_length,
    const ZipCarveState *state,
    uint64_t entry_index,
    uint64_t *failure_offset,
    uint64_t *output_progress);
static inline bool zip_reassembly_verify_entry(
    const uint8_t *data,
    uint64_t data_length,
    const ZipCarveState *state,
    const ZipStateEntry *entry,
    uint64_t *failure_offset,
    uint64_t *output_progress);
static inline bool zip_layout_matches_state(const ZipLayout *layout,
                                            const ZipCarveState *state);
static inline bool zip_reassembly_initialize_candidate(
    CarveInfo *candidate,
    const ZipCarveState *state);
static inline bool zip_copy_actual_bytes(uint64_t actual_offset,
                                         uint64_t length,
                                         uint8_t *destination);
static inline bool zip_find_actual_zip64_record(uint64_t locator_offset,
                                                uint64_t *record_offset,
                                                uint64_t *record_size,
                                                uint64_t *entry_count,
                                                uint64_t *central_size,
                                                uint64_t *central_offset);
static inline bool zip_local_header_fields_match(
    const uint8_t *fixed,
    const uint8_t *variable,
    uint64_t variable_length,
    const ZipEntry *entry,
    uint64_t *data_delta);
static inline bool zip_local_header_matches_actual(
    uint64_t actual_offset,
    const ZipEntry *entry,
    uint64_t *data_delta);
static inline bool zip_copy_gap_logical_bytes(
    uint64_t header_actual,
    uint64_t logical_offset,
    uint64_t length,
    uint64_t gap_offset,
    uint64_t inserted_bytes,
    uint8_t *destination);
static inline bool zip_local_header_matches_across_gap(
    uint64_t header_actual,
    uint64_t inserted_bytes,
    const ZipEntry *entry,
    uint64_t *data_delta,
    uint64_t *gap_offset);
static inline uint64_t zip_reassembly_memory_budget(void);
static inline bool zip_reassembly_memory_requirement(
    uint64_t archive_size,
    uint64_t *required);
static inline ZipMemoryReservationResult zip_reassembly_reserve_memory(
    ThreadWork *work,
    CarveInfo **candidate,
    uint64_t archive_size,
    uint64_t *reservation,
    uuid_string_t uuidp,
    uuid_string_t uuidc);
static inline void zip_reassembly_release_memory(uint64_t *reservation);
static inline ZipInitializationResult zip_reassembly_initialize_pair(
    ThreadWork *work,
    CarveInfo *candidate,
    ZipCarveState **state,
    uint64_t header_actual,
    uint64_t eocd_actual,
    uint64_t *memory_reservation,
    uuid_string_t uuidp,
    uuid_string_t uuidc);
static inline ZipInitializationResult zip_reassembly_initialize_header_seed(
    ThreadWork *work,
    CarveInfo **candidate,
    ZipCarveState **state,
    uint64_t *memory_reservation,
    uuid_string_t uuidp,
    uuid_string_t uuidc);
static inline uint64_t zip_reassembly_helper_limit(uint64_t archive_size);
static int zip_destination_score_compare(const void *left,
                                         const void *right);
static inline uint64_t zip_reassembly_ranked_destination(
    const CarveInfo *candidate,
    uint64_t first,
    uint64_t last,
    uint64_t run_length,
    uint64_t rank);
static inline uint64_t zip_reassembly_first_destination(
    const CarveInfo *candidate,
    uint64_t first,
    uint64_t last);
static inline uint64_t zip_reassembly_next_destination(
    const CarveInfo *candidate,
    uint64_t first,
    uint64_t last,
    uint64_t current);
static inline uint8_t zip_source_confidence_tier(int confidence);
static inline bool zip_mapped_block_index_initialize(
    const CarveInfo *candidate,
    ZipMappedBlockIndex *index);
static inline void zip_mapped_block_index_clear(
    ZipMappedBlockIndex *index);
static inline int64_t zip_mapped_block_index_find(
    const ZipMappedBlockIndex *index,
    int64_t actual);
static inline uint16_t zip_reassembly_source_bucket(
    const CarveInfo *candidate,
    const ZipMappedBlockIndex *mapped_blocks,
    int64_t source_actual,
    uint64_t sample_blocks);
static inline bool zip_reassembly_source_run_viable(
    CarveInfo *candidate,
    uint64_t destination_slot,
    uint64_t run_length,
    int64_t source_actual,
    int64_t *swap_slot);
static inline bool zip_reassembly_source_run_viable_indexed(
    CarveInfo *candidate,
    uint64_t destination_slot,
    uint64_t run_length,
    int64_t source_actual,
    int64_t *swap_slot,
    const ZipMappedBlockIndex *mapped_blocks);
static inline void zip_reassembly_copy_source_run(uint8_t *data,
                                                  uint64_t destination_slot,
                                                  uint64_t run_length,
                                                  int64_t source_actual);
static inline bool zip_reassembly_apply_source_run(
    uint8_t *data,
    const uint8_t *baseline,
    CarveInfo *candidate,
    uint64_t destination_slot,
    uint64_t run_length,
    int64_t source_actual,
    int64_t swap_slot);
static inline bool zip_reassembly_source_u32(int64_t source_actual,
                                             uint64_t source_offset,
                                             uint32_t *value);
static inline bool zip_reassembly_source_crc(int64_t source_actual,
                                             uint64_t source_offset,
                                             uint64_t length,
                                             uint32_t *crc);
static inline void zip_crc_forward_for_len(z_off_t length,
                                           uint32_t forward[32]);
static inline uint32_t zip_crc_apply_forward(const uint32_t forward[32],
                                             uint32_t value);
static inline bool zip_crc_inverse_for_len(z_off_t length,
                                           uint32_t inverse[32]);
static inline uint32_t zip_crc_apply_inverse(const uint32_t inverse[32],
                                             uint32_t value);
static inline bool zip_reassembly_block_crc(int64_t source_actual,
                                            uint32_t *crc);
static inline bool zip_stored_patch_crc(const uint8_t *baseline,
                                        uint64_t baseline_length,
                                        const ZipStateEntry *entry,
                                        uint64_t destination_slot,
                                        uint64_t run_length,
                                        int64_t source_actual,
                                        uint32_t *crc);
static inline void zip_reassembly_commit_source_run(
    CarveInfo *candidate,
    uint64_t destination_slot,
    uint64_t run_length,
    int64_t source_actual,
    int64_t swap_slot);
static inline bool zip_reassembly_capture_gap_baseline(
    CarveInfo *candidate,
    ZipCarveState *state);
static inline bool zip_reassembly_restore_gap_baseline(
    CarveInfo *candidate,
    ZipCarveState *state);
static inline ZipStoredRepairResult zip_reassembly_repair_stored_member(
    ThreadWork *work,
    CarveInfo **candidate,
    ZipCarveState *state,
    const ZipStateEntry *entry,
    uint64_t destination_slot,
    uint64_t run_length,
    int64_t source_actual,
    int64_t swap_slot,
    uuid_string_t uuidp,
    uuid_string_t uuidc);
static inline ZipStoredRepairResult zip_reassembly_repair_stored_gap_ooo(
    ThreadWork *work,
    CarveInfo **candidate,
    ZipCarveState *state,
    const ZipStateEntry *entry,
    uint64_t destination_first,
    uint64_t destination_last,
    uint64_t physical_shift,
    uuid_string_t uuidp,
    uuid_string_t uuidc);
static inline bool zip_reassembly_has_displaced_footer_anchor(
    const CarveInfo *candidate,
    const ZipCarveState *state,
    uint64_t total_blocks);
static inline void zip_reassembly_reset_repair_resume(
    ZipCarveState *state);
static inline ZipGapRepairResult
zip_reassembly_repair_adjacent_displaced_run(
    ThreadWork *work,
    CarveInfo **candidate,
    ZipCarveState *state,
    const ZipStateEntry *entry,
    const uint8_t *first_data,
    uint64_t buffer_size,
    uint64_t first_destination,
    uint64_t first_length,
    int64_t first_source,
    int64_t first_swap_slot,
    uint64_t displaced_length,
    uuid_string_t uuidp,
    uuid_string_t uuidc);
static inline ZipGapRepairResult zip_reassembly_repair_two_runs(
    ThreadWork *work,
    CarveInfo **candidate,
    ZipCarveState *state,
    const ZipStateEntry *entry,
    const uint8_t *baseline,
    uint8_t *trial,
    uint64_t buffer_size,
    uuid_string_t uuidp,
    uuid_string_t uuidc);
static inline ZipGapRepairResult zip_reassembly_repair_zstd_anchored_gap(
    ThreadWork *work,
    CarveInfo **candidate,
    ZipCarveState *state,
    const ZipStateEntry *entry,
    const uint8_t *baseline,
    uint8_t *trial,
    uint64_t buffer_size,
    uuid_string_t uuidp,
    uuid_string_t uuidc);
static inline ZipGapRepairResult zip_reassembly_repair_zero_insertions(
    ThreadWork *work,
    CarveInfo **candidate,
    ZipCarveState *state,
    const ZipStateEntry *entry,
    const uint8_t *baseline,
    uint8_t *trial,
    uint64_t buffer_size,
    uuid_string_t uuidp,
    uuid_string_t uuidc);
static inline ZipGapRepairResult zip_reassembly_repair_staged_gap(
    ThreadWork *work,
    CarveInfo **candidate,
    ZipCarveState *state,
    const ZipStateEntry *entry,
    const uint8_t *baseline,
    uint8_t *trial,
    uint64_t buffer_size,
    uuid_string_t uuidp,
    uuid_string_t uuidc);
static inline ZipGapRepairResult zip_reassembly_repair_delayed_gap(
    ThreadWork *work,
    CarveInfo **candidate,
    ZipCarveState *state,
    const ZipStateEntry *entry,
    const uint8_t *baseline,
    uint8_t *trial,
    uint64_t buffer_size,
    uuid_string_t uuidp,
    uuid_string_t uuidc);
static inline ZipGapRepairResult zip_reassembly_repair_encrypted_rotation(
    ThreadWork *work,
    CarveInfo **candidate,
    ZipCarveState *state,
    uuid_string_t uuidp,
    uuid_string_t uuidc);
static inline void zip_reassembly(ThreadWork *work,
                                  CarveInfo **candidate,
                                  uuid_string_t uuidp,
                                  uuid_string_t uuidc);
static inline void zip_file_validate_seed(char *data,
                                          uint64_t length,
                                          bool *validates,
                                          uint64_t *validates_to,
                                          bool *promising,
                                          uint32_t needleidx,
                                          uint32_t blocksize,
                                          void *carvehashkey);
static inline void zip_candidate_validate(CarveInfo *candidate,
                                          bool *validates,
                                          uint64_t *validates_to,
                                          bool *promising);
static inline void zip_file_validate(char *data,
                                     uint64_t length,
                                     bool *validates,
                                     uint64_t *validates_to,
                                     bool *promising,
                                     uint32_t needleidx,
                                     uint32_t blocksize,
                                     void *carvehashkey);

static inline uint16_t zip_read_le16(const uint8_t *data) {

  return (uint16_t)data[0]
         | (uint16_t)((uint16_t)data[1] << 8);
}

static inline uint32_t zip_read_le32(const uint8_t *data) {

  return (uint32_t)data[0]
         | ((uint32_t)data[1] << 8)
         | ((uint32_t)data[2] << 16)
         | ((uint32_t)data[3] << 24);
}

static inline uint64_t zip_read_le64(const uint8_t *data) {

  return (uint64_t)data[0]
         | ((uint64_t)data[1] << 8)
         | ((uint64_t)data[2] << 16)
         | ((uint64_t)data[3] << 24)
         | ((uint64_t)data[4] << 32)
         | ((uint64_t)data[5] << 40)
         | ((uint64_t)data[6] << 48)
         | ((uint64_t)data[7] << 56);
}

static inline bool zip_has_archive_header(const uint8_t *data,
                                          uint64_t length) {

  if (!data || length < sizeof(uint32_t)) {
    return false;
  }
  if (zip_read_le32(data) == ZIP_LOCAL_HEADER_SIGNATURE) {
    return true;
  }
  return length >= 2 * sizeof(uint32_t)
         && zip_read_le32(data) == ZIP_SINGLE_SEGMENT_MARKER
         && zip_read_le32(data + sizeof(uint32_t))
                == ZIP_LOCAL_HEADER_SIGNATURE;
}

// Locate complete single-disk EOCD records. The EOCD comment length is part of
// the footer so contiguous candidates end at the actual end of the archive.
//
static inline char *zip_footer_discovery(char *base,
                                         uint64_t offset,
                                         uint64_t remaining,
                                         char **matchpos,
                                         uint32_t *matchlen,
                                         uint32_t blocksize) {

  (void)blocksize;
  *matchpos = NULL;
  *matchlen = 0;

  if (!base || remaining < ZIP_EOCD_SIZE) {
    return NULL;
  }

  const uint8_t *search = (const uint8_t *)base + offset;
  uint64_t available = remaining;

  while (available >= ZIP_EOCD_SIZE) {
    const uint8_t *found = (const uint8_t *)memchr(search, 'P',
                                                   (size_t)available);

    if (!found) {
      break;
    }

    const uint64_t consumed = (uint64_t)(found - search);

    available -= consumed;
    if (available >= ZIP_EOCD_SIZE
        && zip_read_le32(found) == ZIP_EOCD_SIGNATURE
        && zip_read_le16(found + 4) == 0
        && zip_read_le16(found + 6) == 0) {
      const uint64_t footer_length = ZIP_EOCD_SIZE
                                     + zip_read_le16(found + 20);

      if (footer_length <= available) {
        *matchpos = (char *)found;
        *matchlen = (uint32_t)footer_length;
        return NULL;
      }
    }

    search = found + 1;
    available--;
  }
  return NULL;
}


static inline bool zip_range_available(uint64_t length, uint64_t offset,
                                       uint64_t wanted) {

  return offset <= length && wanted <= length - offset;
}

static inline bool zip_name_equals(const ZipEntry *entry, const char *name) {

  if (!entry || !name) {
    return false;
  }

  const size_t name_length = strlen(name);

  return name_length == entry->name_length
         && memcmp(entry->name, name, name_length) == 0;
}

static inline uint32_t zip_crc32(const uint8_t *data, uint64_t length) {

  uLong crc = crc32(0L, Z_NULL, 0);

  while (length > 0) {
    const uInt chunk = (uInt)(length > UINT_MAX ? UINT_MAX : length);

    crc = crc32(crc, data, chunk);
    data += chunk;
    length -= chunk;
  }
  return (uint32_t)crc;
}

static inline void zip_write_le32(uint8_t *data, uint32_t value) {

  data[0] = (uint8_t)value;
  data[1] = (uint8_t)(value >> 8);
  data[2] = (uint8_t)(value >> 16);
  data[3] = (uint8_t)(value >> 24);
}

static inline bool zip_apk_take_length_prefixed(
    const uint8_t *data,
    uint64_t length,
    uint64_t *offset,
    const uint8_t **value,
    uint64_t *value_length) {

  if (!data || !offset || !value || !value_length
      || !zip_range_available(length, *offset, sizeof(uint32_t))) {
    return false;
  }

  const uint64_t encoded_length = zip_read_le32(data + *offset);

  *offset += sizeof(uint32_t);
  if (!zip_range_available(length, *offset, encoded_length)) {
    return false;
  }
  *value = data + *offset;
  *value_length = encoded_length;
  *offset += encoded_length;
  return true;
}

static inline const EVP_MD *zip_apk_digest_algorithm(
    uint32_t signature_algorithm) {

  switch (signature_algorithm) {
    case UINT32_C(0x0101):
    case UINT32_C(0x0103):
    case UINT32_C(0x0201):
    case UINT32_C(0x0301):
      return EVP_sha256();

    case UINT32_C(0x0102):
    case UINT32_C(0x0104):
    case UINT32_C(0x0202):
      return EVP_sha512();

    default:
      return NULL;
  }
}

static inline bool zip_apk_extract_scheme_digest(
    const uint8_t *data,
    uint64_t length,
    ZipApkDigestInfo *info) {

  const uint8_t *signers = NULL;
  uint64_t signers_length = 0;
  uint64_t scheme_offset = 0;

  if (!data || !info
      || !zip_apk_take_length_prefixed(data, length, &scheme_offset,
                                       &signers, &signers_length)) {
    return false;
  }

  uint64_t signers_offset = 0;

  while (signers_offset < signers_length) {
    const uint8_t *signer = NULL;
    uint64_t signer_length = 0;

    if (!zip_apk_take_length_prefixed(
            signers, signers_length, &signers_offset,
            &signer, &signer_length)) {
      return false;
    }

    const uint8_t *signed_data = NULL;
    uint64_t signed_data_length = 0;
    uint64_t signer_offset = 0;

    if (!zip_apk_take_length_prefixed(
            signer, signer_length, &signer_offset,
            &signed_data, &signed_data_length)) {
      return false;
    }

    const uint8_t *digests = NULL;
    uint64_t digests_length = 0;
    uint64_t signed_data_offset = 0;

    if (!zip_apk_take_length_prefixed(
            signed_data, signed_data_length, &signed_data_offset,
            &digests, &digests_length)) {
      return false;
    }

    uint64_t digests_offset = 0;

    while (digests_offset < digests_length) {
      const uint8_t *record = NULL;
      uint64_t record_length = 0;

      if (!zip_apk_take_length_prefixed(
              digests, digests_length, &digests_offset,
              &record, &record_length)
          || record_length < sizeof(uint32_t)) {
        return false;
      }

      const EVP_MD *digest = zip_apk_digest_algorithm(
          zip_read_le32(record));
      const uint8_t *expected = NULL;
      uint64_t expected_length = 0;
      uint64_t record_offset = sizeof(uint32_t);

      if (!zip_apk_take_length_prefixed(
              record, record_length, &record_offset,
              &expected, &expected_length)) {
        return false;
      }
      if (!digest) {
        continue;
      }

      const int digest_length = EVP_MD_size(digest);

      if (digest_length <= 0
          || (uint64_t)digest_length != expected_length
          || expected_length > sizeof(info->expected_digest)) {
        continue;
      }
      info->digest = digest;
      info->digest_length = (uint32_t)digest_length;
      memcpy(info->expected_digest, expected, (size_t)expected_length);
      return true;
    }
  }
  return false;
}

static inline bool zip_apk_digest_identify(
    const uint8_t *data,
    uint64_t length,
    uint64_t central_offset,
    uint64_t eocd_offset,
    ZipApkDigestInfo *info) {

  if (!data || !info
      || central_offset < ZIP_APK_SIGNING_FOOTER_SIZE
      || eocd_offset < central_offset
      || !zip_range_available(length, central_offset, sizeof(uint32_t))
      || !zip_range_available(length, eocd_offset, ZIP_EOCD_SIZE)
      || zip_read_le32(data + central_offset)
             != ZIP_CENTRAL_HEADER_SIGNATURE
      || zip_read_le32(data + eocd_offset) != ZIP_EOCD_SIGNATURE) {
    return false;
  }
  memset(info, 0, sizeof(*info));

  const uint64_t footer = central_offset - ZIP_APK_SIGNING_FOOTER_SIZE;

  if (memcmp(data + footer + sizeof(uint64_t), ZIP_APK_SIGNING_MAGIC,
             (size_t)ZIP_APK_SIGNING_MAGIC_SIZE) != 0) {
    return false;
  }

  const uint64_t encoded_size = zip_read_le64(data + footer);

  if (encoded_size < ZIP_APK_SIGNING_FOOTER_SIZE
      || encoded_size > central_offset - sizeof(uint64_t)) {
    return false;
  }

  const uint64_t signing_block_start = central_offset
                                       - encoded_size
                                       - sizeof(uint64_t);

  if (!zip_range_available(length, signing_block_start, sizeof(uint64_t))
      || zip_read_le64(data + signing_block_start) != encoded_size
      || signing_block_start > UINT32_MAX
      || zip_read_le32(data + eocd_offset + 16) != central_offset) {
    return false;
  }

  uint64_t pair_offset = signing_block_start + sizeof(uint64_t);

  while (pair_offset < footer) {
    if (!zip_range_available(footer, pair_offset, sizeof(uint64_t))) {
      return false;
    }

    const uint64_t pair_length = zip_read_le64(data + pair_offset);

    pair_offset += sizeof(uint64_t);
    if (pair_length < sizeof(uint32_t)
        || !zip_range_available(footer, pair_offset, pair_length)) {
      return false;
    }

    const uint32_t pair_id = zip_read_le32(data + pair_offset);

    if (pair_id == ZIP_APK_V2_BLOCK_ID
        || pair_id == ZIP_APK_V3_BLOCK_ID
        || pair_id == ZIP_APK_V31_BLOCK_ID) {
      ZipApkDigestInfo candidate_info;

      memset(&candidate_info, 0, sizeof(candidate_info));
      if (zip_apk_extract_scheme_digest(
              data + pair_offset + sizeof(uint32_t),
              pair_length - sizeof(uint32_t), &candidate_info)) {
        candidate_info.signing_block_start = signing_block_start;
        candidate_info.central_offset = central_offset;
        candidate_info.eocd_offset = eocd_offset;
        candidate_info.archive_size = length;
        *info = candidate_info;
        return true;
      }
    }
    pair_offset += pair_length;
  }
  return pair_offset == footer && info->digest != NULL;
}

static inline bool zip_apk_digest_calculate_chunk(
    ZipApkDigestContext *context,
    const uint8_t *baseline,
    uint64_t chunk_start,
    uint64_t chunk_length,
    uint64_t destination_start,
    uint64_t destination_length,
    int64_t source_actual,
    int64_t swap_slot,
    uint8_t *digest) {

  if (!context || !context->chunk_context || !baseline || !digest
      || chunk_length > UINT32_MAX
      || !zip_range_available(context->info.archive_size,
                              chunk_start, chunk_length)) {
    return false;
  }

  uint8_t header[5] = {UINT8_C(0xa5), 0, 0, 0, 0};

  zip_write_le32(header + 1, (uint32_t)chunk_length);
  if (EVP_DigestInit_ex(context->chunk_context,
                        context->info.digest, NULL) != 1
      || EVP_DigestUpdate(context->chunk_context,
                          header, sizeof(header)) != 1) {
    return false;
  }

  const uint64_t chunk_end = chunk_start + chunk_length;

  if (swap_slot == ZIP_SWAP_SLOT_PER_BLOCK) {
    return false;
  }
  if (swap_slot >= 0) {
    if (scalpel_state.blocksize == 0 || source_actual < 0
        || chunk_length > ZIP_APK_CHUNK_SIZE
        || (uint64_t)swap_slot
               > UINT64_MAX / scalpel_state.blocksize
        || destination_start > UINT64_MAX - destination_length) {
      return false;
    }

    const uint64_t swap_start = (uint64_t)swap_slot
                                * scalpel_state.blocksize;

    if (swap_start > UINT64_MAX - destination_length) {
      return false;
    }
    if (!context->chunk_scratch) {
      context->chunk_scratch = (uint8_t *)malloc(
          (size_t)ZIP_APK_CHUNK_SIZE);
      if (!context->chunk_scratch) {
        return false;
      }
    }
    memcpy(context->chunk_scratch, baseline + chunk_start,
           (size_t)chunk_length);

    const uint64_t destination_end = destination_start
                                     + destination_length;
    uint64_t replacement_start = destination_start > chunk_start
        ? destination_start : chunk_start;
    uint64_t replacement_end = destination_end < chunk_end
        ? destination_end : chunk_end;

    if (replacement_start < replacement_end) {
      uint64_t source_offset = replacement_start - destination_start;
      uint64_t scratch_offset = replacement_start - chunk_start;
      uint64_t replacement_remaining = replacement_end
                                       - replacement_start;

      memset(context->chunk_scratch + scratch_offset, 0,
             (size_t)replacement_remaining);
      while (replacement_remaining > 0) {
        const uint64_t source_block = source_offset
                                      / scalpel_state.blocksize;

        if (source_block > INT64_MAX
            || source_actual > INT64_MAX - (int64_t)source_block) {
          return false;
        }
        const int64_t actual = source_actual + (int64_t)source_block;
        const uint64_t in_block = source_offset
                                  % scalpel_state.blocksize;
        uint64_t block_length = 0;
        const uint8_t *block = (const uint8_t *)
            filemirror_actual_block_data_pointer(
                scalpel_state.filemirror, actual, &block_length);
        uint64_t available = scalpel_state.blocksize - in_block;

        if (available > replacement_remaining) {
          available = replacement_remaining;
        }
        if (block_length > scalpel_state.blocksize) {
          block_length = scalpel_state.blocksize;
        }
        if (block && in_block < block_length) {
          uint64_t copied = block_length - in_block;

          if (copied > available) {
            copied = available;
          }
          memcpy(context->chunk_scratch + scratch_offset,
                 block + in_block, (size_t)copied);
        }
        source_offset += available;
        scratch_offset += available;
        replacement_remaining -= available;
      }
    }

    const uint64_t swap_end = swap_start + destination_length;

    replacement_start = swap_start > chunk_start
        ? swap_start : chunk_start;
    replacement_end = swap_end < chunk_end ? swap_end : chunk_end;
    if (replacement_start < replacement_end) {
      const uint64_t replacement_length = replacement_end
                                          - replacement_start;
      const uint64_t source_offset = destination_start
                                     + replacement_start - swap_start;

      memcpy(context->chunk_scratch + replacement_start - chunk_start,
             baseline + source_offset, (size_t)replacement_length);
    }

    unsigned int final_length = 0;

    return EVP_DigestUpdate(context->chunk_context,
                            context->chunk_scratch,
                            (size_t)chunk_length) == 1
           && EVP_DigestFinal_ex(context->chunk_context,
                                 digest, &final_length) == 1
           && final_length == context->info.digest_length;
  }

  uint64_t replacement_start = destination_start;
  uint64_t replacement_end = destination_start;

  if (destination_length > 0) {
    if (destination_start > UINT64_MAX - destination_length) {
      return false;
    }
    replacement_end = destination_start + destination_length;
    if (replacement_start < chunk_start) {
      replacement_start = chunk_start;
    }
    if (replacement_end > chunk_end) {
      replacement_end = chunk_end;
    }
  }

  if (destination_length == 0 || replacement_start >= replacement_end) {
    unsigned int final_length = 0;

    return EVP_DigestUpdate(context->chunk_context,
                            baseline + chunk_start,
                            (size_t)chunk_length) == 1
           && EVP_DigestFinal_ex(context->chunk_context,
                                 digest, &final_length) == 1
           && final_length == context->info.digest_length;
  }

  if (source_actual < 0
      || EVP_DigestUpdate(context->chunk_context,
                          baseline + chunk_start,
                          (size_t)(replacement_start - chunk_start)) != 1) {
    return false;
  }

  static const uint8_t zeros[4096] = {0};
  uint64_t source_offset = replacement_start - destination_start;
  uint64_t replacement_remaining = replacement_end - replacement_start;

  while (replacement_remaining > 0) {
    const int64_t actual = source_actual
        + (int64_t)(source_offset / scalpel_state.blocksize);
    const uint64_t in_block = source_offset % scalpel_state.blocksize;
    uint64_t block_length = 0;
    const uint8_t *block = (const uint8_t *)
        filemirror_actual_block_data_pointer(
            scalpel_state.filemirror, actual, &block_length);
    uint64_t available = scalpel_state.blocksize - in_block;

    if (available > replacement_remaining) {
      available = replacement_remaining;
    }
    if (block_length > scalpel_state.blocksize) {
      block_length = scalpel_state.blocksize;
    }

    uint64_t copied = 0;

    if (block && in_block < block_length) {
      copied = block_length - in_block;
      if (copied > available) {
        copied = available;
      }
      if (EVP_DigestUpdate(context->chunk_context,
                           block + in_block, (size_t)copied) != 1) {
        return false;
      }
    }

    uint64_t zero_length = available - copied;

    while (zero_length > 0) {
      const size_t zero_chunk = zero_length > sizeof(zeros)
          ? sizeof(zeros) : (size_t)zero_length;

      if (EVP_DigestUpdate(context->chunk_context,
                           zeros, zero_chunk) != 1) {
        return false;
      }
      zero_length -= zero_chunk;
    }
    source_offset += available;
    replacement_remaining -= available;
  }

  unsigned int final_length = 0;

  return EVP_DigestUpdate(context->chunk_context,
                          baseline + replacement_end,
                          (size_t)(chunk_end - replacement_end)) == 1
         && EVP_DigestFinal_ex(context->chunk_context,
                               digest, &final_length) == 1
         && final_length == context->info.digest_length;
}

static inline bool zip_apk_digest_calculate_top(
    ZipApkDigestContext *context,
    uint64_t replacement_first,
    uint64_t replacement_count,
    const uint8_t *replacement_digests,
    uint8_t *digest) {

  if (!context || !context->top_context || !context->chunk_digests
      || !digest || context->total_chunks > UINT32_MAX
      || replacement_first > context->total_chunks
      || replacement_count > context->total_chunks - replacement_first
      || (replacement_count > 0 && !replacement_digests)) {
    return false;
  }

  uint8_t header[5] = {UINT8_C(0x5a), 0, 0, 0, 0};

  zip_write_le32(header + 1, (uint32_t)context->total_chunks);
  if (EVP_DigestInit_ex(context->top_context,
                        context->info.digest, NULL) != 1
      || EVP_DigestUpdate(context->top_context,
                          header, sizeof(header)) != 1) {
    return false;
  }

  for (uint64_t chunk = 0; chunk < context->total_chunks; chunk++) {
    const uint8_t *chunk_digest = context->chunk_digests
        + chunk * context->info.digest_length;

    if (chunk >= replacement_first
        && chunk < replacement_first + replacement_count) {
      chunk_digest = replacement_digests
          + (chunk - replacement_first) * context->info.digest_length;
    }
    if (EVP_DigestUpdate(context->top_context, chunk_digest,
                         context->info.digest_length) != 1) {
      return false;
    }
  }

  unsigned int final_length = 0;

  return EVP_DigestFinal_ex(context->top_context,
                            digest, &final_length) == 1
         && final_length == context->info.digest_length;
}

static inline bool zip_apk_digest_context_initialize(
    const uint8_t *baseline,
    const ZipApkDigestInfo *info,
    ZipApkDigestContext *context) {

  if (!baseline || !info || !info->digest || !context
      || info->digest_length == 0
      || info->digest_length > EVP_MAX_MD_SIZE
      || info->signing_block_start > info->central_offset
      || info->central_offset > info->eocd_offset
      || info->eocd_offset > info->archive_size) {
    return false;
  }

  memset(context, 0, sizeof(*context));
  context->info = *info;

  const uint64_t section_start[3] = {
      0, info->central_offset, info->eocd_offset};
  const uint64_t section_length[3] = {
      info->signing_block_start,
      info->eocd_offset - info->central_offset,
      info->archive_size - info->eocd_offset};

  for (uint64_t section = 0; section < 3; section++) {
    context->section_chunk_first[section] = context->total_chunks;
    context->section_chunk_count[section] = CEILDIV(
        section_length[section], ZIP_APK_CHUNK_SIZE);
    if (context->section_chunk_count[section]
        > UINT64_MAX - context->total_chunks) {
      return false;
    }
    context->total_chunks += context->section_chunk_count[section];
  }
  if (context->total_chunks == 0 || context->total_chunks > UINT32_MAX
      || context->total_chunks
             > SIZE_MAX / info->digest_length) {
    return false;
  }

  context->chunk_digests = (uint8_t *)malloc(
      (size_t)(context->total_chunks * info->digest_length));
  context->chunk_context = EVP_MD_CTX_new();
  context->top_context = EVP_MD_CTX_new();
  if (!context->chunk_digests || !context->chunk_context
      || !context->top_context) {
    zip_apk_digest_context_clear(context);
    return false;
  }

  for (uint64_t section = 0; section < 2; section++) {
    for (uint64_t index = 0;
         index < context->section_chunk_count[section]; index++) {
      const uint64_t relative = index * ZIP_APK_CHUNK_SIZE;
      uint64_t chunk_length = section_length[section] - relative;

      if (chunk_length > ZIP_APK_CHUNK_SIZE) {
        chunk_length = ZIP_APK_CHUNK_SIZE;
      }
      uint8_t *digest = context->chunk_digests
          + (context->section_chunk_first[section] + index)
                * info->digest_length;

      if (!zip_apk_digest_calculate_chunk(
              context, baseline, section_start[section] + relative,
              chunk_length, 0, 0, -1, ZIP_SWAP_SLOT_UNMAPPED,
              digest)) {
        zip_apk_digest_context_clear(context);
        return false;
      }
    }
  }

  if (section_length[2] == 0
      || section_length[2] > ZIP_EOCD_SIZE + UINT16_MAX) {
    zip_apk_digest_context_clear(context);
    return false;
  }

  uint8_t *eocd = (uint8_t *)malloc((size_t)section_length[2]);

  if (!eocd) {
    zip_apk_digest_context_clear(context);
    return false;
  }
  memcpy(eocd, baseline + info->eocd_offset, (size_t)section_length[2]);
  zip_write_le32(eocd + 16, (uint32_t)info->signing_block_start);

  uint8_t header[5] = {UINT8_C(0xa5), 0, 0, 0, 0};
  uint8_t *eocd_digest = context->chunk_digests
      + context->section_chunk_first[2] * info->digest_length;
  unsigned int final_length = 0;

  zip_write_le32(header + 1, (uint32_t)section_length[2]);
  const bool eocd_hashed =
      EVP_DigestInit_ex(context->chunk_context, info->digest, NULL) == 1
      && EVP_DigestUpdate(context->chunk_context,
                          header, sizeof(header)) == 1
      && EVP_DigestUpdate(context->chunk_context,
                          eocd, (size_t)section_length[2]) == 1
      && EVP_DigestFinal_ex(context->chunk_context,
                            eocd_digest, &final_length) == 1
      && final_length == info->digest_length;

  free(eocd);
  if (!eocd_hashed) {
    zip_apk_digest_context_clear(context);
    return false;
  }
  context->initialized = true;
  return true;
}

static inline void zip_apk_digest_context_clear(
    ZipApkDigestContext *context) {

  if (!context) {
    return;
  }
  EVP_MD_CTX_free(context->chunk_context);
  EVP_MD_CTX_free(context->top_context);
  free(context->chunk_digests);
  free(context->chunk_scratch);
  memset(context, 0, sizeof(*context));
}

static inline ZipApkDigestProbeResult zip_apk_digest_probe(
    ZipApkDigestContext *context,
    const uint8_t *baseline,
    uint64_t destination_slot,
    uint64_t run_length,
    int64_t source_actual,
    int64_t swap_slot) {

  if (!context || !context->initialized || !baseline
      || scalpel_state.blocksize == 0 || run_length == 0
      || run_length > ZIP_APK_FAST_RUN_LIMIT
      || destination_slot > UINT64_MAX / scalpel_state.blocksize
      || run_length > UINT64_MAX / scalpel_state.blocksize
      || swap_slot == ZIP_SWAP_SLOT_PER_BLOCK) {
    return ZIP_APK_DIGEST_UNAVAILABLE;
  }

  const uint64_t destination_start = destination_slot
                                     * scalpel_state.blocksize;
  const uint64_t destination_length = run_length
                                      * scalpel_state.blocksize;

  if (destination_length > ZIP_APK_CHUNK_SIZE
      || destination_start >= context->info.signing_block_start
      || destination_length
             > context->info.signing_block_start - destination_start) {
    return ZIP_APK_DIGEST_UNAVAILABLE;
  }

  const uint64_t first_chunk = destination_start / ZIP_APK_CHUNK_SIZE;
  const uint64_t last_chunk = (destination_start + destination_length - 1)
                              / ZIP_APK_CHUNK_SIZE;
  const uint64_t replacement_count = last_chunk - first_chunk + 1;

  if (replacement_count == 0 || replacement_count > 2
      || last_chunk >= context->section_chunk_count[0]) {
    return ZIP_APK_DIGEST_UNAVAILABLE;
  }

  if (swap_slot >= 0) {
    if ((uint64_t)swap_slot
            > UINT64_MAX / scalpel_state.blocksize) {
      return ZIP_APK_DIGEST_UNAVAILABLE;
    }

    uint64_t affected_chunks[4];
    uint64_t affected_count = 0;

    for (uint64_t chunk = first_chunk; chunk <= last_chunk; chunk++) {
      affected_chunks[affected_count++] = chunk;
    }

    const uint64_t swap_start = (uint64_t)swap_slot
                                * scalpel_state.blocksize;

    if (swap_start < context->info.signing_block_start) {
      uint64_t swap_length = context->info.signing_block_start - swap_start;

      if (swap_length > destination_length) {
        swap_length = destination_length;
      }
      const uint64_t swap_first = swap_start / ZIP_APK_CHUNK_SIZE;
      const uint64_t swap_last = (swap_start + swap_length - 1)
                                 / ZIP_APK_CHUNK_SIZE;

      if (swap_last >= context->section_chunk_count[0]) {
        return ZIP_APK_DIGEST_UNAVAILABLE;
      }
      for (uint64_t chunk = swap_first; chunk <= swap_last; chunk++) {
        bool already_present = false;

        for (uint64_t index = 0; index < affected_count; index++) {
          if (affected_chunks[index] == chunk) {
            already_present = true;
            break;
          }
        }
        if (!already_present) {
          if (affected_count >= sizeof(affected_chunks)
                                    / sizeof(affected_chunks[0])) {
            return ZIP_APK_DIGEST_UNAVAILABLE;
          }
          affected_chunks[affected_count++] = chunk;
        }
      }
    }

    uint8_t saved_digests[4 * EVP_MAX_MD_SIZE];

    for (uint64_t index = 0; index < affected_count; index++) {
      memcpy(saved_digests + index * context->info.digest_length,
             context->chunk_digests
                 + affected_chunks[index] * context->info.digest_length,
             context->info.digest_length);
    }

    bool available = true;

    for (uint64_t index = 0; index < affected_count; index++) {
      const uint64_t chunk = affected_chunks[index];
      const uint64_t chunk_start = chunk * ZIP_APK_CHUNK_SIZE;
      uint64_t chunk_length = context->info.signing_block_start - chunk_start;

      if (chunk_length > ZIP_APK_CHUNK_SIZE) {
        chunk_length = ZIP_APK_CHUNK_SIZE;
      }
      if (!zip_apk_digest_calculate_chunk(
              context, baseline, chunk_start, chunk_length,
              destination_start, destination_length, source_actual,
              swap_slot, context->chunk_digests
                  + chunk * context->info.digest_length)) {
        available = false;
        break;
      }
    }

    uint8_t calculated[EVP_MAX_MD_SIZE];

    const bool calculated_ok = available
        && zip_apk_digest_calculate_top(context, 0, 0, NULL, calculated);

    for (uint64_t index = 0; index < affected_count; index++) {
      memcpy(context->chunk_digests
                 + affected_chunks[index] * context->info.digest_length,
             saved_digests + index * context->info.digest_length,
             context->info.digest_length);
    }
    if (!calculated_ok) {
      return ZIP_APK_DIGEST_UNAVAILABLE;
    }
    return memcmp(calculated, context->info.expected_digest,
                  context->info.digest_length) == 0
        ? ZIP_APK_DIGEST_MATCH : ZIP_APK_DIGEST_MISMATCH;
  }

  uint8_t replacement_digests[2 * EVP_MAX_MD_SIZE];

  for (uint64_t index = 0; index < replacement_count; index++) {
    const uint64_t chunk = first_chunk + index;
    const uint64_t chunk_start = chunk * ZIP_APK_CHUNK_SIZE;
    uint64_t chunk_length = context->info.signing_block_start - chunk_start;

    if (chunk_length > ZIP_APK_CHUNK_SIZE) {
      chunk_length = ZIP_APK_CHUNK_SIZE;
    }
    if (!zip_apk_digest_calculate_chunk(
            context, baseline, chunk_start, chunk_length,
            destination_start, destination_length, source_actual,
            ZIP_SWAP_SLOT_UNMAPPED,
            replacement_digests + index * context->info.digest_length)) {
      return ZIP_APK_DIGEST_UNAVAILABLE;
    }
  }

  uint8_t calculated[EVP_MAX_MD_SIZE];

  if (!zip_apk_digest_calculate_top(
          context, first_chunk, replacement_count,
          replacement_digests, calculated)) {
    return ZIP_APK_DIGEST_UNAVAILABLE;
  }
  return memcmp(calculated, context->info.expected_digest,
                context->info.digest_length) == 0
      ? ZIP_APK_DIGEST_MATCH : ZIP_APK_DIGEST_MISMATCH;
}

static inline void zip_layout_clear(ZipLayout *layout) {

  if (!layout) {
    return;
  }
  free(layout->entries);
  memset(layout, 0, sizeof(*layout));
}

static int zip_compare_ranges(const void *left, const void *right) {

  const ZipRange *a = (const ZipRange *)left;
  const ZipRange *b = (const ZipRange *)right;

  if (a->start < b->start) {
    return -1;
  }
  if (a->start > b->start) {
    return 1;
  }
  if (a->end < b->end) {
    return -1;
  }
  if (a->end > b->end) {
    return 1;
  }
  return 0;
}

static int zip_compare_stored_crc_sources(const void *left,
                                          const void *right) {

  const ZipStoredCrcSource *a = (const ZipStoredCrcSource *)left;
  const ZipStoredCrcSource *b = (const ZipStoredCrcSource *)right;

  if (a->contribution < b->contribution) {
    return -1;
  }
  if (a->contribution > b->contribution) {
    return 1;
  }
  if (a->source < b->source) {
    return -1;
  }
  if (a->source > b->source) {
    return 1;
  }
  return 0;
}

static inline void zip_crc_forward_for_len(z_off_t length,
                                           uint32_t forward[32]) {

  const uLong operation = crc32_combine_gen(length);

  for (int bit = 0; bit < 32; bit++) {
    forward[bit] = (uint32_t)crc32_combine_op(
        (uLong)(UINT32_C(1) << bit), 0UL, operation);
  }
}

static inline uint32_t zip_crc_apply_forward(const uint32_t forward[32],
                                             uint32_t value) {

  uint32_t result = 0;

  for (int bit = 0; bit < 32; bit++) {
    if ((value & (UINT32_C(1) << bit)) != 0) {
      result ^= forward[bit];
    }
  }
  return result;
}

static inline bool zip_crc_inverse_for_len(z_off_t length,
                                           uint32_t inverse[32]) {

  uint32_t augmented[32];

  zip_crc_forward_for_len(length, augmented);
  for (int bit = 0; bit < 32; bit++) {
    inverse[bit] = UINT32_C(1) << bit;
  }

  for (int column = 0; column < 32; column++) {
    int pivot = -1;

    for (int row = column; row < 32; row++) {
      if ((augmented[row] & (UINT32_C(1) << column)) != 0) {
        pivot = row;
        break;
      }
    }
    if (pivot < 0) {
      return false;
    }
    if (pivot != column) {
      uint32_t temporary = augmented[column];

      augmented[column] = augmented[pivot];
      augmented[pivot] = temporary;
      temporary = inverse[column];
      inverse[column] = inverse[pivot];
      inverse[pivot] = temporary;
    }
    for (int row = 0; row < 32; row++) {
      if (row != column
          && (augmented[row] & (UINT32_C(1) << column)) != 0) {
        augmented[row] ^= augmented[column];
        inverse[row] ^= inverse[column];
      }
    }
  }
  return true;
}

static inline uint32_t zip_crc_apply_inverse(const uint32_t inverse[32],
                                             uint32_t value) {

  uint32_t result = 0;

  for (int bit = 0; bit < 32; bit++) {
    if ((value & (UINT32_C(1) << bit)) != 0) {
      result ^= inverse[bit];
    }
  }
  return result;
}

// Read the ZIP64 values that replace sentinel fields in a local or central
// header. APPNOTE requires these values to appear in field order.
//
static inline bool zip_parse_zip64_extra(const uint8_t *extra,
                                         uint16_t extra_length,
                                         bool need_uncompressed,
                                         bool need_compressed,
                                         bool need_offset,
                                         bool need_disk,
                                         uint64_t *uncompressed,
                                         uint64_t *compressed,
                                         uint64_t *offset,
                                         uint32_t *disk) {

  uint64_t position = 0;

  while (zip_range_available(extra_length, position, 4)) {
    const uint16_t id = zip_read_le16(extra + position);
    const uint16_t size = zip_read_le16(extra + position + 2);

    position += 4;
    if (!zip_range_available(extra_length, position, size)) {
      return false;
    }
    if (id != ZIP_EXTRA_ID_ZIP64) {
      position += size;
      continue;
    }

    uint64_t value_position = position;
    const uint64_t value_end = position + size;

    if (need_uncompressed) {
      if (!zip_range_available(value_end, value_position, 8)) {
        return false;
      }
      *uncompressed = zip_read_le64(extra + value_position);
      value_position += 8;
    }
    if (need_compressed) {
      if (!zip_range_available(value_end, value_position, 8)) {
        return false;
      }
      *compressed = zip_read_le64(extra + value_position);
      value_position += 8;
    }
    if (need_offset) {
      if (!zip_range_available(value_end, value_position, 8)) {
        return false;
      }
      *offset = zip_read_le64(extra + value_position);
      value_position += 8;
    }
    if (need_disk) {
      if (!zip_range_available(value_end, value_position, 4)) {
        return false;
      }
      *disk = zip_read_le32(extra + value_position);
    }
    return true;
  }
  return !(need_uncompressed || need_compressed || need_offset || need_disk);
}

// Locate a structurally valid Info-ZIP Unicode Path field. The field is
// advisory, so malformed instances are ignored and raw names remain usable.
//
static inline bool zip_find_unicode_path_extra(
    const uint8_t *extra,
    uint16_t extra_length,
    const uint8_t **unicode_name,
    uint16_t *unicode_name_length,
    uint32_t *name_crc32) {

  if (!unicode_name || !unicode_name_length || !name_crc32) {
    return false;
  }

  *unicode_name = NULL;
  *unicode_name_length = 0;
  *name_crc32 = 0;

  uint64_t position = 0;

  while (zip_range_available(extra_length, position, 4)) {
    const uint16_t id = zip_read_le16(extra + position);
    const uint16_t size = zip_read_le16(extra + position + 2);

    position += 4;
    if (!zip_range_available(extra_length, position, size)) {
      return false;
    }
    if (id == ZIP_EXTRA_ID_UNICODE_PATH && size > 5
        && extra[position] == 1) {
      *name_crc32 = zip_read_le32(extra + position + 1);
      *unicode_name = extra + position + 5;
      *unicode_name_length = (uint16_t)(size - 5);
      return true;
    }
    position += size;
  }
  return false;
}

// ZIP writers sometimes encode the same name differently in local and
// central records. Accept that difference only when matching Unicode Path
// fields agree and at least one field authenticates its associated raw name.
//
static inline bool zip_entry_name_matches_local(
    const ZipEntry *entry,
    const uint8_t *local_name,
    uint16_t local_name_length,
    const uint8_t *local_extra,
    uint16_t local_extra_length) {

  if (!entry || !local_name) {
    return false;
  }
  if (local_name_length == entry->name_length
      && memcmp(local_name, entry->name, local_name_length) == 0) {
    return true;
  }
  if (!entry->unicode_name || entry->unicode_name_length == 0) {
    return false;
  }

  const uint8_t *local_unicode_name = NULL;
  uint16_t local_unicode_name_length = 0;
  uint32_t local_name_crc32 = 0;

  if (!zip_find_unicode_path_extra(local_extra, local_extra_length,
                                   &local_unicode_name,
                                   &local_unicode_name_length,
                                   &local_name_crc32)
      || local_unicode_name_length != entry->unicode_name_length
      || memcmp(local_unicode_name, entry->unicode_name,
                local_unicode_name_length) != 0) {
    return false;
  }

  return entry->unicode_name_crc32
             == zip_crc32(entry->name, entry->name_length)
         || local_name_crc32 == zip_crc32(local_name, local_name_length);
}

static inline bool zip_extra_has_aes(const uint8_t *extra,
                                     uint16_t extra_length) {

  uint64_t position = 0;

  while (zip_range_available(extra_length, position, 4)) {
    const uint16_t id = zip_read_le16(extra + position);
    const uint16_t size = zip_read_le16(extra + position + 2);

    position += 4;
    if (!zip_range_available(extra_length, position, size)) {
      return false;
    }
    if (id == ZIP_EXTRA_ID_AES) {
      return true;
    }
    position += size;
  }
  return false;
}

static inline bool zip_parse_zip64_record(const uint8_t *data,
                                          uint64_t length,
                                          uint64_t record,
                                          uint64_t locator,
                                          uint64_t *entry_count,
                                          uint64_t *central_size,
                                          uint64_t *central_offset) {

  if (!zip_range_available(length, record, ZIP64_EOCD_MINIMUM_SIZE)
      || record >= locator
      || zip_read_le32(data + record) != ZIP64_EOCD_SIGNATURE) {
    return false;
  }

  const uint64_t record_payload = zip_read_le64(data + record + 4);
  uint64_t record_total = 0;

  if (record_payload < 44
      || __builtin_add_overflow(record_payload, UINT64_C(12),
                                &record_total)
      || !zip_range_available(length, record, record_total)
      || record + record_total != locator
      || zip_read_le32(data + record + 16) != 0
      || zip_read_le32(data + record + 20) != 0) {
    return false;
  }

  const uint64_t disk_entries = zip_read_le64(data + record + 24);
  const uint64_t total_entries = zip_read_le64(data + record + 32);

  if (disk_entries != total_entries) {
    return false;
  }

  *entry_count = total_entries;
  *central_size = zip_read_le64(data + record + 40);
  *central_offset = zip_read_le64(data + record + 48);
  return true;
}

// Parse the ZIP64 EOCD locator and its associated record. The locator stores
// a logical offset, so a displaced record is found by its physical adjacency
// to the locator. Multi-disk archives are deliberately rejected because one
// evidence image cannot establish bytes stored on a different disk.
//
static inline bool zip_parse_zip64_eocd(const uint8_t *data,
                                        uint64_t length,
                                        uint64_t eocd_offset,
                                        uint64_t *entry_count,
                                        uint64_t *central_size,
                                        uint64_t *central_offset,
                                        uint64_t *logical_record,
                                        uint64_t *observed_record) {

  if (eocd_offset < ZIP64_EOCD_LOCATOR_SIZE) {
    return false;
  }

  const uint64_t locator = eocd_offset - ZIP64_EOCD_LOCATOR_SIZE;

  if (!zip_range_available(length, locator, ZIP64_EOCD_LOCATOR_SIZE)
      || zip_read_le32(data + locator) != ZIP64_EOCD_LOCATOR_SIGNATURE
      || zip_read_le32(data + locator + 4) != 0
      || zip_read_le32(data + locator + 16) != 1) {
    return false;
  }

  *logical_record = zip_read_le64(data + locator + 8);
  if (zip_parse_zip64_record(data, length, *logical_record, locator,
                             entry_count, central_size, central_offset)) {
    *observed_record = *logical_record;
    return true;
  }

  uint64_t search = 0;

  while (search < locator) {
    const uint8_t *found = (const uint8_t *)memchr(
        data + search, 'P', (size_t)(locator - search));

    if (!found) {
      break;
    }

    const uint64_t candidate = (uint64_t)(found - data);

    search = candidate + 1;
    if (zip_parse_zip64_record(data, length, candidate, locator,
                               entry_count, central_size,
                               central_offset)) {
      *observed_record = candidate;
      return true;
    }
  }
  return false;
}

static inline bool zip_parse_eocd(const uint8_t *data,
                                  uint64_t length,
                                  uint64_t eocd_offset,
                                  ZipLayout *layout) {

  if (!data || !layout
      || !zip_range_available(length, eocd_offset, ZIP_EOCD_SIZE)
      || zip_read_le32(data + eocd_offset) != ZIP_EOCD_SIGNATURE) {
    return false;
  }

  const uint16_t disk = zip_read_le16(data + eocd_offset + 4);
  const uint16_t central_disk = zip_read_le16(data + eocd_offset + 6);
  const uint16_t disk_entries = zip_read_le16(data + eocd_offset + 8);
  const uint16_t total_entries = zip_read_le16(data + eocd_offset + 10);
  const uint32_t central_size32 = zip_read_le32(data + eocd_offset + 12);
  const uint32_t central_offset32 = zip_read_le32(data + eocd_offset + 16);
  const uint16_t comment_length = zip_read_le16(data + eocd_offset + 20);
  uint64_t archive_size = 0;

  if (__builtin_add_overflow(eocd_offset, ZIP_EOCD_SIZE, &archive_size)
      || __builtin_add_overflow(archive_size, (uint64_t)comment_length,
                                &archive_size)
      || archive_size > length) {
    return false;
  }

  uint64_t entry_count = total_entries;
  uint64_t central_size = central_size32;
  uint64_t central_offset = central_offset32;
  uint64_t logical_terminal_start = eocd_offset;
  uint64_t observed_terminal_start = eocd_offset;
  const bool needs_zip64 =
      disk == ZIP_UINT16_SENTINEL
      || central_disk == ZIP_UINT16_SENTINEL
      || disk_entries == ZIP_UINT16_SENTINEL
      || total_entries == ZIP_UINT16_SENTINEL
      || central_size32 == ZIP_UINT32_SENTINEL
      || central_offset32 == ZIP_UINT32_SENTINEL;

  if (needs_zip64) {
    uint64_t logical_record = 0;
    uint64_t observed_record = 0;

    if (!zip_parse_zip64_eocd(data, length, eocd_offset,
                              &entry_count, &central_size,
                              &central_offset, &logical_record,
                              &observed_record)) {
      return false;
    }
    layout->zip64 = true;
    logical_terminal_start = logical_record;
    observed_terminal_start = observed_record;
  }
  else if (disk != 0 || central_disk != 0
           || disk_entries != total_entries) {
    return false;
  }

  uint64_t central_end = 0;
  uint64_t observed_central_offset = 0;

  if (entry_count == 0
      || central_size < ZIP_CENTRAL_HEADER_SIZE
      || central_size / ZIP_CENTRAL_HEADER_SIZE < entry_count
      || __builtin_add_overflow(central_offset, central_size, &central_end)
      || central_size > observed_terminal_start) {
    return false;
  }

  observed_central_offset = observed_terminal_start - central_size;
  uint64_t inserted_bytes = 0;
  uint64_t leading_bytes = 0;

  if (observed_central_offset >= central_offset) {
    inserted_bytes = observed_central_offset - central_offset;
    if (inserted_bytes > observed_terminal_start) {
      return false;
    }
    if (!needs_zip64) {
      logical_terminal_start = observed_terminal_start - inserted_bytes;
    }
  }
  else {
    leading_bytes = central_offset - observed_central_offset;
    if (__builtin_add_overflow(observed_terminal_start, leading_bytes,
                               &logical_terminal_start)) {
      return false;
    }
    central_offset -= leading_bytes;
  }

  if (central_end > logical_terminal_start || inserted_bytes > archive_size) {
    return false;
  }

  layout->entry_count = entry_count;
  layout->central_offset = central_offset;
  layout->observed_central_offset = observed_central_offset;
  layout->central_size = central_size;
  layout->archive_size = archive_size - inserted_bytes;
  layout->observed_archive_size = archive_size;
  layout->eocd_offset = eocd_offset;
  layout->leading_bytes = leading_bytes;
  layout->displaced_structure = inserted_bytes != 0;
  return true;
}

// Parse every central-directory entry and retain the metadata needed to
// cross-check local headers and verify entry data.
//
static inline bool zip_parse_central_directory(const uint8_t *data,
                                               uint64_t length,
                                               ZipLayout *layout,
                                               uint64_t *failure_offset) {

  if (!data || !layout || layout->entry_count == 0
      || layout->entry_count > SIZE_MAX / sizeof(*layout->entries)) {
    return false;
  }

  layout->entries = (ZipEntry *)calloc((size_t)layout->entry_count,
                                       sizeof(*layout->entries));
  check_memory_allocation(layout->entries, __LINE__, __FILE__,
                          "layout->entries");

  uint64_t position = layout->observed_central_offset;
  const uint64_t central_end = layout->observed_central_offset
                               + layout->central_size;

  for (uint64_t index = 0; index < layout->entry_count; index++) {
    if (!zip_range_available(central_end, position,
                             ZIP_CENTRAL_HEADER_SIZE)
        || zip_read_le32(data + position)
               != ZIP_CENTRAL_HEADER_SIGNATURE) {
      *failure_offset = position;
      return false;
    }

    ZipEntry *entry = &layout->entries[index];
    const uint16_t name_length = zip_read_le16(data + position + 28);
    const uint16_t extra_length = zip_read_le16(data + position + 30);
    const uint16_t comment_length = zip_read_le16(data + position + 32);
    const uint16_t disk_start16 = zip_read_le16(data + position + 34);
    const uint32_t compressed32 = zip_read_le32(data + position + 20);
    const uint32_t uncompressed32 = zip_read_le32(data + position + 24);
    const uint32_t local_offset32 = zip_read_le32(data + position + 42);
    uint64_t variable_size = 0;

    if (__builtin_add_overflow((uint64_t)name_length,
                               (uint64_t)extra_length, &variable_size)
        || __builtin_add_overflow(variable_size,
                                  (uint64_t)comment_length,
                                  &variable_size)
        || !zip_range_available(central_end,
                                position + ZIP_CENTRAL_HEADER_SIZE,
                                variable_size)) {
      *failure_offset = position;
      return false;
    }

    entry->flags = zip_read_le16(data + position + 8);
    entry->method = zip_read_le16(data + position + 10);
    entry->crc32 = zip_read_le32(data + position + 16);
    entry->compressed_size = compressed32;
    entry->uncompressed_size = uncompressed32;
    uint64_t raw_local_offset = local_offset32;
    entry->name_length = name_length;
    entry->name = data + position + ZIP_CENTRAL_HEADER_SIZE;

    const uint8_t *extra = entry->name + name_length;
    uint32_t disk_start = disk_start16;
    const bool need_uncompressed = uncompressed32 == ZIP_UINT32_SENTINEL;
    const bool need_compressed = compressed32 == ZIP_UINT32_SENTINEL;
    const bool need_offset = local_offset32 == ZIP_UINT32_SENTINEL;
    const bool need_disk = disk_start16 == ZIP_UINT16_SENTINEL;

    zip_find_unicode_path_extra(extra, extra_length,
                                &entry->unicode_name,
                                &entry->unicode_name_length,
                                &entry->unicode_name_crc32);

    if ((need_uncompressed || need_compressed || need_offset || need_disk)
        && !zip_parse_zip64_extra(extra, extra_length,
                                  need_uncompressed, need_compressed,
                                  need_offset, need_disk,
                                  &entry->uncompressed_size,
                                  &entry->compressed_size,
                                  &raw_local_offset, &disk_start)) {
      *failure_offset = position;
      return false;
    }
    if (raw_local_offset < layout->leading_bytes) {
      *failure_offset = position;
      return false;
    }
    entry->local_offset = raw_local_offset - layout->leading_bytes;
    entry->zip64_sizes = need_uncompressed || need_compressed;
    entry->encrypted = (entry->flags & ZIP_FLAG_ENCRYPTED) != 0
                       || entry->method == ZIP_METHOD_AES
                       || zip_extra_has_aes(extra, extra_length);
    if (entry->encrypted) {
      layout->encrypted = true;
    }
    if (disk_start != 0 || entry->name_length == 0
        || entry->local_offset >= layout->central_offset) {
      *failure_offset = position;
      return false;
    }

    position += ZIP_CENTRAL_HEADER_SIZE + variable_size;
  }

  if (position < central_end
      && zip_range_available(central_end, position, 6)
      && zip_read_le32(data + position) == ZIP_DIGITAL_SIGNATURE) {
    const uint16_t signature_size = zip_read_le16(data + position + 4);

    position += 6 + signature_size;
  }
  if (position != central_end || central_end > length) {
    *failure_offset = position;
    return false;
  }
  return true;
}

static inline bool zip_descriptor_matches(const uint8_t *data,
                                          uint64_t limit,
                                          uint64_t offset,
                                          const ZipEntry *entry,
                                          bool has_signature,
                                          bool wide_sizes,
                                          uint64_t *descriptor_end) {

  uint64_t position = offset;

  if (has_signature) {
    if (!zip_range_available(limit, position, 4)
        || zip_read_le32(data + position)
               != ZIP_DATA_DESCRIPTOR_SIGNATURE) {
      return false;
    }
    position += 4;
  }

  const uint64_t descriptor_size = wide_sizes ? 20 : 12;

  if (!zip_range_available(limit, position, descriptor_size)
      || zip_read_le32(data + position) != entry->crc32) {
    return false;
  }

  const uint64_t compressed = wide_sizes
                                  ? zip_read_le64(data + position + 4)
                                  : zip_read_le32(data + position + 4);
  const uint64_t uncompressed = wide_sizes
                                    ? zip_read_le64(data + position + 12)
                                    : zip_read_le32(data + position + 8);

  if (compressed != entry->compressed_size
      || uncompressed != entry->uncompressed_size) {
    return false;
  }
  *descriptor_end = position + descriptor_size;
  return true;
}

static inline bool zip_parse_data_descriptor(const uint8_t *data,
                                             uint64_t limit,
                                             uint64_t offset,
                                             const ZipEntry *entry,
                                             uint64_t *descriptor_end) {

  const bool prefer_wide = entry->zip64_sizes
                           || entry->compressed_size > ZIP_UINT32_SENTINEL
                           || entry->uncompressed_size > ZIP_UINT32_SENTINEL;
  const bool signature_at_offset =
      zip_range_available(limit, offset, 4)
      && zip_read_le32(data + offset) == ZIP_DATA_DESCRIPTOR_SIGNATURE;

  if (zip_descriptor_matches(data, limit, offset, entry,
                             signature_at_offset, prefer_wide,
                             descriptor_end)) {
    return true;
  }
  if (zip_descriptor_matches(data, limit, offset, entry,
                             signature_at_offset, !prefer_wide,
                             descriptor_end)) {
    return true;
  }

  // A CRC equal to the optional descriptor signature is ambiguous. Retry
  // without consuming the four bytes as a signature.
  if (signature_at_offset
      && zip_descriptor_matches(data, limit, offset, entry, false,
                                prefer_wide, descriptor_end)) {
    return true;
  }
  return signature_at_offset
         && zip_descriptor_matches(data, limit, offset, entry, false,
                                   !prefer_wide, descriptor_end);
}

// Copy logical archive bytes from a buffer that contains one physically
// inserted run. Bytes after the gap are shifted by inserted_bytes.
//
static inline bool zip_copy_inserted_buffer_bytes(
    const uint8_t *data,
    uint64_t length,
    uint64_t logical_offset,
    uint64_t wanted,
    uint64_t gap_offset,
    uint64_t inserted_bytes,
    uint8_t *destination) {

  if (!data || (!destination && wanted > 0) || inserted_bytes == 0
      || logical_offset > UINT64_MAX - wanted) {
    return false;
  }

  uint64_t prefix_length = 0;

  if (logical_offset < gap_offset) {
    prefix_length = gap_offset - logical_offset;
    if (prefix_length > wanted) {
      prefix_length = wanted;
    }
  }
  if (!zip_range_available(length, logical_offset, prefix_length)) {
    return false;
  }
  if (prefix_length > 0) {
    memcpy(destination, data + logical_offset, (size_t)prefix_length);
  }

  const uint64_t suffix_length = wanted - prefix_length;

  if (suffix_length > 0) {
    const uint64_t suffix_logical = logical_offset + prefix_length;
    uint64_t suffix_observed = 0;

    if (suffix_logical < gap_offset
        || __builtin_add_overflow(suffix_logical, inserted_bytes,
                                  &suffix_observed)
        || !zip_range_available(length, suffix_observed, suffix_length)) {
      return false;
    }
    memcpy(destination + prefix_length, data + suffix_observed,
           (size_t)suffix_length);
  }
  return true;
}

// Authenticate a local header split by one block-aligned insertion in an
// in-memory candidate. The central entry supplies the expected field values.
//
static inline bool zip_local_header_matches_buffer_gap(
    const uint8_t *data,
    uint64_t length,
    uint64_t inserted_bytes,
    uint32_t blocksize,
    const ZipEntry *entry,
    uint16_t *name_length,
    uint16_t *extra_length,
    uint64_t *data_delta,
    uint64_t *gap_offset) {

  if (name_length) {
    *name_length = 0;
  }
  if (extra_length) {
    *extra_length = 0;
  }
  if (data_delta) {
    *data_delta = 0;
  }
  if (gap_offset) {
    *gap_offset = 0;
  }
  if (!data || !entry || !name_length || !extra_length || !data_delta
      || !gap_offset || blocksize == 0 || inserted_bytes == 0
      || inserted_bytes % blocksize != 0
      || entry->local_offset > UINT64_MAX - blocksize) {
    return false;
  }

  uint64_t candidate_gap = (entry->local_offset / blocksize + 1)
                           * blocksize;
  uint64_t maximum_header_end = 0;

  if (__builtin_add_overflow(entry->local_offset,
                             (uint64_t)ZIP_LOCAL_HEADER_SIZE
                                 + UINT16_MAX + UINT16_MAX,
                             &maximum_header_end)) {
    return false;
  }

  while (candidate_gap < maximum_header_end) {
    uint8_t fixed[ZIP_LOCAL_HEADER_SIZE];

    if (!zip_copy_inserted_buffer_bytes(
            data, length, entry->local_offset, sizeof(fixed),
            candidate_gap, inserted_bytes, fixed)
        || zip_read_le32(fixed) != ZIP_LOCAL_HEADER_SIGNATURE) {
      if (candidate_gap > UINT64_MAX - blocksize) {
        break;
      }
      candidate_gap += blocksize;
      continue;
    }

    const uint16_t trial_name_length = zip_read_le16(fixed + 26);
    const uint16_t trial_extra_length = zip_read_le16(fixed + 28);
    const uint64_t variable_length = (uint64_t)trial_name_length
                                     + trial_extra_length;
    uint64_t variable_offset = 0;
    uint64_t header_end = 0;

    if (__builtin_add_overflow(entry->local_offset,
                               (uint64_t)ZIP_LOCAL_HEADER_SIZE,
                               &variable_offset)
        || __builtin_add_overflow(variable_offset, variable_length,
                                  &header_end)) {
      return false;
    }
    if (candidate_gap >= header_end) {
      if (candidate_gap > UINT64_MAX - blocksize) {
        break;
      }
      candidate_gap += blocksize;
      continue;
    }

    const size_t allocation_length = variable_length > 0
                                         ? (size_t)variable_length : 1;
    uint8_t *variable = (uint8_t *)malloc(allocation_length);

    check_memory_allocation(variable, __LINE__, __FILE__,
                            "split ZIP local-header buffer");
    const bool matches = zip_copy_inserted_buffer_bytes(
                             data, length, variable_offset,
                             variable_length, candidate_gap,
                             inserted_bytes, variable)
                         && zip_local_header_fields_match(
                                fixed, variable, variable_length,
                                entry, data_delta);

    free(variable);
    if (matches) {
      *name_length = trial_name_length;
      *extra_length = trial_extra_length;
      *gap_offset = candidate_gap;
      return true;
    }
    if (candidate_gap > UINT64_MAX - blocksize) {
      break;
    }
    candidate_gap += blocksize;
  }
  return false;
}

// Cross-check every central entry against its local header and establish
// non-overlapping byte ranges for all member records.
//
static inline bool zip_parse_local_headers(const uint8_t *data,
                                           uint64_t length,
                                           uint32_t blocksize,
                                           ZipLayout *layout,
                                           uint64_t *failure_offset) {

  if (!data || !layout || !layout->entries
      || layout->entry_count > SIZE_MAX / sizeof(ZipRange)) {
    return false;
  }

  ZipRange *ranges = (ZipRange *)calloc((size_t)layout->entry_count,
                                        sizeof(*ranges));
  check_memory_allocation(ranges, __LINE__, __FILE__, "ranges");
  uint64_t minimum_observed_local = UINT64_MAX;

  for (uint64_t index = 0; index < layout->entry_count; index++) {
    ZipEntry *entry = &layout->entries[index];
    const uint64_t logical_local = entry->local_offset;
    uint64_t search = logical_local;
    uint64_t observed_local = UINT64_MAX;
    uint16_t local_flags = 0;
    uint16_t local_method = 0;
    uint32_t local_crc = 0;
    uint64_t local_compressed = 0;
    uint64_t local_uncompressed = 0;
    uint16_t name_length = 0;
    uint16_t extra_length = 0;
    uint64_t observed_data_adjustment = 0;

    while (zip_range_available(layout->observed_central_offset, search,
                               ZIP_LOCAL_HEADER_SIZE)) {
      const uint8_t *found = (const uint8_t *)memchr(
          data + search, 'P',
          (size_t)(layout->observed_central_offset - search));

      if (!found) {
        break;
      }
      const uint64_t local = (uint64_t)(found - data);

      search = local + 1;
      if (!zip_range_available(layout->observed_central_offset, local,
                               ZIP_LOCAL_HEADER_SIZE)
          || zip_read_le32(data + local) != ZIP_LOCAL_HEADER_SIGNATURE
          || (logical_local == 0 && local != 0)) {
        continue;
      }

      local_flags = zip_read_le16(data + local + 6);
      local_method = zip_read_le16(data + local + 8);
      local_crc = zip_read_le32(data + local + 14);
      const uint32_t compressed32 = zip_read_le32(data + local + 18);
      const uint32_t uncompressed32 = zip_read_le32(data + local + 22);
      name_length = zip_read_le16(data + local + 26);
      extra_length = zip_read_le16(data + local + 28);
      uint64_t variable_end = 0;

      if (__builtin_add_overflow(local, ZIP_LOCAL_HEADER_SIZE,
                                 &variable_end)
          || __builtin_add_overflow(variable_end,
                                    (uint64_t)name_length,
                                    &variable_end)
          || __builtin_add_overflow(variable_end,
                                    (uint64_t)extra_length,
                                    &variable_end)
          || variable_end > layout->observed_central_offset
          || local_method != entry->method
          || ((local_flags ^ entry->flags)
              & (ZIP_FLAG_ENCRYPTED | ZIP_FLAG_DATA_DESCRIPTOR)) != 0) {
        continue;
      }

      const uint8_t *extra = data + local + ZIP_LOCAL_HEADER_SIZE
                             + name_length;

      if (!zip_entry_name_matches_local(
              entry, data + local + ZIP_LOCAL_HEADER_SIZE, name_length,
              extra, extra_length)) {
        continue;
      }
      uint64_t unused_offset = 0;
      uint32_t unused_disk = 0;
      const bool need_uncompressed =
          uncompressed32 == ZIP_UINT32_SENTINEL;
      const bool need_compressed = compressed32 == ZIP_UINT32_SENTINEL;

      local_compressed = compressed32;
      local_uncompressed = uncompressed32;
      if ((need_uncompressed || need_compressed)
          && !zip_parse_zip64_extra(extra, extra_length,
                                    need_uncompressed, need_compressed,
                                    false, false,
                                    &local_uncompressed,
                                    &local_compressed,
                                    &unused_offset, &unused_disk)) {
        continue;
      }

      const bool has_descriptor =
          (entry->flags & ZIP_FLAG_DATA_DESCRIPTOR) != 0;

      if (!has_descriptor
          && (local_crc != entry->crc32
              || local_compressed != entry->compressed_size
              || local_uncompressed != entry->uncompressed_size)) {
        continue;
      }

      observed_local = local;
      break;
    }

    if (observed_local == UINT64_MAX && layout->leading_bytes == 0
        && layout->observed_central_offset > layout->central_offset
        && blocksize > 0) {
      const uint64_t inserted_bytes = layout->observed_central_offset
                                      - layout->central_offset;
      uint64_t split_delta = 0;
      uint64_t split_gap = 0;

      if (zip_local_header_matches_buffer_gap(
              data, layout->observed_central_offset, inserted_bytes,
              blocksize, entry, &name_length, &extra_length,
              &split_delta, &split_gap)) {
        const uint64_t split_slot = split_gap / blocksize;

        if (layout->physical_gap_slot != 0
            && layout->physical_gap_slot != split_slot) {
          *failure_offset = logical_local;
          free(ranges);
          return false;
        }
        layout->physical_gap_slot = split_slot;
        observed_local = logical_local;
        observed_data_adjustment = inserted_bytes;
      }
    }

    if (observed_local == UINT64_MAX) {
      *failure_offset = logical_local;
      free(ranges);
      return false;
    }

    uint64_t data_offset = 0;
    uint64_t observed_data_offset = 0;

    if (__builtin_add_overflow(logical_local, ZIP_LOCAL_HEADER_SIZE,
                               &data_offset)
        || __builtin_add_overflow(data_offset, (uint64_t)name_length,
                                  &data_offset)
        || __builtin_add_overflow(data_offset, (uint64_t)extra_length,
                                  &data_offset)
        || __builtin_add_overflow(observed_local,
                                  ZIP_LOCAL_HEADER_SIZE,
                                  &observed_data_offset)
        || __builtin_add_overflow(observed_data_offset,
                                  (uint64_t)name_length,
                                  &observed_data_offset)
        || __builtin_add_overflow(observed_data_offset,
                                  (uint64_t)extra_length,
                                  &observed_data_offset)
        || __builtin_add_overflow(observed_data_offset,
                                  observed_data_adjustment,
                                  &observed_data_offset)) {
      *failure_offset = logical_local;
      free(ranges);
      return false;
    }

    uint64_t data_end = 0;

    if (__builtin_add_overflow(data_offset, entry->compressed_size,
                               &data_end)
        || data_end > layout->central_offset) {
      *failure_offset = data_offset;
      free(ranges);
      return false;
    }

    uint64_t range_end = data_end;
    const bool has_descriptor =
        (entry->flags & ZIP_FLAG_DATA_DESCRIPTOR) != 0;

    if (has_descriptor && !layout->displaced_structure
        && !zip_parse_data_descriptor(data, layout->central_offset,
                                      data_end, entry, &range_end)) {
      *failure_offset = data_end;
      free(ranges);
      return false;
    }

    entry->observed_local_offset = observed_local;
    entry->data_offset = data_offset;
    entry->observed_data_offset = observed_data_offset;
    entry->range_end = range_end;
    entry->geometry_known = true;
    ranges[index].start = logical_local;
    ranges[index].end = range_end;
    if (observed_local != logical_local) {
      layout->displaced_structure = true;
    }
    if (observed_local < minimum_observed_local) {
      minimum_observed_local = observed_local;
    }
  }

  qsort(ranges, (size_t)layout->entry_count, sizeof(*ranges),
        zip_compare_ranges);
  for (uint64_t index = 1; index < layout->entry_count; index++) {
    if (ranges[index].start < ranges[index - 1].end) {
      *failure_offset = ranges[index].start;
      free(ranges);
      return false;
    }
  }
  free(ranges);

  if (minimum_observed_local == UINT64_MAX || layout->archive_size > length) {
    *failure_offset = 0;
    return false;
  }
  if (minimum_observed_local > 0
      && !zip_validate_unreferenced_prefix(
             data, minimum_observed_local, failure_offset)) {
    return false;
  }
  return true;
}

// Classify OOXML packages from their package and application roots. ZIP
// validity does not depend on this classification because ordinary archives
// may use the same directory names.
//
static inline void zip_classify_office_layout(ZipLayout *layout) {

  bool content_types = false;
  bool package_relationships = false;
  bool word_root = false;
  bool sheet_root = false;
  bool presentation_root = false;

  for (uint64_t index = 0; index < layout->entry_count; index++) {
    const ZipEntry *entry = &layout->entries[index];

    content_types |= zip_name_equals(entry, "[Content_Types].xml");
    package_relationships |= zip_name_equals(entry, "_rels/.rels");
    word_root |= zip_name_equals(entry, "word/document.xml");
    sheet_root |= zip_name_equals(entry, "xl/workbook.xml");
    presentation_root |=
        zip_name_equals(entry, "ppt/presentation.xml");
  }

  layout->office_document = content_types && package_relationships
                            && word_root;
  layout->office_spreadsheet = content_types && package_relationships
                               && sheet_root;
  layout->office_presentation = content_types && package_relationships
                                && presentation_root;
}

static inline void zip_legacy_bits_initialize(ZipLegacyBitReader *reader,
                                              const uint8_t *data,
                                              uint64_t size) {

  memset(reader, 0, sizeof(*reader));
  reader->data = data;
  reader->size = size;
}

static inline bool zip_method_directly_verifiable(uint16_t method) {

  return method == ZIP_METHOD_STORED
         || method == ZIP_METHOD_SHRINK
         || method == ZIP_METHOD_IMPLODE
         || method == ZIP_METHOD_DEFLATE
         || method == ZIP_METHOD_DEFLATE64
         || method == ZIP_METHOD_BZIP2
         || method == ZIP_METHOD_LZMA
         || method == ZIP_METHOD_ZSTD
         || method == ZIP_METHOD_XZ;
}

static inline bool zip_legacy_bits_read(ZipLegacyBitReader *reader,
                                        uint8_t count,
                                        uint32_t *value) {

  if (!reader || !value || count > 24) {
    return false;
  }
  while (reader->buffered_bits < count) {
    if (reader->next_byte >= reader->size) {
      return false;
    }
    reader->buffer |= (uint64_t)reader->data[reader->next_byte++]
                      << reader->buffered_bits;
    reader->buffered_bits += 8;
  }

  const uint64_t mask = count == 0 ? 0 : (UINT64_C(1) << count) - 1;

  *value = (uint32_t)(reader->buffer & mask);
  reader->buffer >>= count;
  reader->buffered_bits -= count;
  reader->bits_read += count;
  return true;
}

static inline bool zip_legacy_bits_align(ZipLegacyBitReader *reader) {

  const uint8_t padding = (uint8_t)((8 - (reader->bits_read & 7)) & 7);
  uint32_t ignored = 0;

  return padding == 0 || zip_legacy_bits_read(reader, padding, &ignored);
}

static inline uint64_t zip_legacy_bits_consumed(
    const ZipLegacyBitReader *reader) {

  return reader->bits_read / 8 + (reader->bits_read % 8 != 0 ? 1 : 0);
}

static inline bool zip_legacy_huffman_build(ZipLegacyHuffman *decoder,
                                            const uint8_t *lengths,
                                            uint16_t symbol_count,
                                            uint8_t maximum_bits,
                                            bool require_complete,
                                            bool invert_bits) {

  uint16_t counts[ZIP_LEGACY_HUFFMAN_BITS + 1];
  uint32_t next_code[ZIP_LEGACY_HUFFMAN_BITS + 1];
  int32_t remaining = 1;
  uint32_t code = 0;

  if (!decoder || !lengths || symbol_count == 0
      || symbol_count > ZIP_LEGACY_HUFFMAN_SYMBOLS
      || maximum_bits == 0 || maximum_bits > ZIP_LEGACY_HUFFMAN_BITS) {
    return false;
  }

  memset(counts, 0, sizeof(counts));
  memset(next_code, 0, sizeof(next_code));
  for (uint16_t symbol = 0; symbol < symbol_count; symbol++) {
    if (lengths[symbol] > maximum_bits) {
      return false;
    }
    counts[lengths[symbol]]++;
  }
  if (counts[0] == symbol_count) {
    return false;
  }
  for (uint8_t bits = 1; bits <= maximum_bits; bits++) {
    remaining = (remaining << 1) - counts[bits];
    if (remaining < 0) {
      return false;
    }
  }
  if (require_complete && remaining != 0) {
    return false;
  }

  for (uint8_t bits = 1; bits <= maximum_bits; bits++) {
    code = (code + counts[bits - 1]) << 1;
    next_code[bits] = code;
  }

  decoder->node_count = 1;
  decoder->nodes[0].child[0] = -1;
  decoder->nodes[0].child[1] = -1;
  decoder->nodes[0].symbol = -1;
  for (uint16_t symbol = 0; symbol < symbol_count; symbol++) {
    const uint8_t length = lengths[symbol];

    if (length == 0) {
      continue;
    }

    const uint32_t symbol_code = next_code[length]++;
    int16_t node = 0;

    for (uint8_t depth = 0; depth < length; depth++) {
      uint8_t bit = (uint8_t)(
          (symbol_code >> (length - depth - 1)) & 1);

      if (invert_bits) {
        bit ^= 1;
      }
      if (decoder->nodes[node].symbol >= 0) {
        return false;
      }
      if (decoder->nodes[node].child[bit] < 0) {
        if (decoder->node_count >= ZIP_LEGACY_HUFFMAN_NODES) {
          return false;
        }
        const int16_t child = (int16_t)decoder->node_count++;

        decoder->nodes[child].child[0] = -1;
        decoder->nodes[child].child[1] = -1;
        decoder->nodes[child].symbol = -1;
        decoder->nodes[node].child[bit] = child;
      }
      node = decoder->nodes[node].child[bit];
    }
    if (decoder->nodes[node].symbol >= 0
        || decoder->nodes[node].child[0] >= 0
        || decoder->nodes[node].child[1] >= 0) {
      return false;
    }
    decoder->nodes[node].symbol = (int16_t)symbol;
  }
  return true;
}

static inline bool zip_legacy_huffman_decode(
    const ZipLegacyHuffman *decoder,
    ZipLegacyBitReader *reader,
    uint16_t *symbol) {

  int16_t node = 0;

  for (uint8_t depth = 0; depth < ZIP_LEGACY_HUFFMAN_BITS; depth++) {
    uint32_t bit = 0;

    if (!zip_legacy_bits_read(reader, 1, &bit)) {
      return false;
    }
    node = decoder->nodes[node].child[bit];
    if (node < 0 || (uint16_t)node >= decoder->node_count) {
      return false;
    }
    if (decoder->nodes[node].symbol >= 0) {
      *symbol = (uint16_t)decoder->nodes[node].symbol;
      return true;
    }
  }
  return false;
}

static inline void zip_legacy_output_initialize(ZipLegacyOutput *output,
                                                uint64_t expected) {

  memset(output, 0, sizeof(*output));
  output->expected = expected;
  output->crc = (uint32_t)crc32(0L, Z_NULL, 0);
}

static inline bool zip_legacy_output_byte(ZipLegacyOutput *output,
                                          uint8_t value) {

  if (output->produced >= output->expected) {
    return false;
  }

  const uint32_t offset = (uint32_t)(output->produced
                                     & (ZIP_LEGACY_WINDOW_SIZE - 1));

  output->window[offset] = value;
  output->produced++;
  if ((output->produced & (ZIP_LEGACY_WINDOW_SIZE - 1)) == 0) {
    output->crc = (uint32_t)crc32(output->crc, output->window,
                                  ZIP_LEGACY_WINDOW_SIZE);
  }
  return true;
}

static inline bool zip_legacy_output_copy(ZipLegacyOutput *output,
                                          uint32_t distance,
                                          uint32_t length,
                                          bool zero_prefix) {

  if (distance == 0 || distance > ZIP_LEGACY_WINDOW_SIZE
      || length > output->expected - output->produced) {
    return false;
  }
  for (uint32_t index = 0; index < length; index++) {
    uint8_t value = 0;

    if (distance <= output->produced) {
      const uint64_t source = output->produced - distance;

      value = output->window[source & (ZIP_LEGACY_WINDOW_SIZE - 1)];
    }
    else if (!zero_prefix) {
      return false;
    }
    if (!zip_legacy_output_byte(output, value)) {
      return false;
    }
  }
  return true;
}

static inline uint32_t zip_legacy_output_crc(ZipLegacyOutput *output) {

  const uint32_t remaining = (uint32_t)(output->produced
                                        & (ZIP_LEGACY_WINDOW_SIZE - 1));

  if (remaining > 0) {
    output->crc = (uint32_t)crc32(output->crc, output->window, remaining);
  }
  return output->crc;
}

static inline bool zip_legacy_failure(const ZipEntry *entry,
                                      uint64_t input_progress,
                                      uint64_t output_progress_value,
                                      uint64_t *failure_offset,
                                      uint64_t *output_progress) {

  if (input_progress > entry->compressed_size) {
    input_progress = entry->compressed_size;
  }
  *failure_offset = entry->data_offset + input_progress;
  if (output_progress) {
    *output_progress = output_progress_value;
  }
  return false;
}

// PKWARE Shrink is a 9-to-13-bit LZW stream with explicit code-width and
// partial dictionary clear commands. The central-directory size and CRC
// provide the terminal decision.
//
static inline bool zip_verify_shrink_entry(const uint8_t *data,
                                           const ZipEntry *entry,
                                           uint64_t *failure_offset,
                                           uint64_t *output_progress) {

  const uint16_t empty = 256;
  uint16_t parents[ZIP_SHRINK_DICTIONARY_SIZE];
  uint8_t suffixes[ZIP_SHRINK_DICTIONARY_SIZE];
  uint8_t stack[ZIP_SHRINK_DICTIONARY_SIZE];
  ZipLegacyBitReader reader;
  ZipLegacyOutput output;
  uint16_t head = 257;
  uint8_t code_bits = 9;
  int32_t last_symbol = -1;
  uint8_t last_character = 0;

  if (output_progress) {
    *output_progress = 0;
  }
  memset(suffixes, 0, sizeof(suffixes));
  for (uint16_t index = 0; index < ZIP_SHRINK_DICTIONARY_SIZE; index++) {
    parents[index] = empty;
  }
  zip_legacy_bits_initialize(&reader, data + entry->data_offset,
                             entry->compressed_size);
  zip_legacy_output_initialize(&output, entry->uncompressed_size);

  while (output.produced < output.expected) {
    uint32_t value = 0;

    if (!zip_legacy_bits_read(&reader, code_bits, &value)
        || value >= ZIP_SHRINK_DICTIONARY_SIZE) {
      return zip_legacy_failure(entry, zip_legacy_bits_consumed(&reader),
                                output.produced, failure_offset,
                                output_progress);
    }
    if (value == 256) {
      if (!zip_legacy_bits_read(&reader, code_bits, &value)) {
        return zip_legacy_failure(entry, zip_legacy_bits_consumed(&reader),
                                  output.produced, failure_offset,
                                  output_progress);
      }
      if (value == 1) {
        if (code_bits >= 13) {
          return zip_legacy_failure(entry,
                                    zip_legacy_bits_consumed(&reader),
                                    output.produced, failure_offset,
                                    output_progress);
        }
        code_bits++;
        continue;
      }
      if (value != 2) {
        return zip_legacy_failure(entry, zip_legacy_bits_consumed(&reader),
                                  output.produced, failure_offset,
                                  output_progress);
      }

      memset(stack, 0, sizeof(stack));
      for (uint16_t index = 257; index < ZIP_SHRINK_DICTIONARY_SIZE;
           index++) {
        if (parents[index] != empty
            && parents[index] < ZIP_SHRINK_DICTIONARY_SIZE) {
          stack[parents[index]] = 1;
        }
      }
      for (uint16_t index = 257; index < ZIP_SHRINK_DICTIONARY_SIZE;
           index++) {
        if (stack[index] == 0) {
          parents[index] = empty;
        }
      }
      head = 257;
      continue;
    }

    bool inserted = false;

    if (head < ZIP_SHRINK_DICTIONARY_SIZE && last_symbol >= 0) {
      while (head < ZIP_SHRINK_DICTIONARY_SIZE
             && parents[head] != empty) {
        head++;
      }
      if (head < ZIP_SHRINK_DICTIONARY_SIZE) {
        parents[head] = (uint16_t)last_symbol;
        suffixes[head] = last_character;
        head++;
        inserted = true;
      }
    }

    last_symbol = (int32_t)value;
    uint16_t current = (uint16_t)value;
    uint16_t stack_size = 0;

    while (current >= 256) {
      if (current >= ZIP_SHRINK_DICTIONARY_SIZE
          || stack_size >= ZIP_SHRINK_DICTIONARY_SIZE) {
        return zip_legacy_failure(entry,
                                  zip_legacy_bits_consumed(&reader),
                                  output.produced, failure_offset,
                                  output_progress);
      }
      stack[stack_size++] = suffixes[current];
      current = parents[current];
      if (current == empty) {
        return zip_legacy_failure(entry,
                                  zip_legacy_bits_consumed(&reader),
                                  output.produced, failure_offset,
                                  output_progress);
      }
    }
    if (stack_size >= ZIP_SHRINK_DICTIONARY_SIZE) {
      return zip_legacy_failure(entry, zip_legacy_bits_consumed(&reader),
                                output.produced, failure_offset,
                                output_progress);
    }
    stack[stack_size++] = (uint8_t)current;
    last_character = (uint8_t)current;
    if (inserted) {
      suffixes[head - 1] = last_character;
    }
    if (stack_size > output.expected - output.produced) {
      return zip_legacy_failure(entry, zip_legacy_bits_consumed(&reader),
                                output.produced, failure_offset,
                                output_progress);
    }
    while (stack_size > 0) {
      if (!zip_legacy_output_byte(&output, stack[--stack_size])) {
        return zip_legacy_failure(entry,
                                  zip_legacy_bits_consumed(&reader),
                                  output.produced, failure_offset,
                                  output_progress);
      }
    }
  }

  if (output_progress) {
    *output_progress = output.produced;
  }
  if (zip_legacy_output_crc(&output) != entry->crc32) {
    return zip_legacy_failure(entry, zip_legacy_bits_consumed(&reader),
                              output.produced, failure_offset,
                              output_progress);
  }
  return true;
}

static inline bool zip_implode_read_tree(ZipLegacyBitReader *reader,
                                         uint16_t symbol_count,
                                         ZipLegacyHuffman *decoder) {

  uint8_t lengths[ZIP_LEGACY_HUFFMAN_SYMBOLS];
  uint16_t produced = 0;
  uint32_t records = 0;

  memset(lengths, 0, sizeof(lengths));
  if (!zip_legacy_bits_read(reader, 8, &records)) {
    return false;
  }
  records++;
  for (uint32_t record = 0; record < records; record++) {
    uint32_t descriptor = 0;

    if (!zip_legacy_bits_read(reader, 8, &descriptor)) {
      return false;
    }
    const uint16_t repeat = (uint16_t)((descriptor >> 4) + 1);
    const uint8_t length = (uint8_t)((descriptor & 15) + 1);

    if (repeat > symbol_count - produced) {
      return false;
    }
    for (uint16_t index = 0; index < repeat; index++) {
      lengths[produced++] = length;
    }
  }
  return produced == symbol_count
         && zip_legacy_huffman_build(decoder, lengths, symbol_count, 16,
                                     true, true);
}

// Implode carries complete Shannon-Fano trees before an LZ stream. Bit 1 of
// the general-purpose flags selects the 8 KiB dictionary and bit 2 selects a
// coded literal tree.
//
static inline bool zip_verify_implode_entry(const uint8_t *data,
                                            const ZipEntry *entry,
                                            uint64_t *failure_offset,
                                            uint64_t *output_progress) {

  ZipLegacyBitReader reader;
  ZipLegacyHuffman literal_decoder;
  ZipLegacyHuffman length_decoder;
  ZipLegacyHuffman distance_decoder;
  ZipLegacyOutput output;
  const bool coded_literals = (entry->flags & UINT16_C(4)) != 0;
  const uint8_t distance_bits = (entry->flags & UINT16_C(2)) != 0 ? 7 : 6;
  const uint16_t minimum_length = coded_literals ? 3 : 2;

  if (output_progress) {
    *output_progress = 0;
  }
  memset(&literal_decoder, 0, sizeof(literal_decoder));
  zip_legacy_bits_initialize(&reader, data + entry->data_offset,
                             entry->compressed_size);
  zip_legacy_output_initialize(&output, entry->uncompressed_size);

  if ((coded_literals
       && !zip_implode_read_tree(&reader, 256, &literal_decoder))
      || !zip_implode_read_tree(&reader, 64, &length_decoder)
      || !zip_implode_read_tree(&reader, 64, &distance_decoder)) {
    return zip_legacy_failure(entry, zip_legacy_bits_consumed(&reader),
                              output.produced, failure_offset,
                              output_progress);
  }

  while (output.produced < output.expected) {
    uint32_t literal = 0;

    if (!zip_legacy_bits_read(&reader, 1, &literal)) {
      return zip_legacy_failure(entry, zip_legacy_bits_consumed(&reader),
                                output.produced, failure_offset,
                                output_progress);
    }
    if (literal != 0) {
      uint16_t symbol = 0;

      if (coded_literals) {
        if (!zip_legacy_huffman_decode(&literal_decoder, &reader,
                                       &symbol)) {
          return zip_legacy_failure(entry,
                                    zip_legacy_bits_consumed(&reader),
                                    output.produced, failure_offset,
                                    output_progress);
        }
      }
      else {
        if (!zip_legacy_bits_read(&reader, 8, &literal)) {
          return zip_legacy_failure(entry,
                                    zip_legacy_bits_consumed(&reader),
                                    output.produced, failure_offset,
                                    output_progress);
        }
        symbol = (uint16_t)literal;
      }
      if (!zip_legacy_output_byte(&output, (uint8_t)symbol)) {
        return zip_legacy_failure(entry,
                                  zip_legacy_bits_consumed(&reader),
                                  output.produced, failure_offset,
                                  output_progress);
      }
      continue;
    }

    uint32_t low_distance = 0;
    uint16_t high_distance = 0;
    uint16_t length_symbol = 0;

    if (!zip_legacy_bits_read(&reader, distance_bits, &low_distance)
        || !zip_legacy_huffman_decode(&distance_decoder, &reader,
                                      &high_distance)
        || !zip_legacy_huffman_decode(&length_decoder, &reader,
                                      &length_symbol)) {
      return zip_legacy_failure(entry, zip_legacy_bits_consumed(&reader),
                                output.produced, failure_offset,
                                output_progress);
    }

    uint32_t length = (uint32_t)length_symbol + minimum_length;

    if (length_symbol == 63) {
      uint32_t extra = 0;

      if (!zip_legacy_bits_read(&reader, 8, &extra)) {
        return zip_legacy_failure(entry,
                                  zip_legacy_bits_consumed(&reader),
                                  output.produced, failure_offset,
                                  output_progress);
      }
      length += extra;
    }
    const uint32_t distance = ((uint32_t)high_distance << distance_bits)
                              + low_distance + 1;

    if (!zip_legacy_output_copy(&output, distance, length, true)) {
      return zip_legacy_failure(entry, zip_legacy_bits_consumed(&reader),
                                output.produced, failure_offset,
                                output_progress);
    }
  }

  if (output_progress) {
    *output_progress = output.produced;
  }
  if (zip_legacy_output_crc(&output) != entry->crc32) {
    return zip_legacy_failure(entry, zip_legacy_bits_consumed(&reader),
                              output.produced, failure_offset,
                              output_progress);
  }
  return true;
}

static inline bool zip_deflate64_read_dynamic_tables(
    ZipLegacyBitReader *reader,
    ZipLegacyHuffman *literal_decoder,
    ZipLegacyHuffman *distance_decoder) {

  static const uint8_t order[19] = {
      16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
  };
  uint8_t code_lengths[19];
  uint8_t lengths[288 + 32];
  ZipLegacyHuffman code_decoder;
  uint32_t value = 0;

  if (!zip_legacy_bits_read(reader, 5, &value)) {
    return false;
  }
  const uint16_t literal_count = (uint16_t)(value + 257);

  if (!zip_legacy_bits_read(reader, 5, &value)) {
    return false;
  }
  const uint16_t distance_count = (uint16_t)(value + 1);

  if (!zip_legacy_bits_read(reader, 4, &value)
      || literal_count > 286 || distance_count > 32) {
    return false;
  }
  const uint16_t code_count = (uint16_t)(value + 4);

  memset(code_lengths, 0, sizeof(code_lengths));
  memset(lengths, 0, sizeof(lengths));
  for (uint16_t index = 0; index < code_count; index++) {
    if (!zip_legacy_bits_read(reader, 3, &value)) {
      return false;
    }
    code_lengths[order[index]] = (uint8_t)value;
  }
  if (!zip_legacy_huffman_build(&code_decoder, code_lengths, 19, 7,
                                false, false)) {
    return false;
  }

  const uint16_t total = literal_count + distance_count;
  uint16_t produced = 0;

  while (produced < total) {
    uint16_t symbol = 0;

    if (!zip_legacy_huffman_decode(&code_decoder, reader, &symbol)) {
      return false;
    }
    if (symbol <= 15) {
      lengths[produced++] = (uint8_t)symbol;
      continue;
    }

    uint16_t repeat = 0;
    uint8_t repeated_length = 0;

    if (symbol == 16) {
      if (produced == 0 || !zip_legacy_bits_read(reader, 2, &value)) {
        return false;
      }
      repeat = (uint16_t)(value + 3);
      repeated_length = lengths[produced - 1];
    }
    else if (symbol == 17) {
      if (!zip_legacy_bits_read(reader, 3, &value)) {
        return false;
      }
      repeat = (uint16_t)(value + 3);
    }
    else if (symbol == 18) {
      if (!zip_legacy_bits_read(reader, 7, &value)) {
        return false;
      }
      repeat = (uint16_t)(value + 11);
    }
    else {
      return false;
    }
    if (repeat > total - produced) {
      return false;
    }
    for (uint16_t index = 0; index < repeat; index++) {
      lengths[produced++] = repeated_length;
    }
  }

  if (lengths[256] == 0
      || !zip_legacy_huffman_build(literal_decoder, lengths,
                                   literal_count, 15, false, false)
      || !zip_legacy_huffman_build(distance_decoder,
                                   lengths + literal_count,
                                   distance_count, 15, false, false)) {
    return false;
  }
  return true;
}

// Deflate64 follows raw DEFLATE framing with a 64 KiB history, two additional
// distance symbols, and a 16-bit extension for length symbol 285.
//
static inline bool zip_verify_deflate64_entry(const uint8_t *data,
                                              const ZipEntry *entry,
                                              uint64_t *failure_offset,
                                              uint64_t *output_progress) {

  static const uint16_t length_base[29] = {
      3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27,
      31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 3
  };
  static const uint8_t length_bits[29] = {
      0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
      2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 16
  };
  static const uint32_t distance_base[32] = {
      1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
      257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
      8193, 12289, 16385, 24577, 32769, 49153
  };
  static const uint8_t distance_bits[32] = {
      0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
      7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14
  };
  ZipLegacyBitReader reader;
  ZipLegacyOutput output;
  bool final_block = false;

  if (output_progress) {
    *output_progress = 0;
  }
  zip_legacy_bits_initialize(&reader, data + entry->data_offset,
                             entry->compressed_size);
  zip_legacy_output_initialize(&output, entry->uncompressed_size);

  while (!final_block) {
    uint32_t value = 0;
    uint32_t block_type = 0;

    if (!zip_legacy_bits_read(&reader, 1, &value)) {
      return zip_legacy_failure(entry, zip_legacy_bits_consumed(&reader),
                                output.produced, failure_offset,
                                output_progress);
    }
    final_block = value != 0;
    if (!zip_legacy_bits_read(&reader, 2, &block_type)
        || block_type == 3) {
      return zip_legacy_failure(entry, zip_legacy_bits_consumed(&reader),
                                output.produced, failure_offset,
                                output_progress);
    }
    if (block_type == 0) {
      uint32_t length = 0;
      uint32_t complement = 0;

      if (!zip_legacy_bits_align(&reader)
          || !zip_legacy_bits_read(&reader, 16, &length)
          || !zip_legacy_bits_read(&reader, 16, &complement)
          || (uint16_t)length != (uint16_t)~complement
          || length > output.expected - output.produced) {
        return zip_legacy_failure(entry,
                                  zip_legacy_bits_consumed(&reader),
                                  output.produced, failure_offset,
                                  output_progress);
      }
      for (uint32_t index = 0; index < length; index++) {
        if (!zip_legacy_bits_read(&reader, 8, &value)
            || !zip_legacy_output_byte(&output, (uint8_t)value)) {
          return zip_legacy_failure(entry,
                                    zip_legacy_bits_consumed(&reader),
                                    output.produced, failure_offset,
                                    output_progress);
        }
      }
      continue;
    }

    ZipLegacyHuffman literal_decoder;
    ZipLegacyHuffman distance_decoder;

    if (block_type == 1) {
      uint8_t literal_lengths[288];
      uint8_t distance_lengths[32];

      for (uint16_t symbol = 0; symbol < 144; symbol++) {
        literal_lengths[symbol] = 8;
      }
      for (uint16_t symbol = 144; symbol < 256; symbol++) {
        literal_lengths[symbol] = 9;
      }
      for (uint16_t symbol = 256; symbol < 280; symbol++) {
        literal_lengths[symbol] = 7;
      }
      for (uint16_t symbol = 280; symbol < 288; symbol++) {
        literal_lengths[symbol] = 8;
      }
      memset(distance_lengths, 5, sizeof(distance_lengths));
      if (!zip_legacy_huffman_build(&literal_decoder, literal_lengths,
                                    288, 15, true, false)
          || !zip_legacy_huffman_build(&distance_decoder,
                                       distance_lengths, 32, 15,
                                       true, false)) {
        return zip_legacy_failure(entry,
                                  zip_legacy_bits_consumed(&reader),
                                  output.produced, failure_offset,
                                  output_progress);
      }
    }
    else if (!zip_deflate64_read_dynamic_tables(
                 &reader, &literal_decoder, &distance_decoder)) {
      return zip_legacy_failure(entry, zip_legacy_bits_consumed(&reader),
                                output.produced, failure_offset,
                                output_progress);
    }

    for (;;) {
      uint16_t symbol = 0;

      if (!zip_legacy_huffman_decode(&literal_decoder, &reader, &symbol)) {
        return zip_legacy_failure(entry,
                                  zip_legacy_bits_consumed(&reader),
                                  output.produced, failure_offset,
                                  output_progress);
      }
      if (symbol < 256) {
        if (!zip_legacy_output_byte(&output, (uint8_t)symbol)) {
          return zip_legacy_failure(entry,
                                    zip_legacy_bits_consumed(&reader),
                                    output.produced, failure_offset,
                                    output_progress);
        }
        continue;
      }
      if (symbol == 256) {
        break;
      }
      if (symbol > 285) {
        return zip_legacy_failure(entry,
                                  zip_legacy_bits_consumed(&reader),
                                  output.produced, failure_offset,
                                  output_progress);
      }

      const uint16_t length_index = (uint16_t)(symbol - 257);
      uint32_t extra = 0;

      if (!zip_legacy_bits_read(&reader, length_bits[length_index],
                                &extra)) {
        return zip_legacy_failure(entry,
                                  zip_legacy_bits_consumed(&reader),
                                  output.produced, failure_offset,
                                  output_progress);
      }
      const uint32_t length = length_base[length_index] + extra;
      uint16_t distance_symbol = 0;

      if (!zip_legacy_huffman_decode(&distance_decoder, &reader,
                                     &distance_symbol)
          || distance_symbol >= 32
          || !zip_legacy_bits_read(&reader,
                                   distance_bits[distance_symbol],
                                   &extra)) {
        return zip_legacy_failure(entry,
                                  zip_legacy_bits_consumed(&reader),
                                  output.produced, failure_offset,
                                  output_progress);
      }
      const uint32_t distance = distance_base[distance_symbol] + extra;

      if (!zip_legacy_output_copy(&output, distance, length, false)) {
        return zip_legacy_failure(entry,
                                  zip_legacy_bits_consumed(&reader),
                                  output.produced, failure_offset,
                                  output_progress);
      }
    }
  }

  if (output_progress) {
    *output_progress = output.produced;
  }
  if (output.produced != output.expected
      || zip_legacy_output_crc(&output) != entry->crc32) {
    return zip_legacy_failure(entry, zip_legacy_bits_consumed(&reader),
                              output.produced, failure_offset,
                              output_progress);
  }
  return true;
}

// Inflate one raw DEFLATE member while tracking the first compressed byte at
// which the stream ceases to be valid. The central-directory CRC and size are
// checked after stream completion.
//
static inline bool zip_verify_deflate_entry(const uint8_t *data,
                                            const ZipEntry *entry,
                                            uint64_t *failure_offset,
                                            uint64_t *output_progress) {

  z_stream stream;
  uint8_t output[ZIP_VERIFY_BUFFER_SIZE];
  uint64_t supplied = 0;
  uLong crc = crc32(0L, Z_NULL, 0);
  bool ended = false;

  if (output_progress) {
    *output_progress = 0;
  }
  memset(&stream, 0, sizeof(stream));
  if (inflateInit2(&stream, -MAX_WBITS) != Z_OK) {
    return false;
  }

  while (!ended) {
    if (stream.avail_in == 0 && supplied < entry->compressed_size) {
      const uint64_t remaining = entry->compressed_size - supplied;
      const uInt chunk = (uInt)(remaining > UINT_MAX
                                    ? UINT_MAX : remaining);

      stream.next_in = (Bytef *)(data + entry->data_offset + supplied);
      stream.avail_in = chunk;
      supplied += chunk;
    }

    stream.next_out = output;
    stream.avail_out = sizeof(output);
    const int result = inflate(&stream, Z_NO_FLUSH);
    const uInt produced = (uInt)(sizeof(output) - stream.avail_out);

    if (produced > 0) {
      crc = crc32(crc, output, produced);
    }
    if (result == Z_STREAM_END) {
      ended = true;
      break;
    }
    if (result != Z_OK
        || (stream.avail_in == 0
            && supplied == entry->compressed_size
            && produced == 0)) {
      *failure_offset = entry->data_offset + supplied - stream.avail_in;
      if (output_progress) {
        *output_progress = stream.total_out;
      }
      inflateEnd(&stream);
      return false;
    }
  }

  const uint64_t consumed = supplied - stream.avail_in;
  const uint64_t produced_total = stream.total_out;

  if (output_progress) {
    *output_progress = produced_total;
  }
  inflateEnd(&stream);
  if (!ended || consumed > entry->compressed_size
      || produced_total != entry->uncompressed_size
      || (uint32_t)crc != entry->crc32) {
    *failure_offset = entry->data_offset + consumed;
    return false;
  }
  return true;
}

// Feed a bounded raw-DEFLATE segment without reading beyond its end. Leaving
// zlib waiting for more input is a successful prefix operation.
//
static inline ZipInflateFeedResult zip_deflate_feed(
    z_stream *stream,
    const uint8_t *data,
    uint64_t length,
    uLong *crc,
    uint64_t *consumed) {

  uint8_t output[ZIP_VERIFY_BUFFER_SIZE];
  uint64_t offset = 0;

  if (consumed) {
    *consumed = 0;
  }
  if (!stream || !crc || (!data && length > 0)) {
    return ZIP_INFLATE_FAILED;
  }

  while (offset < length) {
    const uint64_t remaining = length - offset;
    const uInt chunk = (uInt)(remaining > UINT_MAX
                                  ? UINT_MAX : remaining);

    stream->next_in = (Bytef *)(data + offset);
    stream->avail_in = chunk;

    for (;;) {
      const uInt before_input = stream->avail_in;

      stream->next_out = output;
      stream->avail_out = sizeof(output);
      const int result = inflate(stream, Z_NO_FLUSH);
      const uInt used = before_input - stream->avail_in;
      const uInt produced = (uInt)(sizeof(output) - stream->avail_out);

      offset += used;
      if (produced > 0) {
        *crc = crc32(*crc, output, produced);
      }
      if (result == Z_STREAM_END) {
        if (consumed) {
          *consumed = offset;
        }
        return ZIP_INFLATE_ENDED;
      }
      if (result == Z_BUF_ERROR && stream->avail_in == 0
          && produced == 0) {
        break;
      }
      if (result != Z_OK || (used == 0 && produced == 0)) {
        if (consumed) {
          *consumed = offset;
        }
        return ZIP_INFLATE_FAILED;
      }
      if (stream->avail_in == 0 && stream->avail_out != 0) {
        break;
      }
    }
  }

  if (consumed) {
    *consumed = offset;
  }
  return ZIP_INFLATE_NEEDS_INPUT;
}

// Inflate the known prefix once and retain zlib's dictionary and bit state at
// the exact byte where a candidate source run begins.
//
static inline bool zip_deflate_prefix_initialize(
    const uint8_t *data,
    const ZipStateEntry *entry,
    uint64_t patch_start,
    uint64_t patch_end,
    ZipDeflatePrefix *prefix) {

  if (!data || !entry || !prefix || entry->method != ZIP_METHOD_DEFLATE
      || entry->data_offset > UINT64_MAX - entry->compressed_size) {
    return false;
  }

  const uint64_t entry_end = entry->data_offset + entry->compressed_size;

  if (patch_start < entry->data_offset || patch_start >= patch_end
      || patch_end > entry_end) {
    return false;
  }

  memset(prefix, 0, sizeof(*prefix));
  if (inflateInit2(&prefix->stream, -MAX_WBITS) != Z_OK) {
    return false;
  }
  prefix->initialized = true;
  prefix->crc = crc32(0L, Z_NULL, 0);
  prefix->patch_start = patch_start;
  prefix->patch_end = patch_end;

  uint64_t consumed = 0;
  const ZipInflateFeedResult result = zip_deflate_feed(
      &prefix->stream, data + entry->data_offset,
      patch_start - entry->data_offset, &prefix->crc, &consumed);

  if (result != ZIP_INFLATE_NEEDS_INPUT
      || consumed != patch_start - entry->data_offset) {
    zip_deflate_prefix_clear(prefix);
    return false;
  }
  return true;
}

static inline void zip_deflate_prefix_clear(ZipDeflatePrefix *prefix) {

  if (!prefix) {
    return;
  }
  if (prefix->initialized) {
    (void)inflateEnd(&prefix->stream);
  }
  memset(prefix, 0, sizeof(*prefix));
}

// Resume a saved DEFLATE prefix with bytes from an actual source run, then
// finish with the unchanged suffix. A false return means the optimized probe
// was unavailable and the caller must use ordinary trial materialization.
//
static inline bool zip_deflate_prefix_probe(
    const ZipDeflatePrefix *prefix,
    const uint8_t *baseline,
    const ZipStateEntry *entry,
    int64_t source_actual,
    uint64_t source_offset,
    bool *valid,
    uint64_t *failure_offset,
    uint64_t *output_progress) {

  if (valid) {
    *valid = false;
  }
  if (output_progress) {
    *output_progress = 0;
  }
  if (!prefix || !prefix->initialized || !baseline || !entry || !valid
      || !failure_offset || source_actual < 0
      || scalpel_state.blocksize == 0
      || entry->data_offset > UINT64_MAX - entry->compressed_size
      || prefix->patch_start >= prefix->patch_end) {
    return false;
  }

  z_stream stream;

  memset(&stream, 0, sizeof(stream));
  if (inflateCopy(&stream, (z_stream *)&prefix->stream) != Z_OK) {
    return false;
  }

  uLong crc = prefix->crc;
  uint64_t patch_consumed = 0;
  uint64_t suffix_consumed = 0;
  uint64_t source_position = source_offset;
  const uint64_t patch_length = prefix->patch_end - prefix->patch_start;
  ZipInflateFeedResult result = ZIP_INFLATE_NEEDS_INPUT;

  while (patch_consumed < patch_length
         && result == ZIP_INFLATE_NEEDS_INPUT) {
    const uint64_t block_offset = source_position
                                  / scalpel_state.blocksize;
    const uint64_t in_block = source_position
                              % scalpel_state.blocksize;

    if (block_offset > INT64_MAX
        || source_actual > INT64_MAX - (int64_t)block_offset) {
      (void)inflateEnd(&stream);
      return false;
    }

    uint64_t block_length = 0;
    const uint8_t *block = (const uint8_t *)
        filemirror_actual_block_data_pointer(
            scalpel_state.filemirror,
            source_actual + (int64_t)block_offset,
            &block_length);

    if (!block || in_block >= block_length) {
      (void)inflateEnd(&stream);
      return false;
    }

    uint64_t available = block_length - in_block;

    if (available > patch_length - patch_consumed) {
      available = patch_length - patch_consumed;
    }

    uint64_t segment_consumed = 0;

    result = zip_deflate_feed(&stream, block + in_block, available,
                              &crc, &segment_consumed);
    patch_consumed += segment_consumed;
    source_position += segment_consumed;
    if (segment_consumed < available
        && result == ZIP_INFLATE_NEEDS_INPUT) {
      result = ZIP_INFLATE_FAILED;
    }
  }

  if (result == ZIP_INFLATE_FAILED) {
    *failure_offset = prefix->patch_start + patch_consumed;
  }
  else if (result == ZIP_INFLATE_NEEDS_INPUT) {
    const uint64_t entry_end = entry->data_offset
                               + entry->compressed_size;

    result = zip_deflate_feed(
        &stream, baseline + prefix->patch_end,
        entry_end - prefix->patch_end, &crc, &suffix_consumed);
    if (result == ZIP_INFLATE_FAILED) {
      *failure_offset = prefix->patch_end + suffix_consumed;
    }
    else if (result == ZIP_INFLATE_NEEDS_INPUT) {
      *failure_offset = entry_end;
    }
  }

  const uint64_t produced = stream.total_out;

  if (output_progress) {
    *output_progress = produced;
  }
  if (result == ZIP_INFLATE_ENDED) {
    *failure_offset = prefix->patch_start + patch_consumed
                      + suffix_consumed;
    *valid = produced == entry->uncompressed_size
             && (uint32_t)crc == entry->crc32;
  }
  (void)inflateEnd(&stream);
  return true;
}

static inline bool zip_verify_bzip2_entry(const uint8_t *data,
                                          const ZipEntry *entry,
                                          uint64_t *failure_offset,
                                          uint64_t *output_progress) {

  bz_stream stream;
  uint8_t output[ZIP_VERIFY_BUFFER_SIZE];
  uint64_t supplied = 0;
  uint64_t produced_total = 0;
  uint32_t crc = (uint32_t)crc32(0L, Z_NULL, 0);
  bool ended = false;

  if (output_progress) {
    *output_progress = 0;
  }
  memset(&stream, 0, sizeof(stream));
  if (BZ2_bzDecompressInit(&stream, 0, 0) != BZ_OK) {
    *failure_offset = entry->data_offset;
    return false;
  }

  for (;;) {
    if (stream.avail_in == 0 && supplied < entry->compressed_size) {
      const uint64_t remaining = entry->compressed_size - supplied;
      const unsigned int chunk = (unsigned int)(
          remaining > UINT_MAX ? UINT_MAX : remaining);

      stream.next_in = (char *)(data + entry->data_offset + supplied);
      stream.avail_in = chunk;
      supplied += chunk;
    }

    stream.next_out = (char *)output;
    stream.avail_out = sizeof(output);
    const int result = BZ2_bzDecompress(&stream);
    const unsigned int produced = (unsigned int)(
        sizeof(output) - stream.avail_out);

    if (produced > 0) {
      crc = (uint32_t)crc32(crc, output, produced);
      produced_total += produced;
    }
    if (result == BZ_STREAM_END) {
      ended = true;
      break;
    }
    if (result != BZ_OK
        || (stream.avail_in == 0
            && supplied == entry->compressed_size
            && produced == 0)) {
      const uint64_t consumed = supplied - stream.avail_in;

      *failure_offset = entry->data_offset + consumed;
      if (output_progress) {
        *output_progress = produced_total;
      }
      BZ2_bzDecompressEnd(&stream);
      return false;
    }
  }

  const uint64_t consumed = supplied - stream.avail_in;

  if (output_progress) {
    *output_progress = produced_total;
  }
  BZ2_bzDecompressEnd(&stream);
  if (!ended || consumed > entry->compressed_size
      || produced_total != entry->uncompressed_size
      || crc != entry->crc32) {
    *failure_offset = entry->data_offset + consumed;
    return false;
  }
  return true;
}

static inline bool zip_verify_lzma_entry(const uint8_t *data,
                                         const ZipEntry *entry,
                                         uint64_t *failure_offset,
                                         uint64_t *output_progress) {

  if (output_progress) {
    *output_progress = 0;
  }
  if (entry->compressed_size < 5) {
    *failure_offset = entry->data_offset;
    return false;
  }

  const uint8_t *compressed = data + entry->data_offset;
  const uint16_t properties_size = zip_read_le16(compressed + 2);
  uint64_t stream_offset = 0;

  if (__builtin_add_overflow(UINT64_C(4),
                             (uint64_t)properties_size,
                             &stream_offset)
      || stream_offset >= entry->compressed_size) {
    *failure_offset = entry->data_offset;
    return false;
  }

  lzma_filter filters[2];
  lzma_stream stream = LZMA_STREAM_INIT;

  memset(filters, 0, sizeof(filters));
  filters[0].id = LZMA_FILTER_LZMA1;
  filters[1].id = LZMA_VLI_UNKNOWN;
  if (lzma_properties_decode(&filters[0], NULL,
                             compressed + 4, properties_size) != LZMA_OK) {
    free(filters[0].options);
    *failure_offset = entry->data_offset;
    return false;
  }

#if defined(LZMA_FILTER_LZMA1EXT)
  lzma_options_lzma *options = (lzma_options_lzma *)filters[0].options;

  filters[0].id = LZMA_FILTER_LZMA1EXT;
  options->ext_flags = (entry->flags & ZIP_FLAG_LZMA_EOPM) != 0
                       ? LZMA_LZMA1EXT_ALLOW_EOPM : 0;
  lzma_set_ext_size(*options, entry->uncompressed_size);
#endif

  if (lzma_raw_decoder(&stream, filters) != LZMA_OK) {
    free(filters[0].options);
    *failure_offset = entry->data_offset;
    return false;
  }
  free(filters[0].options);

  uint8_t output[ZIP_VERIFY_BUFFER_SIZE];
  const uint64_t compressed_stream_size = entry->compressed_size
                                          - stream_offset;
  uint64_t supplied = 0;
  uint64_t produced_total = 0;
  uint32_t crc = (uint32_t)crc32(0L, Z_NULL, 0);
  bool ended = false;

  for (;;) {
    if (stream.avail_in == 0 && supplied < compressed_stream_size) {
      const uint64_t remaining = compressed_stream_size - supplied;
      const size_t chunk = (size_t)(
          remaining > SIZE_MAX ? SIZE_MAX : remaining);

      stream.next_in = compressed + stream_offset + supplied;
      stream.avail_in = chunk;
      supplied += chunk;
    }

    const uint64_t output_remaining = entry->uncompressed_size
                                      - produced_total;
    const size_t output_capacity = output_remaining < sizeof(output)
                                   ? (size_t)output_remaining
                                   : sizeof(output);

    stream.next_out = output;
    stream.avail_out = output_capacity > 0 ? output_capacity : 1;
    const size_t available_before = stream.avail_out;
    const lzma_ret result = lzma_code(&stream, LZMA_RUN);
    const size_t produced = available_before - stream.avail_out;

    if (produced > output_remaining) {
      const uint64_t consumed = supplied - stream.avail_in;

      *failure_offset = entry->data_offset + stream_offset + consumed;
      lzma_end(&stream);
      return false;
    }
    if (produced > 0) {
      crc = (uint32_t)crc32(crc, output, (uInt)produced);
      produced_total += produced;
    }
    if (result == LZMA_STREAM_END) {
      ended = true;
      break;
    }
    if (result != LZMA_OK
#if !defined(LZMA_FILTER_LZMA1EXT)
        && !(result == LZMA_BUF_ERROR
             && produced_total == entry->uncompressed_size)
#endif
       ) {
      const uint64_t consumed = supplied - stream.avail_in;

      *failure_offset = entry->data_offset + stream_offset + consumed;
      if (output_progress) {
        *output_progress = produced_total;
      }
      lzma_end(&stream);
      return false;
    }
#if !defined(LZMA_FILTER_LZMA1EXT)
    // Older liblzma releases cannot decode markerless LZMA1 directly. The
    // declared output size and CRC still provide an exact validation boundary.
    if (produced_total == entry->uncompressed_size) {
      ended = true;
      break;
    }
#endif
    if (stream.avail_in == 0
        && supplied == compressed_stream_size
        && produced == 0) {
      const uint64_t consumed = supplied - stream.avail_in;

      *failure_offset = entry->data_offset + stream_offset + consumed;
      if (output_progress) {
        *output_progress = produced_total;
      }
      lzma_end(&stream);
      return false;
    }
  }

  const uint64_t consumed = supplied - stream.avail_in;

  if (output_progress) {
    *output_progress = produced_total;
  }
  lzma_end(&stream);
  if (!ended || consumed > compressed_stream_size
      || produced_total != entry->uncompressed_size
      || crc != entry->crc32) {
    *failure_offset = entry->data_offset + stream_offset + consumed;
    return false;
  }
  return true;
}

static inline bool zip_verify_zstd_entry(const uint8_t *data,
                                         const ZipEntry *entry,
                                         uint64_t *failure_offset,
                                         uint64_t *output_progress) {

  uint8_t output[ZIP_VERIFY_BUFFER_SIZE];
  ZSTD_DStream *stream = ZSTD_createDStream();
  uint64_t supplied = 0;
  uint64_t produced_total = 0;
  uint32_t crc = (uint32_t)crc32(0L, Z_NULL, 0);
  ZSTD_inBuffer input = {NULL, 0, 0};
  bool ended = false;

  if (output_progress) {
    *output_progress = 0;
  }
  if (!stream || ZSTD_isError(ZSTD_initDStream(stream))) {
    ZSTD_freeDStream(stream);
    *failure_offset = entry->data_offset;
    return false;
  }

  for (;;) {
    if (input.pos == input.size && supplied < entry->compressed_size) {
      const uint64_t remaining = entry->compressed_size - supplied;
      const size_t chunk = (size_t)(remaining > ZIP_ZSTD_INPUT_SIZE
                                        ? ZIP_ZSTD_INPUT_SIZE : remaining);

      input.src = data + entry->data_offset + supplied;
      input.size = chunk;
      input.pos = 0;
      supplied += chunk;
    }

    ZSTD_outBuffer destination = {output, sizeof(output), 0};
    const size_t previous_input = input.pos;
    const size_t result = ZSTD_decompressStream(stream, &destination,
                                                &input);

    if (destination.pos > 0) {
      if ((uint64_t)destination.pos > UINT64_MAX - produced_total) {
        const uint64_t consumed = supplied - (input.size - input.pos);

        *failure_offset = entry->data_offset + consumed;
        ZSTD_freeDStream(stream);
        return false;
      }
      crc = (uint32_t)crc32(crc, output, (uInt)destination.pos);
      produced_total += destination.pos;
      if (produced_total > entry->uncompressed_size) {
        const uint64_t consumed = supplied - (input.size - input.pos);

        *failure_offset = entry->data_offset + consumed;
        if (output_progress) {
          *output_progress = produced_total;
        }
        ZSTD_freeDStream(stream);
        return false;
      }
    }
    if (ZSTD_isError(result)) {
      const uint64_t consumed = supplied - (input.size - input.pos);

      *failure_offset = entry->data_offset + consumed;
      if (output_progress) {
        *output_progress = produced_total;
      }
      ZSTD_freeDStream(stream);
      return false;
    }
    if (result == 0) {
      ended = true;
      break;
    }
    if (input.pos == previous_input && destination.pos == 0
        && supplied == entry->compressed_size) {
      const uint64_t consumed = supplied - (input.size - input.pos);

      *failure_offset = entry->data_offset + consumed;
      if (output_progress) {
        *output_progress = produced_total;
      }
      ZSTD_freeDStream(stream);
      return false;
    }
  }

  const uint64_t consumed = supplied - (input.size - input.pos);

  if (output_progress) {
    *output_progress = produced_total;
  }
  ZSTD_freeDStream(stream);
  if (!ended || consumed > entry->compressed_size
      || produced_total != entry->uncompressed_size
      || crc != entry->crc32) {
    *failure_offset = entry->data_offset + consumed;
    return false;
  }
  return true;
}

// Decode a standard XZ stream while retaining the compressed-input position
// reached before an error. ZIP method 95 stores the XZ stream directly.
//
static inline bool zip_verify_xz_entry(const uint8_t *data,
                                       const ZipEntry *entry,
                                       uint64_t *failure_offset,
                                       uint64_t *output_progress) {

  lzma_stream stream = LZMA_STREAM_INIT;
  uint8_t output[ZIP_VERIFY_BUFFER_SIZE];
  uint64_t supplied = 0;
  uint64_t produced_total = 0;
  uint32_t crc = (uint32_t)crc32(0L, Z_NULL, 0);
  bool ended = false;

  if (output_progress) {
    *output_progress = 0;
  }
  if (lzma_stream_decoder(&stream, UINT64_MAX,
                          LZMA_CONCATENATED) != LZMA_OK) {
    *failure_offset = entry->data_offset;
    return false;
  }

  for (;;) {
    if (stream.avail_in == 0 && supplied < entry->compressed_size) {
      const uint64_t remaining = entry->compressed_size - supplied;
      const size_t chunk = (size_t)(remaining > SIZE_MAX
                                        ? SIZE_MAX : remaining);

      stream.next_in = data + entry->data_offset + supplied;
      stream.avail_in = chunk;
      supplied += chunk;
    }

    stream.next_out = output;
    stream.avail_out = sizeof(output);
    const lzma_action action = supplied == entry->compressed_size
                               ? LZMA_FINISH : LZMA_RUN;
    const lzma_ret result = lzma_code(&stream, action);
    const size_t produced = sizeof(output) - stream.avail_out;

    if (produced > 0) {
      if ((uint64_t)produced > UINT64_MAX - produced_total) {
        const uint64_t consumed = supplied - stream.avail_in;

        *failure_offset = entry->data_offset + consumed;
        lzma_end(&stream);
        return false;
      }
      crc = (uint32_t)crc32(crc, output, (uInt)produced);
      produced_total += produced;
      if (produced_total > entry->uncompressed_size) {
        const uint64_t consumed = supplied - stream.avail_in;

        *failure_offset = entry->data_offset + consumed;
        if (output_progress) {
          *output_progress = produced_total;
        }
        lzma_end(&stream);
        return false;
      }
    }
    if (result == LZMA_STREAM_END) {
      ended = true;
      break;
    }
    if (result != LZMA_OK
        || (stream.avail_in == 0
            && supplied == entry->compressed_size
            && produced == 0)) {
      const uint64_t consumed = supplied - stream.avail_in;

      *failure_offset = entry->data_offset + consumed;
      if (output_progress) {
        *output_progress = produced_total;
      }
      lzma_end(&stream);
      return false;
    }
  }

  const uint64_t consumed = supplied - stream.avail_in;

  if (output_progress) {
    *output_progress = produced_total;
  }
  lzma_end(&stream);
  if (!ended || consumed > entry->compressed_size
      || produced_total != entry->uncompressed_size
      || crc != entry->crc32) {
    *failure_offset = entry->data_offset + consumed;
    return false;
  }
  return true;
}

static inline bool zip_verify_supported_entry(const uint8_t *data,
                                              const ZipEntry *entry,
                                              bool *supported,
                                              uint64_t *failure_offset,
                                              uint64_t *output_progress) {

  *supported = true;
  if (entry->method == ZIP_METHOD_STORED) {
    if (output_progress) {
      *output_progress = entry->uncompressed_size;
    }
    if (entry->compressed_size != entry->uncompressed_size
        || zip_crc32(data + entry->data_offset,
                     entry->compressed_size) != entry->crc32) {
      *failure_offset = entry->data_offset;
      return false;
    }
    return true;
  }
  if (entry->method == ZIP_METHOD_SHRINK) {
    return zip_verify_shrink_entry(data, entry, failure_offset,
                                   output_progress);
  }
  if (entry->method == ZIP_METHOD_IMPLODE) {
    return zip_verify_implode_entry(data, entry, failure_offset,
                                    output_progress);
  }
  if (entry->method == ZIP_METHOD_DEFLATE) {
    return zip_verify_deflate_entry(data, entry, failure_offset,
                                    output_progress);
  }
  if (entry->method == ZIP_METHOD_DEFLATE64) {
    return zip_verify_deflate64_entry(data, entry, failure_offset,
                                      output_progress);
  }
  if (entry->method == ZIP_METHOD_BZIP2) {
    return zip_verify_bzip2_entry(data, entry, failure_offset,
                                  output_progress);
  }
  if (entry->method == ZIP_METHOD_LZMA) {
    return zip_verify_lzma_entry(data, entry, failure_offset,
                                 output_progress);
  }
  if (entry->method == ZIP_METHOD_ZSTD) {
    return zip_verify_zstd_entry(data, entry, failure_offset,
                                 output_progress);
  }
  if (entry->method == ZIP_METHOD_XZ) {
    return zip_verify_xz_entry(data, entry, failure_offset,
                               output_progress);
  }

  *supported = false;
  return true;
}

// Some valid archives begin with local records that are intentionally omitted
// from the central directory. Verify that the complete prefix is a chain of
// self-consistent records rather than accepting arbitrary bytes before the
// first centrally indexed member.
static inline bool zip_validate_unreferenced_prefix(
    const uint8_t *data,
    uint64_t prefix_end,
    uint64_t *failure_offset) {

  if (prefix_end == sizeof(uint32_t)
      && zip_read_le32(data) == ZIP_SINGLE_SEGMENT_MARKER) {
    return true;
  }

  uint64_t position = 0;

  while (position < prefix_end) {
    const uint64_t record_start = position;

    if (!zip_range_available(prefix_end, position, ZIP_LOCAL_HEADER_SIZE)
        || zip_read_le32(data + position) != ZIP_LOCAL_HEADER_SIGNATURE) {
      *failure_offset = position;
      return false;
    }

    ZipEntry entry;
    const uint16_t name_length = zip_read_le16(data + position + 26);
    const uint16_t extra_length = zip_read_le16(data + position + 28);
    const uint32_t compressed32 = zip_read_le32(data + position + 18);
    const uint32_t uncompressed32 = zip_read_le32(data + position + 22);

    memset(&entry, 0, sizeof(entry));
    entry.flags = zip_read_le16(data + position + 6);
    entry.method = zip_read_le16(data + position + 8);
    entry.crc32 = zip_read_le32(data + position + 14);
    entry.compressed_size = compressed32;
    entry.uncompressed_size = uncompressed32;
    entry.name_length = name_length;
    entry.local_offset = position;
    entry.observed_local_offset = position;

    if ((entry.flags & (ZIP_FLAG_ENCRYPTED | ZIP_FLAG_DATA_DESCRIPTOR)) != 0
        || entry.method == ZIP_METHOD_AES
        || __builtin_add_overflow(position, ZIP_LOCAL_HEADER_SIZE, &position)
        || __builtin_add_overflow(position, (uint64_t)name_length, &position)
        || __builtin_add_overflow(position, (uint64_t)extra_length, &position)
        || position > prefix_end) {
      *failure_offset = record_start;
      return false;
    }

    const uint8_t *extra = data + record_start + ZIP_LOCAL_HEADER_SIZE
                           + name_length;
    uint64_t unused_offset = 0;
    uint32_t unused_disk = 0;
    const bool need_uncompressed =
        uncompressed32 == ZIP_UINT32_SENTINEL;
    const bool need_compressed = compressed32 == ZIP_UINT32_SENTINEL;

    if ((need_uncompressed || need_compressed)
        && !zip_parse_zip64_extra(
               extra, extra_length, need_uncompressed, need_compressed,
               false, false, &entry.uncompressed_size,
               &entry.compressed_size, &unused_offset, &unused_disk)) {
      *failure_offset = record_start;
      return false;
    }

    entry.data_offset = position;
    entry.observed_data_offset = position;
    if (__builtin_add_overflow(position, entry.compressed_size, &position)
        || position > prefix_end) {
      *failure_offset = entry.data_offset;
      return false;
    }
    entry.range_end = position;

    bool supported = false;

    if (!zip_verify_supported_entry(data, &entry, &supported,
                                    failure_offset, NULL)
        || !supported) {
      if (!supported) {
        *failure_offset = record_start;
      }
      return false;
    }
  }
  return position == prefix_end;
}

static inline bool zip_verify_entry_data(const uint8_t *data,
                                         const ZipLayout *layout,
                                         bool *needs_libarchive,
                                         uint64_t *failure_offset,
                                         uint64_t *failure_entry) {

  *needs_libarchive = false;
  *failure_entry = UINT64_MAX;
  for (uint64_t index = 0; index < layout->entry_count; index++) {
    const ZipEntry *entry = &layout->entries[index];

    if (entry->encrypted) {
      continue;
    }
    bool supported = false;

    if (!zip_verify_supported_entry(data, entry, &supported,
                                    failure_offset, NULL)) {
      *failure_entry = index;
      return false;
    }
    if (!supported) {
      *needs_libarchive = true;
    }
  }
  return true;
}

static inline bool zip_verify_with_libarchive(const uint8_t *data,
                                              const ZipLayout *layout) {

  if (!data || !layout || !layout->entries
      || layout->entry_count == 0
      || layout->archive_size > SIZE_MAX
      || layout->entry_count > SIZE_MAX / sizeof(bool)) {
    return false;
  }

  struct archive *archive = archive_read_new();

  if (!archive) {
    return false;
  }
  if (archive_read_support_filter_all(archive) != ARCHIVE_OK
      || archive_read_support_format_zip_seekable(archive) != ARCHIVE_OK
      || archive_read_open_memory(archive, data,
                                  (size_t)layout->archive_size)
             != ARCHIVE_OK) {
    archive_read_free(archive);
    return false;
  }

  uint8_t buffer[ZIP_VERIFY_BUFFER_SIZE];
  uint64_t entries = 0;
  bool valid = true;
  bool *matched = (bool *)calloc((size_t)layout->entry_count,
                                 sizeof(*matched));

  check_memory_allocation(matched, __LINE__, __FILE__,
                          "ZIP libarchive entry map");

  for (;;) {
    struct archive_entry *entry = NULL;
    const int header_result = archive_read_next_header(archive, &entry);

    if (header_result == ARCHIVE_EOF) {
      break;
    }
    if (header_result != ARCHIVE_OK && header_result != ARCHIVE_WARN) {
      valid = false;
      break;
    }
    if (entries >= layout->entry_count) {
      valid = false;
      break;
    }

    entries++;

    uint64_t produced = 0;
    uint32_t crc = (uint32_t)crc32(0L, Z_NULL, 0);

    for (;;) {
      const la_ssize_t count = archive_read_data(archive, buffer,
                                                 sizeof(buffer));

      if (count == 0) {
        break;
      }
      if (count < 0) {
        valid = false;
        break;
      }
      if ((uint64_t)count > UINT64_MAX - produced) {
        valid = false;
        break;
      }
      produced += (uint64_t)count;
      crc = (uint32_t)crc32(crc, buffer, (uInt)count);
    }
    if (!valid) {
      break;
    }

    const char *pathname = archive_entry_pathname(entry);
    const size_t pathname_length = pathname ? strlen(pathname) : 0;
    uint64_t expected_index = UINT64_MAX;

    for (uint64_t index = 0; index < layout->entry_count; index++) {
      const ZipEntry *expected = &layout->entries[index];

      if (!matched[index] && !expected->encrypted
          && produced == expected->uncompressed_size
          && crc == expected->crc32
          && pathname && pathname_length == expected->name_length
          && memcmp(pathname, expected->name, pathname_length) == 0) {
        expected_index = index;
        break;
      }
    }
    if (expected_index == UINT64_MAX) {
      for (uint64_t index = 0; index < layout->entry_count; index++) {
        const ZipEntry *expected = &layout->entries[index];

        if (!matched[index] && !expected->encrypted
            && produced == expected->uncompressed_size
            && crc == expected->crc32) {
          expected_index = index;
          break;
        }
      }
    }
    if (expected_index == UINT64_MAX) {
      valid = false;
      break;
    }
    matched[expected_index] = true;
  }

  if (archive_read_close(archive) != ARCHIVE_OK) {
    valid = false;
  }
  archive_read_free(archive);
  free(matched);
  return valid && entries == layout->entry_count;
}

// Find the first EOCD whose complete metadata and member data validate. The
// input buffer may contain lookahead bytes after the archive, so EOCD need not
// be at the end of the supplied buffer.
//
static inline bool zip_find_layout(const uint8_t *data,
                                   uint64_t length,
                                   uint32_t blocksize,
                                   ZipLayout *layout,
                                   uint64_t *failure_offset,
                                   uint64_t *failure_entry,
                                   bool *content_valid) {

  uint64_t search = 4;

  *failure_entry = UINT64_MAX;
  *content_valid = false;

  while (zip_range_available(length, search, ZIP_EOCD_SIZE)) {
    const uint8_t *found = (const uint8_t *)memchr(
        data + search, 'P', (size_t)(length - search));

    if (!found) {
      break;
    }

    const uint64_t offset = (uint64_t)(found - data);
    search = offset + 1;
    if (!zip_range_available(length, offset, ZIP_EOCD_SIZE)
        || zip_read_le32(data + offset) != ZIP_EOCD_SIGNATURE) {
      continue;
    }

    ZipLayout trial;
    uint64_t trial_failure = offset;

    memset(&trial, 0, sizeof(trial));
    if (!zip_parse_eocd(data, length, offset, &trial)
        || !zip_parse_central_directory(data, length, &trial,
                                        &trial_failure)
        || !zip_parse_local_headers(data, length, blocksize, &trial,
                                    &trial_failure)) {
      if (trial_failure > *failure_offset) {
        *failure_offset = trial_failure;
      }
      zip_layout_clear(&trial);
      continue;
    }
    zip_classify_office_layout(&trial);

    bool needs_libarchive = false;

    if (!zip_verify_entry_data(data, &trial, &needs_libarchive,
                               &trial_failure, failure_entry)
        || (needs_libarchive && !trial.encrypted
            && !zip_verify_with_libarchive(data, &trial))) {
      if (trial_failure > *failure_offset) {
        *failure_offset = trial_failure;
      }
      *layout = trial;
      return true;
    }

    *layout = trial;
    *content_valid = true;
    return true;
  }
  return false;
}

static inline void zip_set_partial(uint64_t failure_offset,
                                   uint32_t blocksize,
                                   uint64_t *validates_to) {

  if (failure_offset <= 4 || blocksize == 0) {
    *validates_to = 3;
    return;
  }

  const uint64_t failing_block = failure_offset / blocksize;

  *validates_to = failing_block == 0
                      ? 3
                      : failing_block * (uint64_t)blocksize - 1;
}

// The normal scan owns its decoder-independent progress. Scratch inflater and
// block-index data are rebuilt, but completed source trials are not repeated.
static inline void zip_normal_scan_clear(ZipCarveState *state) {
  if (!state || !state->normal_scan) {
    return;
  }
  ZipNormalScanState *scan = state->normal_scan;
  roaring64_bitmap_free(scan->completed);
  roaring64_bitmap_free(scan->pruned);
  free(scan->outcomes);
  free(scan);
  state->normal_scan = NULL;
}

static inline uint64_t zip_normal_scan_signature(
    CarveInfo *candidate, const ZipCarveState *state,
    const uint8_t *baseline, uint64_t output, uint64_t run_last) {
  uint64_t hash = XXH3_64bits(baseline, (size_t)state->archive_size);
  const uint64_t fields[] = {
    scalpel_state.blocksize, filemirror_filesize(scalpel_state.filemirror),
    blockvector_get_data_length(candidate->b),
    blockvector_get_num_blocks(candidate->b), state->archive_size,
    state->observed_archive_size, state->central_offset, state->eocd_offset,
    state->failure_offset, state->failure_entry, output,
    state->destination_slot, state->run_length, run_last,
    state->structure_pending, state->apk_digest_fast_active,
    state->preferred_run_active, state->broad_scan,
    state->structure_retry_active, state->entry_count
  };
  for (size_t index = 0; index < sizeof(fields) / sizeof(fields[0]); index++) {
    hash = (hash ^ fields[index]) * UINT64_C(1099511628211);
  }
  for (uint64_t slot = 0; slot < blockvector_get_num_blocks(candidate->b);
       slot++) {
    hash = (hash ^ (uint64_t)blockvector_get_actual_blocknumber(candidate->b,
                                                              slot))
        * UINT64_C(1099511628211);
  }
  for (uint64_t index = 0; index < state->entry_count; index++) {
    const ZipStateEntry *entry = &state->entries[index];
    const uint64_t metadata[] = {
      entry->local_offset, entry->observed_local_offset, entry->compressed_size,
      entry->uncompressed_size, entry->data_offset, entry->range_end,
      entry->crc32, entry->name_crc32, entry->flags, entry->method,
      entry->encrypted, entry->geometry_known
    };
    for (size_t field = 0; field < sizeof(metadata) / sizeof(metadata[0]);
         field++) {
      hash = (hash ^ metadata[field]) * UINT64_C(1099511628211);
    }
  }
  return hash;
}

static inline ZipNormalScanState *zip_normal_scan_prepare(
    ZipCarveState *state, uint64_t signature, uint64_t image_blocks) {
  if (state->normal_scan
      && (state->normal_scan->signature != signature
          || state->normal_scan->image_blocks != image_blocks)) {
    zip_normal_scan_clear(state);
  }
  if (!state->normal_scan) {
    state->normal_scan = (ZipNormalScanState *)calloc(1,
                                                   sizeof(*state->normal_scan));
    check_memory_allocation(state->normal_scan, __LINE__, __FILE__,
                            "ZIP normal scan");
    state->normal_scan->signature = signature;
    state->normal_scan->image_blocks = image_blocks;
    state->normal_scan->pending_source = UINT64_MAX;
    state->normal_scan->selected_source = UINT64_MAX;
    state->normal_scan->completed = roaring64_bitmap_create();
    state->normal_scan->pruned = roaring64_bitmap_create();
    check_memory_allocation(state->normal_scan->completed, __LINE__, __FILE__,
                            "ZIP completed sources");
    check_memory_allocation(state->normal_scan->pruned, __LINE__, __FILE__,
                            "ZIP score-pruned sources");
    // Legacy states have no accumulator or physical owner for a nested normal
    // trial. Reconstruct this scope once rather than attach it to a new source.
    if (state->repair_resume.phase == ZIP_REPAIR_PHASE_STORED_PAIR
        || state->repair_resume.phase == ZIP_REPAIR_PHASE_STORED_ADJACENT) {
      zip_reassembly_reset_repair_resume(state);
    }
    state->scan_rank = 0;
  }
  return state->normal_scan;
}

static inline void zip_normal_scan_complete_source(ZipNormalScanState *scan) {
  if (scan->pending_source != UINT64_MAX) {
    roaring64_bitmap_add(scan->completed, scan->pending_source);
    scan->pending_source = UINT64_MAX;
  }
}

static inline void zip_normal_scan_record(
    ZipNormalScanState *scan, uint64_t source, uint64_t run_length,
    uint64_t failure, uint64_t entry, uint64_t output, uint64_t flags) {
  if (scan->outcome_count == scan->outcome_capacity) {
    uint64_t capacity = scan->outcome_capacity > 0
        ? scan->outcome_capacity * 2 : 16;
    if (capacity < scan->outcome_capacity
        || capacity > SIZE_MAX / sizeof(*scan->outcomes)) {
      handle_error(SCALPEL_ERROR_CHECKPOINT, "ZIP outcome capacity",
                   __LINE__, __FILE__);
    }
    scan->outcomes = (ZipScanOutcome *)realloc(
        scan->outcomes, (size_t)capacity * sizeof(*scan->outcomes));
    check_memory_allocation(scan->outcomes, __LINE__, __FILE__,
                            "ZIP completed outcomes");
    scan->outcome_capacity = capacity;
  }
  scan->outcomes[scan->outcome_count++] = (ZipScanOutcome){
    source, run_length, failure, entry, output, flags
  };
}

// Select only currently usable outcomes. If the old winner disappeared, retry
// only sources whose evaluation was pruned by that winner's score.
static inline bool zip_normal_scan_select(
    CarveInfo *candidate, ZipCarveState *state, ZipMappedBlockIndex *index,
    uint64_t baseline_output, ZipScanOutcome *best, int64_t *swap_slot) {
  ZipNormalScanState *scan = state->normal_scan;
  *best = (ZipScanOutcome){UINT64_MAX, state->run_length,
      state->failure_offset, state->failure_entry, baseline_output, 0};
  bool old_available = scan->selected_source == UINT64_MAX;
  for (uint64_t number = 0; number < scan->outcome_count; number++) {
    const ZipScanOutcome *outcome = &scan->outcomes[number];
    int64_t swap = ZIP_SWAP_SLOT_UNMAPPED;
    if (!zip_reassembly_source_run_viable_indexed(
            candidate, state->destination_slot, outcome->run_length,
            (int64_t)outcome->source, &swap, index)) {
      continue;
    }
    if (outcome->source == scan->selected_source
        && outcome->run_length == scan->selected_run) {
      old_available = true;
    }
    if (outcome->flags != 0 || outcome->output > best->output
        || (outcome->output == best->output && outcome->failure > best->failure)) {
      *best = *outcome;
      *swap_slot = swap;
      if (outcome->flags != 0) {
        break;
      }
    }
  }
  bool reconsider = !old_available && !roaring64_bitmap_is_empty(scan->pruned);
  if (reconsider) {
    roaring64_bitmap_andnot_inplace(scan->completed, scan->pruned);
    roaring64_bitmap_clear(scan->pruned);
    state->scan_rank = 0;
  }
  scan->selected_source = best->source;
  scan->selected_run = best->run_length;
  return reconsider;
}

static inline bool zip_normal_scan_valid(const ZipNormalScanState *scan) {
  if (!scan || scan->image_blocks == 0 || scan->image_blocks > INT64_MAX
      || (scan->pending_source != UINT64_MAX
          && scan->pending_source >= scan->image_blocks)
      || (scan->selected_source != UINT64_MAX
          && (scan->selected_source >= scan->image_blocks
              || scan->selected_run == 0
              || scan->selected_run > scan->image_blocks - scan->selected_source))
      || scan->outcome_count > scan->image_blocks
      || scan->outcome_count > scan->outcome_capacity
      || (scan->outcome_count > 0 && !scan->outcomes)
      || !scan->completed || !scan->pruned
      || !roaring64_bitmap_internal_validate(scan->completed, NULL)
      || !roaring64_bitmap_internal_validate(scan->pruned, NULL)
      || (!roaring64_bitmap_is_empty(scan->completed)
          && roaring64_bitmap_maximum(scan->completed) >= scan->image_blocks)
      || (!roaring64_bitmap_is_empty(scan->pruned)
          && roaring64_bitmap_maximum(scan->pruned) >= scan->image_blocks)) {
    return false;
  }
  for (uint64_t number = 0; number < scan->outcome_count; number++) {
    const ZipScanOutcome *outcome = &scan->outcomes[number];
    if (outcome->source >= scan->image_blocks || outcome->run_length == 0
        || outcome->run_length > scan->image_blocks - outcome->source
        || outcome->flags > (ZIP_SCAN_VALID | ZIP_SCAN_ENTRY_VALID
                              | ZIP_SCAN_STRUCTURE)) {
      return false;
    }
  }
  return true;
}

static inline bool zip_normal_scan_codec(
    ZipNormalScanState **scan, FILE *fp, StateSerialization mode) {
  const size_t header_size = offsetof(ZipNormalScanState, completed);
  if (mode == DESERIALIZE) {
    *scan = (ZipNormalScanState *)calloc(1, sizeof(**scan));
    check_memory_allocation(*scan, __LINE__, __FILE__, "ZIP scan restore");
  }
  if ((mode == SERIALIZE && !zip_normal_scan_valid(*scan))
      || (mode == SERIALIZE ? fwrite(*scan, header_size, 1, fp)
                              : fread(*scan, header_size, 1, fp)) != 1
      || (*scan)->image_blocks == 0 || (*scan)->image_blocks > INT64_MAX
      || (*scan)->outcome_count > (*scan)->image_blocks
      || (*scan)->outcome_count > SIZE_MAX / sizeof(ZipScanOutcome)) {
    return false;
  }
  roaring64_bitmap_t **bitmaps[] = {&(*scan)->completed, &(*scan)->pruned};
  for (size_t which = 0; which < 2; which++) {
    uint64_t bytes = mode == SERIALIZE
        ? roaring64_bitmap_portable_size_in_bytes(*bitmaps[which]) : 0;
    if ((mode == SERIALIZE ? fwrite(&bytes, sizeof(bytes), 1, fp)
                            : fread(&bytes, sizeof(bytes), 1, fp)) != 1
        || bytes == 0 || bytes > SIZE_MAX
        || (bytes > 4096 && (bytes - 4096) / 16 > (*scan)->image_blocks)) {
      return false;
    }
    char *buffer = (char *)malloc((size_t)bytes);
    check_memory_allocation(buffer, __LINE__, __FILE__, "ZIP scan bitmap");
    bool ok;
    if (mode == SERIALIZE) {
      ok = roaring64_bitmap_portable_serialize(*bitmaps[which], buffer) == bytes
          && fwrite(buffer, 1, (size_t)bytes, fp) == bytes;
    }
    else {
      ok = fread(buffer, 1, (size_t)bytes, fp) == bytes;
      if (ok) {
        *bitmaps[which] = roaring64_bitmap_portable_deserialize_safe(
            buffer, (size_t)bytes);
        ok = *bitmaps[which] != NULL;
      }
    }
    free(buffer);
    if (!ok) {
      return false;
    }
  }
  if (mode == DESERIALIZE && (*scan)->outcome_count > 0) {
    (*scan)->outcomes = (ZipScanOutcome *)malloc(
        (size_t)(*scan)->outcome_count * sizeof(ZipScanOutcome));
    check_memory_allocation((*scan)->outcomes, __LINE__, __FILE__,
                            "ZIP scan outcomes restore");
    (*scan)->outcome_capacity = (*scan)->outcome_count;
  }
  if ((*scan)->outcome_count > 0
      && (mode == SERIALIZE
          ? fwrite((*scan)->outcomes, sizeof(ZipScanOutcome),
                   (size_t)(*scan)->outcome_count, fp)
          : fread((*scan)->outcomes, sizeof(ZipScanOutcome),
                  (size_t)(*scan)->outcome_count, fp)) != (*scan)->outcome_count) {
    return false;
  }
  return zip_normal_scan_valid(*scan);
}

static inline bool zip_state_size(uint64_t entry_count,
                                  uint64_t gap_tried_bytes,
                                  size_t *size) {

  if (!size
      || entry_count > (SIZE_MAX - offsetof(ZipCarveState, entries))
                            / sizeof(ZipStateEntry)
      || gap_tried_bytes > SIZE_MAX) {
    return false;
  }

  const size_t entries_size = (size_t)entry_count * sizeof(ZipStateEntry);
  const size_t header_and_entries = offsetof(ZipCarveState, entries)
                                    + entries_size;

  if ((size_t)gap_tried_bytes > SIZE_MAX - header_and_entries) {
    return false;
  }
  *size = header_and_entries + (size_t)gap_tried_bytes;
  return true;
}

static inline ZipCarveState *zip_state_from_layout(const ZipLayout *layout,
                                                   uint64_t failure_offset,
                                                   uint64_t failure_entry,
                                                   bool track_gap_hypotheses) {

  size_t state_size = 0;
  uint64_t gap_tried_bytes = 0;

  if (layout && track_gap_hypotheses && scalpel_state.blocksize > 0) {
    const uint64_t archive_blocks = CEILDIV(layout->archive_size,
                                            scalpel_state.blocksize);

    gap_tried_bytes = CEILDIV(archive_blocks, UINT64_C(8));
  }

  if (!layout || !layout->entries
      || !zip_state_size(layout->entry_count, gap_tried_bytes,
                         &state_size)) {
    return NULL;
  }

  ZipCarveState *state = (ZipCarveState *)calloc(1, state_size);

  check_memory_allocation(state, __LINE__, __FILE__, "ZipCarveState");
  state->archive_size = layout->archive_size;
  state->observed_archive_size = layout->observed_archive_size;
  state->physical_gap_slot = layout->physical_gap_slot;
  state->physical_gap_blocks = layout->physical_gap_blocks;
  state->entry_count = layout->entry_count;
  state->central_offset = layout->central_offset;
  state->eocd_offset = layout->eocd_offset
                       - (layout->observed_archive_size
                          - layout->archive_size);
  state->failure_offset = failure_offset;
  state->failure_entry = failure_entry;
  state->apk_digest_entry = UINT64_MAX;
  state->gap_tried_bytes = gap_tried_bytes;
  state->run_length = 1;
  state->scan_rank = 0;
  state->had_physical_gap = layout->observed_archive_size
                                > layout->archive_size
                            || layout->physical_gap_blocks > 0;
  state->structure_pending = layout->displaced_structure;
  zip_reassembly_reset_repair_resume(state);

  for (uint64_t index = 0; index < layout->entry_count; index++) {
    const ZipEntry *source = &layout->entries[index];
    ZipStateEntry *destination = &state->entries[index];

    destination->local_offset = source->local_offset;
    destination->observed_local_offset = source->observed_local_offset;
    destination->compressed_size = source->compressed_size;
    destination->uncompressed_size = source->uncompressed_size;
    destination->data_offset = source->data_offset;
    destination->range_end = source->range_end;
    destination->crc32 = source->crc32;
    destination->name_crc32 = zip_crc32(source->name,
                                        source->name_length);
    destination->flags = source->flags;
    destination->method = source->method;
    destination->encrypted = source->encrypted;
    destination->geometry_known = source->geometry_known;
  }
  return state;
}

static inline uint8_t *zip_state_gap_tried(ZipCarveState *state) {

  if (!state || state->gap_tried_bytes == 0) {
    return NULL;
  }
  return (uint8_t *)(state->entries + state->entry_count);
}

static inline bool zip_state_enable_gap_tracking(ZipCarveState **state) {

  if (!state || !*state || scalpel_state.blocksize == 0) {
    return false;
  }

  const uint64_t archive_blocks = CEILDIV((*state)->archive_size,
                                          scalpel_state.blocksize);
  const uint64_t required_bytes = CEILDIV(archive_blocks, UINT64_C(8));

  if ((*state)->gap_tried_bytes >= required_bytes) {
    return true;
  }

  size_t old_size = 0;
  size_t new_size = 0;

  if (!zip_state_size((*state)->entry_count,
                      (*state)->gap_tried_bytes, &old_size)
      || !zip_state_size((*state)->entry_count,
                         required_bytes, &new_size)) {
    return false;
  }

  ZipCarveState *expanded = (ZipCarveState *)realloc(*state, new_size);

  check_memory_allocation(expanded, __LINE__, __FILE__, "ZipCarveState");
  memset((uint8_t *)expanded + old_size, 0, new_size - old_size);
  expanded->gap_tried_bytes = required_bytes;
  *state = expanded;
  return true;
}

static inline bool zip_serialize_carve_state(void **state,
                                             FILE *fp,
                                             StateSerialization mode) {

  ZipCarveState **zip_state = (ZipCarveState **)state;
  const size_t header_size = offsetof(ZipCarveState, normal_scan);

  if (!zip_state || !fp) {
    return false;
  }

  if (mode == SERIALIZE) {
    uint64_t flags = *zip_state
        ? ((*zip_state)->normal_scan ? 1 : 0)
            | ((*zip_state)->delayed_scan ? 2 : 0)
            | ((*zip_state)->encrypted_scan ? 4 : 0) : 0;
    uint64_t envelope[] = {0, ZIP_CARVE_STATE_MAGIC, ZIP_CARVE_STATE_VERSION,
                            header_size, flags};
    if (!*zip_state || (*zip_state)->archive_size == 0
        || !zip_auxiliary_states_valid(*zip_state)
        || fwrite(envelope, sizeof(envelope), 1, fp) != 1
        || fwrite(*zip_state, header_size, 1, fp) != 1
        || ((*zip_state)->entry_count > 0
            && fwrite((*zip_state)->entries, sizeof(ZipStateEntry),
                      (size_t)(*zip_state)->entry_count, fp)
                   != (size_t)(*zip_state)->entry_count)
        || ((*zip_state)->gap_tried_bytes > 0
            && fwrite(zip_state_gap_tried(*zip_state), 1,
                      (size_t)(*zip_state)->gap_tried_bytes, fp)
                   != (size_t)(*zip_state)->gap_tried_bytes)
        || ((*zip_state)->normal_scan
            && !zip_normal_scan_codec(&(*zip_state)->normal_scan, fp, mode))
        || ((*zip_state)->delayed_scan
            && fwrite((*zip_state)->delayed_scan,
                      sizeof(*(*zip_state)->delayed_scan), 1, fp) != 1)
        || ((*zip_state)->encrypted_scan
            && fwrite((*zip_state)->encrypted_scan,
                      sizeof(*(*zip_state)->encrypted_scan), 1, fp) != 1)) {
      perror("zip carve state serialization");
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
    return true;
  }

  ZipCarveState header;

  memset(&header, 0, sizeof(header));
  uint64_t first = 0;
  uint64_t envelope[4] = {0};
  bool has_normal_scan = false;
  if (fread(&first, sizeof(first), 1, fp) != 1) {
    perror("zip carve state deserialization");
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }
  if (first == 0) {
    if (fread(envelope, sizeof(envelope), 1, fp) != 1
        || envelope[0] != ZIP_CARVE_STATE_MAGIC
        || envelope[1] == 0 || envelope[1] > ZIP_CARVE_STATE_VERSION
        || envelope[2] != header_size
        || envelope[3] > (envelope[1] == 1 ? 1 : 7)
        || fread(&header, header_size, 1, fp) != 1) {
      handle_error(SCALPEL_ERROR_CHECKPOINT, "invalid ZIP state envelope",
                   __LINE__, __FILE__);
    }
    has_normal_scan = (envelope[3] & 1) != 0;
  }
  else {
    // Original records begin with archive_size and have no version marker.
    header.archive_size = first;
    if (fread((uint8_t *)&header + sizeof(first),
              header_size - sizeof(first), 1, fp) != 1) {
      handle_error(SCALPEL_ERROR_CHECKPOINT, "truncated legacy ZIP state",
                   __LINE__, __FILE__);
    }
  }

  size_t state_size = 0;

  const uint64_t archive_blocks = scalpel_state.blocksize > 0
      ? CEILDIV(header.archive_size, scalpel_state.blocksize) : 0;
  const uint64_t maximum_gap_bytes = CEILDIV(archive_blocks, UINT64_C(8));

  if (header.archive_size == 0 || header.archive_size > SIZE_MAX
      || header.entry_count > header.archive_size / ZIP_LOCAL_HEADER_SIZE
      || header.gap_tried_bytes > maximum_gap_bytes
      || !zip_state_size(header.entry_count, header.gap_tried_bytes,
                         &state_size)) {
    handle_error(SCALPEL_ERROR_CHECKPOINT,
                 "invalid ZIP carve state size", __LINE__, __FILE__);
  }

  *zip_state = (ZipCarveState *)calloc(1, state_size);
  check_memory_allocation(*zip_state, __LINE__, __FILE__, "ZipCarveState");
  memcpy(*zip_state, &header, header_size);
  if (header.entry_count > 0
      && fread((*zip_state)->entries, sizeof(ZipStateEntry),
               (size_t)header.entry_count, fp)
             != (size_t)header.entry_count) {
    perror("zip carve state entries deserialization");
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }
  if (header.gap_tried_bytes > 0
      && fread(zip_state_gap_tried(*zip_state), 1,
               (size_t)header.gap_tried_bytes, fp)
             != (size_t)header.gap_tried_bytes) {
    perror("zip carve state gap history deserialization");
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }
  if (has_normal_scan
      && !zip_normal_scan_codec(&(*zip_state)->normal_scan, fp, mode)) {
    zip_free_carve_state(state);
    handle_error(SCALPEL_ERROR_CHECKPOINT, "invalid ZIP normal scan",
                 __LINE__, __FILE__);
  }
  if ((envelope[3] & 2) != 0) {
    (*zip_state)->delayed_scan = (ZipDelayedScanState *)calloc(
        1, sizeof(*(*zip_state)->delayed_scan));
    check_memory_allocation((*zip_state)->delayed_scan, __LINE__, __FILE__,
                            "ZIP delayed scan restore");
    if (fread((*zip_state)->delayed_scan,
              sizeof(*(*zip_state)->delayed_scan), 1, fp) != 1) {
      zip_free_carve_state(state);
      handle_error(SCALPEL_ERROR_CHECKPOINT, "truncated ZIP delayed scan",
                   __LINE__, __FILE__);
    }
  }
  if ((envelope[3] & 4) != 0) {
    (*zip_state)->encrypted_scan = (ZipEncryptedScanState *)calloc(
        1, sizeof(*(*zip_state)->encrypted_scan));
    check_memory_allocation((*zip_state)->encrypted_scan, __LINE__, __FILE__,
                            "ZIP encrypted scan restore");
    if (fread((*zip_state)->encrypted_scan,
              sizeof(*(*zip_state)->encrypted_scan), 1, fp) != 1) {
      zip_free_carve_state(state);
      handle_error(SCALPEL_ERROR_CHECKPOINT, "truncated ZIP encrypted scan",
                   __LINE__, __FILE__);
    }
  }
  if (!zip_auxiliary_states_valid(*zip_state)) {
    zip_free_carve_state(state);
    handle_error(SCALPEL_ERROR_CHECKPOINT, "invalid ZIP repair scan",
                 __LINE__, __FILE__);
  }
  // Older records stored a mutable footer-list index, not a physical offset.
  if (envelope[1] < 2
      && (*zip_state)->repair_resume.phase == ZIP_REPAIR_PHASE_ZSTD_ANCHORED) {
    zip_reassembly_reset_repair_resume(*zip_state);
  }
  return true;
}

static inline void *zip_clone_carve_state(const void *srcstate) {

  const ZipCarveState *source = (const ZipCarveState *)srcstate;
  size_t state_size = 0;

  if (!source || !zip_auxiliary_states_valid(source)
      || !zip_state_size(source->entry_count, source->gap_tried_bytes,
                         &state_size)) {
    return NULL;
  }

  ZipCarveState *destination = (ZipCarveState *)malloc(state_size);

  check_memory_allocation(destination, __LINE__, __FILE__,
                          "ZipCarveState clone");
  memcpy(destination, source, state_size);
  destination->normal_scan = NULL;
  destination->delayed_scan = NULL;
  destination->encrypted_scan = NULL;
  if (source->normal_scan) {
    const ZipNormalScanState *original = source->normal_scan;
    if (!zip_normal_scan_valid(original)) {
      free(destination);
      return NULL;
    }
    ZipNormalScanState *copy = (ZipNormalScanState *)malloc(sizeof(*copy));
    check_memory_allocation(copy, __LINE__, __FILE__, "ZIP scan clone");
    *copy = *original;
    copy->completed = roaring64_bitmap_copy(original->completed);
    copy->pruned = roaring64_bitmap_copy(original->pruned);
    check_memory_allocation(copy->completed, __LINE__, __FILE__,
                            "ZIP completed sources clone");
    check_memory_allocation(copy->pruned, __LINE__, __FILE__,
                            "ZIP score-pruned sources clone");
    copy->outcomes = NULL;
    copy->outcome_capacity = copy->outcome_count;
    if (copy->outcome_count > 0) {
      copy->outcomes = (ZipScanOutcome *)malloc(
          (size_t)copy->outcome_count * sizeof(*copy->outcomes));
      check_memory_allocation(copy->outcomes, __LINE__, __FILE__,
                              "ZIP completed outcomes clone");
      memcpy(copy->outcomes, original->outcomes,
             (size_t)copy->outcome_count * sizeof(*copy->outcomes));
    }
    destination->normal_scan = copy;
  }
  if (source->delayed_scan) {
    destination->delayed_scan = (ZipDelayedScanState *)malloc(
        sizeof(*destination->delayed_scan));
    check_memory_allocation(destination->delayed_scan, __LINE__, __FILE__,
                            "ZIP delayed scan clone");
    *destination->delayed_scan = *source->delayed_scan;
  }
  if (source->encrypted_scan) {
    destination->encrypted_scan = (ZipEncryptedScanState *)malloc(
        sizeof(*destination->encrypted_scan));
    check_memory_allocation(destination->encrypted_scan, __LINE__, __FILE__,
                            "ZIP encrypted scan clone");
    *destination->encrypted_scan = *source->encrypted_scan;
  }
  return destination;
}

static inline void zip_free_carve_state(void **state) {

  if (!state) {
    return;
  }
  zip_normal_scan_clear((ZipCarveState *)*state);
  if (*state) {
    free(((ZipCarveState *)*state)->delayed_scan);
    free(((ZipCarveState *)*state)->encrypted_scan);
  }
  free(*state);
  *state = NULL;
}

static inline void zip_print_carve_state(const void *state) {

  const ZipCarveState *zip_state = (const ZipCarveState *)state;

  if (!zip_state) {
    fprintf(stdout, "NULL");
    return;
  }
  fprintf(stdout,
          "archive=%" PRIu64 " observed_archive=%" PRIu64
          " physical_gap=%" PRIu64 " physical_gap_blocks=%" PRIu64
          " entries=%" PRIu64
          " failure=%" PRIu64 " entry=%" PRIu64
          " destination=%" PRIu64 " run=%" PRIu64
          " preferred_destination=%" PRIu64
          " preferred_run=%" PRIu64
          " structure_resume=%" PRIu64
          " structure_retry_destination=%" PRIu64
          " structure_retry_next=%" PRIu64
          " scan=%" PRId64
          " initialized=%d broad=%d wrapped=%d structure=%d stored_trial=%d"
          " scan_shares=%u clone_scan=%d preferred_active=%d"
          " structure_retry_active=%d structure_retry_pending=%d"
          " gap_hypothesis_isolated=%d"
          " apk_digest_entry=%" PRIu64
          " apk_digest_active=%d apk_digest_complete=%d"
          " repair_phase=%u repair_destination=%" PRIu64
          " repair_first_destination=%" PRIu64
          " repair_run=%" PRIu64 " repair_source=%" PRIu64
          " repair_second_destination=%" PRIu64
          " repair_second_run=%" PRIu64
          " repair_source_rank=%" PRIu64
          " repair_footer=%" PRIu64,
          zip_state->archive_size, zip_state->observed_archive_size,
          zip_state->physical_gap_slot, zip_state->physical_gap_blocks,
          zip_state->entry_count,
          zip_state->failure_offset, zip_state->failure_entry,
          zip_state->destination_slot, zip_state->run_length,
          zip_state->preferred_destination_slot,
          zip_state->preferred_run_length,
          zip_state->structure_resume_destination,
          zip_state->structure_retry_destination,
          zip_state->structure_retry_next_destination,
          zip_state->scan_rank,
          zip_state->initialized,
          zip_state->broad_scan, zip_state->broad_wrapped,
          zip_state->structure_pending,
          zip_state->stored_structure_trial,
          zip_state->scan_shares,
          zip_state->clone_scan_initialized,
          zip_state->preferred_run_active,
          zip_state->structure_retry_active,
          zip_state->structure_retry_pending,
          zip_state->gap_hypothesis_isolated,
          zip_state->apk_digest_entry,
          zip_state->apk_digest_fast_active,
          zip_state->apk_digest_fast_complete,
          zip_state->repair_resume.phase,
          zip_state->repair_resume.destination,
          zip_state->repair_resume.first_destination,
          zip_state->repair_resume.run_length,
          zip_state->repair_resume.source,
          zip_state->repair_resume.second_destination,
          zip_state->repair_resume.second_run_length,
          zip_state->repair_resume.source_rank,
          zip_state->repair_resume.footer_index);
}

static inline bool zip_state_entry_verify(const uint8_t *data,
                                          uint64_t data_length,
                                          const ZipStateEntry *entry,
                                          uint64_t *failure_offset,
                                          uint64_t *output_progress) {

  if (output_progress) {
    *output_progress = 0;
  }
  if (!data || !entry || !failure_offset || entry->encrypted
      || !entry->geometry_known
      || !zip_range_available(data_length, entry->data_offset,
                              entry->compressed_size)) {
    return false;
  }

  ZipEntry trial;

  memset(&trial, 0, sizeof(trial));
  trial.local_offset = entry->local_offset;
  trial.compressed_size = entry->compressed_size;
  trial.uncompressed_size = entry->uncompressed_size;
  trial.data_offset = entry->data_offset;
  trial.range_end = entry->range_end;
  trial.crc32 = entry->crc32;
  trial.flags = entry->flags;
  trial.method = entry->method;

  bool supported = false;

  const bool valid = zip_verify_supported_entry(
      data, &trial, &supported, failure_offset, output_progress);

  if (supported) {
    return valid;
  }

  if (output_progress) {
    *output_progress = 0;
  }
  *failure_offset = entry->data_offset;
  return false;
}

// The streamable ZIP reader can decode an intact member before the central
// directory has been repaired. Locate the selected member by its logical local
// header offset, then independently verify its uncompressed size and CRC.
//
static inline bool zip_state_entry_verify_with_libarchive(
    const uint8_t *data,
    uint64_t data_length,
    const ZipCarveState *state,
    uint64_t entry_index,
    uint64_t *failure_offset,
    uint64_t *output_progress) {

  if (output_progress) {
    *output_progress = 0;
  }
  if (!data || !state || !failure_offset
      || entry_index >= state->entry_count
      || state->archive_size > data_length
      || state->archive_size > SIZE_MAX) {
    return false;
  }

  const ZipStateEntry *expected = &state->entries[entry_index];

  *failure_offset = expected->data_offset;
  if (expected->encrypted || !expected->geometry_known
      || expected->local_offset > INT64_MAX
      || !zip_range_available(data_length, expected->data_offset,
                              expected->compressed_size)) {
    return false;
  }

  struct archive *reader = archive_read_new();

  if (!reader) {
    return false;
  }

  bool opened = false;
  bool valid = false;
  uint64_t produced = 0;
  uint32_t crc = (uint32_t)crc32(0L, Z_NULL, 0);

  if (archive_read_support_filter_all(reader) == ARCHIVE_OK
      && archive_read_support_format_zip_streamable(reader) == ARCHIVE_OK
      && archive_read_open_memory(reader, data,
                                  (size_t)state->archive_size)
             == ARCHIVE_OK) {
    opened = true;

    for (;;) {
      struct archive_entry *archive_entry = NULL;
      const int header_result = archive_read_next_header(reader,
                                                         &archive_entry);

      if (header_result == ARCHIVE_EOF) {
        break;
      }
      if (header_result != ARCHIVE_OK && header_result != ARCHIVE_WARN) {
        break;
      }
      const la_int64_t header_position = archive_read_header_position(reader);

      if (header_position < 0
          || (uint64_t)header_position > expected->local_offset) {
        break;
      }
      if ((uint64_t)header_position < expected->local_offset) {
        continue;
      }

      uint8_t buffer[ZIP_VERIFY_BUFFER_SIZE];

      for (;;) {
        const la_ssize_t count = archive_read_data(reader, buffer,
                                                   sizeof(buffer));

        if (count == 0) {
          valid = produced == expected->uncompressed_size
                  && crc == expected->crc32;
          break;
        }
        if (count < 0 || (uint64_t)count > UINT64_MAX - produced) {
          break;
        }
        produced += (uint64_t)count;
        crc = (uint32_t)crc32(crc, buffer, (uInt)count);
      }
      break;
    }
  }

  if (output_progress) {
    *output_progress = produced;
  }
  if (valid) {
    *failure_offset = expected->range_end;
  }
  if (opened) {
    (void)archive_read_close(reader);
  }
  archive_read_free(reader);
  return valid;
}

static inline bool zip_reassembly_verify_entry(
    const uint8_t *data,
    uint64_t data_length,
    const ZipCarveState *state,
    const ZipStateEntry *entry,
    uint64_t *failure_offset,
    uint64_t *output_progress) {

  if (!state || !entry || state->entry_count == 0) {
    return false;
  }
  const uintptr_t entries_address = (uintptr_t)state->entries;
  const uintptr_t entry_address = (uintptr_t)entry;

  if (entry_address < entries_address
      || (entry_address - entries_address) % sizeof(*entry) != 0) {
    return false;
  }
  const uint64_t entry_index = (uint64_t)(
      (entry_address - entries_address) / sizeof(*entry));

  if (entry_index >= state->entry_count) {
    return false;
  }
  if (zip_method_directly_verifiable(entry->method)) {
    return zip_state_entry_verify(data, data_length, entry,
                                  failure_offset, output_progress);
  }
  return zip_state_entry_verify_with_libarchive(
      data, data_length, state, entry_index,
      failure_offset, output_progress);
}

// A normalized trial may be preserved before member validation only when it
// describes the same archive recorded by the original central directory.
//
static inline bool zip_layout_matches_state(const ZipLayout *layout,
                                            const ZipCarveState *state) {

  if (!layout || !state || !layout->entries
      || layout->archive_size != state->archive_size
      || layout->entry_count != state->entry_count
      || layout->central_offset != state->central_offset) {
    return false;
  }

  for (uint64_t index = 0; index < state->entry_count; index++) {
    const ZipEntry *entry = &layout->entries[index];
    const ZipStateEntry *expected = &state->entries[index];

    if (entry->local_offset != expected->local_offset
        || entry->compressed_size != expected->compressed_size
        || entry->uncompressed_size != expected->uncompressed_size
        || (expected->geometry_known
            && entry->data_offset != expected->data_offset)
        || entry->crc32 != expected->crc32
        || zip_crc32(entry->name, entry->name_length)
               != expected->name_crc32
        || entry->flags != expected->flags
        || entry->method != expected->method
        || entry->encrypted != expected->encrypted) {
      return false;
    }
  }
  return true;
}

static inline bool zip_reassembly_initialize_candidate(
    CarveInfo *candidate,
    const ZipCarveState *state) {

  if (!candidate || !candidate->b || !state || state->archive_size == 0
      || scalpel_state.blocksize == 0
      || blockvector_get_num_blocks(candidate->b) == 0) {
    return false;
  }

  const uint64_t total_blocks = CEILDIV(state->archive_size,
                                        scalpel_state.blocksize);
  const int64_t header_actual =
      blockvector_get_actual_blocknumber(candidate->b, 0);
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);

  if (header_actual < 0 || total_blocks == 0
      || (uint64_t)header_actual >= image_blocks) {
    return false;
  }

  resize_blockvector(candidate->b, total_blocks);
  if (!state->initialized) {
    for (uint64_t slot = 0; slot < total_blocks; slot++) {
      const int64_t actual = header_actual + (int64_t)slot;
      int64_t apparent = actual >= 0 && (uint64_t)actual < image_blocks
                             ? filemirror_apparent_blocknumber(
                                   scalpel_state.filemirror, actual)
                             : -1;

      if (actual >= 0 && (uint64_t)actual < image_blocks && apparent < 0
          && !filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                              actual)) {
        if (slot == 0) {
          return false;
        }
        apparent = -1;
      }
      blockvector_set_apparent_blocknumber(candidate->b, slot, apparent);
    }

    if (state->observed_archive_size > state->archive_size) {
      const uint64_t inserted_bytes = state->observed_archive_size
                                      - state->archive_size;

      if (inserted_bytes % scalpel_state.blocksize == 0
          && total_blocks <= SIZE_MAX / sizeof(uint64_t)) {
        const uint64_t aggregate_shift = inserted_bytes
                                         / scalpel_state.blocksize;
        uint64_t *slot_shift = (uint64_t *)calloc(
            (size_t)total_blocks, sizeof(uint64_t));

        check_memory_allocation(slot_shift, __LINE__, __FILE__,
                                "ZIP cumulative gap initialization");
        for (uint64_t index = 0; index < state->entry_count; index++) {
          const ZipStateEntry *entry = &state->entries[index];

          if (!entry->geometry_known
              || entry->observed_local_offset < entry->local_offset
              || entry->range_end <= entry->local_offset) {
            continue;
          }
          const uint64_t shift_bytes = entry->observed_local_offset
                                       - entry->local_offset;

          if (shift_bytes == 0
              || shift_bytes % scalpel_state.blocksize != 0) {
            continue;
          }
          const uint64_t shift_blocks = shift_bytes
                                        / scalpel_state.blocksize;

          if (shift_blocks > aggregate_shift) {
            continue;
          }
          const uint64_t first_slot = entry->local_offset
                                      / scalpel_state.blocksize;
          uint64_t end_slot = CEILDIV(entry->range_end,
                                      scalpel_state.blocksize);

          if (first_slot >= total_blocks) {
            continue;
          }
          if (end_slot > total_blocks) {
            end_slot = total_blocks;
          }
          for (uint64_t slot = first_slot; slot < end_slot; slot++) {
            if (shift_blocks > slot_shift[slot]) {
              slot_shift[slot] = shift_blocks;
            }
          }
        }

        const uint64_t central_first = state->central_offset
                                       / scalpel_state.blocksize;

        if (central_first < total_blocks) {
          for (uint64_t slot = central_first; slot < total_blocks; slot++) {
            slot_shift[slot] = aggregate_shift;
          }
        }
        for (uint64_t slot = 0; slot < total_blocks; slot++) {
          if (slot_shift[slot] == 0
              || (uint64_t)header_actual > UINT64_MAX - slot
              || (uint64_t)header_actual + slot
                     > UINT64_MAX - slot_shift[slot]) {
            continue;
          }
          const uint64_t actual = (uint64_t)header_actual + slot
                                  + slot_shift[slot];
          const int64_t apparent = actual <= INT64_MAX
              && actual < image_blocks
              ? filemirror_apparent_blocknumber(
                    scalpel_state.filemirror, (int64_t)actual)
              : -1;

          blockvector_set_apparent_blocknumber(candidate->b, slot,
                                                apparent);
        }
        free(slot_shift);
      }
    }
  }

  blockvector_set_data_length(candidate->b, state->archive_size);
  inflate_blockvector(candidate->b);
  return true;
}

// Copy a physical byte range from the evidence image without assuming that the
// range is contained in one block.
//
static inline bool zip_copy_actual_bytes(uint64_t actual_offset,
                                         uint64_t length,
                                         uint8_t *destination) {

  const uint64_t image_size = filemirror_filesize(
      scalpel_state.filemirror);
  const uint64_t blocksize = scalpel_state.blocksize;

  if ((!destination && length > 0) || blocksize == 0
      || actual_offset > image_size || length > image_size - actual_offset) {
    return false;
  }

  while (length > 0) {
    const int64_t actual_block = (int64_t)(actual_offset / blocksize);
    const uint64_t block_offset = actual_offset % blocksize;
    uint64_t block_length = 0;
    const uint8_t *block = (const uint8_t *)
        filemirror_actual_block_data_pointer(scalpel_state.filemirror,
                                             actual_block, &block_length);

    if (!block || block_offset >= block_length
        || filemirror_actual_block_covered(scalpel_state.filemirror,
                                           actual_block)) {
      return false;
    }

    uint64_t count = block_length - block_offset;

    if (count > length) {
      count = length;
    }
    memcpy(destination, block + block_offset, (size_t)count);
    destination += count;
    actual_offset += count;
    length -= count;
  }
  return true;
}

// Locate the ZIP64 EOCD record physically adjacent to its locator. The record
// is variable length, so the stored size is also checked before any fields are
// accepted.
//
static inline bool zip_find_actual_zip64_record(uint64_t locator_offset,
                                                uint64_t *record_offset,
                                                uint64_t *record_size,
                                                uint64_t *entry_count,
                                                uint64_t *central_size,
                                                uint64_t *central_offset) {

  const uint64_t blocksize = scalpel_state.blocksize;
  uint64_t search = locator_offset;

  if (!record_offset || !record_size || !entry_count || !central_size
      || !central_offset || blocksize == 0 || locator_offset < 56) {
    return false;
  }

  while (search > 0) {
    const int64_t actual_block = (int64_t)((search - 1) / blocksize);
    const uint64_t block_start = (uint64_t)actual_block * blocksize;
    uint64_t block_length = 0;
    const uint8_t *block = (const uint8_t *)
        filemirror_actual_block_data_pointer(scalpel_state.filemirror,
                                             actual_block, &block_length);
    uint64_t upper = search - block_start;

    if (!block || filemirror_actual_block_covered(scalpel_state.filemirror,
                                                  actual_block)) {
      search = block_start;
      continue;
    }
    if (upper > block_length) {
      upper = block_length;
    }

    while (upper > 0) {
      upper--;
      if (block[upper] != 'P') {
        continue;
      }

      const uint64_t candidate = block_start + upper;
      uint8_t fixed[ZIP64_EOCD_MINIMUM_SIZE];

      if (candidate > locator_offset
          || locator_offset - candidate < ZIP64_EOCD_MINIMUM_SIZE
          || !zip_copy_actual_bytes(candidate, sizeof(fixed), fixed)
          || zip_read_le32(fixed) != ZIP64_EOCD_SIGNATURE) {
        continue;
      }

      const uint64_t payload = zip_read_le64(fixed + 4);
      uint64_t total = 0;

      if (payload < 44
          || __builtin_add_overflow(payload, UINT64_C(12), &total)
          || total != locator_offset - candidate
          || zip_read_le32(fixed + 16) != 0
          || zip_read_le32(fixed + 20) != 0
          || zip_read_le64(fixed + 24) != zip_read_le64(fixed + 32)) {
        continue;
      }

      *record_offset = candidate;
      *record_size = total;
      *entry_count = zip_read_le64(fixed + 32);
      *central_size = zip_read_le64(fixed + 40);
      *central_offset = zip_read_le64(fixed + 48);
      return true;
    }
    search = block_start;
  }
  return false;
}

// Compare reconstructed local-header fields with the corresponding central
// entry. Callers may supply bytes copied contiguously or across a known gap.
//
static inline bool zip_local_header_fields_match(
    const uint8_t *fixed,
    const uint8_t *variable,
    uint64_t variable_length,
    const ZipEntry *entry,
    uint64_t *data_delta) {

  if (data_delta) {
    *data_delta = 0;
  }
  if (!fixed || !entry || (!variable && variable_length > 0)
      || zip_read_le32(fixed) != ZIP_LOCAL_HEADER_SIGNATURE) {
    return false;
  }

  const uint16_t flags = zip_read_le16(fixed + 6);
  const uint16_t method = zip_read_le16(fixed + 8);
  const uint32_t local_crc = zip_read_le32(fixed + 14);
  const uint32_t compressed32 = zip_read_le32(fixed + 18);
  const uint32_t uncompressed32 = zip_read_le32(fixed + 22);
  const uint16_t name_length = zip_read_le16(fixed + 26);
  const uint16_t extra_length = zip_read_le16(fixed + 28);
  const uint64_t expected_variable_length = (uint64_t)name_length
                                            + extra_length;

  if (method != entry->method
      || ((flags ^ entry->flags)
          & (ZIP_FLAG_ENCRYPTED | ZIP_FLAG_DATA_DESCRIPTOR)) != 0
      || variable_length != expected_variable_length
      || variable_length > SIZE_MAX) {
    return false;
  }
  bool matches = zip_entry_name_matches_local(
      entry, variable, name_length, variable + name_length, extra_length);

  if (matches && (flags & ZIP_FLAG_DATA_DESCRIPTOR) == 0) {
    uint64_t compressed = compressed32;
    uint64_t uncompressed = uncompressed32;
    uint64_t unused_offset = 0;
    uint32_t unused_disk = 0;
    const bool need_uncompressed =
        uncompressed32 == ZIP_UINT32_SENTINEL;
    const bool need_compressed = compressed32 == ZIP_UINT32_SENTINEL;

    if ((need_uncompressed || need_compressed)
        && !zip_parse_zip64_extra(variable + name_length, extra_length,
                                  need_uncompressed, need_compressed,
                                  false, false, &uncompressed, &compressed,
                                  &unused_offset, &unused_disk)) {
      matches = false;
    }
    if (matches && (local_crc != entry->crc32
                    || compressed != entry->compressed_size
                    || uncompressed != entry->uncompressed_size)) {
      matches = false;
    }
  }

  if (matches && data_delta) {
    *data_delta = ZIP_LOCAL_HEADER_SIZE + variable_length;
  }
  return matches;
}

// Match a central-directory entry to a physical local header. Entry data is
// not read here; the match only establishes the archive instance associated
// with a footer seed.
//
static inline bool zip_local_header_matches_actual(
    uint64_t actual_offset,
    const ZipEntry *entry,
    uint64_t *data_delta) {

  uint8_t fixed[ZIP_LOCAL_HEADER_SIZE];
  uint64_t variable_offset = 0;

  if (data_delta) {
    *data_delta = 0;
  }
  if (!entry || !zip_copy_actual_bytes(actual_offset, sizeof(fixed), fixed)
      || zip_read_le32(fixed) != ZIP_LOCAL_HEADER_SIGNATURE
      || __builtin_add_overflow(actual_offset,
                                (uint64_t)ZIP_LOCAL_HEADER_SIZE,
                                &variable_offset)) {
    return false;
  }

  const uint16_t name_length = zip_read_le16(fixed + 26);
  const uint16_t extra_length = zip_read_le16(fixed + 28);
  const uint64_t variable_length = (uint64_t)name_length + extra_length;
  const size_t allocation_length = variable_length > 0
                                       ? (size_t)variable_length : 1;
  uint8_t *variable = (uint8_t *)malloc(allocation_length);

  check_memory_allocation(variable, __LINE__, __FILE__,
                          "ZIP local-header fields");
  const bool matches = zip_copy_actual_bytes(variable_offset,
                                             variable_length, variable)
                       && zip_local_header_fields_match(
                              fixed, variable, variable_length,
                              entry, data_delta);

  free(variable);
  return matches;
}

// Copy bytes from the logical archive view while skipping one physically
// inserted run. The gap offset and all logical offsets are relative to the
// archive header.
//
static inline bool zip_copy_gap_logical_bytes(
    uint64_t header_actual,
    uint64_t logical_offset,
    uint64_t length,
    uint64_t gap_offset,
    uint64_t inserted_bytes,
    uint8_t *destination) {

  uint64_t logical_end = 0;

  if ((!destination && length > 0) || inserted_bytes == 0
      || __builtin_add_overflow(logical_offset, length, &logical_end)) {
    return false;
  }

  uint64_t prefix_length = 0;

  if (logical_offset < gap_offset) {
    prefix_length = gap_offset - logical_offset;
    if (prefix_length > length) {
      prefix_length = length;
    }
  }

  if (prefix_length > 0) {
    uint64_t prefix_actual = 0;

    if (__builtin_add_overflow(header_actual, logical_offset,
                               &prefix_actual)
        || !zip_copy_actual_bytes(prefix_actual, prefix_length,
                                  destination)) {
      return false;
    }
  }

  const uint64_t suffix_length = length - prefix_length;

  if (suffix_length > 0) {
    const uint64_t suffix_logical = logical_offset + prefix_length;
    uint64_t suffix_actual = 0;

    if (suffix_logical < gap_offset
        || __builtin_add_overflow(header_actual, suffix_logical,
                                  &suffix_actual)
        || __builtin_add_overflow(suffix_actual, inserted_bytes,
                                  &suffix_actual)
        || !zip_copy_actual_bytes(suffix_actual, suffix_length,
                                  destination + prefix_length)) {
      return false;
    }
  }
  return logical_end >= logical_offset;
}

// Authenticate a local header whose fixed or variable fields cross one
// block-aligned physical insertion. Only insertion positions inside the local
// header are considered.
//
static inline bool zip_local_header_matches_across_gap(
    uint64_t header_actual,
    uint64_t inserted_bytes,
    const ZipEntry *entry,
    uint64_t *data_delta,
    uint64_t *gap_offset) {

  const uint64_t blocksize = scalpel_state.blocksize;

  if (data_delta) {
    *data_delta = 0;
  }
  if (gap_offset) {
    *gap_offset = 0;
  }
  if (!entry || !data_delta || !gap_offset || blocksize == 0
      || inserted_bytes == 0 || inserted_bytes % blocksize != 0
      || entry->local_offset > UINT64_MAX - blocksize) {
    return false;
  }

  uint64_t candidate_gap = (entry->local_offset / blocksize + 1)
                           * blocksize;
  uint64_t maximum_header_end = 0;

  if (__builtin_add_overflow(entry->local_offset,
                             (uint64_t)ZIP_LOCAL_HEADER_SIZE
                                 + UINT16_MAX + UINT16_MAX,
                             &maximum_header_end)) {
    return false;
  }

  while (candidate_gap < maximum_header_end) {
    uint8_t fixed[ZIP_LOCAL_HEADER_SIZE];

    if (!zip_copy_gap_logical_bytes(
            header_actual, entry->local_offset, sizeof(fixed),
            candidate_gap, inserted_bytes, fixed)
        || zip_read_le32(fixed) != ZIP_LOCAL_HEADER_SIGNATURE) {
      if (candidate_gap > UINT64_MAX - blocksize) {
        break;
      }
      candidate_gap += blocksize;
      continue;
    }

    const uint16_t name_length = zip_read_le16(fixed + 26);
    const uint16_t extra_length = zip_read_le16(fixed + 28);
    const uint64_t variable_length = (uint64_t)name_length + extra_length;
    uint64_t variable_offset = 0;
    uint64_t header_end = 0;

    if (__builtin_add_overflow(entry->local_offset,
                               (uint64_t)ZIP_LOCAL_HEADER_SIZE,
                               &variable_offset)
        || __builtin_add_overflow(variable_offset, variable_length,
                                  &header_end)) {
      return false;
    }
    if (candidate_gap >= header_end) {
      if (candidate_gap > UINT64_MAX - blocksize) {
        break;
      }
      candidate_gap += blocksize;
      continue;
    }

    const size_t allocation_length = variable_length > 0
                                         ? (size_t)variable_length : 1;
    uint8_t *variable = (uint8_t *)malloc(allocation_length);

    check_memory_allocation(variable, __LINE__, __FILE__,
                            "split ZIP local-header fields");
    const bool matches = zip_copy_gap_logical_bytes(
                             header_actual, variable_offset,
                             variable_length, candidate_gap,
                             inserted_bytes, variable)
                         && zip_local_header_fields_match(
                                fixed, variable, variable_length,
                                entry, data_delta);

    free(variable);
    if (matches) {
      *gap_offset = candidate_gap;
      return true;
    }
    if (candidate_gap > UINT64_MAX - blocksize) {
      break;
    }
    candidate_gap += blocksize;
  }
  return false;
}

// Limit simultaneous fragmented ZIP materialization to a conservative share
// of physical memory. The reservation is process local and intentionally is
// not checkpointed.
//
static inline uint64_t zip_reassembly_memory_budget(void) {

  uint64_t budget = atomic_load_explicit(
      &zip_reassembly_memory_budget_cached, memory_order_acquire);

  if (budget != 0) {
    return budget;
  }

  uint64_t physical_memory = 0;

#if defined(__APPLE__)
  size_t physical_memory_size = sizeof(physical_memory);

  if (sysctlbyname("hw.memsize", &physical_memory,
                   &physical_memory_size, NULL, 0) != 0) {
    physical_memory = 0;
  }
#elif defined(_SC_PHYS_PAGES) && defined(_SC_PAGESIZE)
  const long physical_pages = sysconf(_SC_PHYS_PAGES);
  const long page_size = sysconf(_SC_PAGESIZE);

  if (physical_pages > 0 && page_size > 0
      && (uint64_t)physical_pages
             <= UINT64_MAX / (uint64_t)page_size) {
    physical_memory = (uint64_t)physical_pages * (uint64_t)page_size;
  }
#endif

  budget = physical_memory >= ZIP_REASSEMBLY_MEMORY_DIVISOR
               ? physical_memory / ZIP_REASSEMBLY_MEMORY_DIVISOR
               : ZIP_REASSEMBLY_FALLBACK_BUDGET;
  if (budget == 0) {
    budget = ZIP_REASSEMBLY_FALLBACK_BUDGET;
  }

  uint64_t expected = 0;

  if (!atomic_compare_exchange_strong_explicit(
          &zip_reassembly_memory_budget_cached, &expected, budget,
          memory_order_release, memory_order_relaxed)) {
    budget = expected;
  }
  return budget;
}

// Estimate the peak memory needed by one fragmented ZIP worker. The estimate
// covers the candidate, trial buffers, nested repair blockvectors, and their
// block mapping arrays.
//
static inline bool zip_reassembly_memory_requirement(
    uint64_t archive_size,
    uint64_t *required) {

  if (!required || archive_size == 0 || scalpel_state.blocksize == 0) {
    return false;
  }

  const uint64_t blocksize = scalpel_state.blocksize;
  const uint64_t total_blocks = archive_size / blocksize
                                + (archive_size % blocksize != 0);
  uint64_t rounded_size = 0;
  uint64_t buffer_memory = 0;
  uint64_t block_memory = 0;

  if (total_blocks == 0
      || total_blocks > UINT64_MAX / blocksize) {
    return false;
  }
  rounded_size = total_blocks * blocksize;
  if (__builtin_mul_overflow(rounded_size,
                             ZIP_REASSEMBLY_BUFFER_COPIES,
                             &buffer_memory)
      || __builtin_mul_overflow(total_blocks,
                                ZIP_REASSEMBLY_BLOCK_OVERHEAD,
                                &block_memory)
      || __builtin_add_overflow(buffer_memory, block_memory, required)) {
    return false;
  }
  return true;
}

// Reserve the complete working set before archive sized buffers are created.
// Threads wait when other ZIP workers temporarily hold the budget, but still
// return promptly when a checkpoint is requested.
//
static inline ZipMemoryReservationResult zip_reassembly_reserve_memory(
    ThreadWork *work,
    CarveInfo **candidate,
    uint64_t archive_size,
    uint64_t *reservation,
    uuid_string_t uuidp,
    uuid_string_t uuidc) {

  uint64_t required = 0;
  const uint64_t budget = zip_reassembly_memory_budget();

  if (!work || !candidate || !*candidate || !reservation) {
    return ZIP_MEMORY_UNAVAILABLE;
  }
  if (*reservation != 0) {
    return ZIP_MEMORY_ACQUIRED;
  }
  if (!zip_reassembly_memory_requirement(archive_size, &required)
      || required > budget) {
    return ZIP_MEMORY_UNAVAILABLE;
  }

  const struct timespec wait_time = {
      .tv_sec = 0,
      .tv_nsec = ZIP_REASSEMBLY_WAIT_NANOSECONDS};

  for (;;) {
    uint64_t current = atomic_load_explicit(
        &zip_reassembly_memory_reserved, memory_order_acquire);

    if (current <= budget - required
        && atomic_compare_exchange_weak_explicit(
               &zip_reassembly_memory_reserved, &current,
               current + required, memory_order_acq_rel,
               memory_order_relaxed)) {
      *reservation = required;
      return ZIP_MEMORY_ACQUIRED;
    }
    if (reassembly_time_to_checkpoint(work->id, *candidate,
                                      uuidp, uuidc)) {
      return ZIP_MEMORY_STOPPED;
    }
    (void)nanosleep(&wait_time, NULL);
  }
}

// Release a process local fragmented ZIP working set reservation.
//
static inline void zip_reassembly_release_memory(uint64_t *reservation) {

  if (!reservation || *reservation == 0) {
    return;
  }
  atomic_fetch_sub_explicit(&zip_reassembly_memory_reserved,
                            *reservation, memory_order_acq_rel);
  *reservation = 0;
}

// Combine a known archive header with a discovered EOCD. Central-directory
// redundancy confirms the pairing and places the terminal metadata at its
// logical positions before the ordinary ZIP reassembler begins.
//
static inline ZipInitializationResult zip_reassembly_initialize_pair(
    ThreadWork *work,
    CarveInfo *candidate,
    ZipCarveState **state,
    uint64_t header_actual,
    uint64_t eocd_actual,
    uint64_t *memory_reservation,
    uuid_string_t uuidp,
    uuid_string_t uuidc) {

  if (!candidate || !candidate->b || !state || *state
      || !memory_reservation
      || scalpel_state.blocksize == 0
      || candidate->needleidx < 0
      || (uint32_t)candidate->needleidx >= scalpel_state.num_specs) {
    return ZIP_INITIALIZATION_NO_MATCH;
  }

  const uint64_t blocksize = scalpel_state.blocksize;
  uint8_t eocd[ZIP_EOCD_SIZE];
  uint8_t archive_header[2 * sizeof(uint32_t)];
  uint64_t first_local_offset = 0;

  if (header_actual % blocksize != 0
      || !zip_copy_actual_bytes(header_actual, sizeof(uint32_t),
                                archive_header)
      || !zip_copy_actual_bytes(eocd_actual, sizeof(eocd), eocd)
      || zip_read_le32(eocd) != ZIP_EOCD_SIGNATURE) {
    return ZIP_INITIALIZATION_NO_MATCH;
  }

  if (zip_read_le32(archive_header) == ZIP_SINGLE_SEGMENT_MARKER) {
    if (!zip_copy_actual_bytes(header_actual, sizeof(archive_header),
                               archive_header)
        || zip_read_le32(archive_header + sizeof(uint32_t))
               != ZIP_LOCAL_HEADER_SIGNATURE) {
      return ZIP_INITIALIZATION_NO_MATCH;
    }
    first_local_offset = sizeof(uint32_t);
  }
  else if (zip_read_le32(archive_header) != ZIP_LOCAL_HEADER_SIGNATURE) {
    return ZIP_INITIALIZATION_NO_MATCH;
  }

  const uint16_t disk = zip_read_le16(eocd + 4);
  const uint16_t central_disk = zip_read_le16(eocd + 6);
  const uint16_t disk_entries = zip_read_le16(eocd + 8);
  const uint16_t total_entries = zip_read_le16(eocd + 10);
  const uint32_t central_size32 = zip_read_le32(eocd + 12);
  const uint32_t central_offset32 = zip_read_le32(eocd + 16);
  const uint64_t eocd_length = ZIP_EOCD_SIZE + zip_read_le16(eocd + 20);
  const bool zip64 = disk == ZIP_UINT16_SENTINEL
                     || central_disk == ZIP_UINT16_SENTINEL
                     || disk_entries == ZIP_UINT16_SENTINEL
                     || total_entries == ZIP_UINT16_SENTINEL
                     || central_size32 == ZIP_UINT32_SENTINEL
                     || central_offset32 == ZIP_UINT32_SENTINEL;
  uint64_t entry_count = total_entries;
  uint64_t central_size = central_size32;
  uint64_t central_offset = central_offset32;
  uint64_t terminal_actual = eocd_actual;
  uint64_t terminal_length = 0;

  if (!zip64) {
    if (disk != 0 || central_disk != 0 || disk_entries != total_entries) {
      return ZIP_INITIALIZATION_NO_MATCH;
    }
  }
  else {
    if (eocd_actual < ZIP64_EOCD_LOCATOR_SIZE) {
      return ZIP_INITIALIZATION_NO_MATCH;
    }

    const uint64_t locator_actual = eocd_actual
                                    - ZIP64_EOCD_LOCATOR_SIZE;
    uint8_t locator[ZIP64_EOCD_LOCATOR_SIZE];
    uint64_t record_actual = 0;
    uint64_t record_size = 0;

    if (!zip_copy_actual_bytes(locator_actual, sizeof(locator), locator)
        || zip_read_le32(locator) != ZIP64_EOCD_LOCATOR_SIGNATURE
        || zip_read_le32(locator + 4) != 0
        || zip_read_le32(locator + 16) != 1
        || !zip_find_actual_zip64_record(
               locator_actual, &record_actual, &record_size, &entry_count,
               &central_size, &central_offset)) {
      return ZIP_INITIALIZATION_NO_MATCH;
    }
    terminal_actual = record_actual;
    terminal_length = record_size + ZIP64_EOCD_LOCATOR_SIZE;
  }

  if (entry_count == 0 || central_size < ZIP_CENTRAL_HEADER_SIZE
      || central_size / ZIP_CENTRAL_HEADER_SIZE < entry_count
      || central_size > terminal_actual) {
    return ZIP_INITIALIZATION_NO_MATCH;
  }

  const uint64_t metadata_actual = terminal_actual - central_size;
  uint64_t metadata_end = 0;

  if (__builtin_add_overflow(eocd_actual, eocd_length, &metadata_end)
      || metadata_end > filemirror_filesize(scalpel_state.filemirror)
      || metadata_end < metadata_actual) {
    return ZIP_INITIALIZATION_NO_MATCH;
  }

  const uint64_t metadata_length = metadata_end - metadata_actual;
  uint64_t archive_size = 0;
  uint64_t observed_archive_size = 0;
  uint64_t physical_span = 0;

  if (metadata_length > SIZE_MAX
      || __builtin_add_overflow(central_offset, metadata_length,
                                &archive_size)
      || archive_size < ZIP_EOCD_SIZE
      || archive_size
             > scalpel_state.search_specs[candidate->needleidx].MAXIMUMSIZE) {
    return ZIP_INITIALIZATION_NO_MATCH;
  }

  observed_archive_size = archive_size;
  if (metadata_end >= header_actual) {
    physical_span = metadata_end - header_actual;

    if (physical_span >= archive_size
        && (physical_span - archive_size) % blocksize == 0) {
      observed_archive_size = physical_span;
    }
  }

  CarveInfo *reservation_candidate = candidate;
  const ZipMemoryReservationResult memory_result =
      zip_reassembly_reserve_memory(
          work, &reservation_candidate, archive_size,
          memory_reservation, uuidp, uuidc);

  if (memory_result == ZIP_MEMORY_STOPPED) {
    return ZIP_INITIALIZATION_STOPPED;
  }
  if (memory_result == ZIP_MEMORY_UNAVAILABLE) {
    return ZIP_INITIALIZATION_RESOURCE_LIMIT;
  }

  uint8_t *metadata = (uint8_t *)malloc((size_t)metadata_length);

  check_memory_allocation(metadata, __LINE__, __FILE__,
                          "ZIP footer metadata");
  if (!zip_copy_actual_bytes(metadata_actual, metadata_length, metadata)) {
    free(metadata);
    zip_reassembly_release_memory(memory_reservation);
    return ZIP_INITIALIZATION_NO_MATCH;
  }

  ZipLayout footer_layout;
  uint64_t central_failure = 0;

  memset(&footer_layout, 0, sizeof(footer_layout));
  footer_layout.entry_count = entry_count;
  footer_layout.central_offset = central_offset;
  footer_layout.observed_central_offset = 0;
  footer_layout.central_size = central_size;
  footer_layout.archive_size = archive_size;
  footer_layout.observed_archive_size = metadata_length;
  footer_layout.eocd_offset = central_offset + central_size
                              + terminal_length;
  footer_layout.zip64 = zip64;

  if (!zip_parse_central_directory(metadata, metadata_length,
                                   &footer_layout, &central_failure)) {
    zip_layout_clear(&footer_layout);
    free(metadata);
    zip_reassembly_release_memory(memory_reservation);
    return ZIP_INITIALIZATION_NO_MATCH;
  }
  zip_classify_office_layout(&footer_layout);

  const ZipEntry *first_entry = NULL;

  for (uint64_t index = 0; index < footer_layout.entry_count; index++) {
    if (footer_layout.entries[index].local_offset == first_local_offset) {
      first_entry = &footer_layout.entries[index];
      break;
    }
  }
  if (!first_entry) {
    zip_layout_clear(&footer_layout);
    free(metadata);
    zip_reassembly_release_memory(memory_reservation);
    return ZIP_INITIALIZATION_NO_MATCH;
  }

  const int64_t header_block_actual = (int64_t)(header_actual / blocksize);
  const uint64_t inserted_bytes = observed_archive_size - archive_size;
  const uint64_t removed_bytes = physical_span > 0
                                 && physical_span < archive_size
                                 && (archive_size - physical_span)
                                        % blocksize == 0
                                     ? archive_size - physical_span : 0;
  uint64_t first_header_delta = 0;
  uint64_t first_header_gap = 0;
  uint64_t first_header_actual = 0;
  const bool first_header_in_range = !__builtin_add_overflow(
      header_actual, first_local_offset, &first_header_actual);
  bool first_header_matches = first_header_in_range
                              && zip_local_header_matches_actual(
                                     first_header_actual, first_entry,
                                     &first_header_delta);

  if (!first_header_matches && inserted_bytes > 0) {
    first_header_matches = zip_local_header_matches_across_gap(
        header_actual, inserted_bytes, first_entry,
        &first_header_delta, &first_header_gap);
  }

  if (filemirror_actual_block_covered(scalpel_state.filemirror,
                                      header_block_actual)
      || !first_header_matches
      || metadata_actual % blocksize != central_offset % blocksize) {
    zip_layout_clear(&footer_layout);
    free(metadata);
    zip_reassembly_release_memory(memory_reservation);
    return ZIP_INITIALIZATION_NO_MATCH;
  }

  const uint64_t total_blocks = CEILDIV(archive_size, blocksize);
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), blocksize);
  const uint64_t header_block = (uint64_t)header_block_actual;
  const uint64_t inserted_blocks = inserted_bytes / blocksize;
  const uint64_t removed_blocks = removed_bytes / blocksize;
  const uint64_t candidate_failure_slot =
      blockvector_get_num_blocks(candidate->b);
  const uint64_t candidate_failure_offset =
      candidate_failure_slot < total_blocks
          ? candidate_failure_slot * blocksize : UINT64_MAX;
  uint64_t omitted_zero_blocks = 0;

  if (candidate_failure_offset != UINT64_MAX
      && candidate_failure_slot < image_blocks - header_block) {
    const uint64_t first_zero = header_block + candidate_failure_slot;
    uint64_t zero_limit = total_blocks - candidate_failure_slot;

    if (zero_limit > image_blocks - first_zero) {
      zero_limit = image_blocks - first_zero;
    }
    while (omitted_zero_blocks < zero_limit
           && first_zero + omitted_zero_blocks <= INT64_MAX
           && filemirror_actual_block_is_zero(
                  scalpel_state.filemirror,
                  (int64_t)(first_zero + omitted_zero_blocks))) {
      omitted_zero_blocks++;
    }
  }
  uint64_t missing_slot = 0;
  bool footer_geometry_ready = inserted_bytes > 0 || removed_bytes > 0
                               || candidate_failure_offset != UINT64_MAX;
  uint64_t first_displaced_entry = UINT64_MAX;
  uint64_t first_displaced_offset = UINT64_MAX;
  uint64_t exact_gap_entry = UINT64_MAX;
  uint64_t exact_gap_offset = UINT64_MAX;

  if (removed_blocks > 0) {
    missing_slot = blockvector_get_num_blocks(candidate->b);
    if (missing_slot == 0 || missing_slot >= total_blocks
        || removed_blocks > total_blocks - missing_slot) {
      zip_layout_clear(&footer_layout);
      free(metadata);
      zip_reassembly_release_memory(memory_reservation);
      return ZIP_INITIALIZATION_NO_MATCH;
    }
    footer_layout.physical_gap_slot = missing_slot;
    footer_layout.physical_gap_blocks = removed_blocks;
  }

  // The central directory supplies each logical local-header offset. Match
  // every cumulative block shift within the observed physical span so
  // separate inserted gaps can be repaired one member at a time.
  if (footer_geometry_ready) {
    for (uint64_t index = 0; index < footer_layout.entry_count; index++) {
      ZipEntry *entry = &footer_layout.entries[index];
      uint64_t unshifted_actual = 0;
      uint64_t shifted_actual = 0;
      uint64_t unshifted_delta = 0;
      uint64_t shifted_delta = 0;
      uint64_t intermediate_delta = 0;
      uint64_t intermediate_shift = 0;
      uint64_t split_delta = 0;
      uint64_t split_gap = 0;

      if (__builtin_add_overflow(header_actual, entry->local_offset,
                                 &unshifted_actual)
          || __builtin_add_overflow(unshifted_actual, inserted_bytes,
                                    &shifted_actual)) {
        footer_geometry_ready = false;
        break;
      }

      const bool unshifted_match = zip_local_header_matches_actual(
          unshifted_actual, entry, &unshifted_delta);
      const bool shifted_match = zip_local_header_matches_actual(
          shifted_actual, entry, &shifted_delta);
      bool intermediate_match = false;

      if (!unshifted_match && !shifted_match && inserted_blocks > 1) {
        for (uint64_t shift_blocks = 1;
             shift_blocks < inserted_blocks; shift_blocks++) {
          const uint64_t shift_bytes = shift_blocks * blocksize;
          uint64_t intermediate_actual = 0;
          uint64_t candidate_delta = 0;

          if (__builtin_add_overflow(unshifted_actual, shift_bytes,
                                     &intermediate_actual)) {
            break;
          }
          if (zip_local_header_matches_actual(
                  intermediate_actual, entry, &candidate_delta)) {
            intermediate_match = true;
            intermediate_delta = candidate_delta;
            intermediate_shift = shift_bytes;
            break;
          }
        }
      }
      const bool split_match = !unshifted_match && !shifted_match
                               && !intermediate_match
                               && zip_local_header_matches_across_gap(
                                      header_actual, inserted_bytes, entry,
                                      &split_delta, &split_gap);

      if (!unshifted_match && !shifted_match && !intermediate_match
          && !split_match) {
        uint64_t maximum_local_end = 0;
        const bool local_may_cross_failure =
            candidate_failure_offset != UINT64_MAX
            && !__builtin_add_overflow(
                   entry->local_offset,
                   (uint64_t)ZIP_LOCAL_HEADER_SIZE + entry->name_length
                       + UINT16_MAX,
                   &maximum_local_end)
            && maximum_local_end > candidate_failure_offset;
        const bool damaged_local = candidate_failure_offset != UINT64_MAX
                                   && (entry->local_offset
                                          >= candidate_failure_offset
                                       || local_may_cross_failure);

        if (damaged_local) {
          entry->observed_local_offset = entry->local_offset;
          entry->data_offset = entry->local_offset;
          entry->observed_data_offset = entry->local_offset;
          entry->range_end = entry->local_offset + 1;
          entry->geometry_known = false;
          footer_layout.displaced_structure = true;
          if (entry->local_offset < first_displaced_offset) {
            first_displaced_offset = entry->local_offset;
            first_displaced_entry = index;
          }
          continue;
        }
        if (scalpel_state.mode_verbose) {
          lock_fprintf(stdout,
                       "ZIP footer pairing could not locate local entry "
                       "%" PRIu64 " at logical offset %" PRIu64 ".\n",
                       index, entry->local_offset);
        }
        footer_geometry_ready = false;
        break;
      }
      if (split_match && exact_gap_offset != UINT64_MAX
          && exact_gap_offset != split_gap) {
        footer_geometry_ready = false;
        break;
      }

      const bool shifted_only = !unshifted_match && shifted_match;
      const uint64_t observed_shift = shifted_only
          ? inserted_bytes : intermediate_match ? intermediate_shift : 0;
      const uint64_t data_delta = split_match
                                      ? split_delta
                                      : (shifted_only
                                             ? shifted_delta
                                             : intermediate_match
                                                   ? intermediate_delta
                                                   : unshifted_delta);
      uint64_t observed_local = 0;
      uint64_t data_offset = 0;
      uint64_t data_end = 0;
      uint64_t observed_data_offset = 0;

      if (__builtin_add_overflow(entry->local_offset, observed_shift,
                                 &observed_local)
          || __builtin_add_overflow(entry->local_offset, data_delta,
                                 &data_offset)
          || __builtin_add_overflow(data_offset, entry->compressed_size,
                                    &data_end)
          || __builtin_add_overflow(observed_local, data_delta,
                                    &observed_data_offset)
          || (split_match
              && __builtin_add_overflow(observed_data_offset,
                                        inserted_bytes,
                                        &observed_data_offset))
          || data_end > central_offset) {
        footer_geometry_ready = false;
        break;
      }

      entry->observed_local_offset = observed_local;
      entry->data_offset = data_offset;
      entry->observed_data_offset = observed_data_offset;
      entry->range_end = data_end;
      entry->geometry_known = true;
      if (scalpel_state.mode_verbose && inserted_blocks > 1) {
        lock_fprintf(stdout,
                     "ZIP local geometry: entry=%" PRIu64
                     " logical=%" PRIu64 " observed=%" PRIu64
                     " shift_blocks=%" PRIu64 ".\n",
                     index, entry->local_offset,
                     entry->observed_local_offset,
                     observed_shift / blocksize);
      }
      if (observed_shift > 0 || split_match) {
        footer_layout.displaced_structure = true;
        if (entry->local_offset < first_displaced_offset) {
          first_displaced_offset = entry->local_offset;
          first_displaced_entry = index;
        }
      }
      if (split_match) {
        exact_gap_entry = index;
        exact_gap_offset = split_gap;
      }
    }
  }
  uint64_t source_first = metadata_actual / blocksize;
  const uint64_t source_last = (metadata_end - 1) / blocksize;
  uint64_t destination_first = central_offset / blocksize;

  if (destination_first > 1 && source_first > 0) {
    const int64_t previous_actual = (int64_t)(source_first - 1);

    if (!filemirror_actual_block_covered(scalpel_state.filemirror,
                                         previous_actual)
        && filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                           previous_actual) >= 0) {
      source_first--;
      destination_first--;
    }
  }
  const uint64_t source_blocks = source_last - source_first + 1;

  if (total_blocks == 0 || header_block >= image_blocks
      || destination_first >= total_blocks
      || source_blocks > total_blocks - destination_first) {
    zip_layout_clear(&footer_layout);
    free(metadata);
    zip_reassembly_release_memory(memory_reservation);
    return ZIP_INITIALIZATION_NO_MATCH;
  }

  BlockVector *replacement = NULL;

  init_blockvector(scalpel_state.filemirror, &replacement, total_blocks,
                   false);
  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    const bool missing = removed_blocks > 0 && slot >= missing_slot
                         && slot - missing_slot < removed_blocks;
    uint64_t physical_slot = slot;

    if (removed_blocks > 0 && slot >= missing_slot + removed_blocks) {
      physical_slot -= removed_blocks;
    }

    uint64_t actual = 0;
    int64_t apparent = -1;

    if (!missing
        && !__builtin_add_overflow(header_block, physical_slot, &actual)
        && actual < image_blocks) {
      apparent = filemirror_apparent_blocknumber(
          scalpel_state.filemirror, (int64_t)actual);
    }

    blockvector_set_apparent_blocknumber(replacement, slot, apparent);
  }

  if (inserted_blocks > 1
      && total_blocks <= SIZE_MAX / sizeof(uint64_t)) {
    uint64_t *slot_shift = (uint64_t *)calloc(
        (size_t)total_blocks, sizeof(uint64_t));

    check_memory_allocation(slot_shift, __LINE__, __FILE__,
                            "ZIP cumulative gap shifts");
    for (uint64_t index = 0; index < footer_layout.entry_count; index++) {
      const ZipEntry *entry = &footer_layout.entries[index];

      if (!entry->geometry_known
          || entry->observed_local_offset < entry->local_offset
          || entry->observed_data_offset < entry->data_offset) {
        continue;
      }
      const uint64_t local_shift = entry->observed_local_offset
                                   - entry->local_offset;
      const uint64_t data_shift = entry->observed_data_offset
                                  - entry->data_offset;

      if (local_shift == 0 || local_shift != data_shift
          || local_shift % blocksize != 0 || entry->range_end == 0) {
        continue;
      }
      const uint64_t shift_blocks = local_shift / blocksize;
      const uint64_t first_slot = entry->local_offset / blocksize;
      uint64_t end_slot = CEILDIV(entry->range_end, blocksize);

      if (first_slot >= total_blocks) {
        continue;
      }
      if (end_slot > total_blocks) {
        end_slot = total_blocks;
      }
      for (uint64_t slot = first_slot; slot < end_slot; slot++) {
        if (shift_blocks > slot_shift[slot]) {
          slot_shift[slot] = shift_blocks;
        }
      }
    }
    for (uint64_t slot = 0; slot < total_blocks; slot++) {
      if (slot_shift[slot] == 0) {
        continue;
      }
      uint64_t actual = 0;
      int64_t apparent = -1;

      if (!__builtin_add_overflow(header_block, slot, &actual)
          && !__builtin_add_overflow(actual, slot_shift[slot], &actual)
          && actual < image_blocks) {
        apparent = filemirror_apparent_blocknumber(
            scalpel_state.filemirror, (int64_t)actual);
      }
      blockvector_set_apparent_blocknumber(replacement, slot, apparent);
    }
    free(slot_shift);
  }
  for (uint64_t offset = 0; offset < source_blocks; offset++) {
    const int64_t source_actual = (int64_t)(source_first + offset);
    const int64_t source_apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, source_actual);

    if (source_apparent < 0
        || filemirror_actual_block_covered(scalpel_state.filemirror,
                                           source_actual)) {
      free_blockvector(&replacement);
      zip_layout_clear(&footer_layout);
      free(metadata);
      zip_reassembly_release_memory(memory_reservation);
      return ZIP_INITIALIZATION_NO_MATCH;
    }
    blockvector_set_apparent_blocknumber(replacement,
                                         destination_first + offset,
                                         source_apparent);
  }

  blockvector_set_data_length(replacement, archive_size);
  inflate_blockvector(replacement);

  ZipLayout trial_layout;
  uint64_t failure_offset = 4;
  uint64_t failure_entry = UINT64_MAX;
  bool content_valid = false;

  memset(&trial_layout, 0, sizeof(trial_layout));
  bool trial_matches = zip_find_layout(
      (const uint8_t *)blockvector_get_data_pointer(replacement),
      archive_size, scalpel_state.blocksize, &trial_layout, &failure_offset,
      &failure_entry, &content_valid)
      && trial_layout.archive_size == archive_size
      && trial_layout.entry_count == footer_layout.entry_count
      && trial_layout.central_offset == footer_layout.central_offset;

  if (trial_matches) {
    for (uint64_t index = 0; index < trial_layout.entry_count; index++) {
      const ZipEntry *trial_entry = &trial_layout.entries[index];
      const ZipEntry *footer_entry = &footer_layout.entries[index];

      if (trial_entry->local_offset != footer_entry->local_offset
          || trial_entry->compressed_size != footer_entry->compressed_size
          || trial_entry->uncompressed_size != footer_entry->uncompressed_size
          || trial_entry->crc32 != footer_entry->crc32
          || trial_entry->flags != footer_entry->flags
          || trial_entry->method != footer_entry->method
          || trial_entry->name_length != footer_entry->name_length
          || memcmp(trial_entry->name, footer_entry->name,
                    trial_entry->name_length) != 0) {
        trial_matches = false;
        break;
      }
    }
  }

  if (trial_matches) {
    if (removed_blocks > 0) {
      trial_layout.physical_gap_slot = missing_slot;
      trial_layout.physical_gap_blocks = removed_blocks;
    }
    *state = zip_state_from_layout(&trial_layout, failure_offset,
                                   failure_entry, inserted_bytes > 0);
  }
  else if (footer_geometry_ready) {
    // A physical gap can move local headers and member data together, making
    // the initial contiguous trial structurally unparsable. The independently
    // matched local and central records still provide complete state for an
    // exact member-level repair.
    footer_layout.observed_archive_size = archive_size;
    footer_layout.displaced_structure = true;
    failure_entry = first_displaced_entry;
    failure_offset = exact_gap_offset != UINT64_MAX
                         ? exact_gap_offset
                         : (first_displaced_entry < footer_layout.entry_count
                                ? footer_layout.entries[first_displaced_entry]
                                      .data_offset
                                : 4);
    *state = zip_state_from_layout(&footer_layout, failure_offset,
                                   failure_entry, inserted_bytes > 0);

    if (*state) {
      const uint8_t *replacement_data = (const uint8_t *)
          blockvector_get_data_pointer(replacement);
      uint64_t selected_local = first_displaced_offset;

      for (uint64_t index = 0; index < (*state)->entry_count; index++) {
        const ZipStateEntry *entry = &(*state)->entries[index];

        if (entry->encrypted || !entry->geometry_known) {
          continue;
        }

        uint64_t entry_failure = entry->data_offset;
        uint64_t output_progress = 0;

        if (!zip_reassembly_verify_entry(
                replacement_data, archive_size, *state, entry,
                &entry_failure, &output_progress)
            && entry->local_offset < selected_local) {
          selected_local = entry->local_offset;
          (*state)->failure_entry = index;
          (*state)->failure_offset = entry_failure;
        }
      }

      if ((*state)->failure_entry >= (*state)->entry_count
          && (*state)->entry_count > 0) {
        uint64_t earliest = 0;

        for (uint64_t index = 1; index < (*state)->entry_count; index++) {
          if ((*state)->entries[index].local_offset
              < (*state)->entries[earliest].local_offset) {
            earliest = index;
          }
        }
        (*state)->failure_entry = earliest;
        (*state)->failure_offset = (*state)->entries[earliest].data_offset;
      }
      if (exact_gap_offset != UINT64_MAX
          && exact_gap_entry < (*state)->entry_count) {
        (*state)->physical_gap_slot = exact_gap_offset / blocksize;
        (*state)->failure_entry = exact_gap_entry;
        (*state)->failure_offset = exact_gap_offset;
      }
    }
  }
  zip_layout_clear(&trial_layout);

  if (*state && removed_blocks > 0) {
    const uint64_t missing_offset = missing_slot * blocksize;

    (*state)->physical_gap_slot = missing_slot;
    (*state)->physical_gap_blocks = removed_blocks;
    (*state)->had_physical_gap = true;
    (*state)->failure_offset = missing_offset;
    (*state)->failure_entry = UINT64_MAX;
    for (uint64_t index = 0; index < (*state)->entry_count; index++) {
      const ZipStateEntry *entry = &(*state)->entries[index];

      if (missing_offset >= entry->local_offset
          && missing_offset < entry->range_end) {
        (*state)->failure_entry = index;
        break;
      }
    }
    (*state)->preferred_destination_slot = missing_slot;
    (*state)->preferred_run_length = removed_blocks;
    (*state)->preferred_run_active = true;
  }
  else if (*state && candidate_failure_offset != UINT64_MAX
           && inserted_bytes == 0) {
    (*state)->physical_gap_slot = candidate_failure_slot;
    (*state)->physical_gap_blocks = omitted_zero_blocks;
    (*state)->failure_offset = candidate_failure_offset;
    if ((*state)->failure_entry >= (*state)->entry_count
        || !(*state)->entries[(*state)->failure_entry].geometry_known) {
      (*state)->failure_entry = UINT64_MAX;
    }
    if (omitted_zero_blocks > 0) {
      (*state)->had_physical_gap = true;
      (*state)->preferred_destination_slot = candidate_failure_slot;
      (*state)->preferred_run_length = omitted_zero_blocks;
      (*state)->preferred_run_active = true;
    }
  }

  if (!*state) {
    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout,
                   "ZIP footer pairing rejected: normalized=%d "
                   "physical_geometry=%d inserted=%" PRIu64
                   " removed=%" PRIu64 ".\n",
                   trial_matches, footer_geometry_ready, inserted_bytes,
                   removed_bytes);
    }
    free_blockvector(&replacement);
    zip_layout_clear(&footer_layout);
    free(metadata);
    zip_reassembly_release_memory(memory_reservation);
    return ZIP_INITIALIZATION_NO_MATCH;
  }
  // The normalized trial has logical length archive_size. Retain the physical
  // header-to-footer span so gap repair can recover the displaced suffix
  // without searching the complete image.
  (*state)->observed_archive_size = observed_archive_size;
  if (inserted_bytes > 0) {
    (*state)->gap_base_observed_archive_size = observed_archive_size;
    (*state)->gap_base_physical_gap_slot = (*state)->physical_gap_slot;
    (*state)->gap_base_physical_gap_blocks =
        (*state)->physical_gap_blocks;
    (*state)->gap_base_header_actual = header_block;
    (*state)->gap_base_metadata_source_first = source_first;
    (*state)->gap_base_metadata_destination_first = destination_first;
    (*state)->gap_base_metadata_blocks = source_blocks;
    (*state)->gap_base_mapping_available = true;
  }
  (*state)->initialized = true;

  free_blockvector(&candidate->b);
  candidate->b = replacement;
  candidate->start = filemirror_apparent_location(
      scalpel_state.filemirror, header_actual);
  candidate->stop = candidate->start + archive_size - 1;

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout,
                 "ZIP footer pairing accepted: header=%" PRIu64
                 " eocd=%" PRIu64 " archive=%" PRIu64
                 " observed=%" PRIu64 " physical_gap=%" PRIu64
                 " physical_gap_blocks=%" PRIu64 ".\n",
                 header_actual, eocd_actual, archive_size,
                 observed_archive_size, (*state)->physical_gap_slot,
                 (*state)->physical_gap_blocks);
  }

  zip_layout_clear(&footer_layout);
  free(metadata);
  return ZIP_INITIALIZATION_MATCHED;
}

// A header-only F2 candidate can use any discovered EOCD, including one that
// precedes the header physically. Test candidates in increasing physical
// distance from the header so a nearby compatible archive is not preempted by
// a distant archive with similar metadata.
//
static inline ZipInitializationResult zip_reassembly_initialize_header_seed(
    ThreadWork *work,
    CarveInfo **candidate,
    ZipCarveState **state,
    uint64_t *memory_reservation,
    uuid_string_t uuidp,
    uuid_string_t uuidc) {

  if (!work || !candidate || !*candidate || !(*candidate)->b
      || !state || *state || !memory_reservation
      || scalpel_state.blocksize == 0
      || (*candidate)->needleidx < 0
      || (uint32_t)(*candidate)->needleidx >= scalpel_state.num_specs
      || blockvector_get_num_blocks((*candidate)->b) == 0) {
    return ZIP_INITIALIZATION_NO_MATCH;
  }

  const int64_t header_block = blockvector_get_actual_blocknumber(
      (*candidate)->b, 0);
  uint64_t header_in_block = (*candidate)->start
                             % scalpel_state.blocksize;

  if (header_block < 0
      || (uint64_t)header_block
             > UINT64_MAX / scalpel_state.blocksize) {
    return ZIP_INITIALIZATION_NO_MATCH;
  }
  const uint64_t block_actual = (uint64_t)header_block
                                * scalpel_state.blocksize;

  // Header discovery can retain the local-header signature four bytes after
  // a segment marker instead of the marker itself. Both identify the same
  // block-aligned archive, so normalize that seed before footer pairing.
  if (header_in_block == sizeof(uint32_t)) {
    uint8_t archive_header[2 * sizeof(uint32_t)];

    if (zip_copy_actual_bytes(block_actual, sizeof(archive_header),
                              archive_header)
        && zip_read_le32(archive_header) == ZIP_SINGLE_SEGMENT_MARKER
        && zip_read_le32(archive_header + sizeof(uint32_t))
               == ZIP_LOCAL_HEADER_SIGNATURE) {
      header_in_block = 0;
    }
  }
  if (header_in_block != 0) {
    return ZIP_INITIALIZATION_NO_MATCH;
  }

  const uint64_t header_actual = block_actual;
  SearchSpec *spec = &scalpel_state.search_specs[(*candidate)->needleidx];
  bool resource_limited = false;
  uint64_t lower = 0;
  uint64_t upper = spec->offsets.numfooters;

  while (lower < upper) {
    const uint64_t middle = lower + (upper - lower) / 2;

    if (spec->offsets.footers[middle] < header_actual) {
      lower = middle + 1;
    }
    else {
      upper = middle;
    }
  }

  uint64_t left = lower;
  uint64_t right = lower;

  while (left > 0 || right < spec->offsets.numfooters) {
    uint64_t index = 0;

    if (left == 0) {
      index = right++;
    }
    else if (right >= spec->offsets.numfooters) {
      index = --left;
    }
    else {
      const uint64_t left_distance = header_actual
                                     - spec->offsets.footers[left - 1];
      const uint64_t right_distance = spec->offsets.footers[right]
                                      - header_actual;

      if (right_distance <= left_distance) {
        index = right++;
      }
      else {
        index = --left;
      }
    }

    const ZipInitializationResult result =
        zip_reassembly_initialize_pair(
            work, *candidate, state, header_actual,
            spec->offsets.footers[index], memory_reservation,
            uuidp, uuidc);

    if (result == ZIP_INITIALIZATION_MATCHED
        || result == ZIP_INITIALIZATION_STOPPED) {
      return result;
    }
    if (result == ZIP_INITIALIZATION_RESOURCE_LIMIT) {
      resource_limited = true;
    }
  }
  return resource_limited ? ZIP_INITIALIZATION_RESOURCE_LIMIT
                          : ZIP_INITIALIZATION_NO_MATCH;
}

static int zip_destination_score_compare(const void *left,
                                         const void *right) {

  const ZipDestinationScore *a = (const ZipDestinationScore *)left;
  const ZipDestinationScore *b = (const ZipDestinationScore *)right;

  if (a->minimum_confidence != b->minimum_confidence) {
    return a->minimum_confidence < b->minimum_confidence ? -1 : 1;
  }
  if (a->confidence_sum != b->confidence_sum) {
    return a->confidence_sum < b->confidence_sum ? -1 : 1;
  }
  if (a->left_confidence != b->left_confidence) {
    return a->left_confidence > b->left_confidence ? -1 : 1;
  }
  if (a->right_confidence != b->right_confidence) {
    return a->right_confidence > b->right_confidence ? -1 : 1;
  }
  if (a->slot != b->slot) {
    return a->slot < b->slot ? -1 : 1;
  }
  return 0;
}

static inline uint8_t zip_source_confidence_tier(int confidence) {

  if (confidence >= (int)BLOCK_CONFIDENCE_VALID) {
    return 7;
  }
  if (confidence >= 16) {
    return 6;
  }
  if (confidence >= 8) {
    return 5;
  }
  if (confidence >= 6) {
    return 4;
  }
  if (confidence >= 4) {
    return 3;
  }
  if (confidence >= 3) {
    return 2;
  }
  if (confidence >= 2) {
    return 1;
  }
  return 0;
}

// Rank possible replacement positions for helper candidates. A low-confidence
// run after a stronger block is a useful fragmentation-boundary hypothesis.
// The primary candidate does not use this ordering and remains exhaustive.
//
static inline uint64_t zip_reassembly_ranked_destination(
    const CarveInfo *candidate,
    uint64_t first,
    uint64_t last,
    uint64_t run_length,
    uint64_t rank) {

  if (!candidate || !candidate->b || run_length == 0 || first > last) {
    return UINT64_MAX;
  }
  const uint64_t candidate_blocks = blockvector_get_num_blocks(candidate->b);

  if (first >= candidate_blocks || run_length > candidate_blocks - first) {
    return UINT64_MAX;
  }
  uint64_t final_start = candidate_blocks - run_length;

  if (last < final_start) {
    final_start = last;
  }
  if (first > final_start) {
    return UINT64_MAX;
  }
  const uint64_t count = final_start - first + 1;

  if (count > SIZE_MAX / sizeof(ZipDestinationScore)) {
    return UINT64_MAX;
  }
  ZipDestinationScore *scores = (ZipDestinationScore *)malloc(
      (size_t)count * sizeof(*scores));

  if (!scores) {
    return UINT64_MAX;
  }

  for (uint64_t index = 0; index < count; index++) {
    const uint64_t slot = first + index;
    ZipDestinationScore *score = &scores[index];

    score->slot = slot;
    score->confidence_sum = 0;
    score->minimum_confidence = (int)BLOCK_CONFIDENCE_VALID;

    for (uint64_t offset = 0; offset < run_length; offset++) {
      const int64_t actual = blockvector_get_actual_blocknumber(
          candidate->b, slot + offset);
      int confidence = actual < 0
                       || filemirror_actual_block_is_zero(
                              scalpel_state.filemirror, actual)
          ? (int)BLOCK_CONFIDENCE_INVALID
          : (int)filemirror_get_blocktype(
                scalpel_state.filemirror, actual, candidate->needleidx);

      if (confidence < (int)BLOCK_CONFIDENCE_INVALID) {
        confidence = (int)BLOCK_CONFIDENCE_INVALID;
      }
      if (confidence > (int)BLOCK_CONFIDENCE_VALID) {
        confidence = (int)BLOCK_CONFIDENCE_VALID;
      }
      if (confidence < score->minimum_confidence) {
        score->minimum_confidence = confidence;
      }
      score->confidence_sum += (uint64_t)confidence;
    }

    const int64_t left_actual = slot > 0
        ? blockvector_get_actual_blocknumber(candidate->b, slot - 1) : -1;
    const uint64_t right_slot = slot + run_length;
    const int64_t right_actual = right_slot < candidate_blocks
        ? blockvector_get_actual_blocknumber(candidate->b, right_slot) : -1;

    score->left_confidence = left_actual < 0
        ? (int)BLOCK_CONFIDENCE_INVALID
        : (int)filemirror_get_blocktype(
              scalpel_state.filemirror, left_actual, candidate->needleidx);
    score->right_confidence = right_actual < 0
        ? (int)BLOCK_CONFIDENCE_INVALID
        : (int)filemirror_get_blocktype(
              scalpel_state.filemirror, right_actual, candidate->needleidx);
  }

  qsort(scores, (size_t)count, sizeof(*scores),
        zip_destination_score_compare);
  const uint64_t selected = scores[rank % count].slot;

  free(scores);
  return selected;
}

// Blocks that are least likely to belong to this file type are the strongest
// destination candidates. Equal-confidence blocks retain physical order.
//
static inline uint64_t zip_reassembly_first_destination(
    const CarveInfo *candidate,
    uint64_t first,
    uint64_t last) {

  uint64_t selected = first;
  BlockValidationDecision selected_confidence = BLOCK_CONFIDENCE_VALID;

  if (!candidate || !candidate->b || first > last) {
    return UINT64_MAX;
  }
  for (uint64_t slot = first; slot <= last; slot++) {
    const int64_t actual = blockvector_get_actual_blocknumber(
        candidate->b, slot);
    const BlockValidationDecision confidence = actual < 0
        || filemirror_actual_block_is_zero(scalpel_state.filemirror, actual)
        ? BLOCK_CONFIDENCE_INVALID
        : filemirror_get_blocktype(scalpel_state.filemirror, actual,
                                   candidate->needleidx);

    if (confidence < selected_confidence) {
      selected = slot;
      selected_confidence = confidence;
      if (selected_confidence == BLOCK_CONFIDENCE_INVALID) {
        break;
      }
    }
  }
  return selected;
}

static inline uint64_t zip_reassembly_helper_limit(uint64_t archive_size) {

  uint64_t limit = scalpel_state.max_reassembly_threads > 1
      ? (uint64_t)scalpel_state.max_reassembly_threads - 1 : 0;

  if (limit > UINT32_MAX) {
    limit = UINT32_MAX;
  }

#if defined(_SC_AVPHYS_PAGES) && defined(_SC_PAGESIZE)
  const long available_pages = sysconf(_SC_AVPHYS_PAGES);
  const long page_size = sysconf(_SC_PAGESIZE);

  if (available_pages > 0 && page_size > 0 && archive_size > 0) {
    const uint64_t available_bytes =
        (uint64_t)available_pages > UINT64_MAX / (uint64_t)page_size
            ? UINT64_MAX
            : (uint64_t)available_pages * (uint64_t)page_size;
    const uint64_t helper_bytes = archive_size > UINT64_MAX / 3
        ? UINT64_MAX : archive_size * 3;
    const uint64_t memory_limit = helper_bytes == 0
        ? 0 : (available_bytes / 8) / helper_bytes;

    if (memory_limit < limit) {
      limit = memory_limit;
    }
  }
#else
  (void)archive_size;
#endif
  return limit;
}

static inline uint64_t zip_reassembly_next_destination(
    const CarveInfo *candidate,
    uint64_t first,
    uint64_t last,
    uint64_t current) {

  if (!candidate || !candidate->b || first > last
      || current < first || current > last) {
    return UINT64_MAX;
  }

  const int64_t current_actual = blockvector_get_actual_blocknumber(
      candidate->b, current);
  const BlockValidationDecision current_confidence = current_actual < 0
      || filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                         current_actual)
      ? BLOCK_CONFIDENCE_INVALID
      : filemirror_get_blocktype(scalpel_state.filemirror, current_actual,
                                 candidate->needleidx);
  uint64_t selected = UINT64_MAX;
  BlockValidationDecision selected_confidence = BLOCK_CONFIDENCE_VALID;

  // Consume the current confidence tier in physical order. This keeps a
  // confidence-ordered scan linear when many blocks have the same score.
  //
  for (uint64_t slot = current + 1; slot <= last; slot++) {
    const int64_t actual = blockvector_get_actual_blocknumber(
        candidate->b, slot);
    const BlockValidationDecision confidence = actual < 0
        || filemirror_actual_block_is_zero(scalpel_state.filemirror, actual)
        ? BLOCK_CONFIDENCE_INVALID
        : filemirror_get_blocktype(scalpel_state.filemirror, actual,
                                   candidate->needleidx);

    if (confidence == current_confidence) {
      return slot;
    }
  }

  // The current tier is exhausted. Find the first block in the next higher
  // confidence tier; lower tiers were exhausted by earlier calls.
  //
  for (uint64_t slot = first; slot <= last; slot++) {
    const int64_t actual = blockvector_get_actual_blocknumber(
        candidate->b, slot);
    const BlockValidationDecision confidence = actual < 0
        || filemirror_actual_block_is_zero(scalpel_state.filemirror, actual)
        ? BLOCK_CONFIDENCE_INVALID
        : filemirror_get_blocktype(scalpel_state.filemirror, actual,
                                   candidate->needleidx);

    if (confidence <= current_confidence) {
      continue;
    }
    if (selected == UINT64_MAX || confidence < selected_confidence
        || (confidence == selected_confidence && slot < selected)) {
      selected = slot;
      selected_confidence = confidence;
    }
  }
  return selected;
}

// Build an inverse index for the candidate's current block mapping. ZIP
// source trials repeatedly ask whether an actual block is already present;
// keeping that lookup local avoids repeatedly walking a large blockvector.
//
static inline bool zip_mapped_block_index_initialize(
    const CarveInfo *candidate,
    ZipMappedBlockIndex *index) {

  if (!candidate || !candidate->b || !index) {
    return false;
  }

  memset(index, 0, sizeof(*index));
  const uint64_t candidate_blocks = blockvector_get_num_blocks(candidate->b);
  uint64_t capacity = 16;

  if (candidate_blocks > UINT64_MAX / 2) {
    return false;
  }
  const uint64_t wanted = candidate_blocks * 2;

  while (capacity < wanted) {
    if (capacity > UINT64_MAX / 2) {
      return false;
    }
    capacity *= 2;
  }
  if (capacity > SIZE_MAX / sizeof(*index->entries)) {
    return false;
  }

  index->entries = (ZipMappedBlock *)malloc(
      (size_t)capacity * sizeof(*index->entries));
  if (!index->entries) {
    return false;
  }
  index->capacity = capacity;
  memset(index->entries, 0xff,
         (size_t)capacity * sizeof(*index->entries));

  for (uint64_t slot = 0; slot < candidate_blocks; slot++) {
    const int64_t actual = blockvector_get_actual_blocknumber(
        candidate->b, slot);

    if (actual < 0) {
      continue;
    }
    uint64_t bucket = (uint64_t)actual
                      * UINT64_C(11400714819323198485);

    bucket &= capacity - 1;
    while (index->entries[bucket].actual >= 0
           && index->entries[bucket].actual != actual) {
      bucket = (bucket + 1) & (capacity - 1);
    }
    if (index->entries[bucket].actual == actual) {
      index->entries[bucket].slot = ZIP_MAPPED_SLOT_DUPLICATE;
    }
    else {
      index->entries[bucket].actual = actual;
      index->entries[bucket].slot = (int64_t)slot;
    }
  }
  return true;
}

static inline void zip_mapped_block_index_clear(
    ZipMappedBlockIndex *index) {

  if (!index) {
    return;
  }
  free(index->entries);
  memset(index, 0, sizeof(*index));
}

static inline int64_t zip_mapped_block_index_find(
    const ZipMappedBlockIndex *index,
    int64_t actual) {

  if (!index || !index->entries || index->capacity == 0 || actual < 0) {
    return ZIP_SWAP_SLOT_UNMAPPED;
  }
  uint64_t bucket = (uint64_t)actual
                    * UINT64_C(11400714819323198485);

  bucket &= index->capacity - 1;
  while (index->entries[bucket].actual >= 0) {
    if (index->entries[bucket].actual == actual) {
      return index->entries[bucket].slot;
    }
    bucket = (bucket + 1) & (index->capacity - 1);
  }
  return ZIP_SWAP_SLOT_UNMAPPED;
}

static inline uint16_t zip_reassembly_source_bucket(
    const CarveInfo *candidate,
    const ZipMappedBlockIndex *mapped_blocks,
    int64_t source_actual,
    uint64_t sample_blocks) {

  uint64_t confidence_sum = 0;
  uint8_t mapped = 0;
  uint8_t reserved = 0;

  for (uint64_t sample = 0; sample < sample_blocks; sample++) {
    const int64_t actual = source_actual + (int64_t)sample;
    int block_confidence = (int)filemirror_get_blocktype(
        scalpel_state.filemirror, actual, candidate->needleidx);

    if (block_confidence < (int)BLOCK_CONFIDENCE_LOW) {
      block_confidence = (int)BLOCK_CONFIDENCE_LOW;
    }
    if (block_confidence > (int)BLOCK_CONFIDENCE_VALID) {
      block_confidence = (int)BLOCK_CONFIDENCE_VALID;
    }
    confidence_sum += (uint64_t)block_confidence;
    if (zip_mapped_block_index_find(mapped_blocks, actual) >= 0) {
      mapped = 1;
    }
    if (scalpel_state.reservations
        && filemirror_actual_block_reserved(
               scalpel_state.filemirror, actual) > 0) {
      reserved = 1;
    }
  }

  const int average_confidence =
      (int)(confidence_sum / sample_blocks);

  return (uint16_t)(mapped * 2 * ZIP_SOURCE_CONFIDENCE_TIERS
                    + reserved * ZIP_SOURCE_CONFIDENCE_TIERS
                    + zip_source_confidence_tier(average_confidence));
}

static inline bool zip_reassembly_source_run_viable_indexed(
    CarveInfo *candidate,
    uint64_t destination_slot,
    uint64_t run_length,
    int64_t source_actual,
    int64_t *swap_slot,
    const ZipMappedBlockIndex *mapped_blocks) {

  const uint64_t candidate_blocks = blockvector_get_num_blocks(candidate->b);
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);
  bool changes_mapping = false;
  bool per_block_swap = false;
  int64_t detected_swap_slot = ZIP_SWAP_SLOT_UNMAPPED;
  uint64_t external_mapped = 0;

  if (swap_slot) {
    *swap_slot = ZIP_SWAP_SLOT_UNMAPPED;
  }
  if (source_actual < 0 || run_length == 0
      || destination_slot >= candidate_blocks
      || run_length > candidate_blocks - destination_slot
      || (uint64_t)source_actual >= image_blocks
      || run_length > image_blocks - (uint64_t)source_actual) {
    return false;
  }

  for (uint64_t offset = 0; offset < run_length; offset++) {
    const int64_t actual = source_actual + (int64_t)offset;
    const bool zero = filemirror_actual_block_is_zero(
        scalpel_state.filemirror, actual);
    const int64_t apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, actual);

    if (filemirror_actual_block_covered(scalpel_state.filemirror, actual)
        && !zero) {
      return false;
    }
    if (apparent >= 0
        && filemirror_get_blocktype(scalpel_state.filemirror, actual,
                                    candidate->needleidx)
               == BLOCK_CONFIDENCE_INVALID) {
      return false;
    }

    int64_t mapped_slot = zip_mapped_block_index_find(mapped_blocks,
                                                       actual);

    if (!mapped_blocks || !mapped_blocks->entries) {
      for (uint64_t slot = 0; slot < candidate_blocks; slot++) {
        if (blockvector_get_actual_blocknumber(candidate->b, slot)
            == actual) {
          if (mapped_slot >= 0) {
            return false;
          }
          mapped_slot = (int64_t)slot;
        }
      }
    }
    else if (mapped_slot == ZIP_MAPPED_SLOT_DUPLICATE) {
      return false;
    }

    if (mapped_slot >= 0) {
      if ((uint64_t)mapped_slot == destination_slot + offset) {
        // This source block is already in its requested position.
      }
      else if ((uint64_t)mapped_slot >= destination_slot
               && (uint64_t)mapped_slot
                      < destination_slot + run_length) {
        per_block_swap = true;
      }
      else {
        const int64_t run_start = mapped_slot - (int64_t)offset;

        external_mapped++;
        if (detected_swap_slot == ZIP_SWAP_SLOT_UNMAPPED) {
          detected_swap_slot = run_start;
        }
        else if (detected_swap_slot != run_start) {
          per_block_swap = true;
        }
      }
    }

    if (blockvector_get_actual_blocknumber(candidate->b,
                                           destination_slot + offset)
        != actual) {
      changes_mapping = true;
    }
  }
  if (!changes_mapping) {
    return false;
  }
  if (external_mapped == run_length && !per_block_swap) {
    if (detected_swap_slot < 0
        || (uint64_t)detected_swap_slot > candidate_blocks - run_length
        || ((uint64_t)detected_swap_slot
                < destination_slot + run_length
            && destination_slot
                   < (uint64_t)detected_swap_slot + run_length)) {
      return false;
    }
    if (swap_slot) {
      *swap_slot = detected_swap_slot;
    }
  }
  else if (external_mapped > 0 || per_block_swap) {
    if (swap_slot) {
      *swap_slot = ZIP_SWAP_SLOT_PER_BLOCK;
    }
  }
  return true;
}

static inline bool zip_reassembly_source_run_viable(
    CarveInfo *candidate,
    uint64_t destination_slot,
    uint64_t run_length,
    int64_t source_actual,
    int64_t *swap_slot) {

  return zip_reassembly_source_run_viable_indexed(
      candidate, destination_slot, run_length, source_actual,
      swap_slot, NULL);
}

static inline void zip_reassembly_copy_source_run(uint8_t *data,
                                                  uint64_t destination_slot,
                                                  uint64_t run_length,
                                                  int64_t source_actual) {

  for (uint64_t offset = 0; offset < run_length; offset++) {
    uint64_t source_length = 0;
    const uint8_t *source = (const uint8_t *)
        filemirror_actual_block_data_pointer(
            scalpel_state.filemirror, source_actual + (int64_t)offset,
            &source_length);
    uint8_t *destination = data
        + (destination_slot + offset) * scalpel_state.blocksize;

    memset(destination, 0, scalpel_state.blocksize);
    if (source && source_length > 0) {
      memcpy(destination, source, source_length);
    }
  }
}

// Apply a source run to a trial buffer using the same mapping that will be
// committed to the blockvector. Mixed source runs vacate outside slots rather
// than propagating unrelated destination blocks into them.
//
static inline bool zip_reassembly_apply_source_run(
    uint8_t *data,
    const uint8_t *baseline,
    CarveInfo *candidate,
    uint64_t destination_slot,
    uint64_t run_length,
    int64_t source_actual,
    int64_t swap_slot) {

  if (!data || !baseline || !candidate || !candidate->b) {
    return false;
  }

  const uint64_t blocksize = scalpel_state.blocksize;

  if (swap_slot >= 0) {
    memcpy(data + (uint64_t)swap_slot * blocksize,
           baseline + destination_slot * blocksize,
           (size_t)(run_length * blocksize));
  }
  else if (swap_slot == ZIP_SWAP_SLOT_PER_BLOCK) {
    const uint64_t candidate_blocks = blockvector_get_num_blocks(candidate->b);

    for (uint64_t source_offset = 0; source_offset < run_length;
         source_offset++) {
      const int64_t actual = source_actual + (int64_t)source_offset;
      int64_t mapped_slot = ZIP_SWAP_SLOT_UNMAPPED;

      for (uint64_t slot = 0; slot < candidate_blocks; slot++) {
        if ((slot < destination_slot
             || slot >= destination_slot + run_length)
            && blockvector_get_actual_blocknumber(candidate->b, slot)
                   == actual) {
          mapped_slot = (int64_t)slot;
          break;
        }
      }
      if (mapped_slot < 0) {
        continue;
      }
      memset(data + (uint64_t)mapped_slot * blocksize, 0,
             (size_t)blocksize);
    }
  }

  zip_reassembly_copy_source_run(data, destination_slot, run_length,
                                 source_actual);
  return true;
}

static inline bool zip_reassembly_source_u32(int64_t source_actual,
                                             uint64_t source_offset,
                                             uint32_t *value) {

  if (source_actual < 0 || !value || scalpel_state.blocksize == 0) {
    return false;
  }

  uint32_t result = 0;

  for (uint64_t index = 0; index < sizeof(uint32_t); index++) {
    const uint64_t offset = source_offset + index;
    const int64_t actual = source_actual
                           + (int64_t)(offset / scalpel_state.blocksize);
    const uint64_t in_block = offset % scalpel_state.blocksize;
    uint64_t block_length = 0;
    const uint8_t *block = (const uint8_t *)
        filemirror_actual_block_data_pointer(scalpel_state.filemirror,
                                             actual, &block_length);

    if (!block || in_block >= block_length) {
      return false;
    }
    result |= (uint32_t)block[in_block] << (index * 8);
  }
  *value = result;
  return true;
}

static inline bool zip_reassembly_source_crc(int64_t source_actual,
                                             uint64_t source_offset,
                                             uint64_t length,
                                             uint32_t *crc) {

  if (source_actual < 0 || !crc || scalpel_state.blocksize == 0) {
    return false;
  }

  uLong result = crc32(0L, Z_NULL, 0);
  uint64_t consumed = 0;

  while (consumed < length) {
    const uint64_t offset = source_offset + consumed;
    const int64_t actual = source_actual
                           + (int64_t)(offset / scalpel_state.blocksize);
    const uint64_t in_block = offset % scalpel_state.blocksize;
    uint64_t block_length = 0;
    const uint8_t *block = (const uint8_t *)
        filemirror_actual_block_data_pointer(scalpel_state.filemirror,
                                             actual, &block_length);

    if (!block || in_block >= block_length) {
      return false;
    }
    uint64_t available = block_length - in_block;

    if (available > length - consumed) {
      available = length - consumed;
    }
    result = crc32(result, block + in_block, (uInt)available);
    consumed += available;
  }
  *crc = (uint32_t)result;
  return true;
}

static inline bool zip_reassembly_block_crc(int64_t source_actual,
                                            uint32_t *crc) {

  if (source_actual < 0 || !crc || scalpel_state.blocksize == 0) {
    return false;
  }

  uint64_t block_length = 0;
  const uint8_t *block = (const uint8_t *)
      filemirror_actual_block_data_pointer(scalpel_state.filemirror,
                                           source_actual, &block_length);

  if (!block) {
    return false;
  }
  if (block_length > scalpel_state.blocksize) {
    block_length = scalpel_state.blocksize;
  }

  uLong result = crc32(0L, Z_NULL, 0);

  if (block_length > 0) {
    result = crc32(result, block, (uInt)block_length);
  }

  static const uint8_t zeroes[256] = {0};
  uint64_t padding = scalpel_state.blocksize - block_length;

  while (padding > 0) {
    const uInt amount = padding > sizeof(zeroes)
                            ? (uInt)sizeof(zeroes) : (uInt)padding;

    result = crc32(result, zeroes, amount);
    padding -= amount;
  }
  *crc = (uint32_t)result;
  return true;
}

static inline bool zip_stored_patch_crc(const uint8_t *baseline,
                                        uint64_t baseline_length,
                                        const ZipStateEntry *entry,
                                        uint64_t destination_slot,
                                        uint64_t run_length,
                                        int64_t source_actual,
                                        uint32_t *crc) {

  if (!baseline || !entry || !crc || source_actual < 0
      || scalpel_state.blocksize == 0 || run_length == 0
      || entry->compressed_size != entry->uncompressed_size
      || entry->data_offset > UINT64_MAX - entry->compressed_size
      || destination_slot > UINT64_MAX / scalpel_state.blocksize
      || run_length > UINT64_MAX / scalpel_state.blocksize) {
    return false;
  }

  const uint64_t entry_start = entry->data_offset;
  const uint64_t entry_end = entry_start + entry->compressed_size;

  if (entry_end > baseline_length) {
    return false;
  }

  const uint64_t destination_start = destination_slot
                                     * scalpel_state.blocksize;
  const uint64_t run_bytes = run_length * scalpel_state.blocksize;

  if (destination_start > UINT64_MAX - run_bytes) {
    return false;
  }

  const uint64_t destination_end = destination_start + run_bytes;
  const uint64_t patch_start = destination_start > entry_start
                                   ? destination_start : entry_start;
  const uint64_t patch_end = destination_end < entry_end
                                 ? destination_end : entry_end;

  if (patch_start >= patch_end) {
    return false;
  }

  const uint64_t prefix_length = patch_start - entry_start;
  const uint64_t patch_length = patch_end - patch_start;
  const uint64_t suffix_length = entry_end - patch_end;
  const uint64_t source_offset = patch_start - destination_start;
  uint32_t source_crc = 0;

  if (!zip_reassembly_source_crc(source_actual, source_offset,
                                 patch_length, &source_crc)) {
    return false;
  }

  uint32_t combined_crc = (uint32_t)crc32_combine(
      zip_crc32(baseline + entry_start, prefix_length), source_crc,
      (z_off_t)patch_length);

  combined_crc = (uint32_t)crc32_combine(
      combined_crc, zip_crc32(baseline + patch_end, suffix_length),
      (z_off_t)suffix_length);
  *crc = combined_crc;
  return true;
}

static inline void zip_reassembly_commit_source_run(
    CarveInfo *candidate,
    uint64_t destination_slot,
    uint64_t run_length,
    int64_t source_actual,
    int64_t swap_slot) {

  if (swap_slot == ZIP_SWAP_SLOT_PER_BLOCK) {
    const uint64_t candidate_blocks = blockvector_get_num_blocks(candidate->b);

    for (uint64_t source_offset = 0; source_offset < run_length;
         source_offset++) {
      const int64_t actual = source_actual + (int64_t)source_offset;
      int64_t mapped_slot = ZIP_SWAP_SLOT_UNMAPPED;

      for (uint64_t slot = 0; slot < candidate_blocks; slot++) {
        if ((slot < destination_slot
             || slot >= destination_slot + run_length)
            && blockvector_get_actual_blocknumber(candidate->b, slot)
                   == actual) {
          mapped_slot = (int64_t)slot;
          break;
        }
      }
      if (mapped_slot < 0) {
        continue;
      }
      blockvector_set_apparent_blocknumber(candidate->b,
                                            (uint64_t)mapped_slot,
                                            ZIP_SWAP_SLOT_UNMAPPED);
    }
  }

  for (uint64_t offset = 0; offset < run_length; offset++) {
    const uint64_t destination = destination_slot + offset;
    const int64_t destination_apparent =
        blockvector_get_apparent_blocknumber(candidate->b, destination);
    int64_t source_apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, source_actual + (int64_t)offset);

    if (swap_slot >= 0) {
      const uint64_t source = (uint64_t)swap_slot + offset;

      source_apparent = blockvector_get_apparent_blocknumber(candidate->b,
                                                              source);
      blockvector_set_apparent_blocknumber(candidate->b, source,
                                            destination_apparent);
    }

    blockvector_set_apparent_blocknumber(candidate->b, destination,
                                          source_apparent);
  }
  inflate_blockvector(candidate->b);
}

// Record the deterministic mapping that existed before physical-gap repair.
// A footer-paired candidate may contain one contiguous metadata run anchored
// elsewhere in the image; every other slot must follow the header physically.
//
static inline bool zip_reassembly_capture_gap_baseline(
    CarveInfo *candidate,
    ZipCarveState *state) {

  if (!candidate || !candidate->b || !state
      || scalpel_state.blocksize == 0) {
    return false;
  }
  if (state->gap_base_mapping_available) {
    return true;
  }

  const uint64_t total_blocks = CEILDIV(state->archive_size,
                                        scalpel_state.blocksize);
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);
  const int64_t header_actual = blockvector_get_actual_blocknumber(
      candidate->b, 0);

  if (total_blocks == 0 || image_blocks == 0 || header_actual < 0
      || blockvector_get_num_blocks(candidate->b) != total_blocks
      || (uint64_t)header_actual > image_blocks - total_blocks
      || total_blocks - 1
             > (uint64_t)INT64_MAX - (uint64_t)header_actual) {
    return false;
  }

  uint64_t metadata_source = 0;
  uint64_t metadata_destination = 0;
  uint64_t metadata_blocks = 0;
  bool metadata_finished = false;

  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    const int64_t actual = blockvector_get_actual_blocknumber(
        candidate->b, slot);
    const int64_t expected = header_actual + (int64_t)slot;

    if (actual == expected) {
      if (metadata_blocks > 0) {
        metadata_finished = true;
      }
      continue;
    }
    if (slot == 0 || actual < 0 || metadata_finished) {
      return false;
    }
    if (metadata_blocks == 0) {
      metadata_source = (uint64_t)actual;
      metadata_destination = slot;
      metadata_blocks = 1;
      continue;
    }
    if (metadata_source
            > (uint64_t)INT64_MAX - metadata_blocks
        || slot != metadata_destination + metadata_blocks
        || (uint64_t)actual != metadata_source + metadata_blocks) {
      return false;
    }
    metadata_blocks++;
  }

  state->gap_base_observed_archive_size = state->observed_archive_size;
  state->gap_base_physical_gap_slot = state->physical_gap_slot;
  state->gap_base_physical_gap_blocks = state->physical_gap_blocks;
  state->gap_base_header_actual = (uint64_t)header_actual;
  state->gap_base_metadata_source_first = metadata_source;
  state->gap_base_metadata_destination_first = metadata_destination;
  state->gap_base_metadata_blocks = metadata_blocks;
  state->gap_base_mapping_available = true;
  return true;
}

// Restore the deterministic header-to-footer mapping created during ZIP
// pairing. This lets a candidate exhaust all repairs beneath one gap
// hypothesis and then continue with the next hypothesis without retaining a
// second archive-sized blockvector.
//
static inline bool zip_reassembly_restore_gap_baseline(
    CarveInfo *candidate,
    ZipCarveState *state) {

  if (!candidate || !candidate->b || !state
      || !state->gap_base_mapping_available
      || scalpel_state.blocksize == 0) {
    return false;
  }

  const uint64_t total_blocks = CEILDIV(state->archive_size,
                                        scalpel_state.blocksize);
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);
  const uint64_t header_actual = state->gap_base_header_actual;

  if (total_blocks == 0
      || total_blocks > image_blocks
      || header_actual > INT64_MAX
      || total_blocks - 1 > (uint64_t)INT64_MAX - header_actual
      || blockvector_get_num_blocks(candidate->b) != total_blocks
      || header_actual > image_blocks - total_blocks) {
    return false;
  }
  if (state->gap_base_metadata_blocks > 0
      && (state->gap_base_metadata_destination_first >= total_blocks
          || state->gap_base_metadata_blocks
                 > total_blocks
                       - state->gap_base_metadata_destination_first
          || state->gap_base_metadata_source_first >= image_blocks
          || state->gap_base_metadata_blocks
                 > image_blocks - state->gap_base_metadata_source_first)) {
    return false;
  }

  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    const int64_t actual = (int64_t)(header_actual + slot);
    const int64_t apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, actual);

    blockvector_set_apparent_blocknumber(candidate->b, slot, apparent);
  }
  for (uint64_t offset = 0; offset < state->gap_base_metadata_blocks;
       offset++) {
    const int64_t source_actual = (int64_t)(
        state->gap_base_metadata_source_first + offset);
    const int64_t source_apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, source_actual);

    blockvector_set_apparent_blocknumber(
        candidate->b, state->gap_base_metadata_destination_first + offset,
        source_apparent);
  }
  blockvector_set_data_length(candidate->b, state->archive_size);
  inflate_blockvector(candidate->b);

  state->observed_archive_size = state->gap_base_observed_archive_size;
  state->physical_gap_slot = state->gap_base_physical_gap_slot;
  state->physical_gap_blocks = state->gap_base_physical_gap_blocks;
  state->failure_offset = state->gap_base_failure_offset;
  state->failure_entry = state->gap_base_failure_entry;
  state->destination_slot = 0;
  state->run_length = 1;
  state->preferred_run_length = 0;
  state->preferred_destination_slot = 0;
  state->seam_boundary_slot = 0;
  state->structure_resume_destination = 0;
  state->structure_destination_last = 0;
  state->structure_failure_offset = 0;
  state->structure_failure_entry = 0;
  state->structure_retry_destination = 0;
  state->structure_retry_next_destination = 0;
  state->structure_retry_first_destination = 0;
  state->seam_left_actual = 0;
  state->seam_right_actual = 0;
  state->scan_rank = 0;
  state->seam_variant = ZIP_SEAM_NONE;
  state->initialized = true;
  state->had_physical_gap = true;
  state->broad_scan = false;
  state->broad_wrapped = false;
  state->structure_pending = state->gap_base_structure_pending;
  state->stored_structure_trial = false;
  state->clone_scan_initialized = false;
  state->preferred_run_active = false;
  state->structure_retry_active = false;
  state->structure_retry_pending = false;
  state->gap_repair_applied = false;
  state->gap_hypothesis_isolated = false;
  zip_reassembly_reset_repair_resume(state);
  return true;
}

static inline void zip_reassembly_reset_repair_resume(
    ZipCarveState *state) {

  if (!state) {
    return;
  }
  memset(&state->repair_resume, 0, sizeof(state->repair_resume));
  state->repair_resume.best_source = -1;
  state->repair_resume.best_swap_slot = ZIP_SWAP_SLOT_UNMAPPED;
  state->repair_resume.best_confidence_gain = INT64_MIN;
}

// A physical insertion followed by one displaced run leaves a stored member
// in four exact pieces: its original prefix, a locally shifted run, the
// displaced run, and a locally shifted tail. Build CRC indexes for possible
// displaced runs and use the member CRC to solve all three boundaries without
// inflating or materializing unsuccessful trials.
//
static inline ZipStoredRepairResult zip_reassembly_repair_stored_gap_ooo(
    ThreadWork *work,
    CarveInfo **candidate,
    ZipCarveState *state,
    const ZipStateEntry *entry,
    uint64_t destination_first,
    uint64_t destination_last,
    uint64_t physical_shift,
    uuid_string_t uuidp,
    uuid_string_t uuidc) {

  if (!work || !candidate || !*candidate || !state || !entry
      || !(*candidate)->b || scalpel_state.blocksize == 0
      || entry->method != ZIP_METHOD_STORED
      || entry->compressed_size == 0
      || entry->compressed_size != entry->uncompressed_size
      || entry->data_offset > UINT64_MAX - entry->compressed_size
      || physical_shift == 0
      || (state->repair_resume.phase != ZIP_REPAIR_PHASE_NONE
          && state->repair_resume.phase
                 != ZIP_REPAIR_PHASE_STORED_GAP_OOO)) {
    return ZIP_STORED_REPAIR_NONE;
  }

  const uint64_t blocksize = scalpel_state.blocksize;
  const uint64_t entry_end = entry->data_offset + entry->compressed_size;
  const uint64_t total_blocks = CEILDIV(state->archive_size, blocksize);
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), blocksize);
  const uint64_t first_member_boundary = CEILDIV(entry->data_offset,
                                                  blocksize);
  const uint64_t last_member_block = (entry_end - 1) / blocksize;
  const int64_t header_actual = blockvector_get_actual_blocknumber(
      (*candidate)->b, 0);

  if (destination_first < first_member_boundary) {
    destination_first = first_member_boundary;
  }
  if (destination_last > last_member_block) {
    destination_last = last_member_block;
  }
  if (header_actual < 0 || destination_last >= total_blocks
      || destination_first > destination_last
      || destination_last - destination_first < 2
      || entry_end > INT64_MAX) {
    return ZIP_STORED_REPAIR_NONE;
  }

  uint64_t shifted_first = 0;
  uint64_t shifted_archive_end = 0;

  if (__builtin_add_overflow((uint64_t)header_actual, destination_first,
                             &shifted_first)
      || __builtin_add_overflow(shifted_first, physical_shift,
                                &shifted_first)
      || __builtin_add_overflow((uint64_t)header_actual, total_blocks,
                                &shifted_archive_end)
      || __builtin_add_overflow(shifted_archive_end, physical_shift,
                                &shifted_archive_end)
      || shifted_first > INT64_MAX || shifted_archive_end > image_blocks) {
    return ZIP_STORED_REPAIR_NONE;
  }

  const uint8_t *baseline = (const uint8_t *)
      blockvector_get_data_pointer((*candidate)->b);
  const uint64_t baseline_length = blockvector_get_data_length(
      (*candidate)->b);
  const uint64_t first_byte = destination_first * blocksize;
  const uint64_t boundary_count = destination_last
                                  - destination_first + 1;
  const uint64_t maximum_displaced_length = boundary_count - 2;

  if (!baseline || baseline_length < state->archive_size
      || first_byte < entry->data_offset || first_byte > entry_end
      || boundary_count > SIZE_MAX / sizeof(uint32_t)
      || maximum_displaced_length >= SIZE_MAX / sizeof(uLong)) {
    return ZIP_STORED_REPAIR_NONE;
  }

  uint32_t *baseline_prefix = (uint32_t *)calloc(
      (size_t)boundary_count, sizeof(*baseline_prefix));
  uint32_t *shifted_prefix = (uint32_t *)calloc(
      (size_t)boundary_count, sizeof(*shifted_prefix));
  uLong *block_operators = (uLong *)calloc(
      (size_t)(maximum_displaced_length + 1),
      sizeof(*block_operators));

  if (!baseline_prefix || !shifted_prefix || !block_operators) {
    free(block_operators);
    free(shifted_prefix);
    free(baseline_prefix);
    return ZIP_STORED_REPAIR_NONE;
  }

  const uLong block_operator = crc32_combine_gen((z_off_t)blocksize);

  block_operators[0] = crc32_combine_gen(0);
  for (uint64_t length = 1; length <= maximum_displaced_length;
       length++) {
    block_operators[length] = crc32_combine_gen(
        (z_off_t)(length * blocksize));
  }

  baseline_prefix[0] = zip_crc32(
      baseline + entry->data_offset, first_byte - entry->data_offset);
  shifted_prefix[0] = 0;
  for (uint64_t offset = 0; offset + 1 < boundary_count; offset++) {
    const uint64_t destination = destination_first + offset;
    const uint64_t baseline_offset = destination * blocksize;
    uint32_t shifted_block_crc = 0;

    if (!zip_reassembly_block_crc(
            (int64_t)(shifted_first + offset), &shifted_block_crc)) {
      free(block_operators);
      free(shifted_prefix);
      free(baseline_prefix);
      return ZIP_STORED_REPAIR_NONE;
    }
    const uint32_t baseline_block_crc = zip_crc32(
        baseline + baseline_offset, blocksize);

    baseline_prefix[offset + 1] = (uint32_t)crc32_combine_op(
        baseline_prefix[offset], baseline_block_crc, block_operator);
    shifted_prefix[offset + 1] = (uint32_t)crc32_combine_op(
        shifted_prefix[offset], shifted_block_crc, block_operator);
  }

  uint32_t shifted_full_crc = 0;

  if (!zip_reassembly_source_crc((int64_t)shifted_first, 0,
                                 entry_end - first_byte,
                                 &shifted_full_crc)) {
    free(block_operators);
    free(shifted_prefix);
    free(baseline_prefix);
    return ZIP_STORED_REPAIR_NONE;
  }

  const uint64_t fixed_crc_bytes = maximum_displaced_length
                                   * sizeof(uint32_t);
  const uint64_t bytes_per_source = sizeof(ZipStoredCrcSource)
                                    + 2 * sizeof(uint32_t);

  if (fixed_crc_bytes >= ZIP_STORED_CRC_INDEX_BUDGET
      || bytes_per_source == 0) {
    free(block_operators);
    free(shifted_prefix);
    free(baseline_prefix);
    return ZIP_STORED_REPAIR_NONE;
  }

  uint64_t index_capacity = (ZIP_STORED_CRC_INDEX_BUDGET - fixed_crc_bytes)
                            / bytes_per_source;

  if (index_capacity == 0) {
    index_capacity = 1;
  }
  if (index_capacity > image_blocks) {
    index_capacity = image_blocks;
  }
  if (index_capacity > SIZE_MAX / sizeof(ZipStoredCrcSource)
      || index_capacity > SIZE_MAX / sizeof(uint32_t)
      || maximum_displaced_length > SIZE_MAX - index_capacity
      || index_capacity + maximum_displaced_length
             > SIZE_MAX / sizeof(uint32_t)) {
    free(block_operators);
    free(shifted_prefix);
    free(baseline_prefix);
    return ZIP_STORED_REPAIR_NONE;
  }

  ZipStoredCrcSource *crc_sources = (ZipStoredCrcSource *)malloc(
      (size_t)index_capacity * sizeof(*crc_sources));
  uint32_t *run_crcs = (uint32_t *)calloc(
      (size_t)index_capacity, sizeof(*run_crcs));
  uint32_t *block_crcs = (uint32_t *)malloc(
      (size_t)(index_capacity + maximum_displaced_length)
      * sizeof(*block_crcs));

  if (!crc_sources || !run_crcs || !block_crcs) {
    free(block_crcs);
    free(run_crcs);
    free(crc_sources);
    free(block_operators);
    free(shifted_prefix);
    free(baseline_prefix);
    return ZIP_STORED_REPAIR_NONE;
  }

  const bool resuming = state->repair_resume.phase
                        == ZIP_REPAIR_PHASE_STORED_GAP_OOO;
  const uint64_t resume_chunk = resuming
      ? state->repair_resume.source_rank : 0;
  uint64_t resume_length = resuming
      && state->repair_resume.run_length > 0
          ? state->repair_resume.run_length : 1;
  const uint64_t resume_destination = resuming
      ? state->repair_resume.destination : 0;
  const uint64_t resume_first = resuming
      ? state->repair_resume.first_destination : 0;
  ZipStoredRepairResult result = ZIP_STORED_REPAIR_NONE;
  uint64_t probes = 0;

  if (resume_length > maximum_displaced_length) {
    resume_length = 1;
  }

  for (uint64_t chunk_start = resume_chunk;
       chunk_start < image_blocks; chunk_start += index_capacity) {
    uint64_t chunk_end = chunk_start + index_capacity;

    if (chunk_end < chunk_start || chunk_end > image_blocks) {
      chunk_end = image_blocks;
    }
    const uint64_t chunk_count = chunk_end - chunk_start;
    uint64_t block_end = chunk_end + maximum_displaced_length;

    if (block_end < chunk_end || block_end > image_blocks) {
      block_end = image_blocks;
    }
    const uint64_t block_count = block_end - chunk_start;

    memset(run_crcs, 0, (size_t)chunk_count * sizeof(*run_crcs));
    for (uint64_t block = 0; block < block_count; block++) {
      if ((block & UINT64_C(0xff)) == 0) {
        if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
          result = ZIP_STORED_REPAIR_STOPPED;
          goto zip_stored_gap_ooo_done;
        }
        if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                 memory_order_acquire)) {
          state->repair_resume.phase = ZIP_REPAIR_PHASE_STORED_GAP_OOO;
          state->repair_resume.source_rank = chunk_start;
          state->repair_resume.run_length = resume_length;
          state->repair_resume.destination = resume_destination;
          state->repair_resume.first_destination = resume_first;
          carve_put_state((*candidate)->carvehashkey, state);
          if (reassembly_time_to_checkpoint(work->id, *candidate,
                                            uuidp, uuidc)) {
            result = ZIP_STORED_REPAIR_STOPPED;
            goto zip_stored_gap_ooo_done;
          }
        }
      }
      if (!zip_reassembly_block_crc(
              (int64_t)(chunk_start + block), &block_crcs[block])) {
        goto zip_stored_gap_ooo_done;
      }
    }

    const uint64_t length_start = chunk_start == resume_chunk
                                      ? resume_length : 1;

    for (uint64_t length = 1; length <= maximum_displaced_length;
         length++) {
      uint64_t crc_source_count = 0;

      for (uint64_t source = 0; source < chunk_count; source++) {
        if (source + length > block_count
            || chunk_start + source + length > image_blocks) {
          continue;
        }
        run_crcs[source] = (uint32_t)crc32_combine_op(
            run_crcs[source], block_crcs[source + length - 1],
            block_operator);
        if (length < length_start) {
          continue;
        }
        crc_sources[crc_source_count].source = chunk_start + source;
        crc_sources[crc_source_count].contribution = run_crcs[source];
        crc_source_count++;
      }
      if (length < length_start) {
        continue;
      }

      qsort(crc_sources, (size_t)crc_source_count,
            sizeof(*crc_sources), zip_compare_stored_crc_sources);

      const uint64_t destination_max = destination_last - length;
      uint64_t displaced_destination = destination_max;
      bool resume_this_length = resuming && chunk_start == resume_chunk
          && length == resume_length;

      if (resume_this_length && resume_destination >= destination_first + 1
          && resume_destination <= destination_max) {
        displaced_destination = resume_destination;
      }

      for (;; displaced_destination--) {
        const uint64_t tail_destination = displaced_destination + length;
        const uint64_t tail_index = tail_destination - destination_first;
        const uint64_t suffix_length = entry_end
                                       - tail_destination * blocksize;
        const uLong suffix_operator = crc32_combine_gen(
            (z_off_t)suffix_length);
        const uint64_t after_prefix_length = entry_end
            - displaced_destination * blocksize;
        const uLong after_prefix_operator = crc32_combine_gen(
            (z_off_t)after_prefix_length);
        const uint32_t suffix_crc = shifted_full_crc
            ^ (uint32_t)crc32_combine_op(
                  shifted_prefix[tail_index], 0UL, suffix_operator);
        uint32_t suffix_inverse[32];

        if (!zip_crc_inverse_for_len((z_off_t)suffix_length,
                                     suffix_inverse)) {
          resume_this_length = false;
          if (displaced_destination == destination_first + 1) {
            break;
          }
          continue;
        }

        uint64_t shifted_destination = displaced_destination - 1;

        if (resume_this_length && displaced_destination == resume_destination
            && resume_first >= destination_first
            && resume_first < displaced_destination) {
          shifted_destination = resume_first;
        }

        for (;; shifted_destination--) {
          probes++;
          if ((probes & UINT64_C(0xff)) == 0) {
            if (reassembly_check_kill_queue(work, candidate,
                                            uuidp, uuidc)) {
              result = ZIP_STORED_REPAIR_STOPPED;
              goto zip_stored_gap_ooo_done;
            }
            if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                     memory_order_acquire)) {
              state->repair_resume.phase = ZIP_REPAIR_PHASE_STORED_GAP_OOO;
              state->repair_resume.source_rank = chunk_start;
              state->repair_resume.run_length = length;
              state->repair_resume.destination = displaced_destination;
              state->repair_resume.first_destination = shifted_destination;
              carve_put_state((*candidate)->carvehashkey, state);
              if (reassembly_time_to_checkpoint(work->id, *candidate,
                                                uuidp, uuidc)) {
                result = ZIP_STORED_REPAIR_STOPPED;
                goto zip_stored_gap_ooo_done;
              }
            }
          }

          const uint64_t shifted_index = shifted_destination
                                         - destination_first;
          const uint64_t displaced_index = displaced_destination
                                           - destination_first;
          const uint64_t shifted_length = displaced_destination
                                          - shifted_destination;
          const uint32_t shifted_crc = shifted_prefix[displaced_index]
              ^ (uint32_t)crc32_combine_op(
                    shifted_prefix[shifted_index], 0UL,
                    block_operators[shifted_length]);
          const uint32_t prefix_crc = (uint32_t)crc32_combine_op(
              baseline_prefix[shifted_index], shifted_crc,
              block_operators[shifted_length]);
          const uint32_t required_shifted = entry->crc32
              ^ (uint32_t)crc32_combine_op(
                    prefix_crc, 0UL, after_prefix_operator)
              ^ suffix_crc;
          const uint32_t required_crc = zip_crc_apply_inverse(
              suffix_inverse, required_shifted);
          uint64_t lower = 0;
          uint64_t upper = crc_source_count;

          while (lower < upper) {
            const uint64_t middle = lower + (upper - lower) / 2;

            if (crc_sources[middle].contribution < required_crc) {
              lower = middle + 1;
            }
            else {
              upper = middle;
            }
          }

          for (uint64_t match = lower;
               match < crc_source_count
               && crc_sources[match].contribution == required_crc;
               match++) {
            BlockVector *repaired = NULL;

            clone_blockvector((*candidate)->b, &repaired, true);
            CarveInfo repaired_candidate = **candidate;

            repaired_candidate.b = repaired;
            int64_t shifted_swap_slot = ZIP_SWAP_SLOT_UNMAPPED;
            const int64_t shifted_source = (int64_t)(
                (uint64_t)header_actual + shifted_destination
                + physical_shift);

            if (!zip_reassembly_source_run_viable(
                    &repaired_candidate, shifted_destination,
                    shifted_length, shifted_source, &shifted_swap_slot)) {
              free_blockvector(&repaired);
              continue;
            }
            zip_reassembly_commit_source_run(
                &repaired_candidate, shifted_destination,
                shifted_length, shifted_source, shifted_swap_slot);

            int64_t displaced_swap_slot = ZIP_SWAP_SLOT_UNMAPPED;
            const int64_t displaced_source = (int64_t)
                crc_sources[match].source;

            if (!zip_reassembly_source_run_viable(
                    &repaired_candidate, displaced_destination,
                    length, displaced_source, &displaced_swap_slot)) {
              free_blockvector(&repaired);
              continue;
            }
            zip_reassembly_commit_source_run(
                &repaired_candidate, displaced_destination,
                length, displaced_source, displaced_swap_slot);

            const uint64_t tail_length = total_blocks - tail_destination;
            int64_t tail_swap_slot = ZIP_SWAP_SLOT_UNMAPPED;
            const int64_t tail_source = (int64_t)(
                (uint64_t)header_actual + tail_destination
                + physical_shift);

            if (!zip_reassembly_source_run_viable(
                    &repaired_candidate, tail_destination,
                    tail_length, tail_source, &tail_swap_slot)) {
              free_blockvector(&repaired);
              continue;
            }
            zip_reassembly_commit_source_run(
                &repaired_candidate, tail_destination,
                tail_length, tail_source, tail_swap_slot);

            uint64_t failure_offset = entry->data_offset;
            uint64_t output_progress = 0;

            if (!zip_reassembly_verify_entry(
                    (const uint8_t *)blockvector_get_data_pointer(repaired),
                    blockvector_get_data_length(repaired), state, entry,
                    &failure_offset, &output_progress)) {
              free_blockvector(&repaired);
              continue;
            }

            BlockVector *old_blockvector = (*candidate)->b;

            (*candidate)->b = repaired;
            free_blockvector(&old_blockvector);
            result = ZIP_STORED_REPAIR_SOLVED;
            goto zip_stored_gap_ooo_done;
          }

          if (shifted_destination == destination_first) {
            break;
          }
          resume_this_length = false;
        }
        resume_this_length = false;
        if (displaced_destination == destination_first + 1) {
          break;
        }
      }
    }
  }

zip_stored_gap_ooo_done:
  free(block_crcs);
  free(run_crcs);
  free(crc_sources);
  free(block_operators);
  free(shifted_prefix);
  free(baseline_prefix);
  if (result != ZIP_STORED_REPAIR_STOPPED) {
    zip_reassembly_reset_repair_resume(state);
  }
  return result;
}

// A footer-anchored suffix can leave one displaced run beyond the physical
// end of the archive. For a stored member, test that adjacent run at every
// member position and length. The member CRC makes every accepted repair
// exact rather than heuristic.
//
static inline ZipStoredRepairResult zip_reassembly_repair_stored_member(
    ThreadWork *work,
    CarveInfo **candidate,
    ZipCarveState *state,
    const ZipStateEntry *entry,
    uint64_t destination_slot,
    uint64_t run_length,
    int64_t source_actual,
    int64_t swap_slot,
    uuid_string_t uuidp,
    uuid_string_t uuidc) {

  if (!work || !candidate || !*candidate || !state || !entry
      || scalpel_state.blocksize == 0
      || entry->method != ZIP_METHOD_STORED
      || entry->compressed_size != entry->uncompressed_size
      || entry->compressed_size == 0
      || entry->data_offset > UINT64_MAX - entry->compressed_size
      || source_actual < 0 || run_length == 0
      || (uint64_t)source_actual > INT64_MAX - run_length) {
    return ZIP_STORED_REPAIR_NONE;
  }

  const uint64_t blocksize = scalpel_state.blocksize;
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), blocksize);
  const uint64_t entry_end = entry->data_offset + entry->compressed_size;
  const uint64_t entry_first = entry->data_offset / blocksize;
  const uint64_t entry_last = (entry_end - 1) / blocksize;

  BlockVector *anchored = NULL;

  clone_blockvector((*candidate)->b, &anchored, true);
  CarveInfo anchored_candidate = **candidate;

  anchored_candidate.b = anchored;
  zip_reassembly_commit_source_run(&anchored_candidate, destination_slot,
                                   run_length, source_actual, swap_slot);

  uint64_t failure_offset = entry->data_offset;
  uint64_t output_progress = 0;

  if (zip_reassembly_verify_entry(
          (const uint8_t *)blockvector_get_data_pointer(anchored),
          blockvector_get_data_length(anchored), state, entry,
          &failure_offset, &output_progress)) {
    BlockVector *old_blockvector = (*candidate)->b;

    (*candidate)->b = anchored;
    free_blockvector(&old_blockvector);
    zip_reassembly_reset_repair_resume(state);
    return ZIP_STORED_REPAIR_SOLVED;
  }

  const int64_t header_actual = blockvector_get_actual_blocknumber(
      anchored, 0);
  const int64_t expected_source = header_actual >= 0
      && destination_slot <= (uint64_t)(INT64_MAX - header_actual)
          ? header_actual + (int64_t)destination_slot : -1;
  const uint64_t first_member_slot = entry_first > 0 ? entry_first : 1;
  bool resume_pair = state->repair_resume.phase
                     == ZIP_REPAIR_PHASE_STORED_PAIR;
  bool resume_adjacent = state->repair_resume.phase
                         == ZIP_REPAIR_PHASE_STORED_ADJACENT;

  if (state->repair_resume.phase != ZIP_REPAIR_PHASE_NONE
      && !resume_pair && !resume_adjacent) {
    zip_reassembly_reset_repair_resume(state);
  }

  // A positive displacement of a trusted tail identifies an inserted gap.
  // Before that tail, test a locally shifted run followed by one independently
  // displaced run. The stored member CRC makes a successful pairing exact.
  if (!resume_adjacent && expected_source >= 0
      && source_actual > expected_source
      && destination_slot >= first_member_slot + 2) {
    const uint64_t structural_shift = (uint64_t)(source_actual
                                                  - expected_source);
    const uint64_t second_destination_start = resume_pair
        ? state->repair_resume.destination : destination_slot - 1;

    for (uint64_t second_destination = second_destination_start;
         second_destination > first_member_slot; second_destination--) {
      const uint64_t second_length = destination_slot
                                     - second_destination;
      const uint64_t destination_start = second_destination * blocksize;
      const uint64_t destination_end = destination_slot * blocksize;
      const uint64_t patch_start = destination_start > entry->data_offset
                                       ? destination_start
                                       : entry->data_offset;
      const uint64_t patch_end = destination_end < entry_end
                                     ? destination_end : entry_end;

      if (patch_start >= patch_end) {
        resume_pair = false;
        continue;
      }

      uint64_t expected_second = 0;

      if (__builtin_add_overflow((uint64_t)header_actual,
                                 second_destination,
                                 &expected_second)
          || expected_second >= image_blocks) {
        resume_pair = false;
        continue;
      }

      const uint64_t patch_length = patch_end - patch_start;
      const uint64_t suffix_length = entry_end - patch_end;
      const uint64_t source_offset = patch_start - destination_start;
      const uint64_t maximum_distance = expected_second
          > image_blocks - expected_second - 1
              ? expected_second : image_blocks - expected_second - 1;
      const uint64_t scan_limit = maximum_distance * 2 + 1;
      const uint64_t clone_source_start = (*candidate)->clone
          ? XXH3_64bits((*candidate)->clone_binuuid,
                        sizeof(uuid_t)) % scan_limit
          : 0;
      uint64_t index_capacity = ZIP_STORED_CRC_INDEX_BUDGET
                                / sizeof(ZipStoredCrcSource);

      if (index_capacity == 0) {
        index_capacity = 1;
      }
      if (index_capacity > scan_limit) {
        index_capacity = scan_limit;
      }

      ZipStoredCrcSource stack_source;
      ZipStoredCrcSource *crc_sources = (ZipStoredCrcSource *)malloc(
          (size_t)index_capacity * sizeof(*crc_sources));
      const bool crc_sources_allocated = crc_sources != NULL;

      if (!crc_sources) {
        crc_sources = &stack_source;
        index_capacity = 1;
      }

      uint64_t chunk_start = resume_pair
          && second_destination == state->repair_resume.destination
              ? state->repair_resume.source_rank : 0;

      if (chunk_start >= scan_limit) {
        chunk_start = 0;
      }

      while (chunk_start < scan_limit) {
        uint64_t chunk_end = chunk_start + index_capacity;

        if (chunk_end < chunk_start || chunk_end > scan_limit) {
          chunk_end = scan_limit;
        }

        uint64_t crc_source_count = 0;

        for (uint64_t rank = chunk_start; rank < chunk_end; rank++) {
          if ((rank & UINT64_C(0xff)) == 0) {
            if (reassembly_check_kill_queue(work, candidate,
                                            uuidp, uuidc)) {
              if (crc_sources_allocated) {
                free(crc_sources);
              }
              free_blockvector(&anchored);
              return ZIP_STORED_REPAIR_STOPPED;
            }
            if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                     memory_order_acquire)) {
              state->repair_resume.phase = ZIP_REPAIR_PHASE_STORED_PAIR;
              state->repair_resume.destination = second_destination;
              state->repair_resume.first_destination =
                  second_destination - 1;
              state->repair_resume.source_rank = chunk_start;
              carve_put_state((*candidate)->carvehashkey, state);
              if (reassembly_time_to_checkpoint(work->id, *candidate,
                                                uuidp, uuidc)) {
                if (crc_sources_allocated) {
                  free(crc_sources);
                }
                free_blockvector(&anchored);
                return ZIP_STORED_REPAIR_STOPPED;
              }
            }
          }

          const uint64_t source_rank = (*candidate)->clone
              ? (rank + clone_source_start) % scan_limit : rank;
          uint64_t second_source = expected_second;

          if (source_rank > 0) {
            const uint64_t distance = (source_rank + 1) / 2;

            if ((source_rank & UINT64_C(1)) != 0) {
              if (distance >= image_blocks - expected_second) {
                continue;
              }
              second_source = expected_second + distance;
            }
            else {
              if (distance > expected_second) {
                continue;
              }
              second_source = expected_second - distance;
            }
          }
          if (second_source > INT64_MAX
              || second_length > image_blocks - second_source) {
            continue;
          }

          uint32_t source_crc = 0;

          if (!zip_reassembly_source_crc(
                  (int64_t)second_source, source_offset,
                  patch_length, &source_crc)) {
            continue;
          }
          crc_sources[crc_source_count].source = second_source;
          crc_sources[crc_source_count].contribution =
              (uint32_t)crc32_combine(source_crc, 0,
                                      (z_off_t)suffix_length);
          crc_source_count++;
        }

        qsort(crc_sources, (size_t)crc_source_count,
              sizeof(*crc_sources), zip_compare_stored_crc_sources);

        uint64_t first_destination_start = resume_pair
            && second_destination == state->repair_resume.destination
            && chunk_start == state->repair_resume.source_rank
                ? state->repair_resume.first_destination
                : second_destination - 1;

        if (first_destination_start < first_member_slot
            || first_destination_start >= second_destination) {
          first_destination_start = second_destination - 1;
        }

        for (uint64_t first_destination = first_destination_start;;
             first_destination--) {
          if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
            if (crc_sources_allocated) {
              free(crc_sources);
            }
            free_blockvector(&anchored);
            return ZIP_STORED_REPAIR_STOPPED;
          }
          if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                   memory_order_acquire)) {
            state->repair_resume.phase = ZIP_REPAIR_PHASE_STORED_PAIR;
            state->repair_resume.destination = second_destination;
            state->repair_resume.first_destination = first_destination;
            state->repair_resume.source_rank = chunk_start;
            carve_put_state((*candidate)->carvehashkey, state);
            if (reassembly_time_to_checkpoint(work->id, *candidate,
                                              uuidp, uuidc)) {
              if (crc_sources_allocated) {
                free(crc_sources);
              }
              free_blockvector(&anchored);
              return ZIP_STORED_REPAIR_STOPPED;
            }
          }

          const uint64_t first_length = second_destination
                                        - first_destination;
          uint64_t first_source_unsigned = 0;
          const bool first_source_overflow = __builtin_add_overflow(
              (uint64_t)header_actual, first_destination,
              &first_source_unsigned)
              || __builtin_add_overflow(first_source_unsigned,
                                        structural_shift,
                                        &first_source_unsigned);

          if (!first_source_overflow
              && first_source_unsigned < image_blocks
              && first_source_unsigned <= INT64_MAX
              && first_length <= image_blocks - first_source_unsigned) {
            BlockVector *staged = NULL;

            clone_blockvector(anchored, &staged, true);
            CarveInfo staged_candidate = **candidate;

            staged_candidate.b = staged;
            int64_t first_swap_slot = ZIP_SWAP_SLOT_UNMAPPED;

            if (zip_reassembly_source_run_viable(
                    &staged_candidate, first_destination, first_length,
                    (int64_t)first_source_unsigned, &first_swap_slot)) {
              zip_reassembly_commit_source_run(
                  &staged_candidate, first_destination, first_length,
                  (int64_t)first_source_unsigned, first_swap_slot);

              const uint8_t *staged_data = (const uint8_t *)
                  blockvector_get_data_pointer(staged);
              const uint64_t staged_length =
                  blockvector_get_data_length(staged);

              if (entry_end <= staged_length) {
                const uint64_t prefix_length = patch_start
                                               - entry->data_offset;
                const uint32_t prefix_crc = zip_crc32(
                    staged_data + entry->data_offset, prefix_length);
                const uint32_t suffix_crc = zip_crc32(
                    staged_data + patch_end, suffix_length);
                const uint32_t required_contribution = entry->crc32
                    ^ (uint32_t)crc32_combine(
                          prefix_crc, 0,
                          (z_off_t)(patch_length + suffix_length))
                    ^ suffix_crc;
                uint64_t lower = 0;
                uint64_t upper = crc_source_count;

                while (lower < upper) {
                  const uint64_t middle = lower + (upper - lower) / 2;

                  if (crc_sources[middle].contribution
                      < required_contribution) {
                    lower = middle + 1;
                  }
                  else {
                    upper = middle;
                  }
                }

                for (uint64_t match = lower;
                     match < crc_source_count
                     && crc_sources[match].contribution
                            == required_contribution;
                     match++) {
                  BlockVector *repaired = NULL;

                  clone_blockvector(staged, &repaired, true);
                  CarveInfo repaired_candidate = **candidate;

                  repaired_candidate.b = repaired;
                  int64_t second_swap_slot = ZIP_SWAP_SLOT_UNMAPPED;
                  const int64_t second_source =
                      (int64_t)crc_sources[match].source;

                  if (!zip_reassembly_source_run_viable(
                          &repaired_candidate, second_destination,
                          second_length, second_source,
                          &second_swap_slot)) {
                    free_blockvector(&repaired);
                    continue;
                  }
                  zip_reassembly_commit_source_run(
                      &repaired_candidate, second_destination,
                      second_length, second_source, second_swap_slot);

                  failure_offset = entry->data_offset;
                  output_progress = 0;
                  if (!zip_reassembly_verify_entry(
                          (const uint8_t *)
                              blockvector_get_data_pointer(repaired),
                          blockvector_get_data_length(repaired), state, entry,
                          &failure_offset, &output_progress)) {
                    free_blockvector(&repaired);
                    continue;
                  }

                  BlockVector *old_blockvector = (*candidate)->b;

                  (*candidate)->b = repaired;
                  free_blockvector(&old_blockvector);
                  free_blockvector(&staged);
                  if (crc_sources_allocated) {
                    free(crc_sources);
                  }
                  free_blockvector(&anchored);
                  zip_reassembly_reset_repair_resume(state);
                  return ZIP_STORED_REPAIR_SOLVED;
                }
              }
            }
            free_blockvector(&staged);
          }
          if (first_destination == first_member_slot) {
            break;
          }
          resume_pair = false;
        }
        resume_pair = false;
        chunk_start = chunk_end;
      }
      if (crc_sources_allocated) {
        free(crc_sources);
      }
    }
  }

  if (resume_pair) {
    zip_reassembly_reset_repair_resume(state);
    resume_pair = false;
  }

  const int64_t displaced_source = source_actual + (int64_t)run_length;

  if (displaced_source < 0
      || (uint64_t)displaced_source >= image_blocks) {
    free_blockvector(&anchored);
    zip_reassembly_reset_repair_resume(state);
    return ZIP_STORED_REPAIR_NONE;
  }

  uint64_t maximum_run = image_blocks - (uint64_t)displaced_source;
  const uint64_t member_blocks = entry_last - entry_first + 1;

  if (maximum_run > member_blocks) {
    maximum_run = member_blocks;
  }

  const uint64_t second_length_start = resume_adjacent
      ? state->repair_resume.run_length : 1;

  for (uint64_t second_length = second_length_start;
       second_length <= maximum_run;
       second_length++) {
    const uint64_t second_destination_start = resume_adjacent
        && second_length == state->repair_resume.run_length
            ? state->repair_resume.destination : entry_first;

    for (uint64_t second_destination = second_destination_start;
         second_destination <= entry_last
         && second_length <= entry_last - second_destination + 1;
         second_destination++) {
      const uint64_t probe = second_length * member_blocks
                             + second_destination - entry_first;

      if ((probe & UINT64_C(0xff)) == 0) {
        if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
          free_blockvector(&anchored);
          return ZIP_STORED_REPAIR_STOPPED;
        }
        if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                 memory_order_acquire)) {
          state->repair_resume.phase = ZIP_REPAIR_PHASE_STORED_ADJACENT;
          state->repair_resume.run_length = second_length;
          state->repair_resume.destination = second_destination;
          carve_put_state((*candidate)->carvehashkey, state);
          if (reassembly_time_to_checkpoint(work->id, *candidate,
                                            uuidp, uuidc)) {
            free_blockvector(&anchored);
            return ZIP_STORED_REPAIR_STOPPED;
          }
        }
      }

      int64_t second_swap_slot = ZIP_SWAP_SLOT_UNMAPPED;

      if (!zip_reassembly_source_run_viable(
              &anchored_candidate, second_destination, second_length,
              displaced_source, &second_swap_slot)) {
        continue;
      }

      uint32_t repaired_crc = 0;
      const uint8_t *anchored_data = (const uint8_t *)
          blockvector_get_data_pointer(anchored);

      if (second_swap_slot == ZIP_SWAP_SLOT_UNMAPPED
          && zip_stored_patch_crc(
                 anchored_data, blockvector_get_data_length(anchored),
                 entry, second_destination, second_length, displaced_source,
                 &repaired_crc)
          && repaired_crc != entry->crc32) {
        continue;
      }

      BlockVector *repaired = NULL;

      clone_blockvector(anchored, &repaired, true);
      CarveInfo repaired_candidate = **candidate;

      repaired_candidate.b = repaired;
      int64_t repaired_swap_slot = ZIP_SWAP_SLOT_UNMAPPED;

      if (!zip_reassembly_source_run_viable(
              &repaired_candidate, second_destination, second_length,
              displaced_source, &repaired_swap_slot)) {
        free_blockvector(&repaired);
        continue;
      }
      zip_reassembly_commit_source_run(
          &repaired_candidate, second_destination, second_length,
          displaced_source, repaired_swap_slot);

      failure_offset = entry->data_offset;
      output_progress = 0;
      if (!zip_reassembly_verify_entry(
              (const uint8_t *)blockvector_get_data_pointer(repaired),
              blockvector_get_data_length(repaired), state, entry,
              &failure_offset, &output_progress)) {
        free_blockvector(&repaired);
        continue;
      }

      BlockVector *old_blockvector = (*candidate)->b;

      (*candidate)->b = repaired;
      free_blockvector(&old_blockvector);
      free_blockvector(&anchored);
      zip_reassembly_reset_repair_resume(state);
      return ZIP_STORED_REPAIR_SOLVED;
    }
    resume_adjacent = false;
  }

  free_blockvector(&anchored);
  zip_reassembly_reset_repair_resume(state);
  return ZIP_STORED_REPAIR_NONE;
}

static inline bool zip_reassembly_has_displaced_footer_anchor(
    const CarveInfo *candidate,
    const ZipCarveState *state,
    uint64_t total_blocks) {

  if (!candidate || !state || total_blocks == 0
      || scalpel_state.blocksize == 0 || candidate->needleidx < 0
      || (uint32_t)candidate->needleidx >= scalpel_state.num_specs) {
    return false;
  }

  const int64_t header_actual = blockvector_get_actual_blocknumber(
      candidate->b, 0);

  if (header_actual < 0) {
    return false;
  }

  const SearchSpec *spec = &scalpel_state.search_specs[candidate->needleidx];
  const uint64_t header_block = (uint64_t)header_actual;

  for (uint64_t source_index = 0;
       source_index < spec->offsets.numfooters; source_index++) {
    const uint64_t footer = spec->offsets.footers[source_index];

    if (footer < state->eocd_offset) {
      continue;
    }
    const uint64_t archive_origin = footer - state->eocd_offset;

    if (archive_origin % scalpel_state.blocksize != 0) {
      continue;
    }
    const uint64_t archive_origin_block = archive_origin
                                          / scalpel_state.blocksize;
    const uint64_t anchor_distance = archive_origin_block > header_block
        ? archive_origin_block - header_block
        : header_block - archive_origin_block;

    if (anchor_distance > total_blocks) {
      return true;
    }
  }
  return false;
}

// A physical gap followed immediately by a displaced run leaves two damaged
// regions after the suffix is normalized. Test that adjacent run first because
// it is the strongest two-run layout hypothesis. Only exact member validation
// can commit the pair.
//
static inline ZipGapRepairResult
zip_reassembly_repair_adjacent_displaced_run(
    ThreadWork *work,
    CarveInfo **candidate,
    ZipCarveState *state,
    const ZipStateEntry *entry,
    const uint8_t *first_data,
    uint64_t buffer_size,
    uint64_t first_destination,
    uint64_t first_length,
    int64_t first_source,
    int64_t first_swap_slot,
    uint64_t displaced_length,
    uuid_string_t uuidp,
    uuid_string_t uuidc) {

  if (!work || !candidate || !*candidate || !state || !entry || !first_data
      || !zip_method_directly_verifiable(entry->method)
      || scalpel_state.blocksize == 0 || displaced_length == 0) {
    return ZIP_GAP_REPAIR_NONE;
  }

  const uint64_t total_blocks = blockvector_get_num_blocks((*candidate)->b);
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);
  uint64_t second_destination = 0;

  if (image_blocks == 0
      || __builtin_add_overflow(first_destination, displaced_length,
                                &second_destination)
      || second_destination >= total_blocks
      || displaced_length > total_blocks - second_destination) {
    return ZIP_GAP_REPAIR_NONE;
  }

  const uint64_t entry_first = entry->data_offset
                               / scalpel_state.blocksize;
  const uint64_t entry_last = (entry->range_end - 1)
                              / scalpel_state.blocksize;

  if (second_destination < entry_first || second_destination > entry_last
      || displaced_length > entry_last - second_destination + 1) {
    return ZIP_GAP_REPAIR_NONE;
  }

  BlockVector *first_repair = NULL;

  clone_blockvector((*candidate)->b, &first_repair, true);
  CarveInfo first_candidate = **candidate;

  first_candidate.b = first_repair;
  zip_reassembly_commit_source_run(
      &first_candidate, first_destination, first_length,
      first_source, first_swap_slot);

  const int64_t previous_actual = blockvector_get_actual_blocknumber(
      first_repair, second_destination - 1);
  uint64_t expected_source = previous_actual >= 0
      && (uint64_t)previous_actual < image_blocks - 1
          ? (uint64_t)previous_actual + 1 : 0;
  const uint64_t maximum_distance = expected_source
      > image_blocks - expected_source - 1
          ? expected_source : image_blocks - expected_source - 1;

  if (maximum_distance > (UINT64_MAX - 1) / 2) {
    free_blockvector(&first_repair);
    return ZIP_GAP_REPAIR_NONE;
  }

  const uint64_t scan_limit = maximum_distance * 2 + 1;
  uint8_t *second_trial = (uint8_t *)malloc((size_t)buffer_size);

  check_memory_allocation(second_trial, __LINE__, __FILE__,
                          "ZIP adjacent displaced-run trial");
  ZipMappedBlockIndex mapped_blocks;

  memset(&mapped_blocks, 0, sizeof(mapped_blocks));
  (void)zip_mapped_block_index_initialize(&first_candidate, &mapped_blocks);

  uint64_t view = XXH3_64bits(first_data, (size_t)buffer_size);
  view = (view ^ image_blocks) * UINT64_C(1099511628211);
  view = (view ^ scalpel_state.blocksize) * UINT64_C(1099511628211);
  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    view = (view ^ (uint64_t)blockvector_get_actual_blocknumber(first_repair,
                                                               slot))
        * UINT64_C(1099511628211);
  }
  const bool resume = state->repair_resume.phase
          == ZIP_REPAIR_PHASE_DELAYED_ADJACENT
      && state->repair_resume.source == (uint64_t)first_source
      && state->repair_resume.run_length == first_length
      && state->repair_resume.second_destination == first_destination
      && state->repair_resume.second_run_length == displaced_length
      && state->repair_resume.footer_index == view
      && state->repair_resume.source_rank <= scan_limit;
  uint64_t source_rank = resume ? state->repair_resume.source_rank : 0;
  state->repair_resume.phase = ZIP_REPAIR_PHASE_DELAYED_ADJACENT;
  state->repair_resume.source = (uint64_t)first_source;
  state->repair_resume.run_length = first_length;
  state->repair_resume.second_destination = first_destination;
  state->repair_resume.second_run_length = displaced_length;
  state->repair_resume.footer_index = view;

  for (; source_rank < scan_limit; source_rank++) {
    if ((source_rank & UINT64_C(0xff)) == 0) {
      if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
        zip_mapped_block_index_clear(&mapped_blocks);
        free(second_trial);
        free_blockvector(&first_repair);
        return ZIP_GAP_REPAIR_STOPPED;
      }
      if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                               memory_order_acquire)) {
        // Keep the caller's delay/best tuple and this trial's own source cursor.
        state->repair_resume.source_rank = source_rank;
        carve_put_state((*candidate)->carvehashkey, state);
        if (reassembly_time_to_checkpoint(work->id, *candidate,
                                          uuidp, uuidc)) {
          zip_mapped_block_index_clear(&mapped_blocks);
          free(second_trial);
          free_blockvector(&first_repair);
          return ZIP_GAP_REPAIR_STOPPED;
        }
      }
    }

    uint64_t second_source = expected_source;

    if (source_rank > 0) {
      const uint64_t distance = (source_rank + 1) / 2;

      if ((source_rank & UINT64_C(1)) != 0) {
        if (distance >= image_blocks - expected_source) {
          continue;
        }
        second_source = expected_source + distance;
      }
      else {
        if (distance > expected_source) {
          continue;
        }
        second_source = expected_source - distance;
      }
    }
    if (displaced_length > image_blocks - second_source
        || second_source > INT64_MAX) {
      continue;
    }

    int64_t second_swap_slot = ZIP_SWAP_SLOT_UNMAPPED;

    if (!zip_reassembly_source_run_viable_indexed(
            &first_candidate, second_destination, displaced_length,
            (int64_t)second_source, &second_swap_slot, &mapped_blocks)) {
      continue;
    }

    memcpy(second_trial, first_data, (size_t)buffer_size);
    if (!zip_reassembly_apply_source_run(
            second_trial, first_data, &first_candidate,
            second_destination, displaced_length,
            (int64_t)second_source, second_swap_slot)) {
      continue;
    }

    uint64_t failure_offset = state->failure_offset;
    uint64_t output_progress = 0;

    if (!zip_reassembly_verify_entry(
            second_trial, state->archive_size, state, entry,
            &failure_offset, &output_progress)) {
      continue;
    }

    BlockVector *solved = NULL;

    clone_blockvector(first_repair, &solved, true);
    CarveInfo solved_candidate = first_candidate;

    solved_candidate.b = solved;
    zip_reassembly_commit_source_run(
        &solved_candidate, second_destination, displaced_length,
        (int64_t)second_source, second_swap_slot);
    failure_offset = state->failure_offset;
    output_progress = 0;
    if (!zip_reassembly_verify_entry(
            (const uint8_t *)blockvector_get_data_pointer(solved),
            blockvector_get_data_length(solved), state, entry,
            &failure_offset, &output_progress)) {
      free_blockvector(&solved);
      continue;
    }

    BlockVector *old_blockvector = (*candidate)->b;

    (*candidate)->b = solved;
    free_blockvector(&old_blockvector);
    zip_mapped_block_index_clear(&mapped_blocks);
    free(second_trial);
    free_blockvector(&first_repair);
    blockvector_set_data_length((*candidate)->b, state->archive_size);
    state->failure_offset = failure_offset;
    state->destination_slot = 0;
    state->run_length = 1;
    state->scan_rank = 0;
    state->broad_scan = false;
    state->broad_wrapped = false;
    state->scan_shares = 0;
    state->preferred_destination_slot = 0;
    state->preferred_run_active = false;
    state->preferred_run_length = 0;
    zip_reassembly_reset_repair_resume(state);
    return ZIP_GAP_REPAIR_APPLIED;
  }

  zip_mapped_block_index_clear(&mapped_blocks);
  free(second_trial);
  free_blockvector(&first_repair);
  state->repair_resume.phase = ZIP_REPAIR_PHASE_DELAYED;
  state->repair_resume.source_rank = 0;
  return ZIP_GAP_REPAIR_NONE;
}

// When a gap is followed by a displaced run, repairing either run alone can
// advance decompression without satisfying the final checksum. Use that
// progress only to select exact two-run trials; no partial repair is committed.
//
static inline ZipGapRepairResult zip_reassembly_repair_two_runs(
    ThreadWork *work,
    CarveInfo **candidate,
    ZipCarveState *state,
    const ZipStateEntry *entry,
    const uint8_t *baseline,
    uint8_t *trial,
    uint64_t buffer_size,
    uuid_string_t uuidp,
    uuid_string_t uuidc) {

  if (!work || !candidate || !*candidate || !state || !entry
      || !baseline || !trial
      || scalpel_state.blocksize == 0 || (*candidate)->needleidx < 0
      || (uint32_t)(*candidate)->needleidx >= scalpel_state.num_specs) {
    return ZIP_GAP_REPAIR_NONE;
  }

  const uint64_t total_blocks = CEILDIV(state->archive_size,
                                        scalpel_state.blocksize);
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror),
      scalpel_state.blocksize);
  const uint64_t entry_first = entry->data_offset
                               / scalpel_state.blocksize;
  const uint64_t inserted_bytes = state->observed_archive_size
                                  > state->archive_size
      ? state->observed_archive_size - state->archive_size : 0;
  const uint64_t physical_shift = inserted_bytes
                                  / scalpel_state.blocksize;
  uint64_t destination = state->failure_offset
                         / scalpel_state.blocksize;
  const int64_t header_actual = blockvector_get_actual_blocknumber(
      (*candidate)->b, 0);

  if (header_actual < 0 || total_blocks < 2 || image_blocks == 0
      || inserted_bytes == 0
      || inserted_bytes % scalpel_state.blocksize != 0
      || physical_shift == 0
      || blockvector_get_num_blocks((*candidate)->b) != total_blocks) {
    return ZIP_GAP_REPAIR_NONE;
  }
  if (destination >= total_blocks) {
    destination = total_blocks - 1;
  }
  if (destination < entry_first) {
    return ZIP_GAP_REPAIR_NONE;
  }

  uint64_t baseline_failure = state->failure_offset;
  uint64_t baseline_output = 0;

  if (zip_reassembly_verify_entry(
          baseline, state->archive_size, state, entry,
          &baseline_failure, &baseline_output)) {
    zip_reassembly_reset_repair_resume(state);
    return ZIP_GAP_REPAIR_NONE;
  }

  bool resume_first = state->repair_resume.phase
                      == ZIP_REPAIR_PHASE_TWO_RUN_FIRST;
  bool resume_second = state->repair_resume.phase
                       == ZIP_REPAIR_PHASE_TWO_RUN_SECOND;

  if (state->repair_resume.phase != ZIP_REPAIR_PHASE_NONE
      && !resume_first && !resume_second) {
    zip_reassembly_reset_repair_resume(state);
  }
  if (resume_first || resume_second) {
    destination = state->repair_resume.destination;
    if (destination < entry_first || destination >= total_blocks) {
      zip_reassembly_reset_repair_resume(state);
      return ZIP_GAP_REPAIR_NONE;
    }
  }

  uint64_t probes = 0;
  uint64_t best_first_failure = resume_first || resume_second
      ? state->repair_resume.best_failure : baseline_failure;
  uint64_t best_first_output = resume_first || resume_second
      ? state->repair_resume.best_output : baseline_output;
  const uint64_t helper_limit = zip_reassembly_helper_limit(
      state->archive_size);

  for (;;) {
    uint64_t first_source = 0;

    if (!__builtin_add_overflow((uint64_t)header_actual,
                                destination, &first_source)
        && !__builtin_add_overflow(first_source, physical_shift,
                                   &first_source)
        && first_source < image_blocks) {
      const uint64_t first_length_max = total_blocks - destination;

      const uint64_t first_length_start = resume_first || resume_second
          ? state->repair_resume.run_length : first_length_max;

      for (uint64_t first_length = first_length_start;
           first_length > 0; first_length--) {
        if (first_length > image_blocks - first_source) {
          continue;
        }
        const uint64_t first_source_last = first_source;

        const uint64_t source_start = (resume_first || resume_second)
            && first_length == state->repair_resume.run_length
                ? state->repair_resume.source : first_source;

        for (uint64_t source = source_start;
             source <= first_source_last; source++) {
          if ((probes++ & UINT64_C(0xff)) == 0) {
            if (reassembly_check_kill_queue(work, candidate,
                                            uuidp, uuidc)) {
              return ZIP_GAP_REPAIR_STOPPED;
            }
            if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                     memory_order_acquire)) {
              state->repair_resume.phase =
                  ZIP_REPAIR_PHASE_TWO_RUN_FIRST;
              state->repair_resume.destination = destination;
              state->repair_resume.run_length = first_length;
              state->repair_resume.source = source;
              state->repair_resume.best_failure = best_first_failure;
              state->repair_resume.best_output = best_first_output;
              carve_put_state((*candidate)->carvehashkey, state);
              if (reassembly_time_to_checkpoint(work->id, *candidate,
                                                uuidp, uuidc)) {
                return ZIP_GAP_REPAIR_STOPPED;
              }
            }
          }
          if (source > INT64_MAX) {
            break;
          }

          int64_t first_swap_slot = ZIP_SWAP_SLOT_UNMAPPED;

          if (!zip_reassembly_source_run_viable(
                  *candidate, destination, first_length,
                  (int64_t)source, &first_swap_slot)) {
            continue;
          }

          memcpy(trial, baseline, (size_t)buffer_size);
          if (!zip_reassembly_apply_source_run(
                  trial, baseline, *candidate, destination,
                  first_length, (int64_t)source, first_swap_slot)) {
            continue;
          }

          uint64_t first_failure = state->failure_offset;
          uint64_t first_output = 0;
          const bool first_valid = zip_reassembly_verify_entry(
              trial, state->archive_size, state, entry,
              &first_failure, &first_output);

          const bool advances_frontier =
              first_failure > best_first_failure
              || (first_failure == best_first_failure
                  && first_output > best_first_output);
          const bool resume_this_second = resume_second
              && destination == state->repair_resume.destination
              && first_length == state->repair_resume.run_length
              && source == state->repair_resume.source;

          if (!first_valid && !advances_frontier && !resume_this_second) {
            continue;
          }
          if (advances_frontier) {
            best_first_failure = first_failure;
            best_first_output = first_output;
          }
          BlockVector *first_repair = NULL;

          clone_blockvector((*candidate)->b, &first_repair, true);
          CarveInfo first_candidate = **candidate;

          first_candidate.b = first_repair;
          zip_reassembly_commit_source_run(
              &first_candidate, destination, first_length,
              (int64_t)source, first_swap_slot);

          if (first_valid) {
            uint64_t repaired_failure = state->failure_offset;
            uint64_t repaired_output = 0;

            if (!zip_reassembly_verify_entry(
                    (const uint8_t *)blockvector_get_data_pointer(
                        first_repair),
                    blockvector_get_data_length(first_repair), state, entry,
                    &repaired_failure, &repaired_output)) {
              free_blockvector(&first_repair);
              continue;
            }

            BlockVector *old_blockvector = (*candidate)->b;

            (*candidate)->b = first_repair;
            free_blockvector(&old_blockvector);
            blockvector_set_data_length((*candidate)->b,
                                        state->archive_size);
            state->failure_offset = repaired_failure;
            state->destination_slot = 0;
            state->run_length = 1;
            state->scan_rank = 0;
            state->broad_scan = false;
            state->broad_wrapped = false;
            state->scan_shares = 0;
            state->preferred_destination_slot = 0;
            state->preferred_run_active = false;
            state->preferred_run_length = 0;
            zip_reassembly_reset_repair_resume(state);
            return ZIP_GAP_REPAIR_APPLIED;
          }

          uint64_t reported_second_destination = first_failure
                                                 / scalpel_state.blocksize;
          uint64_t boundary_second_destination = total_blocks;
          const uint64_t entry_last = (entry->range_end - 1)
                                      / scalpel_state.blocksize;

          if (reported_second_destination >= total_blocks) {
            reported_second_destination = total_blocks - 1;
          }
          if (!__builtin_add_overflow(destination, first_length,
                                      &boundary_second_destination)
              && boundary_second_destination >= total_blocks) {
            boundary_second_destination = total_blocks;
          }

          // Decoder error positions can lag behind the damaged input. The
          // physical boundary is therefore the strongest second-run hint,
          // followed by the decoder position. The remaining member slots are
          // still searched so delayed reporting cannot hide an exact repair.
          const uint64_t broad_destination_count = entry_last >= entry_first
              ? entry_last - entry_first + 1 : 0;
          bool resume_destination_reached = !resume_this_second;

          for (uint64_t destination_rank = 0;
               destination_rank < broad_destination_count + 2;
               destination_rank++) {
            uint64_t second_destination = destination_rank == 0
                ? boundary_second_destination
                : (destination_rank == 1
                       ? reported_second_destination
                       : entry_first + destination_rank - 2);

            if (second_destination < entry_first
                || second_destination > entry_last
                || second_destination >= total_blocks
                || (destination_rank >= 1
                    && second_destination
                           == boundary_second_destination)
                || (destination_rank >= 2
                    && second_destination
                           == reported_second_destination)) {
              continue;
            }

            const bool resume_this_destination = resume_this_second
                && second_destination
                       == state->repair_resume.second_destination;

            if (!resume_destination_reached) {
              if (!resume_this_destination) {
                continue;
              }
              resume_destination_reached = true;
            }

            const uint64_t second_length_max = total_blocks
                                               - second_destination;
            int64_t previous_actual = second_destination > 0
                ? blockvector_get_actual_blocknumber(
                      first_repair, second_destination - 1)
                : header_actual - 1;
            uint64_t expected_second_source = previous_actual >= 0
                && (uint64_t)previous_actual < image_blocks - 1
                    ? (uint64_t)previous_actual + 1
                    : (uint64_t)header_actual + second_destination;

            if (expected_second_source >= image_blocks) {
              expected_second_source = image_blocks - 1;
            }
            const uint64_t second_maximum_distance = expected_second_source
                > image_blocks - expected_second_source - 1
                    ? expected_second_source
                    : image_blocks - expected_second_source - 1;
            const uint64_t second_scan_limit =
                second_maximum_distance * 2 + 1;

            const uint64_t second_length_start = resume_this_destination
                ? state->repair_resume.second_run_length : 1;

            for (uint64_t second_length = second_length_start;
                 second_length <= second_length_max; second_length++) {
              if (second_length > image_blocks) {
                break;
              }

              const uint64_t source_rank_start = resume_this_destination
                  && second_length
                         == state->repair_resume.second_run_length
                      ? state->repair_resume.source_rank : 0;

              for (uint64_t source_rank = source_rank_start;
                   source_rank < second_scan_limit; source_rank++) {
                if ((probes++ & UINT64_C(0xff)) == 0) {
                  if (reassembly_check_kill_queue(work, candidate,
                                                  uuidp, uuidc)) {
                    free_blockvector(&first_repair);
                    return ZIP_GAP_REPAIR_STOPPED;
                  }
                  if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                           memory_order_acquire)) {
                    state->repair_resume.phase =
                        ZIP_REPAIR_PHASE_TWO_RUN_SECOND;
                    state->repair_resume.destination = destination;
                    state->repair_resume.run_length = first_length;
                    state->repair_resume.source = source;
                    state->repair_resume.second_destination =
                        second_destination;
                    state->repair_resume.second_run_length = second_length;
                    state->repair_resume.source_rank = source_rank;
                    state->repair_resume.best_failure = best_first_failure;
                    state->repair_resume.best_output = best_first_output;
                    carve_put_state((*candidate)->carvehashkey, state);
                    if (reassembly_time_to_checkpoint(
                           work->id, *candidate, uuidp, uuidc)) {
                      free_blockvector(&first_repair);
                      return ZIP_GAP_REPAIR_STOPPED;
                    }
                  }
                }
                uint64_t second_source = expected_second_source;

                if (source_rank > 0) {
                  const uint64_t distance = (source_rank + 1) / 2;

                  if ((source_rank & UINT64_C(1)) != 0) {
                    if (distance
                        >= image_blocks - expected_second_source) {
                      continue;
                    }
                    second_source = expected_second_source + distance;
                  }
                  else {
                    if (distance > expected_second_source) {
                      continue;
                    }
                    second_source = expected_second_source - distance;
                  }
                }
                if (second_length > image_blocks - second_source) {
                  continue;
                }
                if (second_source > INT64_MAX) {
                  break;
                }

                // The primary retains exhaustive coverage. Helpers begin at
                // complementary likely boundaries, short run lengths, and
                // source regions; every accepted repair still requires exact
                // member validation.
                if (!(*candidate)->clone
                    && state->scan_shares < helper_limit) {
                  const ZipRepairResume parent_resume = state->repair_resume;
                  const uint64_t helper_index = state->scan_shares;
                  const uint64_t helper_combination = helper_index % 4;
                  const uint64_t helper_source_lanes =
                      CEILDIV(helper_limit, UINT64_C(4));
                  const uint64_t helper_source_lane = helper_index / 4;
                  uint64_t helper_destination = reported_second_destination;
                  uint64_t helper_length = helper_combination < 2 ? 2 : 1;

                  if ((helper_combination == 0 || helper_combination == 2)
                      && reported_second_destination > entry_first) {
                    helper_destination = reported_second_destination - 1;
                  }
                  if (helper_length
                      > total_blocks - helper_destination) {
                    helper_length = 1;
                  }

                  const int64_t helper_previous_actual =
                      helper_destination > 0
                          ? blockvector_get_actual_blocknumber(
                                first_repair, helper_destination - 1)
                          : header_actual - 1;
                  uint64_t helper_expected_source =
                      helper_previous_actual >= 0
                      && (uint64_t)helper_previous_actual < image_blocks - 1
                          ? (uint64_t)helper_previous_actual + 1
                          : (uint64_t)header_actual + helper_destination;

                  if (helper_expected_source >= image_blocks) {
                    helper_expected_source = image_blocks - 1;
                  }
                  const uint64_t helper_maximum_distance =
                      helper_expected_source
                              > image_blocks - helper_expected_source - 1
                          ? helper_expected_source
                          : image_blocks - helper_expected_source - 1;
                  const uint64_t helper_scan_limit =
                      helper_maximum_distance * 2 + 1;
                  const uint64_t helper_lane_width = helper_source_lanes > 0
                      ? helper_scan_limit / helper_source_lanes : 0;
                  const uint64_t helper_lane_remainder =
                      helper_source_lanes > 0
                          ? helper_scan_limit % helper_source_lanes : 0;
                  const uint64_t helper_source_rank =
                      helper_lane_width * helper_source_lane
                      + (helper_source_lane < helper_lane_remainder
                             ? helper_source_lane
                             : helper_lane_remainder);

                  state->repair_resume.phase =
                      ZIP_REPAIR_PHASE_TWO_RUN_SECOND;
                  state->repair_resume.destination = destination;
                  state->repair_resume.run_length = first_length;
                  state->repair_resume.source = source;
                  state->repair_resume.second_destination =
                      helper_destination;
                  state->repair_resume.second_run_length = helper_length;
                  state->repair_resume.source_rank = helper_source_rank;
                  state->repair_resume.best_failure = best_first_failure;
                  state->repair_resume.best_output = best_first_output;
                  carve_put_state((*candidate)->carvehashkey, state);

                  const int shares = reassembly_share_work_count(
                      work->id, *candidate);

                  state->repair_resume = parent_resume;
                  if (shares > 0) {
                    const uint64_t remaining = helper_limit
                                               - state->scan_shares;
                    const uint64_t accepted = (uint64_t)shares < remaining
                        ? (uint64_t)shares : remaining;

                    state->scan_shares += (uint32_t)accepted;
                  }
                  carve_put_state((*candidate)->carvehashkey, state);
                }

                int64_t second_swap_slot = ZIP_SWAP_SLOT_UNMAPPED;

                if (!zip_reassembly_source_run_viable(
                        &first_candidate, second_destination,
                        second_length, (int64_t)second_source,
                        &second_swap_slot)) {
                  continue;
                }

                const uint64_t first_saved_length =
                    blockvector_get_data_length(first_repair);

                blockvector_set_data_length(first_repair, buffer_size);
                const uint8_t *first_data = (const uint8_t *)
                    blockvector_get_data_pointer(first_repair);

                blockvector_set_data_length(first_repair,
                                            first_saved_length);

                memcpy(trial, first_data, (size_t)buffer_size);
                if (!zip_reassembly_apply_source_run(
                        trial, first_data, &first_candidate,
                        second_destination, second_length,
                        (int64_t)second_source, second_swap_slot)) {
                  continue;
                }

                uint64_t second_failure = state->failure_offset;
                uint64_t second_output = 0;

                if (!zip_reassembly_verify_entry(
                        trial, state->archive_size, state, entry,
                        &second_failure, &second_output)) {
                  continue;
                }

                BlockVector *solved = NULL;

                clone_blockvector(first_repair, &solved, true);
                CarveInfo solved_candidate = first_candidate;

                solved_candidate.b = solved;
                zip_reassembly_commit_source_run(
                    &solved_candidate, second_destination,
                    second_length, (int64_t)second_source,
                    second_swap_slot);
                second_failure = state->failure_offset;
                second_output = 0;
                if (!zip_reassembly_verify_entry(
                        (const uint8_t *)blockvector_get_data_pointer(
                            solved),
                        blockvector_get_data_length(solved), state, entry,
                        &second_failure, &second_output)) {
                  free_blockvector(&solved);
                  continue;
                }

                BlockVector *old_blockvector = (*candidate)->b;

                (*candidate)->b = solved;
                free_blockvector(&old_blockvector);
                free_blockvector(&first_repair);
                blockvector_set_data_length((*candidate)->b,
                                            state->archive_size);
                state->failure_offset = second_failure;
                state->destination_slot = 0;
                state->run_length = 1;
                state->scan_rank = 0;
                state->broad_scan = false;
                state->broad_wrapped = false;
                state->scan_shares = 0;
                state->preferred_destination_slot = 0;
                state->preferred_run_active = false;
                state->preferred_run_length = 0;
                zip_reassembly_reset_repair_resume(state);
                return ZIP_GAP_REPAIR_APPLIED;
              }
              resume_second = false;
            }
          }
          free_blockvector(&first_repair);
        }
        resume_first = false;
        resume_second = false;
      }
    }

    if (destination == entry_first) {
      break;
    }
    destination--;
  }
  zip_reassembly_reset_repair_resume(state);
  return ZIP_GAP_REPAIR_NONE;
}

// A footer anchor may already place a displaced terminal run correctly. Find
// the end of the still-contiguous baseline mapping, then test physical source
// runs without replacing that anchor. A successful Zstandard checksum makes
// the selected run exact.
//
static inline ZipGapRepairResult zip_reassembly_repair_zstd_anchored_gap(
    ThreadWork *work,
    CarveInfo **candidate,
    ZipCarveState *state,
    const ZipStateEntry *entry,
    const uint8_t *baseline,
    uint8_t *trial,
    uint64_t buffer_size,
    uuid_string_t uuidp,
    uuid_string_t uuidc) {

  if (!work || !candidate || !*candidate || !state || !entry
      || !baseline || !trial || entry->method != ZIP_METHOD_ZSTD
      || scalpel_state.blocksize == 0) {
    return ZIP_GAP_REPAIR_NONE;
  }

  const uint64_t total_blocks = CEILDIV(state->archive_size,
                                        scalpel_state.blocksize);
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror),
      scalpel_state.blocksize);
  const uint64_t entry_first = entry->data_offset
                               / scalpel_state.blocksize;
  uint64_t destination = state->failure_offset
                         / scalpel_state.blocksize;
  const int64_t header_actual = blockvector_get_actual_blocknumber(
      (*candidate)->b, 0);

  if (header_actual < 0 || total_blocks == 0 || image_blocks == 0
      || blockvector_get_num_blocks((*candidate)->b) != total_blocks) {
    return ZIP_GAP_REPAIR_NONE;
  }
  if (destination >= total_blocks) {
    destination = total_blocks - 1;
  }
  if (destination < entry_first) {
    return ZIP_GAP_REPAIR_NONE;
  }

  bool resume = state->repair_resume.phase
                == ZIP_REPAIR_PHASE_ZSTD_ANCHORED;

  if (state->repair_resume.phase != ZIP_REPAIR_PHASE_NONE && !resume) {
    zip_reassembly_reset_repair_resume(state);
  }

  BlockVector *anchored = NULL;
  CarveInfo anchored_candidate = **candidate;
  CarveInfo *repair_candidate = *candidate;
  const uint8_t *repair_baseline = baseline;
  SearchSpec *spec = &scalpel_state.search_specs[(*candidate)->needleidx];
  uint64_t selected_footer_index = UINT64_MAX;
  uint64_t footer_start = 0;
  if (resume) {
    uint64_t last = spec->offsets.numfooters;
    while (footer_start < last) {
      uint64_t middle = footer_start + (last - footer_start) / 2;
      if (spec->offsets.footers[middle] < state->repair_resume.footer_index) {
        footer_start = middle + 1;
      }
      else {
        last = middle;
      }
    }
  }

  for (uint64_t footer_index = footer_start;
       footer_index < spec->offsets.numfooters; footer_index++) {
    const uint64_t footer = spec->offsets.footers[footer_index];
    if ((footer_index & UINT64_C(0xff)) == 0
        && atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                memory_order_acquire)) {
      state->repair_resume.phase = ZIP_REPAIR_PHASE_ZSTD_ANCHORED;
      if (!resume || footer != state->repair_resume.footer_index) {
        state->repair_resume.footer_index = footer;
        state->repair_resume.destination = destination;
        state->repair_resume.source = 0;
      }
      carve_put_state((*candidate)->carvehashkey, state);
      if (reassembly_time_to_checkpoint(work->id, *candidate,
                                        uuidp, uuidc)) {
        return ZIP_GAP_REPAIR_STOPPED;
      }
    }
    if (footer < state->eocd_offset) {
      continue;
    }
    const uint64_t archive_origin = footer - state->eocd_offset;

    if (archive_origin % scalpel_state.blocksize != 0) {
      continue;
    }
    const uint64_t archive_origin_block = archive_origin
                                          / scalpel_state.blocksize;
    const uint64_t anchor_distance = archive_origin_block
                                         > (uint64_t)header_actual
        ? archive_origin_block - (uint64_t)header_actual
        : (uint64_t)header_actual - archive_origin_block;

    if (anchor_distance <= total_blocks) {
      continue;
    }

    uint64_t anchor_destination = state->central_offset
                                  / scalpel_state.blocksize;

    if (anchor_destination > 1) {
      anchor_destination--;
    }
    if (anchor_destination >= total_blocks) {
      continue;
    }
    const uint64_t anchor_length = total_blocks - anchor_destination;
    uint64_t anchor_source = 0;

    if (__builtin_add_overflow(archive_origin_block,
                               anchor_destination, &anchor_source)
        || anchor_source > INT64_MAX
        || anchor_source >= image_blocks
        || anchor_length > image_blocks - anchor_source) {
      continue;
    }

    int64_t anchor_swap_slot = ZIP_SWAP_SLOT_UNMAPPED;

    if (!zip_reassembly_source_run_viable(
            *candidate, anchor_destination, anchor_length,
            (int64_t)anchor_source, &anchor_swap_slot)) {
      continue;
    }

    clone_blockvector((*candidate)->b, &anchored, true);
    anchored_candidate.b = anchored;
    zip_reassembly_commit_source_run(
        &anchored_candidate, anchor_destination, anchor_length,
        (int64_t)anchor_source, anchor_swap_slot);

    ZipLayout anchor_layout;
    uint64_t anchor_failure = state->failure_offset;
    uint64_t anchor_entry = state->failure_entry;
    bool anchor_valid = false;

    memset(&anchor_layout, 0, sizeof(anchor_layout));
    const bool anchor_structure = zip_find_layout(
        (const uint8_t *)blockvector_get_data_pointer(anchored),
        state->archive_size, scalpel_state.blocksize, &anchor_layout,
        &anchor_failure,
        &anchor_entry, &anchor_valid);
    const bool anchor_matches = anchor_structure
        && !anchor_layout.displaced_structure
        && zip_layout_matches_state(&anchor_layout, state);

    zip_layout_clear(&anchor_layout);
    if (!anchor_matches) {
      free_blockvector(&anchored);
      continue;
    }
    repair_candidate = &anchored_candidate;
    repair_baseline = NULL;
    selected_footer_index = footer_index;
    break;
  }

  if (selected_footer_index == UINT64_MAX) {
    zip_reassembly_reset_repair_resume(state);
    return ZIP_GAP_REPAIR_NONE;
  }

  resume = resume && spec->offsets.footers[selected_footer_index]
      == state->repair_resume.footer_index;
  if (resume) {
    destination = state->repair_resume.destination;
    if (destination < entry_first || destination >= total_blocks) {
      free_blockvector(&anchored);
      zip_reassembly_reset_repair_resume(state);
      return ZIP_GAP_REPAIR_NONE;
    }
  }

  for (;;) {
    uint64_t anchor = destination + 1;

    while (anchor < total_blocks) {
      uint64_t expected = 0;

      if (__builtin_add_overflow((uint64_t)header_actual, anchor,
                                 &expected)
          || expected > INT64_MAX
          || blockvector_get_actual_blocknumber(repair_candidate->b, anchor)
                 != (int64_t)expected) {
        break;
      }
      anchor++;
    }

    const uint64_t run_length = anchor - destination;
    uint64_t source_first = 0;

    if (run_length > 0
        && !__builtin_add_overflow((uint64_t)header_actual,
                                   destination + 1, &source_first)
        && source_first < image_blocks
        && run_length <= image_blocks - source_first) {
      const uint64_t source_last = image_blocks - run_length;

      const uint64_t source_start = resume
          && spec->offsets.footers[selected_footer_index]
                 == state->repair_resume.footer_index
          && destination == state->repair_resume.destination
          && state->repair_resume.source >= source_first
          && state->repair_resume.source <= source_last
              ? state->repair_resume.source : source_first;

      for (uint64_t source = source_start; source <= source_last; source++) {
        if ((source & UINT64_C(0xff)) == 0) {
          if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
            free_blockvector(&anchored);
            return ZIP_GAP_REPAIR_STOPPED;
          }
          if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                   memory_order_acquire)) {
            state->repair_resume.phase = ZIP_REPAIR_PHASE_ZSTD_ANCHORED;
            state->repair_resume.footer_index =
                spec->offsets.footers[selected_footer_index];
            state->repair_resume.destination = destination;
            state->repair_resume.source = source;
            carve_put_state((*candidate)->carvehashkey, state);
            if (reassembly_time_to_checkpoint(work->id, *candidate,
                                              uuidp, uuidc)) {
              free_blockvector(&anchored);
              return ZIP_GAP_REPAIR_STOPPED;
            }
          }
        }
        if (source > INT64_MAX) {
          break;
        }

        int64_t swap_slot = ZIP_SWAP_SLOT_UNMAPPED;

        if (!zip_reassembly_source_run_viable(
                repair_candidate, destination, run_length,
                (int64_t)source, &swap_slot)) {
          continue;
        }

        if (anchored) {
          const uint64_t anchored_saved_length =
              blockvector_get_data_length(anchored);

          blockvector_set_data_length(anchored, buffer_size);
          repair_baseline = (const uint8_t *)
              blockvector_get_data_pointer(anchored);
          blockvector_set_data_length(anchored,
                                      anchored_saved_length);
        }
        memcpy(trial, repair_baseline, (size_t)buffer_size);
        if (!zip_reassembly_apply_source_run(
                trial, repair_baseline, repair_candidate,
                destination, run_length,
                (int64_t)source, swap_slot)) {
          continue;
        }

        uint64_t failure_offset = state->failure_offset;
        uint64_t output_progress = 0;

        if (!zip_reassembly_verify_entry(
                trial, state->archive_size, state, entry,
                &failure_offset, &output_progress)) {
          continue;
        }

        BlockVector *repaired = NULL;

        clone_blockvector(repair_candidate->b, &repaired, true);
        CarveInfo repaired_candidate = *repair_candidate;

        repaired_candidate.b = repaired;
        zip_reassembly_commit_source_run(
            &repaired_candidate, destination, run_length,
            (int64_t)source, swap_slot);
        failure_offset = state->failure_offset;
        output_progress = 0;
        if (!zip_reassembly_verify_entry(
                (const uint8_t *)blockvector_get_data_pointer(repaired),
                blockvector_get_data_length(repaired), state, entry,
                &failure_offset, &output_progress)) {
          free_blockvector(&repaired);
          continue;
        }

        BlockVector *old_blockvector = (*candidate)->b;

        (*candidate)->b = repaired;
        free_blockvector(&old_blockvector);
        free_blockvector(&anchored);
        blockvector_set_data_length((*candidate)->b,
                                    state->archive_size);
        state->failure_offset = failure_offset;
        state->destination_slot = 0;
        state->run_length = 1;
        state->scan_rank = 0;
        state->broad_scan = false;
        state->broad_wrapped = false;
        state->scan_shares = 0;
        state->preferred_destination_slot = 0;
        state->preferred_run_active = false;
        state->preferred_run_length = 0;
        zip_reassembly_reset_repair_resume(state);
        return ZIP_GAP_REPAIR_APPLIED;
      }
    }

    resume = false;

    if (destination == entry_first) {
      break;
    }
    destination--;
  }
  free_blockvector(&anchored);
  zip_reassembly_reset_repair_resume(state);
  return ZIP_GAP_REPAIR_NONE;
}

// When every inserted block is zero, the observed size delta identifies the
// complete set of physical insertions. Normalize that mapping in one pass,
// but commit it only when ZIP structure and member validation improve.
static inline ZipGapRepairResult zip_reassembly_repair_zero_insertions(
    ThreadWork *work,
    CarveInfo **candidate,
    ZipCarveState *state,
    const ZipStateEntry *entry,
    const uint8_t *baseline,
    uint8_t *trial,
    uint64_t buffer_size,
    uuid_string_t uuidp,
    uuid_string_t uuidc) {

  if (!work || !candidate || !*candidate || !state || !entry
      || !baseline || !trial || (*candidate)->clone || entry->encrypted
      || scalpel_state.blocksize == 0
      || !zip_method_directly_verifiable(entry->method)
      || state->observed_archive_size <= state->archive_size) {
    return ZIP_GAP_REPAIR_NONE;
  }

  const uint64_t blocksize = scalpel_state.blocksize;
  const uint64_t inserted_bytes = state->observed_archive_size
                                  - state->archive_size;

  if (inserted_bytes % blocksize != 0) {
    return ZIP_GAP_REPAIR_NONE;
  }
  const uint64_t inserted_blocks = inserted_bytes / blocksize;
  const uint64_t total_blocks = CEILDIV(state->archive_size, blocksize);
  const uint64_t observed_blocks = CEILDIV(
      state->observed_archive_size, blocksize);
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), blocksize);
  const int64_t header_actual = blockvector_get_actual_blocknumber(
      (*candidate)->b, 0);

  if (inserted_blocks < 2 || total_blocks == 0
      || inserted_blocks > UINT64_MAX - total_blocks
      || observed_blocks != total_blocks + inserted_blocks
      || observed_blocks > image_blocks || header_actual < 0
      || (uint64_t)header_actual > image_blocks - observed_blocks
      || total_blocks > buffer_size / blocksize) {
    return ZIP_GAP_REPAIR_NONE;
  }

  uint64_t baseline_failure = state->failure_offset;
  uint64_t baseline_output = 0;

  (void)zip_reassembly_verify_entry(
      baseline, state->archive_size, state, entry,
      &baseline_failure, &baseline_output);
  if (observed_blocks > SIZE_MAX / sizeof(uint64_t)) {
    return ZIP_GAP_REPAIR_NONE;
  }
  uint64_t *run_starts = (uint64_t *)malloc(
      (size_t)observed_blocks * sizeof(*run_starts));
  uint64_t *run_lengths = (uint64_t *)malloc(
      (size_t)observed_blocks * sizeof(*run_lengths));

  check_memory_allocation(run_starts, __LINE__, __FILE__,
                          "ZIP zero-run starts");
  check_memory_allocation(run_lengths, __LINE__, __FILE__,
                          "ZIP zero-run lengths");
  uint64_t run_count = 0;
  uint64_t observed = 1;

  while (observed < observed_blocks) {
    const int64_t actual = header_actual + (int64_t)observed;

    if (!filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                         actual)) {
      observed++;
      continue;
    }
    const uint64_t run_start = observed;

    do {
      observed++;
    } while (observed < observed_blocks
             && filemirror_actual_block_is_zero(
                    scalpel_state.filemirror,
                    header_actual + (int64_t)observed));
    run_starts[run_count] = run_start;
    run_lengths[run_count] = observed - run_start;
    run_count++;
  }
  if (run_count == 0 || run_count > ZIP_ZERO_GAP_RUN_LIMIT) {
    free(run_lengths);
    free(run_starts);
    if (state->repair_resume.phase
        == ZIP_REPAIR_PHASE_ZERO_INSERTIONS) {
      zip_reassembly_reset_repair_resume(state);
    }
    return ZIP_GAP_REPAIR_NONE;
  }
  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout,
                 "ZIP repeated zero-gap candidates: runs=%" PRIu64
                 " inserted=%" PRIu64 ".\n",
                 run_count, inserted_blocks);
  }

  const uint64_t mask_limit = UINT64_C(1) << run_count;
  uint64_t mask = state->repair_resume.phase
                      == ZIP_REPAIR_PHASE_ZERO_INSERTIONS
                  ? state->repair_resume.source_rank : UINT64_C(1);

  if (mask == 0 || mask >= mask_limit) {
    mask = UINT64_C(1);
  }
  uint64_t matched_mask = UINT64_MAX;

  for (; mask < mask_limit; mask++) {
    if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
      free(run_lengths);
      free(run_starts);
      return ZIP_GAP_REPAIR_STOPPED;
    }
    if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                             memory_order_acquire)) {
      state->repair_resume.phase =
          ZIP_REPAIR_PHASE_ZERO_INSERTIONS;
      state->repair_resume.source_rank = mask;
      carve_put_state((*candidate)->carvehashkey, state);
      if (reassembly_time_to_checkpoint(work->id, *candidate,
                                        uuidp, uuidc)) {
        free(run_lengths);
        free(run_starts);
        return ZIP_GAP_REPAIR_STOPPED;
      }
    }

    uint64_t selected_blocks = 0;

    for (uint64_t run = 0; run < run_count; run++) {
      if ((mask & (UINT64_C(1) << run)) == 0) {
        continue;
      }
      if (run_lengths[run] > inserted_blocks - selected_blocks) {
        selected_blocks = inserted_blocks + 1;
        break;
      }
      selected_blocks += run_lengths[run];
    }
    if (selected_blocks != inserted_blocks) {
      continue;
    }

    memset(trial, 0, (size_t)buffer_size);
    uint64_t destination = 0;
    uint64_t run = 0;
    bool mapping_available = true;

    for (observed = 0; observed < observed_blocks; observed++) {
      if (run < run_count && observed == run_starts[run]) {
        const bool selected = (mask & (UINT64_C(1) << run)) != 0;
        const uint64_t run_length = run_lengths[run];

        run++;
        if (selected) {
          observed += run_length - 1;
          continue;
        }
      }

      const int64_t actual = header_actual + (int64_t)observed;

      if (destination >= total_blocks
          || filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                             actual) < 0) {
        mapping_available = false;
        break;
      }
      zip_reassembly_copy_source_run(trial, destination, 1, actual);
      destination++;
    }
    if (!mapping_available || destination != total_blocks) {
      continue;
    }

    ZipLayout layout;
    uint64_t layout_failure = 0;
    uint64_t layout_entry = UINT64_MAX;
    bool archive_valid = false;

    memset(&layout, 0, sizeof(layout));
    const bool structure_valid = zip_find_layout(
        trial, state->archive_size, scalpel_state.blocksize, &layout,
        &layout_failure, &layout_entry, &archive_valid);
    const bool structure_normalized = structure_valid
        && !layout.displaced_structure
        && zip_layout_matches_state(&layout, state);

    zip_layout_clear(&layout);
    if (!structure_normalized) {
      continue;
    }

    uint64_t repaired_failure = state->failure_offset;
    uint64_t repaired_output = 0;
    const bool entry_valid = zip_reassembly_verify_entry(
        trial, state->archive_size, state, entry,
        &repaired_failure, &repaired_output);

    const bool member_progress = repaired_failure >= baseline_failure
        && repaired_output >= baseline_output
        && (repaired_failure > baseline_failure
            || repaired_output > baseline_output);

    if (archive_valid || entry_valid || member_progress) {
      matched_mask = mask;
      break;
    }
  }
  if (matched_mask == UINT64_MAX) {
    free(run_lengths);
    free(run_starts);
    zip_reassembly_reset_repair_resume(state);
    return ZIP_GAP_REPAIR_NONE;
  }
  if (!state->gap_base_mapping_available) {
    state->gap_base_observed_archive_size =
        state->observed_archive_size;
    state->gap_base_physical_gap_slot = state->physical_gap_slot;
    state->gap_base_physical_gap_blocks = state->physical_gap_blocks;
    state->gap_base_header_actual = (uint64_t)header_actual;
    state->gap_base_metadata_source_first = 0;
    state->gap_base_metadata_destination_first = 0;
    state->gap_base_metadata_blocks = 0;
    state->gap_base_mapping_available = true;
  }
  if (!state->gap_base_initialized) {
    state->gap_base_failure_offset = state->failure_offset;
    state->gap_base_failure_entry = state->failure_entry;
    state->gap_base_structure_pending = state->structure_pending;
    state->gap_base_initialized = true;
  }

  uint64_t destination = 0;
  uint64_t run = 0;

  for (observed = 0; observed < observed_blocks; observed++) {
    if (run < run_count && observed == run_starts[run]) {
      const bool selected =
          (matched_mask & (UINT64_C(1) << run)) != 0;
      const uint64_t run_length = run_lengths[run];

      run++;
      if (selected) {
        observed += run_length - 1;
        continue;
      }
    }
    const int64_t actual = header_actual + (int64_t)observed;
    const int64_t apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, actual);

    if (apparent < 0 || destination >= total_blocks) {
      if (scalpel_state.mode_verbose) {
        lock_fprintf(stdout,
                     "ZIP repeated zero-gap commit rejected: observed=%"
                     PRIu64 " actual=%" PRId64 " apparent=%" PRId64
                     " destination=%" PRIu64 ".\n",
                     observed, actual, apparent, destination);
      }
      free(run_lengths);
      free(run_starts);
      return ZIP_GAP_REPAIR_NONE;
    }
    blockvector_set_apparent_blocknumber((*candidate)->b, destination,
                                          apparent);
    destination++;
  }
  free(run_lengths);
  free(run_starts);
  blockvector_set_data_length((*candidate)->b, state->archive_size);
  inflate_blockvector((*candidate)->b);

  state->observed_archive_size = state->archive_size;
  state->physical_gap_slot = 0;
  state->physical_gap_blocks = 0;
  state->failure_offset = state->archive_size;
  state->failure_entry = UINT64_MAX;
  uint64_t earliest_failure = UINT64_MAX;
  const uint8_t *repaired_data = (const uint8_t *)
      blockvector_get_data_pointer((*candidate)->b);

  for (uint64_t index = 0; index < state->entry_count; index++) {
    const ZipStateEntry *state_entry = &state->entries[index];

    if (!state_entry->geometry_known) {
      if (state_entry->local_offset < earliest_failure) {
        earliest_failure = state_entry->local_offset;
        state->failure_offset = state_entry->local_offset;
        state->failure_entry = UINT64_MAX;
      }
      continue;
    }
    if (state_entry->encrypted) {
      continue;
    }

    uint64_t member_failure = state_entry->data_offset;
    uint64_t member_output = 0;

    if (!zip_reassembly_verify_entry(
            repaired_data, state->archive_size, state, state_entry,
            &member_failure, &member_output)
        && state_entry->local_offset < earliest_failure) {
      earliest_failure = state_entry->local_offset;
      state->failure_offset = member_failure;
      state->failure_entry = index;
    }
  }

  state->destination_slot = 0;
  state->run_length = 1;
  state->preferred_run_length = 0;
  state->preferred_destination_slot = 0;
  state->scan_rank = 0;
  state->scan_shares = 0;
  state->broad_scan = false;
  state->broad_wrapped = false;
  state->structure_pending = false;
  state->stored_structure_trial = false;
  state->clone_scan_initialized = false;
  state->preferred_run_active = false;
  state->structure_retry_active = false;
  state->structure_retry_pending = false;
  state->gap_repair_applied = true;
  state->gap_hypothesis_isolated = false;
  state->apk_digest_entry = UINT64_MAX;
  state->apk_digest_fast_active = false;
  state->apk_digest_fast_complete = false;
  zip_reassembly_reset_repair_resume(state);

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout,
                 "ZIP repeated zero-gap repair verified: blocks=%" PRIu64
                 " failure=%" PRIu64 ".\n",
                 inserted_blocks, state->failure_offset);
  }
  return ZIP_GAP_REPAIR_APPLIED;
}

// Multiple inserted gaps create several cumulative physical shifts. Exact
// local-header matches identify those shifts, and a member CRC or decoder can
// then prove one transition at a time without treating their sum as one gap.
static inline ZipGapRepairResult zip_reassembly_repair_staged_gap(
    ThreadWork *work,
    CarveInfo **candidate,
    ZipCarveState *state,
    const ZipStateEntry *entry,
    const uint8_t *baseline,
    uint8_t *trial,
    uint64_t buffer_size,
    uuid_string_t uuidp,
    uuid_string_t uuidc) {

  if (!work || !candidate || !*candidate || !state || !entry
      || !baseline || !trial || (*candidate)->clone
      || scalpel_state.blocksize == 0
      || state->observed_archive_size <= state->archive_size
      || entry->range_end == 0) {
    return ZIP_GAP_REPAIR_NONE;
  }

  const uint64_t blocksize = scalpel_state.blocksize;
  const uint64_t inserted_bytes = state->observed_archive_size
                                  - state->archive_size;

  if (inserted_bytes % blocksize != 0) {
    return ZIP_GAP_REPAIR_NONE;
  }
  const uint64_t aggregate_shift = inserted_bytes / blocksize;

  if (aggregate_shift < 2
      || entry->observed_local_offset < entry->local_offset) {
    return ZIP_GAP_REPAIR_NONE;
  }
  const uint64_t current_shift_bytes = entry->observed_local_offset
                                       - entry->local_offset;

  if (current_shift_bytes % blocksize != 0) {
    return ZIP_GAP_REPAIR_NONE;
  }
  const uint64_t current_shift = current_shift_bytes / blocksize;
  uint64_t next_shift = aggregate_shift;
  bool intermediate_shift_present = false;

  for (uint64_t index = 0; index < state->entry_count; index++) {
    const ZipStateEntry *candidate_entry = &state->entries[index];

    if (!candidate_entry->geometry_known
        || candidate_entry->observed_local_offset
               < candidate_entry->local_offset) {
      continue;
    }
    const uint64_t shift_bytes = candidate_entry->observed_local_offset
                                 - candidate_entry->local_offset;

    if (shift_bytes % blocksize != 0) {
      continue;
    }
    const uint64_t shift = shift_bytes / blocksize;

    if (shift > 0 && shift < aggregate_shift) {
      intermediate_shift_present = true;
    }
    if (candidate_entry->local_offset > entry->local_offset
        && shift > current_shift && shift < next_shift) {
      next_shift = shift;
    }
  }
  if (!intermediate_shift_present || current_shift >= aggregate_shift
      || next_shift <= current_shift) {
    return ZIP_GAP_REPAIR_NONE;
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout,
                 "ZIP staged physical-gap repair: local=%" PRIu64
                 " current_shift=%" PRIu64 " next_shift=%" PRIu64
                 " aggregate_shift=%" PRIu64 ".\n",
                 entry->local_offset, current_shift, next_shift,
                 aggregate_shift);
  }

  const uint64_t total_blocks = CEILDIV(state->archive_size, blocksize);
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), blocksize);
  const int64_t header_actual = blockvector_get_actual_blocknumber(
      (*candidate)->b, 0);
  uint64_t entry_first = entry->data_offset / blocksize;
  uint64_t entry_last = (entry->range_end - 1) / blocksize;
  uint64_t failure_block = state->failure_offset / blocksize;

  if (header_actual < 0 || total_blocks == 0 || image_blocks == 0
      || entry_first >= total_blocks) {
    return ZIP_GAP_REPAIR_NONE;
  }
  const uint64_t first_destination = entry_first > 0 ? entry_first : 1;

  if (entry_last >= total_blocks) {
    entry_last = total_blocks - 1;
  }
  if (failure_block > entry_last) {
    failure_block = entry_last;
  }
  if (failure_block < first_destination) {
    return ZIP_GAP_REPAIR_NONE;
  }

  const bool resume = state->repair_resume.phase
                      == ZIP_REPAIR_PHASE_STAGED_GAP
                      && state->repair_resume.run_length == next_shift;
  const uint64_t maximum_rank = failure_block - first_destination;
  uint64_t rank = resume ? state->repair_resume.destination : 0;

  if (rank > maximum_rank) {
    rank = 0;
  }

  ZipMappedBlockIndex mapped_blocks;

  memset(&mapped_blocks, 0, sizeof(mapped_blocks));
  (void)zip_mapped_block_index_initialize(*candidate, &mapped_blocks);

  for (; rank <= maximum_rank; rank++) {
    if ((rank & UINT64_C(0x0f)) == 0) {
      if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
        zip_mapped_block_index_clear(&mapped_blocks);
        return ZIP_GAP_REPAIR_STOPPED;
      }
      if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                               memory_order_acquire)) {
        state->repair_resume.phase = ZIP_REPAIR_PHASE_STAGED_GAP;
        state->repair_resume.destination = rank;
        state->repair_resume.run_length = next_shift;
        carve_put_state((*candidate)->carvehashkey, state);
        if (reassembly_time_to_checkpoint(work->id, *candidate,
                                          uuidp, uuidc)) {
          zip_mapped_block_index_clear(&mapped_blocks);
          return ZIP_GAP_REPAIR_STOPPED;
        }
      }
    }

    const uint64_t destination = failure_block - rank;
    const uint64_t run_length = entry_last - destination + 1;
    uint64_t source = 0;

    if (__builtin_add_overflow((uint64_t)header_actual, destination,
                               &source)
        || __builtin_add_overflow(source, next_shift, &source)
        || source > INT64_MAX || source >= image_blocks
        || run_length > image_blocks - source) {
      continue;
    }
    int64_t swap_slot = ZIP_SWAP_SLOT_UNMAPPED;

    if (!zip_reassembly_source_run_viable_indexed(
            *candidate, destination, run_length, (int64_t)source,
            &swap_slot, &mapped_blocks)) {
      continue;
    }
    memcpy(trial, baseline, (size_t)buffer_size);
    if (!zip_reassembly_apply_source_run(
            trial, baseline, *candidate, destination, run_length,
            (int64_t)source, swap_slot)) {
      continue;
    }

    uint64_t failure = state->failure_offset;
    uint64_t output = 0;

    if (!zip_reassembly_verify_entry(
            trial, state->archive_size, state, entry,
            &failure, &output)) {
      continue;
    }

    zip_reassembly_commit_source_run(
        *candidate, destination, run_length, (int64_t)source, swap_slot);
    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout,
                   "ZIP staged physical-gap member verified: local=%"
                   PRIu64 " destination=%" PRIu64
                   " blocks=%" PRIu64 " shift=%" PRIu64 ".\n",
                   entry->local_offset, destination, run_length,
                   next_shift);
    }
    blockvector_set_data_length((*candidate)->b, state->archive_size);
    zip_mapped_block_index_clear(&mapped_blocks);

    state->failure_offset = state->archive_size;
    state->failure_entry = UINT64_MAX;
    uint64_t earliest_failure = UINT64_MAX;
    const uint8_t *repaired_data = (const uint8_t *)
        blockvector_get_data_pointer((*candidate)->b);

    for (uint64_t index = 0; index < state->entry_count; index++) {
      const ZipStateEntry *state_entry = &state->entries[index];

      if (!state_entry->geometry_known) {
        if (state_entry->local_offset < earliest_failure) {
          earliest_failure = state_entry->local_offset;
          state->failure_offset = state_entry->local_offset;
          state->failure_entry = UINT64_MAX;
        }
        continue;
      }
      if (state_entry->encrypted) {
        continue;
      }

      uint64_t entry_failure = state_entry->data_offset;
      uint64_t entry_output = 0;

      if (!zip_reassembly_verify_entry(
              repaired_data, state->archive_size, state, state_entry,
              &entry_failure, &entry_output)
          && state_entry->local_offset < earliest_failure) {
        earliest_failure = state_entry->local_offset;
        state->failure_offset = entry_failure;
        state->failure_entry = index;
      }
    }

    if (next_shift >= aggregate_shift) {
      state->observed_archive_size = state->archive_size;
    }
    state->physical_gap_slot = 0;
    state->physical_gap_blocks = 0;
    state->destination_slot = 0;
    state->run_length = 1;
    state->preferred_run_length = 0;
    state->preferred_destination_slot = 0;
    state->scan_rank = 0;
    state->scan_shares = 0;
    state->broad_scan = false;
    state->broad_wrapped = false;
    state->clone_scan_initialized = false;
    state->preferred_run_active = false;
    state->structure_retry_active = false;
    state->structure_retry_pending = false;
    state->gap_base_mapping_available = false;
    state->gap_base_initialized = false;
    state->gap_repair_applied = false;
    state->gap_hypothesis_isolated = false;
    state->apk_digest_entry = UINT64_MAX;
    state->apk_digest_fast_active = false;
    state->apk_digest_fast_complete = false;
    uint8_t *gap_tried = zip_state_gap_tried(state);

    if (gap_tried && state->gap_tried_bytes > 0) {
      memset(gap_tried, 0, (size_t)state->gap_tried_bytes);
    }
    zip_reassembly_reset_repair_resume(state);
    return ZIP_GAP_REPAIR_APPLIED;
  }

  zip_mapped_block_index_clear(&mapped_blocks);
  if (state->repair_resume.phase == ZIP_REPAIR_PHASE_STAGED_GAP) {
    zip_reassembly_reset_repair_resume(state);
  }
  return ZIP_GAP_REPAIR_NONE;
}

// A decoder can report damage after the first bad byte. An inserted gap has
// stronger physical evidence: the correct suffix remains adjacent to the gap
// in the image. Evaluate every physically consistent suffix alignment and
// commit only the one that advances verification farthest.
//
static inline ZipGapRepairResult zip_reassembly_repair_delayed_gap(
    ThreadWork *work,
    CarveInfo **candidate,
    ZipCarveState *state,
    const ZipStateEntry *entry,
    const uint8_t *baseline,
    uint8_t *trial,
    uint64_t buffer_size,
    uuid_string_t uuidp,
    uuid_string_t uuidc) {

  if (!work || !candidate || !*candidate || !state || !entry
      || !baseline || !trial || scalpel_state.blocksize == 0) {
    return ZIP_GAP_REPAIR_NONE;
  }

  const uint64_t total_blocks = CEILDIV(state->archive_size,
                                        scalpel_state.blocksize);
  const bool directly_verifiable = zip_method_directly_verifiable(
      entry->method);
  bool two_runs_exhausted = false;

  if (state->repair_resume.phase == ZIP_REPAIR_PHASE_NONE
      || state->repair_resume.phase
             == ZIP_REPAIR_PHASE_ZERO_INSERTIONS) {
    const ZipGapRepairResult zero_result =
        zip_reassembly_repair_zero_insertions(
            work, candidate, state, entry, baseline, trial,
            buffer_size, uuidp, uuidc);

    if (zero_result != ZIP_GAP_REPAIR_NONE) {
      return zero_result;
    }
  }
  if (state->repair_resume.phase == ZIP_REPAIR_PHASE_NONE
      || state->repair_resume.phase == ZIP_REPAIR_PHASE_STAGED_GAP) {
    const ZipGapRepairResult staged_result =
        zip_reassembly_repair_staged_gap(
            work, candidate, state, entry, baseline, trial,
            buffer_size, uuidp, uuidc);

    if (staged_result != ZIP_GAP_REPAIR_NONE) {
      return staged_result;
    }
  }

  if (entry->method == ZIP_METHOD_STORED
      && (state->repair_resume.phase == ZIP_REPAIR_PHASE_STORED_PAIR
          || state->repair_resume.phase
                 == ZIP_REPAIR_PHASE_STORED_ADJACENT)
      && state->repair_resume.best_destination > 0
      && state->repair_resume.best_run_length > 0
      && state->repair_resume.best_source >= 0) {
    const ZipStoredRepairResult stored_result =
        zip_reassembly_repair_stored_member(
            work, candidate, state, entry,
            state->repair_resume.best_destination,
            state->repair_resume.best_run_length,
            state->repair_resume.best_source,
            state->repair_resume.best_swap_slot,
            uuidp, uuidc);

    if (stored_result == ZIP_STORED_REPAIR_STOPPED) {
      return ZIP_GAP_REPAIR_STOPPED;
    }
    if (stored_result == ZIP_STORED_REPAIR_SOLVED) {
      blockvector_set_data_length((*candidate)->b, state->archive_size);
      return ZIP_GAP_REPAIR_APPLIED;
    }
  }

  if (directly_verifiable && entry->method == ZIP_METHOD_ZSTD) {
    if (state->repair_resume.phase == ZIP_REPAIR_PHASE_ZSTD_ANCHORED
        || (state->repair_resume.phase == ZIP_REPAIR_PHASE_NONE
            && zip_reassembly_has_displaced_footer_anchor(
                   *candidate, state, total_blocks))) {
      const ZipGapRepairResult anchored_result =
          zip_reassembly_repair_zstd_anchored_gap(
              work, candidate, state, entry, baseline, trial,
              buffer_size, uuidp, uuidc);

      if (anchored_result != ZIP_GAP_REPAIR_NONE) {
        return anchored_result;
      }
    }
  }
  if (state->repair_resume.phase == ZIP_REPAIR_PHASE_TWO_RUN_FIRST
      || state->repair_resume.phase == ZIP_REPAIR_PHASE_TWO_RUN_SECOND) {
    const ZipGapRepairResult two_run_result =
        zip_reassembly_repair_two_runs(
            work, candidate, state, entry, baseline, trial,
            buffer_size, uuidp, uuidc);

    if (two_run_result != ZIP_GAP_REPAIR_NONE) {
      return two_run_result;
    }
    two_runs_exhausted = true;
  }

  uint64_t failure_block = state->failure_offset
                           / scalpel_state.blocksize;
  uint64_t entry_first = 1;
  const int64_t header_actual = blockvector_get_actual_blocknumber(
      (*candidate)->b, 0);

  // Stored data has no decoder position beyond its CRC failure. Its complete
  // member range supplies the conservative upper bound instead.
  if ((!directly_verifiable || entry->method == ZIP_METHOD_STORED)
      && entry->range_end > 0) {
    failure_block = (entry->range_end - 1) / scalpel_state.blocksize;
  }

  if (state->observed_archive_size <= state->archive_size) {
    return ZIP_GAP_REPAIR_NONE;
  }

  const uint64_t inserted_bytes = state->observed_archive_size
                                  - state->archive_size;

  if (inserted_bytes % scalpel_state.blocksize != 0) {
    return ZIP_GAP_REPAIR_NONE;
  }

  const uint64_t physical_shift = inserted_bytes
                                  / scalpel_state.blocksize;

  if (physical_shift == 0 || header_actual < 0) {
    return ZIP_GAP_REPAIR_NONE;
  }

  if (state->physical_gap_slot > 0) {
    if (state->physical_gap_slot >= total_blocks) {
      return ZIP_GAP_REPAIR_NONE;
    }
    entry_first = state->physical_gap_slot;
    failure_block = state->physical_gap_slot;
  }
  else {
    // Local headers that retain their logical offsets precede the insertion;
    // headers displaced by exactly inserted_bytes follow it. Together they
    // bracket the physical gap even when the first failing member begins much
    // later in the archive.
    for (uint64_t index = 0; index < state->entry_count; index++) {
      const ZipStateEntry *state_entry = &state->entries[index];
      const uint64_t local_block = state_entry->local_offset
                                   / scalpel_state.blocksize;

      if (!state_entry->geometry_known) {
        continue;
      }
      if (state_entry->observed_local_offset == state_entry->local_offset) {
        if (local_block < total_blocks - 1
            && local_block + 1 > entry_first) {
          entry_first = local_block + 1;
        }
      }
      else if (state_entry->observed_local_offset
                    > state_entry->local_offset
               && state_entry->observed_local_offset
                        - state_entry->local_offset == inserted_bytes
               && local_block < failure_block) {
        failure_block = local_block;
      }
    }
  }

  if (failure_block < entry_first || failure_block >= total_blocks) {
    return ZIP_GAP_REPAIR_NONE;
  }
  if (!state->gap_base_mapping_available) {
    (void)zip_reassembly_capture_gap_baseline(*candidate, state);
  }
  if (!state->gap_base_initialized
      && state->gap_base_mapping_available) {
    state->gap_base_failure_offset = state->failure_offset;
    state->gap_base_failure_entry = state->failure_entry;
    state->gap_base_structure_pending = state->structure_pending;
    state->gap_base_initialized = true;
  }
  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout,
                 "ZIP physical-gap bounds: first=%" PRIu64
                 " failure=%" PRIu64 " shift=%" PRIu64 ".\n",
                 entry_first, failure_block, physical_shift);
  }

  if (entry->method == ZIP_METHOD_STORED
      && (state->repair_resume.phase == ZIP_REPAIR_PHASE_NONE
          || state->repair_resume.phase
                 == ZIP_REPAIR_PHASE_STORED_GAP_OOO)) {
    const ZipStoredRepairResult stored_result =
        zip_reassembly_repair_stored_gap_ooo(
            work, candidate, state, entry, entry_first, failure_block,
            physical_shift, uuidp, uuidc);

    if (stored_result == ZIP_STORED_REPAIR_STOPPED) {
      return ZIP_GAP_REPAIR_STOPPED;
    }
    if (stored_result == ZIP_STORED_REPAIR_SOLVED) {
      blockvector_set_data_length((*candidate)->b, state->archive_size);
      return ZIP_GAP_REPAIR_APPLIED;
    }
  }

  // Resolve one physical-gap hypothesis before sharing source-search work.
  // If that hypothesis is exhausted, the baseline is restored and every
  // surviving worker advances to the next strongest hypothesis.
  //

  bool resume = state->repair_resume.phase == ZIP_REPAIR_PHASE_DELAYED
      || state->repair_resume.phase == ZIP_REPAIR_PHASE_DELAYED_ADJACENT;

  if (state->repair_resume.phase != ZIP_REPAIR_PHASE_NONE && !resume) {
    zip_reassembly_reset_repair_resume(state);
  }

  uint64_t delayed_view = zip_normal_scan_signature(
      *candidate, state, baseline, entry->local_offset, failure_block);
  delayed_view ^= state->gap_hypothesis_isolated;
  if (state->gap_tried_bytes > 0) {
    delayed_view ^= XXH3_64bits(zip_state_gap_tried(state),
                               (size_t)state->gap_tried_bytes);
  }
  bool delayed_usable = state->delayed_scan
      && state->delayed_scan->signature == delayed_view;
  if (delayed_usable && (resume || state->delayed_scan->finished)) {
    const ZipRepairResume *saved = state->delayed_scan->finished
        ? &state->delayed_scan->best : &state->repair_resume;
    int64_t swap = ZIP_SWAP_SLOT_UNMAPPED;
    if (saved->best_source >= 0
        && !zip_reassembly_source_run_viable(
               *candidate, saved->best_destination, saved->best_run_length,
               saved->best_source, &swap)) {
      delayed_usable = false;
    }
    for (size_t i = 0; delayed_usable && i < ZIP_DEFLATE_GAP_PROBE_COUNT;
         i++) {
      const ZipGapProbe *probe = &state->delayed_scan->probes[i];
      if ((probe->flags & 1)
          && !zip_reassembly_source_run_viable(
                 *candidate, probe->destination,
                 total_blocks - probe->destination, probe->source, &swap)) {
        delayed_usable = false;
      }
    }
  }
  if (!delayed_usable) {
    free(state->delayed_scan);
    state->delayed_scan = (ZipDelayedScanState *)calloc(
        1, sizeof(*state->delayed_scan));
    check_memory_allocation(state->delayed_scan, __LINE__, __FILE__,
                            "ZIP delayed scan");
    state->delayed_scan->signature = delayed_view;
    state->delayed_scan->best.best_source = -1;
    state->delayed_scan->best.best_confidence_gain = INT64_MIN;
    // Missing or unavailable prior observations cannot rank the remaining
    // suffix fairly. Rebuild only this physical-gap scope.
    if (resume && !state->gap_hypothesis_isolated) {
      zip_reassembly_reset_repair_resume(state);
      resume = false;
    }
  }
  ZipDelayedScanState *delayed = state->delayed_scan;
  if (delayed->finished) {
    state->repair_resume = delayed->best;
    resume = true;
  }

  uint64_t best_destination = resume
      ? state->repair_resume.best_destination : 0;
  uint64_t best_suffix_length = resume
      ? state->repair_resume.best_run_length : 0;
  uint64_t best_failure = resume
      ? state->repair_resume.best_failure : state->failure_offset;
  uint64_t baseline_failure = state->failure_offset;
  uint64_t baseline_output = 0;

  (void)zip_reassembly_verify_entry(
      baseline, state->archive_size, state, entry,
      &baseline_failure, &baseline_output);
  uint64_t best_output = resume
      ? state->repair_resume.best_output : baseline_output;
  int64_t best_source = resume
      ? state->repair_resume.best_source : -1;
  int64_t best_swap_slot = resume
      ? state->repair_resume.best_swap_slot : ZIP_SWAP_SLOT_UNMAPPED;
  int64_t best_confidence_gain = resume
      ? state->repair_resume.best_confidence_gain : INT64_MIN;
  const uint64_t delay_start = delayed->finished ? failure_block - entry_first + 1
      : resume ? state->repair_resume.destination : 0;
  const uint64_t maximum_delay = failure_block - entry_first;
  const uint64_t delay_end = resume && state->gap_hypothesis_isolated
      ? state->repair_resume.first_destination : maximum_delay;
  const uint64_t gap_share_limit = zip_reassembly_helper_limit(
      state->archive_size);
  uint8_t *gap_tried = zip_state_gap_tried(state);
  ZipMappedBlockIndex mapped_blocks;
  bool exact_layout_found = delayed->exact != 0;
  ZipGapProbe *gap_probes = delayed->probes;

  memset(&mapped_blocks, 0, sizeof(mapped_blocks));
  (void)zip_mapped_block_index_initialize(*candidate, &mapped_blocks);

  for (uint64_t delay = delay_start; delay <= delay_end; delay++) {
    const bool delay_previously_tried = gap_tried
        && delay / 8 < state->gap_tried_bytes
        && (gap_tried[delay / 8]
            & (uint8_t)(UINT8_C(1) << (delay % 8))) != 0;

    if (delay_previously_tried && state->gap_hypothesis_isolated) {
      continue;
    }
    if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
      zip_mapped_block_index_clear(&mapped_blocks);
      return ZIP_GAP_REPAIR_STOPPED;
    }
    if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
      if (state->repair_resume.phase != ZIP_REPAIR_PHASE_DELAYED_ADJACENT) {
        state->repair_resume.phase = ZIP_REPAIR_PHASE_DELAYED;
      }
      state->repair_resume.destination = delay;
      state->repair_resume.best_destination = best_destination;
      state->repair_resume.best_run_length = best_suffix_length;
      state->repair_resume.best_failure = best_failure;
      state->repair_resume.best_output = best_output;
      state->repair_resume.best_source = best_source;
      state->repair_resume.best_swap_slot = best_swap_slot;
      state->repair_resume.best_confidence_gain = best_confidence_gain;
      delayed->best = state->repair_resume;
      delayed->next_delay = delay;
      carve_put_state((*candidate)->carvehashkey, state);
      if (reassembly_time_to_checkpoint(work->id, *candidate,
                                        uuidp, uuidc)) {
        zip_mapped_block_index_clear(&mapped_blocks);
        return ZIP_GAP_REPAIR_STOPPED;
      }
    }

    // The decoder can report damage several blocks after a physical gap.
    // Give each idle helper one distinct gap hypothesis so exact downstream
    // validation can resolve that ambiguity without serially exhausting a
    // complete source search beneath every earlier hypothesis.
    if (!delay_previously_tried && !(*candidate)->clone
        && entry->method != ZIP_METHOD_BZIP2
        && state->scan_shares < gap_share_limit) {
      const ZipRepairResume parent_resume = state->repair_resume;
      const bool parent_isolated = state->gap_hypothesis_isolated;

      zip_reassembly_reset_repair_resume(state);
      state->repair_resume.phase = ZIP_REPAIR_PHASE_DELAYED;
      state->repair_resume.destination = delay;
      state->repair_resume.first_destination = delay;
      state->repair_resume.best_failure = baseline_failure;
      state->repair_resume.best_output = baseline_output;
      state->gap_hypothesis_isolated = true;
      carve_put_state((*candidate)->carvehashkey, state);

      const int shares = reassembly_share_work_count(work->id,
                                                     *candidate);

      state->repair_resume = parent_resume;
      state->gap_hypothesis_isolated = parent_isolated;
      if (shares > 0) {
        const uint64_t remaining = gap_share_limit - state->scan_shares;
        const uint64_t accepted = (uint64_t)shares < remaining
                                      ? (uint64_t)shares : remaining;

        state->scan_shares += (uint32_t)accepted;
      }
      carve_put_state((*candidate)->carvehashkey, state);
    }

    const uint64_t destination = failure_block - delay;
    const uint64_t suffix_length = total_blocks - destination;
    uint64_t source_block = 0;

    if (__builtin_add_overflow((uint64_t)header_actual, destination,
                               &source_block)
        || __builtin_add_overflow(source_block, physical_shift,
                                  &source_block)
        || source_block > INT64_MAX) {
      continue;
    }
    const int64_t source_actual = (int64_t)source_block;
    int64_t swap_slot = ZIP_SWAP_SLOT_UNMAPPED;
    int64_t probe_confidence_gain = 0;

    if (!zip_reassembly_source_run_viable_indexed(
            *candidate, destination, suffix_length,
            source_actual, &swap_slot, &mapped_blocks)) {
      if (scalpel_state.mode_verbose) {
        lock_fprintf(stdout,
                     "ZIP physical-gap suffix rejected: destination=%"
                     PRIu64 " length=%" PRIu64 " source=%" PRId64 ".\n",
                     destination, suffix_length, source_actual);
      }
      continue;
    }

    uint64_t confidence_samples = physical_shift;

    if (confidence_samples > suffix_length) {
      confidence_samples = suffix_length;
    }
    if (confidence_samples > ZIP_SOURCE_CONFIDENCE_SAMPLE_BLOCKS) {
      confidence_samples = ZIP_SOURCE_CONFIDENCE_SAMPLE_BLOCKS;
    }

    for (uint64_t sample = 0; sample < confidence_samples; sample++) {
      const int64_t destination_actual =
          blockvector_get_actual_blocknumber((*candidate)->b,
                                             destination + sample);
      const BlockValidationDecision destination_confidence =
          destination_actual < 0 ? BLOCK_CONFIDENCE_INVALID
              : filemirror_get_blocktype(scalpel_state.filemirror,
                                         destination_actual,
                                         (*candidate)->needleidx);
      const BlockValidationDecision source_confidence =
          filemirror_get_blocktype(scalpel_state.filemirror,
                                   source_actual + (int64_t)sample,
                                   (*candidate)->needleidx);

      if (source_confidence > BLOCK_CONFIDENCE_LOW + 2) {
        probe_confidence_gain++;
      }
      if (destination_confidence > BLOCK_CONFIDENCE_LOW + 2) {
        probe_confidence_gain--;
      }
    }

    memcpy(trial, baseline, (size_t)buffer_size);
    if (!zip_reassembly_apply_source_run(
            trial, baseline, *candidate, destination, suffix_length,
            source_actual, swap_slot)) {
      continue;
    }

    uint64_t probe_failure = state->failure_offset;
    uint64_t probe_output = 0;
    bool probe_valid = false;
    bool archive_valid = false;

    probe_valid = zip_reassembly_verify_entry(
        trial, state->archive_size, state, entry,
        &probe_failure, &probe_output);
    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout,
                   "ZIP physical-gap suffix probe: destination=%" PRIu64
                   " length=%" PRIu64 " source=%" PRId64
                   " valid=%d failure=%" PRIu64
                   " output=%" PRIu64 ".\n",
                   destination, suffix_length, source_actual,
                   probe_valid, probe_failure, probe_output);
    }
    if (probe_valid) {
      ZipLayout probe_layout;
      uint64_t archive_failure = state->failure_offset;
      uint64_t archive_entry = UINT64_MAX;
      bool content_valid = false;

      memset(&probe_layout, 0, sizeof(probe_layout));
      archive_valid = zip_find_layout(
          trial, state->archive_size, scalpel_state.blocksize,
          &probe_layout, &archive_failure, &archive_entry,
          &content_valid)
          && content_valid && !probe_layout.displaced_structure
          && zip_layout_matches_state(&probe_layout, state);
      zip_layout_clear(&probe_layout);
    }
    else if (entry->method == ZIP_METHOD_BZIP2
             || entry->method == ZIP_METHOD_ZSTD
             || entry->method == ZIP_METHOD_XZ) {
      state->repair_resume.destination = delay;
      state->repair_resume.best_destination = best_destination;
      state->repair_resume.best_run_length = best_suffix_length;
      state->repair_resume.best_failure = best_failure;
      state->repair_resume.best_output = best_output;
      state->repair_resume.best_source = best_source;
      state->repair_resume.best_swap_slot = best_swap_slot;
      state->repair_resume.best_confidence_gain = best_confidence_gain;
      const ZipGapRepairResult adjacent_result =
          zip_reassembly_repair_adjacent_displaced_run(
              work, candidate, state, entry, trial, buffer_size,
              destination, suffix_length, source_actual, swap_slot,
              physical_shift, uuidp, uuidc);

      if (adjacent_result != ZIP_GAP_REPAIR_NONE) {
        zip_mapped_block_index_clear(&mapped_blocks);
        return adjacent_result;
      }
    }

    if (!(*candidate)->clone && !state->gap_hypothesis_isolated
        && delay < ZIP_DEFLATE_GAP_PROBE_COUNT) {
      const size_t probe_index = (size_t)delay;

      gap_probes[probe_index].flags = 1
          | (!delay_previously_tried ? 2 : 0) | (archive_valid ? 4 : 0);
      gap_probes[probe_index].destination = destination;
      gap_probes[probe_index].failure = probe_failure;
      gap_probes[probe_index].output = probe_output;
      gap_probes[probe_index].source = source_actual;
      gap_probes[probe_index].swap = swap_slot;
      gap_probes[probe_index].confidence = probe_confidence_gain;
    }

    // A decoder can report identical terminal progress for several adjacent
    // positions. Retain the boundary nearest the reported failure first;
    // baseline restoration covers every earlier tied boundary if needed.
    //
    bool better_output = probe_output > best_output;

    if (directly_verifiable
        && entry->data_offset <= UINT64_MAX - entry->compressed_size) {
      const uint64_t compressed_end = entry->data_offset
                                      + entry->compressed_size;

      if (probe_failure >= compressed_end
          && best_failure >= compressed_end) {
        const uint64_t probe_distance = probe_output
            > entry->uncompressed_size
                ? probe_output - entry->uncompressed_size
                : entry->uncompressed_size - probe_output;
        const uint64_t best_distance = best_output
            > entry->uncompressed_size
                ? best_output - entry->uncompressed_size
                : entry->uncompressed_size - best_output;

        better_output = probe_confidence_gain > best_confidence_gain
            || (probe_confidence_gain == best_confidence_gain
                && probe_distance < best_distance);
      }
    }
    const bool better_failure = directly_verifiable
        && (probe_failure > best_failure
            || (probe_failure == best_failure && better_output));

    // Methods delegated to libarchive provide an exact final verdict but no
    // decoder frontier for an incomplete repair. Prefer the earliest untried
    // boundary in the affected member, then restore the baseline and advance
    // through every remaining physical hypothesis.
    if (!delay_previously_tried
        && (archive_valid || better_failure
            || !directly_verifiable
            || (state->gap_hypothesis_isolated && best_source < 0)
            || (probe_valid && best_source < 0))) {
      best_destination = destination;
      best_suffix_length = suffix_length;
      best_failure = probe_failure;
      best_output = probe_output;
      best_source = source_actual;
      best_swap_slot = swap_slot;
      best_confidence_gain = probe_confidence_gain;
      if (archive_valid) {
        exact_layout_found = true;
      }
      // Preserve an exactly verified member repair before searching for a
      // separate defect elsewhere in the archive.
      if (probe_valid) {
        break;
      }
    }
    resume = false;
  }

  // DEFLATE can consume several blocks after corruption before reporting an
  // error. Equivalent failure positions form a plateau around that uncertain
  // boundary. Preserve the strongest decoder-progress hypothesis, then try
  // the strongest positions around the longest plateau. Exact member and
  // archive validation remain the acceptance criteria, and all other gap
  // positions remain in the exhaustive fallback.
  if (!exact_layout_found && !(*candidate)->clone
      && directly_verifiable
      && (entry->method == ZIP_METHOD_DEFLATE
          || entry->method == ZIP_METHOD_DEFLATE64)) {
    uint64_t longest_start = 0;
    uint64_t longest_end = 0;
    uint64_t longest_length = 0;
    uint64_t run_start = 0;
    uint64_t run_length = 0;
    uint64_t run_failure = 0;

    for (uint64_t index = 0;
         index < ZIP_DEFLATE_GAP_PROBE_COUNT; index++) {
      if ((gap_probes[index].flags & 1)
          && (run_length == 0
              || gap_probes[index].failure == run_failure)) {
        if (run_length == 0) {
          run_start = index;
          run_failure = gap_probes[index].failure;
        }
        run_length++;
      }
      else {
        if (run_length > longest_length) {
          longest_start = run_start;
          longest_end = index - 1;
          longest_length = run_length;
        }
        if (gap_probes[index].flags & 1) {
          run_start = index;
          run_length = 1;
          run_failure = gap_probes[index].failure;
        }
        else {
          run_length = 0;
        }
      }
    }
    if (run_length > longest_length) {
      longest_start = run_start;
      longest_end = ZIP_DEFLATE_GAP_PROBE_COUNT - 1;
      longest_length = run_length;
    }

    uint64_t priority[4] = {
        best_source >= 0 && best_destination <= failure_block
            ? failure_block - best_destination : 0,
        0, 0, 0};
    size_t priority_count = 1;
    const uint64_t required_plateau = physical_shift + 1;

    if (required_plateau > physical_shift
        && longest_length >= required_plateau) {
      uint64_t shifted = longest_end >= physical_shift
          ? longest_end - physical_shift : longest_start;

      if (shifted < longest_start) {
        shifted = longest_start;
      }
      priority[priority_count++] = shifted;
      if (shifted > longest_start) {
        priority[priority_count++] = shifted - 1;
      }
      priority[priority_count++] = longest_end;
    }

    uint64_t selected_probe = UINT64_MAX;

    for (size_t priority_index = 0;
         priority_index < priority_count; priority_index++) {
      const uint64_t probe_index = priority[priority_index];
      bool duplicate = false;

      for (size_t earlier = 0; earlier < priority_index; earlier++) {
        if (priority[earlier] == probe_index) {
          duplicate = true;
          break;
        }
      }
      if (!duplicate && probe_index < ZIP_DEFLATE_GAP_PROBE_COUNT
          && (gap_probes[probe_index].flags & 2)) {
        selected_probe = probe_index;
        break;
      }
    }

    if (selected_probe != UINT64_MAX) {
      const size_t probe_index = (size_t)selected_probe;

      best_destination = gap_probes[probe_index].destination;
      best_suffix_length = total_blocks - best_destination;
      best_failure = gap_probes[probe_index].failure;
      best_output = gap_probes[probe_index].output;
      best_source = gap_probes[probe_index].source;
      best_swap_slot = gap_probes[probe_index].swap;
      best_confidence_gain = gap_probes[probe_index].confidence;
      exact_layout_found = (gap_probes[probe_index].flags & 4) != 0;
      if (scalpel_state.mode_verbose) {
        lock_fprintf(stdout,
                     "ZIP physical-gap plateau priority: delay=%" PRIu64
                     " plateau=%" PRIu64 "-%" PRIu64 ".\n",
                     selected_probe, longest_start, longest_end);
      }
    }
  }

  // A restorable, physically constrained repair can be committed before the
  // exhaustive two-run solver. Normal reassembly searches the remaining
  // displacement, then restores this gap hypothesis if needed.
  //
  delayed->finished = 1;
  delayed->exact = exact_layout_found;
  delayed->best = state->repair_resume;
  delayed->best.best_destination = best_destination;
  delayed->best.best_run_length = best_suffix_length;
  delayed->best.best_failure = best_failure;
  delayed->best.best_output = best_output;
  delayed->best.best_source = best_source;
  delayed->best.best_swap_slot = best_swap_slot;
  delayed->best.best_confidence_gain = best_confidence_gain;
  if (!exact_layout_found && !two_runs_exhausted
      && (best_source < 0 || !state->gap_base_initialized
          || entry->method == ZIP_METHOD_BZIP2)) {
    zip_mapped_block_index_clear(&mapped_blocks);
    const ZipGapRepairResult two_run_result =
        zip_reassembly_repair_two_runs(
            work, candidate, state, entry, baseline, trial,
            buffer_size, uuidp, uuidc);

    if (two_run_result != ZIP_GAP_REPAIR_NONE) {
      return two_run_result;
    }
  }

  if (best_source < 0) {
    zip_mapped_block_index_clear(&mapped_blocks);
    zip_reassembly_reset_repair_resume(state);
    return ZIP_GAP_REPAIR_NONE;
  }

  zip_reassembly_commit_source_run(
      *candidate, best_destination, best_suffix_length,
      best_source, best_swap_slot);
  const uint64_t selected_delay = failure_block - best_destination;

  if (gap_tried && selected_delay / 8 < state->gap_tried_bytes) {
    gap_tried[selected_delay / 8] |= (uint8_t)(
        UINT8_C(1) << (selected_delay % 8));
  }
  state->gap_repair_applied = state->gap_base_initialized;
  blockvector_set_data_length((*candidate)->b, state->archive_size);
  state->observed_archive_size = state->archive_size;
  state->physical_gap_slot = 0;
  state->physical_gap_blocks = 0;
  state->failure_offset = state->archive_size;
  state->failure_entry = UINT64_MAX;

  const uint8_t *repaired_data = (const uint8_t *)
      blockvector_get_data_pointer((*candidate)->b);
  uint64_t earliest_failure = UINT64_MAX;

  for (uint64_t index = 0; index < state->entry_count; index++) {
    const ZipStateEntry *state_entry = &state->entries[index];

    if (!state_entry->geometry_known) {
      if (state_entry->local_offset < earliest_failure) {
        earliest_failure = state_entry->local_offset;
        state->failure_offset = state_entry->local_offset;
        state->failure_entry = UINT64_MAX;
      }
      continue;
    }
    if (state_entry->encrypted) {
      continue;
    }

    uint64_t entry_failure = state_entry->data_offset;
    uint64_t output_progress = 0;

    if (!zip_reassembly_verify_entry(
            repaired_data, state->archive_size, state, state_entry,
            &entry_failure, &output_progress)
        && state_entry->local_offset < earliest_failure) {
      earliest_failure = state_entry->local_offset;
      state->failure_offset = entry_failure;
      state->failure_entry = index;
    }
  }
  if (earliest_failure == UINT64_MAX) {
    state->failure_offset = best_failure;
  }
  state->destination_slot = 0;
  state->run_length = 1;
  state->scan_rank = 0;
  state->broad_scan = false;
  state->broad_wrapped = false;
  uint64_t unresolved_first = 0;
  uint64_t unresolved_blocks = 0;

  // Once the physical gap is removed, an unavailable run at the decoder's
  // failure is direct evidence of a second displacement. Search that run
  // before weaker destination hypotheses; broad scanning remains exhaustive.
  const uint64_t failure_slot = state->failure_offset
                                / scalpel_state.blocksize;

  if (failure_slot > 0 && failure_slot < total_blocks) {
    const int64_t failure_actual = blockvector_get_actual_blocknumber(
        (*candidate)->b, failure_slot);
    const bool failure_unavailable = failure_actual < 0
        || filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                           failure_actual);

    if (failure_unavailable) {
      unresolved_first = failure_slot;
      while (unresolved_first > 1) {
        const int64_t previous_actual = blockvector_get_actual_blocknumber(
            (*candidate)->b, unresolved_first - 1);

        if (previous_actual >= 0
            && !filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                                previous_actual)) {
          break;
        }
        unresolved_first--;
      }
      uint64_t slot = unresolved_first;

      while (slot < total_blocks) {
        const int64_t actual = blockvector_get_actual_blocknumber(
            (*candidate)->b, slot);

        if (actual >= 0
            && !filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                                actual)) {
          break;
        }
        unresolved_blocks++;
        slot++;
      }
    }
  }
  if (unresolved_blocks == 0) {
    for (uint64_t slot = 1; slot < total_blocks; slot++) {
      if (blockvector_get_actual_blocknumber((*candidate)->b, slot) >= 0) {
        continue;
      }
      unresolved_first = slot;
      while (slot < total_blocks
             && blockvector_get_actual_blocknumber((*candidate)->b, slot) < 0) {
        unresolved_blocks++;
        slot++;
      }
      break;
    }
  }
  if (unresolved_blocks > 0) {
    state->preferred_destination_slot = unresolved_first;
    state->preferred_run_active = true;
    state->preferred_run_length = unresolved_blocks;
  }
  else if (physical_shift < total_blocks
           && best_destination < total_blocks - physical_shift) {
    state->preferred_destination_slot = best_destination + physical_shift;
    state->preferred_run_active = true;
    state->preferred_run_length = physical_shift;
  }
  else {
    state->preferred_destination_slot = 0;
    state->preferred_run_active = false;
    state->preferred_run_length = 0;
  }
  zip_reassembly_reset_repair_resume(state);
  zip_mapped_block_index_clear(&mapped_blocks);
  return ZIP_GAP_REPAIR_APPLIED;
}


// Publish a structurally complete archive only after applying the configured
// candidate policy to its final physical layout. Container-aware policies can
// retain an exact nested archive without allowing it to cover parent blocks.
//
// An encrypted member cannot be checked without its key. When the terminal
// metadata run is physically adjacent to the archive header, however, the two
// runs form a rotation whose exposed boundary can be ranked using block type
// confidence. A bounded set of the strongest interpretations remains
// PROMISING because the ciphertext itself cannot resolve nearby boundaries.
//
static inline ZipGapRepairResult zip_reassembly_repair_encrypted_rotation(
    ThreadWork *work,
    CarveInfo **candidate,
    ZipCarveState *state,
    uuid_string_t uuidp,
    uuid_string_t uuidc) {

  if (!work || !candidate || !*candidate || !(*candidate)->b || !state
      || scalpel_state.blocksize == 0 || (*candidate)->needleidx < 0) {
    return ZIP_GAP_REPAIR_NONE;
  }

  const uint64_t blocksize = scalpel_state.blocksize;
  const uint64_t total_blocks = CEILDIV(state->archive_size, blocksize);
  const uint64_t candidate_blocks =
      blockvector_get_num_blocks((*candidate)->b);
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), blocksize);

  if (total_blocks < 3 || candidate_blocks < total_blocks
      || total_blocks > SIZE_MAX / blocksize) {
    return ZIP_GAP_REPAIR_NONE;
  }

  const int64_t header_actual = blockvector_get_actual_blocknumber(
      (*candidate)->b, 0);
  const int64_t terminal_actual = blockvector_get_actual_blocknumber(
      (*candidate)->b, total_blocks - 1);

  if (header_actual <= 0 || terminal_actual < 0
      || terminal_actual == INT64_MAX
      || terminal_actual + 1 != header_actual) {
    return ZIP_GAP_REPAIR_NONE;
  }

  const uint8_t *rotation_baseline = (const uint8_t *)
      blockvector_get_data_pointer((*candidate)->b);
  const uint64_t rotation_view = zip_normal_scan_signature(
      *candidate, state, rotation_baseline, 0, total_blocks);
  bool resuming = state->repair_resume.phase
      == ZIP_REPAIR_PHASE_ENCRYPTED_ROTATION;
  bool validating = state->repair_resume.phase
      == ZIP_REPAIR_PHASE_ENCRYPTED_VALIDATE;

  if (state->repair_resume.phase != ZIP_REPAIR_PHASE_NONE
      && !resuming && !validating) {
    return ZIP_GAP_REPAIR_NONE;
  }
  if (!state->encrypted_scan
      || state->encrypted_scan->signature != rotation_view) {
    bool old_scan = state->encrypted_scan != NULL;
    free(state->encrypted_scan);
    state->encrypted_scan = (ZipEncryptedScanState *)calloc(
        1, sizeof(*state->encrypted_scan));
    check_memory_allocation(state->encrypted_scan, __LINE__, __FILE__,
                            "ZIP encrypted scan");
    state->encrypted_scan->signature = rotation_view;
    if (validating || old_scan) {
      zip_reassembly_reset_repair_resume(state);
      resuming = validating = false;
    }
  }
  ZipEncryptedScanState *encrypted = state->encrypted_scan;

  uint64_t resume_entry = resuming ? state->repair_resume.footer_index : 0;
  uint64_t resume_split = resuming ? state->repair_resume.destination : 0;
  uint64_t best_split = resuming
      ? state->repair_resume.best_destination : 0;
  int64_t best_score = resuming
      ? state->repair_resume.best_confidence_gain : INT64_MIN;
  uint64_t best_header_gain = resuming
      ? state->repair_resume.best_failure : 0;
  if (validating) {
    best_split = encrypted->best_split;
    best_score = encrypted->best_score;
    best_header_gain = encrypted->best_header_gain;
  }
  bool saw_classifier_evidence = best_split > 0;

  for (uint64_t entry_index = validating ? state->entry_count : resume_entry;
       entry_index < state->entry_count; entry_index++) {
    const ZipStateEntry *entry = &state->entries[entry_index];

    if (!entry->encrypted || !entry->geometry_known
        || entry->range_end <= entry->data_offset) {
      continue;
    }

    uint64_t first_split = CEILDIV(entry->data_offset, blocksize);
    uint64_t last_split = (entry->range_end - 1) / blocksize;

    if (first_split == 0) {
      first_split = 1;
    }
    if (last_split >= total_blocks) {
      last_split = total_blocks - 1;
    }
    if (first_split > last_split) {
      continue;
    }
    uint64_t confidence_window = ZIP_ENCRYPTED_ROTATION_WINDOW_BLOCKS;
    const uint64_t split_count = last_split - first_split + 1;

    if (confidence_window > split_count / 4) {
      confidence_window = split_count / 4;
    }
    if (confidence_window < 4) {
      continue;
    }
    // The score's window belongs to the full member, not its untested suffix.
    if (resuming && entry_index == resume_entry
        && resume_split >= first_split && resume_split <= last_split) {
      first_split = resume_split;
    }

    bool windows_initialized = false;
    uint64_t header_before = 0;
    uint64_t header_after = 0;
    uint64_t prior_header_boundary = 0;

    for (uint64_t split = first_split; split <= last_split; split++) {
      if ((split & UINT64_C(0xff)) == 0) {
        if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
          state->repair_resume.phase =
              ZIP_REPAIR_PHASE_ENCRYPTED_ROTATION;
          state->repair_resume.footer_index = entry_index;
          state->repair_resume.destination = split;
          state->repair_resume.best_destination = best_split;
          state->repair_resume.best_confidence_gain = best_score;
          state->repair_resume.best_failure = best_header_gain;
          state->repair_resume.best_output = 0;
          return ZIP_GAP_REPAIR_STOPPED;
        }
        if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                 memory_order_acquire)) {
          state->repair_resume.phase =
              ZIP_REPAIR_PHASE_ENCRYPTED_ROTATION;
          state->repair_resume.footer_index = entry_index;
          state->repair_resume.destination = split;
          state->repair_resume.best_destination = best_split;
          state->repair_resume.best_confidence_gain = best_score;
          state->repair_resume.best_failure = best_header_gain;
          state->repair_resume.best_output = 0;
          carve_put_state((*candidate)->carvehashkey, state);
          if (reassembly_time_to_checkpoint(work->id, *candidate,
                                            uuidp, uuidc)) {
            return ZIP_GAP_REPAIR_STOPPED;
          }
        }
      }

      const uint64_t terminal_run = total_blocks - split;

      if (terminal_run > (uint64_t)terminal_actual + 1
          || (uint64_t)header_actual > UINT64_MAX - split) {
        windows_initialized = false;
        continue;
      }
      const uint64_t header_boundary = (uint64_t)header_actual + split;

      if (header_boundary < confidence_window
          || header_boundary > image_blocks
          || confidence_window > image_blocks - header_boundary) {
        windows_initialized = false;
        continue;
      }

      if (!windows_initialized
          || header_boundary != prior_header_boundary + 1) {
        header_before = 0;
        header_after = 0;

        for (uint64_t sample = 0; sample < confidence_window; sample++) {
          header_before += zip_source_confidence_tier(
              (int)filemirror_get_blocktype(
                  scalpel_state.filemirror,
                  (int64_t)(header_boundary - confidence_window + sample),
                  (*candidate)->needleidx));
          header_after += zip_source_confidence_tier(
              (int)filemirror_get_blocktype(
                  scalpel_state.filemirror,
                  (int64_t)(header_boundary + sample),
                  (*candidate)->needleidx));
        }
        windows_initialized = true;
      }
      else {
        const uint64_t old_header_boundary = header_boundary - 1;

        header_before -= zip_source_confidence_tier(
            (int)filemirror_get_blocktype(
                scalpel_state.filemirror,
                (int64_t)(old_header_boundary - confidence_window),
                (*candidate)->needleidx));
        header_before += zip_source_confidence_tier(
            (int)filemirror_get_blocktype(
                scalpel_state.filemirror, (int64_t)old_header_boundary,
                (*candidate)->needleidx));
        header_after -= zip_source_confidence_tier(
            (int)filemirror_get_blocktype(
                scalpel_state.filemirror, (int64_t)old_header_boundary,
                (*candidate)->needleidx));
        header_after += zip_source_confidence_tier(
            (int)filemirror_get_blocktype(
                scalpel_state.filemirror,
                (int64_t)(old_header_boundary + confidence_window),
                (*candidate)->needleidx));
      }
      prior_header_boundary = header_boundary;

      const int64_t header_gain = (int64_t)header_before
                                  - (int64_t)header_after;
      const int64_t score = header_gain;

      if (header_gain > 0
          && (best_split == 0
              || (uint64_t)header_gain > best_header_gain
              || ((uint64_t)header_gain == best_header_gain
                  && score > best_score))) {
        best_split = split;
        best_score = score;
        best_header_gain = (uint64_t)header_gain;
        saw_classifier_evidence = true;
      }
    }
    resume_split = 0;
  }

  zip_reassembly_reset_repair_resume(state);
  if (!saw_classifier_evidence || best_split == 0
      || best_split >= total_blocks) {
    return ZIP_GAP_REPAIR_NONE;
  }

  // A single moving window locates the transition efficiently but can place
  // its maximum a few blocks away from the physical boundary. Refine that
  // neighborhood at several scales, retaining a bounded set of the strongest
  // structurally valid interpretations because encrypted bytes cannot resolve
  // the remaining ambiguity without a key.
  uint64_t *hypothesis_splits = encrypted->hypothesis_splits;
  int64_t *hypothesis_scores = encrypted->hypothesis_scores;
  uint32_t hypothesis_count = validating
      ? (uint32_t)encrypted->hypothesis_count : 0;
  uint64_t refine_first = best_split > ZIP_ENCRYPTED_ROTATION_REFINE_BLOCKS
                              ? best_split - ZIP_ENCRYPTED_ROTATION_REFINE_BLOCKS
                              : 1;
  uint64_t refine_last = best_split + ZIP_ENCRYPTED_ROTATION_REFINE_BLOCKS;

  if (refine_last < best_split || refine_last >= total_blocks) {
    refine_last = total_blocks - 1;
  }
  for (uint64_t split = validating ? refine_last + 1 : refine_first;
       split <= refine_last; split++) {
    if ((uint64_t)header_actual > UINT64_MAX - split) {
      continue;
    }
    const uint64_t boundary = (uint64_t)header_actual + split;

    if (boundary < ZIP_ENCRYPTED_ROTATION_REFINE_BLOCKS
        || boundary > image_blocks
        || ZIP_ENCRYPTED_ROTATION_REFINE_BLOCKS
               > image_blocks - boundary) {
      continue;
    }

    int64_t multiscale_score = 0;

    for (uint64_t window = 2;
         window <= ZIP_ENCRYPTED_ROTATION_REFINE_BLOCKS; window *= 2) {
      uint64_t before = 0;
      uint64_t after = 0;

      for (uint64_t sample = 0; sample < window; sample++) {
        before += zip_source_confidence_tier(
            (int)filemirror_get_blocktype(
                scalpel_state.filemirror,
                (int64_t)(boundary - window + sample),
                (*candidate)->needleidx));
        after += zip_source_confidence_tier(
            (int)filemirror_get_blocktype(
                scalpel_state.filemirror, (int64_t)(boundary + sample),
                (*candidate)->needleidx));
      }
      multiscale_score += (int64_t)before - (int64_t)after;
    }

    const uint64_t distance = split > best_split
                                  ? split - best_split : best_split - split;
    uint32_t position = 0;

    while (position < hypothesis_count) {
      const uint64_t retained_split = hypothesis_splits[position];
      const uint64_t retained_distance = retained_split > best_split
          ? retained_split - best_split : best_split - retained_split;

      if (multiscale_score > hypothesis_scores[position]
          || (multiscale_score == hypothesis_scores[position]
              && distance < retained_distance)) {
        break;
      }
      position++;
    }
    if (position >= ZIP_ENCRYPTED_ROTATION_HYPOTHESIS_LIMIT) {
      continue;
    }
    if (hypothesis_count < ZIP_ENCRYPTED_ROTATION_HYPOTHESIS_LIMIT) {
      hypothesis_count++;
    }
    for (uint32_t move = hypothesis_count - 1; move > position; move--) {
      hypothesis_splits[move] = hypothesis_splits[move - 1];
      hypothesis_scores[move] = hypothesis_scores[move - 1];
    }
    hypothesis_splits[position] = split;
    hypothesis_scores[position] = multiscale_score;
  }
  if (hypothesis_count == 0) {
    hypothesis_splits[0] = best_split;
    hypothesis_scores[0] = best_score;
    hypothesis_count = 1;
  }
  encrypted->best_split = best_split;
  encrypted->best_score = best_score;
  encrypted->best_header_gain = best_header_gain;
  encrypted->hypothesis_count = hypothesis_count;
  if (!validating) {
    encrypted->next_hypothesis = 0;
    encrypted->valid_count = 0;
  }

  ZipMappedBlockIndex mapped_blocks;
  uint64_t *valid_splits = encrypted->valid_splits;
  int64_t *valid_sources = encrypted->valid_sources;
  int64_t *valid_swaps = encrypted->valid_swaps;
  int64_t *valid_scores = encrypted->valid_scores;
  uint32_t valid_count = (uint32_t)encrypted->valid_count;

  memset(&mapped_blocks, 0, sizeof(mapped_blocks));
  (void)zip_mapped_block_index_initialize(*candidate, &mapped_blocks);

  const uint64_t buffer_size = total_blocks * blocksize;
  const uint8_t *baseline = (const uint8_t *)
      blockvector_get_data_pointer((*candidate)->b);
  uint8_t *trial = (uint8_t *)malloc((size_t)buffer_size);

  check_memory_allocation(trial, __LINE__, __FILE__,
                          "encrypted ZIP rotation trial");
  for (uint32_t index = (uint32_t)encrypted->next_hypothesis;
       index < hypothesis_count; index++) {
    encrypted->next_hypothesis = index;
    encrypted->valid_count = valid_count;
    if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
      free(trial);
      zip_mapped_block_index_clear(&mapped_blocks);
      return ZIP_GAP_REPAIR_STOPPED;
    }
    if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
      state->repair_resume.phase = ZIP_REPAIR_PHASE_ENCRYPTED_VALIDATE;
      carve_put_state((*candidate)->carvehashkey, state);
      if (reassembly_time_to_checkpoint(work->id, *candidate,
                                        uuidp, uuidc)) {
        free(trial);
        zip_mapped_block_index_clear(&mapped_blocks);
        return ZIP_GAP_REPAIR_STOPPED;
      }
    }

    const uint64_t split = hypothesis_splits[index];
    const uint64_t terminal_run = total_blocks - split;

    if (terminal_run > (uint64_t)terminal_actual + 1) {
      continue;
    }
    const int64_t source_actual = (int64_t)(
        (uint64_t)terminal_actual + 1 - terminal_run);
    int64_t swap_slot = ZIP_SWAP_SLOT_UNMAPPED;

    if (!zip_reassembly_source_run_viable_indexed(
            *candidate, split, terminal_run, source_actual, &swap_slot,
            &mapped_blocks)) {
      continue;
    }

    memcpy(trial, baseline, (size_t)state->archive_size);
    if (buffer_size > state->archive_size) {
      memset(trial + state->archive_size, 0,
             (size_t)(buffer_size - state->archive_size));
    }

    bool applied = false;

    if (zip_reassembly_apply_source_run(
            trial, baseline, *candidate, split, terminal_run,
            source_actual, swap_slot)) {
      ZipLayout trial_layout;
      uint64_t trial_failure = state->failure_offset;
      uint64_t trial_entry = state->failure_entry;
      bool trial_content_valid = false;

      memset(&trial_layout, 0, sizeof(trial_layout));
      applied = zip_find_layout(
          trial, state->archive_size, scalpel_state.blocksize,
          &trial_layout, &trial_failure, &trial_entry,
          &trial_content_valid)
          && trial_content_valid && trial_layout.encrypted
          && !trial_layout.displaced_structure
          && zip_layout_matches_state(&trial_layout, state);
      zip_layout_clear(&trial_layout);
    }
    if (applied) {
      valid_splits[valid_count] = split;
      valid_sources[valid_count] = source_actual;
      valid_swaps[valid_count] = swap_slot;
      valid_scores[valid_count] = hypothesis_scores[index];
      valid_count++;
    }
  }
  free(trial);
  zip_mapped_block_index_clear(&mapped_blocks);

  // A retained interpretation must still be usable after other candidates
  // claim blocks. Recheck availability, not already completed decoding.
  uint32_t available_count = 0;
  for (uint32_t index = 0; index < valid_count; index++) {
    int64_t swap = ZIP_SWAP_SLOT_UNMAPPED;
    if (zip_reassembly_source_run_viable(*candidate, valid_splits[index],
            total_blocks - valid_splits[index], valid_sources[index], &swap)) {
      valid_splits[available_count] = valid_splits[index];
      valid_sources[available_count] = valid_sources[index];
      valid_swaps[available_count] = swap;
      valid_scores[available_count] = valid_scores[index];
      available_count++;
    }
  }
  valid_count = available_count;
  encrypted->next_hypothesis = hypothesis_count;
  encrypted->valid_count = valid_count;
  zip_reassembly_reset_repair_resume(state);
  if (valid_count == 0) {
    return ZIP_GAP_REPAIR_NONE;
  }

  uint64_t terminal_length = 0;

  (void)filemirror_actual_block_data_pointer(
      scalpel_state.filemirror, terminal_actual, &terminal_length);
  if (terminal_length > blocksize) {
    terminal_length = blocksize;
  }

  if (scalpel_state.write_promising && valid_count > 1) {
    BlockVector *parent_blockvector = (*candidate)->b;
    const CarveInfoFlavor parent_flavor = (*candidate)->flavor;

    for (uint32_t index = 1; index < valid_count; index++) {
      BlockVector *hypothesis = NULL;
      const uint64_t terminal_run = total_blocks - valid_splits[index];

      clone_blockvector(parent_blockvector, &hypothesis, true);
      (*candidate)->b = hypothesis;
      zip_reassembly_commit_source_run(
          *candidate, valid_splits[index], terminal_run,
          valid_sources[index], valid_swaps[index]);
      if (terminal_length > 0) {
        const uint64_t promising_length = (total_blocks - 1) * blocksize
                                          + terminal_length;

        if (promising_length >= state->archive_size) {
          blockvector_set_data_length((*candidate)->b, promising_length);
        }
      }
      (*candidate)->flavor = PROMISING;
      write_candidate(candidate, true);
      free_blockvector(&((*candidate)->b));
      (*candidate)->b = parent_blockvector;
      (*candidate)->flavor = parent_flavor;
    }
  }

  best_split = valid_splits[0];
  best_score = valid_scores[0];
  const uint64_t terminal_run = total_blocks - best_split;
  const int64_t source_actual = valid_sources[0];

  zip_reassembly_commit_source_run(
      *candidate, best_split, terminal_run, source_actual, valid_swaps[0]);
  if (terminal_length > 0) {
    const uint64_t promising_length = (total_blocks - 1) * blocksize
                                      + terminal_length;

    if (promising_length >= state->archive_size) {
      blockvector_set_data_length((*candidate)->b, promising_length);
    }
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout,
                 "ZIP encrypted rotation retained as PROMISING: "
                 "split=%" PRIu64 " source=%" PRId64
                 " blocks=%" PRIu64 " confidence=%" PRId64
                 " hypotheses=%u.\n",
                 best_split, source_actual, terminal_run, best_score,
                 valid_count);
  }
  return ZIP_GAP_REPAIR_APPLIED;
}


static inline void zip_reassembly_publish_complete(
    CarveInfo **candidate,
    ZipCarveState **state,
    uint8_t *trial,
    uint8_t *baseline,
    uint64_t archive_size,
    uint64_t *memory_reservation) {

  bool validates = true;
  bool promising = false;
  uint64_t validates_to = archive_size - 1;

  blockvector_set_data_length((*candidate)->b, archive_size);
  resize_blockvector((*candidate)->b,
                     CEILDIV(archive_size, scalpel_state.blocksize));

  if (scalpel_state.search_specs[(*candidate)->needleidx]
          .CANDIDATEVALIDATOR) {
    scalpel_state.search_specs[(*candidate)->needleidx]
        .CANDIDATEVALIDATOR(*candidate, &validates, &validates_to,
                            &promising);
  }

  free(trial);
  free(baseline);
  zip_free_carve_state((void **)state);

  if (validates) {
    (*candidate)->flavor = VALIDATED;
    write_candidate(candidate, false);
  }
  else if (promising && scalpel_state.write_promising) {
    (*candidate)->flavor = PROMISING;
    write_candidate(candidate, false);
  }
  else {
    destroy_candidate(candidate);
  }
  zip_reassembly_release_memory(memory_reservation);
}


static inline void zip_reassembly(ThreadWork *work,
                                  CarveInfo **candidate,
                                  uuid_string_t uuidp,
                                  uuid_string_t uuidc) {

  ZipCarveState *state = (ZipCarveState *)
      carve_get_state((*candidate)->carvehashkey);
  uint64_t memory_reservation = 0;

  if (state && scalpel_state.mode_verbose) {
    lock_fprintf(stdout,
                 "ZIP reassembly state: archive=%" PRIu64
                 " observed=%" PRIu64 " failure=%" PRIu64
                 " entry=%" PRIu64 " physical_gap=%" PRIu64
                 " initialized=%d gap_base=%d gap_applied=%d.\n",
                 state->archive_size, state->observed_archive_size,
                 state->failure_offset, state->failure_entry,
                 state->physical_gap_slot,
                 state->initialized, state->gap_base_initialized,
                 state->gap_repair_applied);
  }

  // A ZIP stream enclosed by a recoverable compound document is retained as
  // an exact artifact without taking exclusive ownership of the parent blocks.
  if (state && state->enclosed_by_cfbf) {
    zip_free_carve_state((void **)&state);
    if (scalpel_state.write_promising
        && !(*candidate)->partial_artifact_written) {
      (*candidate)->flavor = PROMISING;
      write_candidate(candidate, false);
    }
    else {
      destroy_candidate(candidate);
    }
    return;
  }

  if (!state) {
    inflate_blockvector((*candidate)->b);

    const ZipInitializationResult initialization_result =
        zip_reassembly_initialize_header_seed(
            work, candidate, &state, &memory_reservation, uuidp, uuidc);

    if (initialization_result == ZIP_INITIALIZATION_STOPPED) {
      deflate_blockvector((*candidate)->b);
      return;
    }
    if (initialization_result != ZIP_INITIALIZATION_MATCHED) {
      if (initialization_result == ZIP_INITIALIZATION_RESOURCE_LIMIT
          && scalpel_state.mode_verbose) {
        lock_fprintf(stdout,
                     "ZIP fragmented recovery cannot reserve a safe "
                     "working set for this candidate; leaving it "
                     "promising.\n");
      }
      if (scalpel_state.write_promising
          && !(*candidate)->partial_artifact_written) {
        (*candidate)->flavor = PROMISING;
        write_candidate(candidate, true);
      }
      destroy_candidate(candidate);
      return;
    }
  }

  if (state->observed_archive_size > state->archive_size
      && state->gap_tried_bytes == 0
      && zip_state_enable_gap_tracking(&state)) {
    carve_put_state((*candidate)->carvehashkey, state);
  }

  if (memory_reservation == 0) {
    const ZipMemoryReservationResult memory_result =
        zip_reassembly_reserve_memory(
            work, candidate, state->archive_size,
            &memory_reservation, uuidp, uuidc);

    if (memory_result == ZIP_MEMORY_STOPPED) {
      deflate_blockvector((*candidate)->b);
      zip_free_carve_state((void **)&state);
      return;
    }
    if (memory_result == ZIP_MEMORY_UNAVAILABLE) {
      if (scalpel_state.mode_verbose) {
        lock_fprintf(stdout,
                     "ZIP fragmented recovery cannot reserve a safe "
                     "working set for this candidate; leaving it "
                     "promising.\n");
      }
      zip_free_carve_state((void **)&state);
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

  if (!zip_reassembly_initialize_candidate(*candidate, state)) {
    zip_free_carve_state((void **)&state);
    destroy_candidate(candidate);
    zip_reassembly_release_memory(&memory_reservation);
    return;
  }

  state->initialized = true;
  carve_put_state((*candidate)->carvehashkey, state);

  bool encrypted_archive = false;

  for (uint64_t index = 0; index < state->entry_count; index++) {
    if (state->entries[index].encrypted) {
      encrypted_archive = true;
      break;
    }
  }

  if (encrypted_archive) {
    const ZipGapRepairResult rotation_result =
        zip_reassembly_repair_encrypted_rotation(
            work, candidate, state, uuidp, uuidc);

    if (rotation_result == ZIP_GAP_REPAIR_STOPPED) {
      deflate_blockvector((*candidate)->b);
      zip_reassembly_release_memory(&memory_reservation);
      zip_free_carve_state((void **)&state);
      return;
    }
    if (rotation_result == ZIP_GAP_REPAIR_APPLIED) {
      zip_free_carve_state((void **)&state);
      if (scalpel_state.write_promising) {
        (*candidate)->flavor = PROMISING;
        write_candidate(candidate, false);
      }
      else {
        destroy_candidate(candidate);
      }
      zip_reassembly_release_memory(&memory_reservation);
      return;
    }

    const uint64_t total_blocks = CEILDIV(state->archive_size,
                                          scalpel_state.blocksize);
    uint64_t unresolved_first = total_blocks;
    uint64_t unresolved_blocks = 0;
    uint64_t suffix_slot = total_blocks;
    bool unmapped_run_complete = false;
    bool multiple_unmapped_runs = false;

    for (uint64_t slot = 0; slot < total_blocks; slot++) {
      if ((slot & UINT64_C(0xff)) == 0) {
        if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
          zip_reassembly_release_memory(&memory_reservation);
          zip_free_carve_state((void **)&state);
          return;
        }
        if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                 memory_order_acquire)
            && reassembly_time_to_checkpoint(work->id, *candidate,
                                              uuidp, uuidc)) {
          deflate_blockvector((*candidate)->b);
          zip_reassembly_release_memory(&memory_reservation);
          zip_free_carve_state((void **)&state);
          return;
        }
      }

      const int64_t actual = blockvector_get_actual_blocknumber(
          (*candidate)->b, slot);

      if (actual < 0) {
        if (unmapped_run_complete) {
          multiple_unmapped_runs = true;
          break;
        }
        if (unresolved_first == total_blocks) {
          unresolved_first = slot;
        }
        unresolved_blocks++;
      }
      else if (unresolved_blocks > 0 && !unmapped_run_complete) {
        suffix_slot = slot;
        unmapped_run_complete = true;
      }
    }

    bool encrypted_span = false;
    uint64_t unresolved_end = 0;

    if (!multiple_unmapped_runs && unresolved_blocks > 0
        && unresolved_first > 0 && suffix_slot < total_blocks
        && !__builtin_mul_overflow(
               unresolved_first + unresolved_blocks,
               scalpel_state.blocksize, &unresolved_end)) {
      if (unresolved_end > state->archive_size) {
        unresolved_end = state->archive_size;
      }
      const uint64_t unresolved_start = unresolved_first
                                        * scalpel_state.blocksize;

      for (uint64_t index = 0; index < state->entry_count; index++) {
        const ZipStateEntry *entry = &state->entries[index];

        if (entry->encrypted && entry->geometry_known
            && unresolved_start >= entry->local_offset
            && unresolved_end <= entry->range_end) {
          encrypted_span = true;
          break;
        }
      }
    }

    bool adjacent_run_applied = false;
    const int64_t suffix_actual = suffix_slot < total_blocks
        ? blockvector_get_actual_blocknumber((*candidate)->b, suffix_slot)
        : -1;

    if (encrypted_span && suffix_actual >= 0
        && (uint64_t)suffix_actual >= unresolved_blocks
        && total_blocks <= SIZE_MAX / scalpel_state.blocksize) {
      const int64_t source_actual = suffix_actual
                                    - (int64_t)unresolved_blocks;
      ZipMappedBlockIndex mapped_blocks;
      int64_t swap_slot = ZIP_SWAP_SLOT_UNMAPPED;

      memset(&mapped_blocks, 0, sizeof(mapped_blocks));
      (void)zip_mapped_block_index_initialize(*candidate, &mapped_blocks);

      if (zip_reassembly_source_run_viable_indexed(
              *candidate, unresolved_first, unresolved_blocks,
              source_actual, &swap_slot, &mapped_blocks)
          && swap_slot == ZIP_SWAP_SLOT_UNMAPPED) {
        const uint64_t buffer_size = total_blocks
                                     * scalpel_state.blocksize;
        uint8_t *trial = (uint8_t *)malloc((size_t)buffer_size);

        check_memory_allocation(trial, __LINE__, __FILE__,
                                "encrypted ZIP adjacent-run trial");
        const uint8_t *baseline = (const uint8_t *)
            blockvector_get_data_pointer((*candidate)->b);

        memcpy(trial, baseline, (size_t)state->archive_size);
        if (buffer_size > state->archive_size) {
          memset(trial + state->archive_size, 0,
                 (size_t)(buffer_size - state->archive_size));
        }
        if (zip_reassembly_apply_source_run(
                trial, baseline, *candidate, unresolved_first,
                unresolved_blocks, source_actual, swap_slot)) {
          ZipLayout trial_layout;
          uint64_t trial_failure = state->failure_offset;
          uint64_t trial_entry = state->failure_entry;
          bool trial_content_valid = false;

          memset(&trial_layout, 0, sizeof(trial_layout));
          adjacent_run_applied = zip_find_layout(
              trial, state->archive_size, scalpel_state.blocksize,
              &trial_layout, &trial_failure, &trial_entry,
              &trial_content_valid)
              && trial_content_valid && trial_layout.encrypted
              && !trial_layout.displaced_structure
              && zip_layout_matches_state(&trial_layout, state);
          zip_layout_clear(&trial_layout);
          if (adjacent_run_applied) {
            zip_reassembly_commit_source_run(
                *candidate, unresolved_first, unresolved_blocks,
                source_actual, swap_slot);
            blockvector_set_data_length((*candidate)->b,
                                        state->archive_size);
          }
        }
        free(trial);
      }
      zip_mapped_block_index_clear(&mapped_blocks);
    }

    if (scalpel_state.mode_verbose && adjacent_run_applied) {
      lock_fprintf(stdout,
                   "ZIP encrypted adjacent run retained as PROMISING: "
                   "destination=%" PRIu64 " blocks=%" PRIu64 ".\n",
                   unresolved_first, unresolved_blocks);
    }
    zip_free_carve_state((void **)&state);
    if (scalpel_state.write_promising) {
      (*candidate)->flavor = PROMISING;
      write_candidate(candidate, false);
    }
    else {
      destroy_candidate(candidate);
    }
    zip_reassembly_release_memory(&memory_reservation);
    return;
  }

  const uint64_t total_blocks = CEILDIV(state->archive_size,
                                        scalpel_state.blocksize);
  const uint64_t buffer_size = total_blocks * scalpel_state.blocksize;
  uint8_t *baseline = (uint8_t *)malloc((size_t)buffer_size);
  uint8_t *trial = (uint8_t *)malloc((size_t)buffer_size);

  check_memory_allocation(baseline, __LINE__, __FILE__,
                          "ZIP reassembly baseline");
  check_memory_allocation(trial, __LINE__, __FILE__,
                          "ZIP reassembly trial");

  for (;;) {
    memcpy(baseline, blockvector_get_data_pointer((*candidate)->b),
           (size_t)state->archive_size);
    if (buffer_size > state->archive_size) {
      memset(baseline + state->archive_size, 0,
             (size_t)(buffer_size - state->archive_size));
    }
    memcpy(trial, baseline, (size_t)buffer_size);

    uint64_t current_output_progress = 0;
    bool target_still_invalid = false;

    // Recheck the known failing member before walking the complete archive.
    // A failed member proves that the archive cannot yet validate. Once the
    // member is repaired, the full validator identifies the next failure or
    // supplies the final acceptance decision.
    if (!state->structure_pending
        && state->observed_archive_size == state->archive_size
        && state->failure_entry < state->entry_count) {
      const ZipStateEntry *target =
          &state->entries[state->failure_entry];

      if (target->geometry_known && !target->encrypted) {
        uint64_t target_failure = state->failure_offset;

        target_still_invalid = !zip_reassembly_verify_entry(
            baseline, state->archive_size, state, target,
            &target_failure, &current_output_progress);
        if (target_still_invalid) {
          state->failure_offset = target_failure;
        }
      }
    }

    if (!target_still_invalid) {
      ZipLayout current_layout;
      uint64_t current_failure = 4;
      uint64_t current_entry = UINT64_MAX;
      bool current_valid = false;

      memset(&current_layout, 0, sizeof(current_layout));
      const bool current_structure = zip_find_layout(
          baseline, state->archive_size, scalpel_state.blocksize,
          &current_layout,
          &current_failure, &current_entry, &current_valid);

      const bool current_displaced = current_structure
                                     && current_layout.displaced_structure;
      const bool current_matches = current_structure
                                   && zip_layout_matches_state(&current_layout,
                                                               state);

      if (current_matches) {
        state->structure_pending = current_displaced;
      }

      if (current_matches && current_valid && !current_displaced) {
        zip_layout_clear(&current_layout);
        zip_reassembly_publish_complete(candidate, &state, trial, baseline,
                                        state->archive_size,
                                        &memory_reservation);
        return;
      }
      if (current_matches) {
        state->failure_offset = current_failure;
        state->failure_entry = current_entry;
      }
      zip_layout_clear(&current_layout);
      current_output_progress = 0;
    }

    // Central-directory order need not follow physical member order. When the
    // archive-wide decoder cannot identify a failing member, or before an
    // inserted-gap repair, select the earliest member that actually fails.
    if (state->failure_entry >= state->entry_count
        || state->observed_archive_size > state->archive_size) {
      uint64_t earliest_failing_local = UINT64_MAX;

      for (uint64_t index = 0; index < state->entry_count; index++) {
        const ZipStateEntry *state_entry = &state->entries[index];

        if (!state_entry->geometry_known || state_entry->encrypted) {
          continue;
        }

        uint64_t entry_failure = state_entry->data_offset;
        uint64_t entry_output = 0;

        if (!zip_reassembly_verify_entry(
                baseline, state->archive_size, state, state_entry,
                &entry_failure, &entry_output)
            && state_entry->local_offset < earliest_failing_local) {
          earliest_failing_local = state_entry->local_offset;
          state->failure_offset = entry_failure;
          state->failure_entry = index;
        }
      }
    }

    const ZipStateEntry *entry = NULL;

    if (state->failure_entry < state->entry_count
        && state->entries[state->failure_entry].geometry_known) {
      entry = &state->entries[state->failure_entry];
    }
    else {
      bool missing_geometry = false;

      if (state->structure_pending) {
        uint64_t earliest_local = UINT64_MAX;

        for (uint64_t index = 0; index < state->entry_count; index++) {
          if (!state->entries[index].geometry_known
              && state->entries[index].local_offset < earliest_local) {
            earliest_local = state->entries[index].local_offset;
          }
        }
        if (earliest_local != UINT64_MAX) {
          state->failure_offset = earliest_local;
          state->failure_entry = UINT64_MAX;
          missing_geometry = true;
        }
      }
      if (!missing_geometry) {
        for (uint64_t index = 0; index < state->entry_count; index++) {
          if (state->entries[index].geometry_known
              && state->failure_offset >= state->entries[index].data_offset
              && state->failure_offset < state->entries[index].range_end) {
            state->failure_entry = index;
            entry = &state->entries[index];
            break;
          }
        }
      }
    }

    if (entry && !entry->encrypted && !target_still_invalid) {
      uint64_t baseline_failure = state->failure_offset;

      (void)zip_reassembly_verify_entry(
          baseline, state->archive_size, state, entry,
          &baseline_failure, &current_output_progress);
    }

    if (entry && state->observed_archive_size > state->archive_size
        && !state->gap_repair_applied) {
      if (scalpel_state.mode_verbose) {
        lock_fprintf(stdout,
                     "ZIP exact physical-gap repair: method=%u "
                     "local=%" PRIu64 " data=%" PRIu64
                     " end=%" PRIu64 ".\n",
                     entry->method, entry->local_offset,
                     entry->data_offset, entry->range_end);
      }
      const ZipGapRepairResult gap_result =
          zip_reassembly_repair_delayed_gap(
              work, candidate, state, entry, baseline, trial,
              buffer_size, uuidp, uuidc);

      if (gap_result == ZIP_GAP_REPAIR_STOPPED) {
        free(trial);
        free(baseline);
        if (*candidate) {
          deflate_blockvector((*candidate)->b);
        }
        zip_reassembly_release_memory(&memory_reservation);
        zip_free_carve_state((void **)&state);
        return;
      }
      if (gap_result == ZIP_GAP_REPAIR_APPLIED) {
        carve_put_state((*candidate)->carvehashkey, state);
        continue;
      }
    }

    ZipApkDigestInfo apk_digest_info;

    memset(&apk_digest_info, 0, sizeof(apk_digest_info));
    if (state->apk_digest_entry != state->failure_entry) {
      state->apk_digest_entry = state->failure_entry;
      state->apk_digest_fast_active = false;
      state->apk_digest_fast_complete = false;
    }

    const bool apk_digest_eligible = entry
        && entry->method == ZIP_METHOD_DEFLATE
        && !entry->encrypted && !state->structure_pending
        && state->observed_archive_size == state->archive_size;
    const bool apk_digest_identified = apk_digest_eligible
        && !state->apk_digest_fast_complete
        && zip_apk_digest_identify(
               baseline, state->archive_size, state->central_offset,
               state->eocd_offset, &apk_digest_info);

    if (scalpel_state.mode_verbose && apk_digest_eligible
        && !state->apk_digest_fast_complete
        && !state->apk_digest_fast_active) {
      lock_fprintf(stdout,
                   "ZIP APK signed-content probe: entry=%" PRIu64
                   " output=%" PRIu64 " expected=%" PRIu64
                   " signing_block=%" PRIu64 " identified=%d.\n",
                   state->failure_entry, current_output_progress,
                   entry->uncompressed_size,
                   apk_digest_info.signing_block_start,
                   apk_digest_identified);
    }
    if (apk_digest_identified
        && entry->range_end <= apk_digest_info.signing_block_start) {
      if (!state->apk_digest_fast_active) {
        state->apk_digest_fast_active = true;
        state->destination_slot = 0;
        state->run_length = 1;
        state->scan_rank = 0;
        state->broad_scan = false;
        state->broad_wrapped = false;
        state->clone_scan_initialized = false;
        if (!state->gap_repair_applied) {
          state->preferred_run_active = false;
          state->preferred_run_length = 0;
          state->preferred_destination_slot = 0;
        }
        if (scalpel_state.mode_verbose) {
          lock_fprintf(stdout,
                       "ZIP APK signed-content fast scan: entry=%" PRIu64
                       " member_blocks=%" PRIu64 ".\n",
                       state->failure_entry,
                       CEILDIV(entry->range_end, scalpel_state.blocksize)
                           - entry->data_offset / scalpel_state.blocksize);
        }
      }
    }
    else if (state->apk_digest_fast_active
             || (apk_digest_eligible
                 && !state->apk_digest_fast_complete)) {
      state->apk_digest_fast_active = false;
      state->apk_digest_fast_complete = true;
    }

    uint64_t destination_first = state->failure_offset
                                 / scalpel_state.blocksize;
    uint64_t destination_last = total_blocks - 1;
    uint64_t run_last = destination_last;
    bool scan_all_destinations = true;
    bool targeted_scan = false;

    if (entry) {
      const bool directly_verifiable =
          zip_method_directly_verifiable(entry->method);

      destination_first = entry->data_offset / scalpel_state.blocksize;
      destination_last = (entry->range_end - 1)
                         / scalpel_state.blocksize;
      run_last = destination_last;
      // Deflate-family decoders can consume several blocks after damaged
      // input before reporting failure, so begin with a short window ending
      // at the reported block. Shrink and Implode can reach the final CRC with
      // corrupted input, so they scan the whole member. BZIP2 can report
      // damage a few blocks late after a gap has been resolved, so its
      // targeted path begins two blocks earlier. A stored member's CRC
      // identifies only the member, making every member block a destination.
      if (directly_verifiable && entry->method != ZIP_METHOD_STORED
          && entry->method != ZIP_METHOD_SHRINK
          && entry->method != ZIP_METHOD_IMPLODE
          && entry->method != ZIP_METHOD_ZSTD
          && !state->broad_scan
          && state->failure_offset >= entry->data_offset
          && state->failure_offset < entry->range_end) {
        const uint64_t failure_block = state->failure_offset
                                       / scalpel_state.blocksize;
        const uint64_t entry_first = entry->data_offset
                                     / scalpel_state.blocksize;

        if (entry->method == ZIP_METHOD_BZIP2) {
          uint64_t rewind = failure_block - entry_first;

          if (rewind > 2) {
            rewind = 2;
          }
          destination_first = failure_block - rewind;
          destination_last = destination_first;
        }
        else if (entry->method == ZIP_METHOD_DEFLATE
                 || entry->method == ZIP_METHOD_DEFLATE64
                 || entry->method == ZIP_METHOD_LZMA) {
          uint64_t rewind = failure_block - entry_first;

          if (rewind > ZIP_DEFLATE_TARGET_REWIND_BLOCKS) {
            rewind = ZIP_DEFLATE_TARGET_REWIND_BLOCKS;
          }
          destination_first = failure_block - rewind;
          destination_last = failure_block;
        }
        else {
          destination_first = failure_block;
          destination_last = destination_first;
        }
        scan_all_destinations = true;
        targeted_scan = true;
      }
      else if (state->broad_scan
               && state->failure_offset >= entry->data_offset
               && state->failure_offset < entry->range_end) {
        const uint64_t entry_first = entry->data_offset
                                     / scalpel_state.blocksize;
        const uint64_t failure_block = state->failure_offset
                                       / scalpel_state.blocksize;
        const uint64_t near_failure = failure_block > entry_first
                                          ? failure_block - 1
                                          : failure_block;

        if (!state->broad_wrapped) {
          destination_first = near_failure;
        }
        else if (near_failure > entry_first) {
          destination_first = entry_first;
          destination_last = near_failure - 1;
        }
      }
    }
    else {
      destination_first = state->failure_offset
                          / scalpel_state.blocksize;
    }
    if (state->apk_digest_fast_active) {
      destination_first = entry->data_offset / scalpel_state.blocksize;
      destination_last = (entry->range_end - 1)
                         / scalpel_state.blocksize;
      run_last = destination_last;
      scan_all_destinations = true;
      targeted_scan = false;

      // The APK digest is independent of decoder progress. When inflate
      // identifies a damaged region, search that region first and retain the
      // existing exhaustive ZIP search as the fallback.
      if (state->failure_offset >= entry->data_offset
          && state->failure_offset < entry->range_end) {
        const uint64_t entry_first = entry->data_offset
                                     / scalpel_state.blocksize;
        const uint64_t failure_block = state->failure_offset
                                       / scalpel_state.blocksize;
        uint64_t rewind = failure_block - entry_first;

        if (rewind > ZIP_DEFLATE_TARGET_REWIND_BLOCKS) {
          rewind = ZIP_DEFLATE_TARGET_REWIND_BLOCKS;
        }
        destination_first = failure_block - rewind;
        destination_last = failure_block;
        targeted_scan = true;
      }
    }
    if (state->had_physical_gap && state->physical_gap_slot > 0
        && state->physical_gap_slot < total_blocks
        && !state->broad_scan && !state->structure_retry_active
        && !state->apk_digest_fast_active) {
      destination_first = state->physical_gap_slot;
      destination_last = state->physical_gap_slot;
      scan_all_destinations = false;
      targeted_scan = true;
    }
    if (state->structure_retry_active) {
      destination_first = state->structure_retry_destination;
      destination_last = state->structure_retry_destination;
      run_last = state->structure_retry_destination;
      scan_all_destinations = false;
      targeted_scan = true;
    }
    if (destination_first >= total_blocks) {
      destination_first = 1;
      destination_last = total_blocks - 1;
      run_last = destination_last;
      scan_all_destinations = true;
    }
    if (destination_first == 0) {
      destination_first = 1;
    }
    if (destination_last >= total_blocks) {
      destination_last = total_blocks - 1;
    }
    if (run_last >= total_blocks) {
      run_last = total_blocks - 1;
    }
    if (state->preferred_run_active
        && !state->structure_retry_active
        && state->preferred_destination_slot > 0
        && state->preferred_destination_slot <= destination_last
        && (!entry
            || (state->preferred_destination_slot
                    >= entry->data_offset / scalpel_state.blocksize
                && state->preferred_destination_slot
                    <= (entry->range_end - 1)
                       / scalpel_state.blocksize))
        && state->preferred_run_length
               <= total_blocks - state->preferred_destination_slot) {
      destination_first = state->preferred_destination_slot;
      destination_last = state->preferred_destination_slot;
      run_last = total_blocks - 1;
      state->destination_slot = state->preferred_destination_slot;
      state->run_length = state->preferred_run_length;
      scan_all_destinations = false;
    }
    if (destination_first > destination_last
        || destination_first > run_last) {
      goto zip_reassembly_exhausted;
    }
    const bool reverse_targeted_destinations =
        targeted_scan && scan_all_destinations
        && destination_first < destination_last;

    const uint64_t share_limit =
        zip_reassembly_helper_limit(state->archive_size);

    if ((*candidate)->clone && !state->clone_scan_initialized) {
      uint64_t maximum_run = total_blocks;

      if (state->apk_digest_fast_active) {
        state->run_length = state->preferred_run_active
            ? state->preferred_run_length : 1;
      }
      else if (maximum_run > 1) {
        maximum_run--;
        if (maximum_run > ZIP_HELPER_INITIAL_RUN_LIMIT) {
          maximum_run = ZIP_HELPER_INITIAL_RUN_LIMIT;
        }
        // The primary covers one-block substitutions. Helpers begin with two
        // blocks and at independently selected destinations, then advance
        // normally. This distributes both dimensions of the exact search.
        state->run_length = maximum_run > 1 ? 2 : 1;
      }
      if (scan_all_destinations) {
        const uint64_t helper_index = (uint64_t)state->scan_shares;
        const uint64_t ranked_destination =
            zip_reassembly_ranked_destination(
                *candidate, destination_first, destination_last,
                state->run_length, helper_index);

        state->destination_slot = ranked_destination == UINT64_MAX
            ? destination_first : ranked_destination;
        state->clone_destination_rank = ranked_destination == UINT64_MAX
            ? UINT64_MAX : helper_index;
        state->clone_destination_stride = share_limit + 1;
      }
      else {
        state->destination_slot = destination_first;
        state->clone_destination_rank = UINT64_MAX;
        state->clone_destination_stride = 1;
      }
      state->scan_rank = 0;
      state->clone_scan_initialized = true;
      if (scalpel_state.mode_verbose) {
        lock_fprintf(stdout,
                     "ZIP helper scan: destination=%" PRIu64
                     " stride=%" PRIu64 " run=%" PRIu64 ".\n",
                     state->destination_slot,
                     state->clone_destination_stride,
                     state->run_length);
      }
      carve_put_state((*candidate)->carvehashkey, state);
    }

    if (state->run_length == 0) {
      state->run_length = 1;
    }
    if (state->destination_slot < destination_first
        || state->destination_slot > destination_last) {
      if (reverse_targeted_destinations && !(*candidate)->clone) {
        state->destination_slot = destination_last;
      }
      else {
        state->destination_slot = scan_all_destinations
            ? zip_reassembly_first_destination(
                  *candidate, destination_first, destination_last)
            : destination_first;
      }
    }
    if (!scan_all_destinations) {
      state->destination_slot = destination_first;
    }

    const uint64_t maximum_run = run_last
                                 - state->destination_slot + 1;

    if (state->run_length > maximum_run) {
      goto zip_reassembly_advance_search;
    }

    const uint64_t run_bytes = state->run_length
                               * scalpel_state.blocksize;
    const uint64_t destination_byte = state->destination_slot
                                      * scalpel_state.blocksize;
    const uint64_t image_blocks = CEILDIV(
        filemirror_filesize(scalpel_state.filemirror),
        scalpel_state.blocksize);
    const int64_t header_actual =
        blockvector_get_actual_blocknumber((*candidate)->b, 0);
    const uint64_t expected_actual = (uint64_t)header_actual
                                     + state->destination_slot;
    const uint64_t maximum_distance = expected_actual
        > image_blocks - expected_actual - 1
            ? expected_actual : image_blocks - expected_actual - 1;
    const uint64_t scan_limit = maximum_distance * 2 + 1;
    ZipNormalScanState *normal_scan = zip_normal_scan_prepare(state,
        zip_normal_scan_signature(*candidate, state, baseline,
                                  current_output_progress, run_last),
        image_blocks);
    int64_t best_source = -1;
    int64_t best_swap_slot = ZIP_SWAP_SLOT_UNMAPPED;
    uint64_t best_run_length = state->run_length;
    uint64_t best_failure = state->failure_offset;
    uint64_t best_entry = state->failure_entry;
    uint64_t best_output_progress = current_output_progress;
    bool best_valid = false;
    bool best_entry_valid = false;
    bool best_structure_progress = false;
    bool stored_patch = false;
    uint64_t stored_patch_start = 0;
    uint64_t stored_patch_length = 0;
    uint64_t stored_suffix_length = 0;
    uint32_t stored_prefix_crc = 0;
    uint32_t stored_suffix_crc = 0;
    ZipDeflatePrefix deflate_prefix;
    ZipApkDigestContext apk_digest_context;

    memset(&deflate_prefix, 0, sizeof(deflate_prefix));
    memset(&apk_digest_context, 0, sizeof(apk_digest_context));

    if (state->apk_digest_fast_active
        && !zip_apk_digest_context_initialize(
               baseline, &apk_digest_info, &apk_digest_context)) {
      state->apk_digest_fast_active = false;
      state->apk_digest_fast_complete = true;
      state->destination_slot = 0;
      state->run_length = 1;
      state->scan_rank = 0;
      state->broad_scan = false;
      state->broad_wrapped = false;
      state->clone_scan_initialized = false;
      carve_put_state((*candidate)->carvehashkey, state);
      continue;
    }

    if (entry && entry->method == ZIP_METHOD_STORED
        && entry->compressed_size == entry->uncompressed_size) {
      const uint64_t entry_start = entry->data_offset;
      const uint64_t entry_end = entry_start + entry->compressed_size;
      const uint64_t destination_end = destination_byte + run_bytes;

      stored_patch_start = destination_byte > entry_start
                               ? destination_byte : entry_start;
      const uint64_t stored_patch_end = destination_end < entry_end
                                            ? destination_end : entry_end;
      if (stored_patch_start < stored_patch_end) {
        const uint64_t prefix_length = stored_patch_start - entry_start;

        stored_patch = true;
        stored_patch_length = stored_patch_end - stored_patch_start;
        stored_suffix_length = entry_end - stored_patch_end;
        stored_prefix_crc = zip_crc32(baseline + entry_start,
                                      prefix_length);
        stored_suffix_crc = zip_crc32(baseline + stored_patch_end,
                                      stored_suffix_length);
      }
    }

    if (entry && entry->method == ZIP_METHOD_DEFLATE
        && destination_byte < entry->range_end
        && run_bytes <= UINT64_MAX - destination_byte) {
      const uint64_t destination_end = destination_byte + run_bytes;
      const uint64_t patch_start = destination_byte > entry->data_offset
                                       ? destination_byte
                                       : entry->data_offset;
      const uint64_t patch_end = destination_end < entry->range_end
                                     ? destination_end
                                     : entry->range_end;

      if (patch_start < patch_end) {
        (void)zip_deflate_prefix_initialize(
            baseline, entry, patch_start, patch_end, &deflate_prefix);
        if (deflate_prefix.initialized && scalpel_state.mode_verbose) {
          lock_fprintf(stdout,
                       "ZIP DEFLATE prefix cached: entry=%" PRIu64
                       " destination=%" PRIu64 " prefix=%" PRIu64
                       " patch=%" PRIu64 ".\n",
                       state->failure_entry, state->destination_slot,
                       patch_start - entry->data_offset,
                       patch_end - patch_start);
        }
      }
    }

    ZipMappedBlockIndex mapped_blocks;

    memset(&mapped_blocks, 0, sizeof(mapped_blocks));
    (void)zip_mapped_block_index_initialize(*candidate, &mapped_blocks);

    ZipScanOutcome retained_best;
    (void)zip_normal_scan_select(*candidate, state, &mapped_blocks,
                                 current_output_progress, &retained_best,
                                 &best_swap_slot);
    if (retained_best.source != UINT64_MAX) {
      best_source = (int64_t)retained_best.source;
      best_run_length = retained_best.run_length;
      best_failure = retained_best.failure;
      best_entry = retained_best.entry;
      best_output_progress = retained_best.output;
      best_valid = (retained_best.flags & ZIP_SCAN_VALID) != 0;
      best_entry_valid = (retained_best.flags & ZIP_SCAN_ENTRY_VALID) != 0;
      best_structure_progress = (retained_best.flags & ZIP_SCAN_STRUCTURE) != 0;
    }

    // A physically displaced run is normally absent from the current
    // candidate and has no active reservations. Prefer unmapped and
    // unreserved sources, then stronger file type evidence. Confidence only
    // controls ordering; every source remains eligible.
    //
    bool source_bucket_present[4 * ZIP_SOURCE_CONFIDENCE_TIERS] = {false};
    uint16_t source_bucket_order[4 * ZIP_SOURCE_CONFIDENCE_TIERS] = {0};
    uint16_t source_bucket_count = 0;
    const uint64_t source_confidence_samples = state->run_length
        < ZIP_SOURCE_CONFIDENCE_SAMPLE_BLOCKS
            ? state->run_length : ZIP_SOURCE_CONFIDENCE_SAMPLE_BLOCKS;
    uint64_t plan_signature = expected_actual;

    for (uint64_t actual = 0; actual < image_blocks; actual++) {
      if (state->run_length > image_blocks - actual) {
        continue;
      }

      const uint16_t source_bucket = zip_reassembly_source_bucket(
          *candidate, &mapped_blocks, (int64_t)actual,
          source_confidence_samples);

      source_bucket_present[source_bucket] = true;
      plan_signature = (plan_signature ^ source_bucket)
          * UINT64_C(1099511628211);
    }
    for (uint8_t mapped = 0; mapped <= 1; mapped++) {
      for (uint8_t reserved = 0; reserved <= 1; reserved++) {
        for (int confidence_tier = ZIP_SOURCE_CONFIDENCE_TIERS - 1;
             confidence_tier >= 0;
             confidence_tier--) {
          const uint16_t source_bucket = (uint16_t)(
              mapped * 2 * ZIP_SOURCE_CONFIDENCE_TIERS
              + reserved * ZIP_SOURCE_CONFIDENCE_TIERS
              + confidence_tier);

          if (source_bucket_present[source_bucket]) {
            source_bucket_order[source_bucket_count++] = source_bucket;
          }
        }
      }
    }
    if (source_bucket_count == 0) {
      source_bucket_order[0] = 0;
      source_bucket_count = 1;
    }

    // Confidence controls source ordering, not eligibility. A true displaced
    // run may receive the minimum classification score, so every worker must
    // retain complete source coverage.
    //
    const bool source_bucketed = source_bucket_count > 0 && scan_limit
        <= (uint64_t)INT64_MAX / (source_bucket_count + 1);
    const uint64_t bucket_scan_count = source_bucket_count == 0
        ? 0 : source_bucketed
            ? scan_limit * source_bucket_count : scan_limit;
    // A final unbucketed pass catches sources that moved to an earlier bucket
    // while other candidates changed reservations. Completed trials are skipped.
    const uint64_t scan_count = bucket_scan_count
        + (source_bucketed ? scan_limit : 0);

    if (state->scan_rank < 0
        || (uint64_t)state->scan_rank >= scan_count) {
      state->scan_rank = 0;
    }
    const uint64_t clone_source_start = (*candidate)->clone
        ? XXH3_64bits((*candidate)->clone_binuuid, sizeof(uuid_t))
              % scan_limit
        : 0;
    plan_signature = (plan_signature ^ clone_source_start)
        * UINT64_C(1099511628211);
    plan_signature = (plan_signature ^ ((*candidate)->clone
        ? (uint64_t)state->scan_shares + 1 : 0)) * UINT64_C(1099511628211);
    if (normal_scan->plan_signature != plan_signature) {
      normal_scan->plan_signature = plan_signature;
      state->scan_rank = 0;
    }
    bool anchored_repair_solved = false;
    bool pending_first = normal_scan->pending_source != UINT64_MAX;

    for (uint64_t rank = (uint64_t)state->scan_rank;
         pending_first || rank < scan_count;
         zip_normal_scan_complete_source(normal_scan),
         pending_first ? (pending_first = false) : (rank++, false)) {
      if ((rank & UINT64_C(0xff)) == 0) {
        if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
          zip_mapped_block_index_clear(&mapped_blocks);
          zip_deflate_prefix_clear(&deflate_prefix);
          zip_apk_digest_context_clear(&apk_digest_context);
          free(trial);
          free(baseline);
          zip_reassembly_release_memory(&memory_reservation);
          zip_free_carve_state((void **)&state);
          return;
        }
        if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                 memory_order_acquire)) {
          state->scan_rank = (int64_t)rank;
          carve_put_state((*candidate)->carvehashkey, state);
          if (reassembly_time_to_checkpoint(work->id, *candidate,
                                            uuidp, uuidc)) {
            zip_mapped_block_index_clear(&mapped_blocks);
            zip_deflate_prefix_clear(&deflate_prefix);
            zip_apk_digest_context_clear(&apk_digest_context);
            free(trial);
            free(baseline);
            deflate_blockvector((*candidate)->b);
            zip_reassembly_release_memory(&memory_reservation);
            zip_free_carve_state((void **)&state);
            return;
          }
        }
      }

      const bool reconcile = source_bucketed && rank >= bucket_scan_count;
      uint64_t source_phase = source_bucketed && !reconcile
          ? rank / scan_limit : 0;

      // Helpers retain complete source coverage, but rotate the bucket order
      // so idle threads immediately explore different evidence classes.
      if (source_bucketed && !reconcile && (*candidate)->clone) {
        const uint64_t phase_offset =
            ((uint64_t)state->scan_shares + 1) % source_bucket_count;

        source_phase = (source_phase + phase_offset)
                       % source_bucket_count;
      }
      uint64_t source_rank = source_bucketed
          ? rank % scan_limit : rank;

      // Every helper covers the complete source space, but clone UUIDs
      // distribute their starting points. This reduces duplicate scans while
      // preserving complete coverage if only one helper survives.
      if ((*candidate)->clone) {
        source_rank = (source_rank + clone_source_start) % scan_limit;
      }
      uint64_t source_block = expected_actual;

      if (pending_first) {
        source_block = normal_scan->pending_source;
      }
      else if (source_rank > 0) {
        const uint64_t distance = (source_rank + 1) / 2;

        if ((source_rank & UINT64_C(1)) != 0) {
          if (distance >= image_blocks - expected_actual) {
            continue;
          }
          source_block = expected_actual + distance;
        }
        else {
          if (distance > expected_actual) {
            continue;
          }
          source_block = expected_actual - distance;
        }
      }

      const int64_t source_actual = (int64_t)source_block;

      if (roaring64_bitmap_contains(normal_scan->completed, source_block)) {
        continue;
      }
      if (source_bucketed && !reconcile && !pending_first) {
        if (state->run_length > image_blocks - source_block) {
          continue;
        }

        const uint16_t source_bucket = zip_reassembly_source_bucket(
            *candidate, &mapped_blocks, source_actual,
            source_confidence_samples);

        if (source_bucket != source_bucket_order[source_phase]) {
          continue;
        }
      }
      normal_scan->pending_source = source_block;
      state->scan_rank = (int64_t)rank;

      // Share immediately before expensive source validation. The prior
      // helper has time to leave the promising queue while this thread probes
      // a source, allowing subsequent probes to fan out across idle workers.
      //
      if (state->scan_shares < share_limit && !(*candidate)->clone) {
        state->scan_rank = (int64_t)rank;
        carve_put_state((*candidate)->carvehashkey, state);
        const int shares = reassembly_share_work_count(work->id,
                                                       *candidate);

        if (shares > 0) {
          const uint64_t remaining = share_limit - state->scan_shares;
          const uint64_t accepted = (uint64_t)shares < remaining
                                        ? (uint64_t)shares : remaining;

          state->scan_shares += (uint32_t)accepted;
          carve_put_state((*candidate)->carvehashkey, state);
        }
      }

      if (state->run_length == 1
          && !state->apk_digest_fast_active) {
        const uint64_t tail_length = total_blocks
                                     - state->destination_slot;
        int64_t tail_swap_slot = ZIP_SWAP_SLOT_UNMAPPED;
        const bool tail_viable = tail_length > 1
            && zip_reassembly_source_run_viable_indexed(
                   *candidate, state->destination_slot, tail_length,
                   source_actual, &tail_swap_slot, &mapped_blocks);

        if (tail_viable) {
          uint32_t source_central_signature = 0;
          uint32_t source_eocd_signature = 0;
          const bool source_signatures =
              state->central_offset >= destination_byte
              && state->eocd_offset >= destination_byte
              && zip_reassembly_source_u32(
                     source_actual,
                     state->central_offset - destination_byte,
                     &source_central_signature)
              && source_central_signature == ZIP_CENTRAL_HEADER_SIGNATURE
              && zip_reassembly_source_u32(
                     source_actual,
                     state->eocd_offset - destination_byte,
                     &source_eocd_signature)
              && source_eocd_signature == ZIP_EOCD_SIGNATURE;

          if (!source_signatures) {
            goto zip_reassembly_skip_tail_trial;
          }
          memcpy(trial, baseline, (size_t)buffer_size);
          if (!zip_reassembly_apply_source_run(
                  trial, baseline, *candidate,
                  state->destination_slot, tail_length,
                  source_actual, tail_swap_slot)) {
            goto zip_reassembly_skip_tail_trial;
          }

          ZipLayout tail_layout;
          uint64_t tail_failure = state->failure_offset;
          uint64_t tail_entry = state->failure_entry;
          bool tail_valid = false;

          memset(&tail_layout, 0, sizeof(tail_layout));
          const bool tail_signatures =
              zip_range_available(state->archive_size,
                                  state->central_offset, sizeof(uint32_t))
              && zip_read_le32(trial + state->central_offset)
                     == ZIP_CENTRAL_HEADER_SIGNATURE
              && zip_range_available(state->archive_size,
                                     state->eocd_offset, sizeof(uint32_t))
              && zip_read_le32(trial + state->eocd_offset)
                     == ZIP_EOCD_SIGNATURE;
          const bool tail_structure = tail_signatures
              && zip_find_layout(trial, state->archive_size,
                                 scalpel_state.blocksize, &tail_layout,
                                 &tail_failure, &tail_entry, &tail_valid);
          const bool tail_normalized = tail_structure
                                       && !tail_layout.displaced_structure
                                       && zip_layout_matches_state(
                                              &tail_layout, state);
          uint64_t tail_decoder_failure = state->failure_offset;
          uint64_t tail_output_progress = 0;
          const bool tail_entry_valid = entry && !entry->encrypted
              && zip_reassembly_verify_entry(
                     trial, state->archive_size, state, entry,
                     &tail_decoder_failure, &tail_output_progress);
          if (tail_normalized && !tail_valid && entry
              && entry->method == ZIP_METHOD_STORED) {
            const ZipStoredRepairResult repair_result =
                zip_reassembly_repair_stored_member(
                    work, candidate, state, entry,
                    state->destination_slot, tail_length,
                    source_actual, tail_swap_slot, uuidp, uuidc);

            if (repair_result == ZIP_STORED_REPAIR_STOPPED) {
              zip_layout_clear(&tail_layout);
              zip_mapped_block_index_clear(&mapped_blocks);
              zip_deflate_prefix_clear(&deflate_prefix);
              zip_apk_digest_context_clear(&apk_digest_context);
              free(trial);
              free(baseline);
              if (*candidate) {
                deflate_blockvector((*candidate)->b);
              }
              zip_reassembly_release_memory(&memory_reservation);
              zip_free_carve_state((void **)&state);
              return;
            }
            if (repair_result == ZIP_STORED_REPAIR_SOLVED) {
              anchored_repair_solved = true;
              zip_layout_clear(&tail_layout);
              break;
            }
          }
          const bool tail_progress = tail_normalized
              && (state->structure_pending || tail_entry_valid
                  || tail_output_progress > current_output_progress);
          zip_layout_clear(&tail_layout);
          memcpy(trial, baseline, (size_t)buffer_size);
          if (tail_normalized && (tail_valid || tail_progress)) {
            best_source = source_actual;
            best_swap_slot = tail_swap_slot;
            best_run_length = tail_length;
            best_failure = tail_failure;
            best_entry = tail_entry;
            best_valid = tail_valid;
            best_entry_valid = tail_entry_valid;
            best_output_progress = tail_output_progress;
            best_structure_progress = tail_progress
                                      && !tail_valid
                                      && !tail_entry_valid;
            zip_normal_scan_record(normal_scan, source_block, tail_length,
                best_failure, best_entry, best_output_progress,
                (best_valid ? ZIP_SCAN_VALID : 0)
                | (best_entry_valid ? ZIP_SCAN_ENTRY_VALID : 0)
                | (best_structure_progress ? ZIP_SCAN_STRUCTURE : 0));
            break;
          }
        }
      }

zip_reassembly_skip_tail_trial:
      ;
      bool preferred_stored_crc_match = false;

      if (stored_patch && state->preferred_run_active) {
        uint32_t source_crc = 0;
        const uint64_t source_patch_offset = stored_patch_start
                                             - destination_byte;

        if (!zip_reassembly_source_crc(source_actual,
                                       source_patch_offset,
                                       stored_patch_length,
                                       &source_crc)) {
          continue;
        }
        uint32_t combined_crc = (uint32_t)crc32_combine(
            stored_prefix_crc, source_crc,
            (z_off_t)stored_patch_length);

        combined_crc = (uint32_t)crc32_combine(
            combined_crc, stored_suffix_crc,
            (z_off_t)stored_suffix_length);
        preferred_stored_crc_match = combined_crc == entry->crc32;
        if (!preferred_stored_crc_match) {
          continue;
        }
      }

      int64_t trial_swap_slot = ZIP_SWAP_SLOT_UNMAPPED;
      uint64_t trial_run_length = state->run_length;

      const bool source_viable = zip_reassembly_source_run_viable_indexed(
          *candidate, state->destination_slot, trial_run_length,
          source_actual, &trial_swap_slot, &mapped_blocks);

      if (!source_viable) {
        normal_scan->pending_source = UINT64_MAX;
        continue;
      }

      bool deflate_probe_used = false;
      bool deflate_probe_valid = false;
      uint64_t deflate_probe_failure = state->failure_offset;
      uint64_t deflate_probe_output = 0;

      if (deflate_prefix.initialized
          && trial_swap_slot == ZIP_SWAP_SLOT_UNMAPPED) {
        const uint64_t source_patch_offset =
            deflate_prefix.patch_start - destination_byte;

        deflate_probe_used = zip_deflate_prefix_probe(
            &deflate_prefix, baseline, entry, source_actual,
            source_patch_offset, &deflate_probe_valid,
            &deflate_probe_failure, &deflate_probe_output);

        // A complete signed-APK repair must also restore the failing DEFLATE
        // member. Reject syntactically invalid sources before hashing the
        // affected 1 MiB signing chunk.
        if (state->apk_digest_fast_active && deflate_probe_used
            && !deflate_probe_valid) {
          continue;
        }
      }
      if (state->apk_digest_fast_active) {
        const ZipApkDigestProbeResult apk_result = zip_apk_digest_probe(
            &apk_digest_context, baseline, state->destination_slot,
            trial_run_length, source_actual, trial_swap_slot);

        if (apk_result != ZIP_APK_DIGEST_MATCH) {
          continue;
        }
        if (scalpel_state.mode_verbose) {
          lock_fprintf(stdout,
                       "ZIP APK signed-content match: destination=%" PRIu64
                       " run=%" PRIu64 " source=%" PRId64 ".\n",
                       state->destination_slot, trial_run_length,
                       source_actual);
        }
      }
      bool stored_crc_match = preferred_stored_crc_match
                              && trial_swap_slot
                                     == ZIP_SWAP_SLOT_UNMAPPED;

      if (stored_patch && trial_swap_slot == ZIP_SWAP_SLOT_UNMAPPED
          && !preferred_stored_crc_match) {
        uint32_t source_crc = 0;
        const uint64_t source_patch_offset = stored_patch_start
                                             - destination_byte;

        if (!zip_reassembly_source_crc(source_actual,
                                       source_patch_offset,
                                       stored_patch_length,
                                       &source_crc)) {
          continue;
        }
        uint32_t combined_crc = (uint32_t)crc32_combine(
            stored_prefix_crc, source_crc,
            (z_off_t)stored_patch_length);

        combined_crc = (uint32_t)crc32_combine(
            combined_crc, stored_suffix_crc,
            (z_off_t)stored_suffix_length);
        stored_crc_match = combined_crc == entry->crc32;
        if (!stored_crc_match) {
          continue;
        }
      }

      if (!state->apk_digest_fast_active && deflate_probe_used
          && !deflate_probe_valid
            && deflate_probe_output <= best_output_progress
            && (deflate_probe_output < best_output_progress
                || deflate_probe_failure <= best_failure)) {
        if (deflate_probe_output > current_output_progress
            || (deflate_probe_output == current_output_progress
                && deflate_probe_failure > state->failure_offset)) {
          roaring64_bitmap_add(normal_scan->pruned, source_block);
        }
        continue;
      }

      memcpy(trial, baseline, (size_t)buffer_size);
      if (!zip_reassembly_apply_source_run(
              trial, baseline, *candidate, state->destination_slot,
              trial_run_length, source_actual, trial_swap_slot)) {
        continue;
      }

      uint64_t trial_failure = state->failure_offset;
      uint64_t trial_output_progress = 0;
      bool entry_valid = false;

      if (stored_patch && trial_swap_slot == ZIP_SWAP_SLOT_UNMAPPED) {
        entry_valid = stored_crc_match;
        if (entry_valid) {
          trial_output_progress = entry->uncompressed_size;
        }
        if (!entry_valid) {
          trial_failure = entry->data_offset;
        }
      }
      else if (entry && !entry->encrypted) {
        if (deflate_probe_used) {
          entry_valid = deflate_probe_valid;
          trial_failure = deflate_probe_failure;
          trial_output_progress = deflate_probe_output;
        }
        else {
          entry_valid = zip_reassembly_verify_entry(
              trial, state->archive_size, state, entry,
              &trial_failure, &trial_output_progress);
        }
        if (!entry_valid && zip_method_directly_verifiable(entry->method)
            && state->run_length == 1
            && trial_failure / scalpel_state.blocksize
                   > state->destination_slot) {
          uint64_t extended_run = trial_failure
                                  / scalpel_state.blocksize
                                  - state->destination_slot + 1;

          if (extended_run > run_last - state->destination_slot + 1) {
            extended_run = run_last - state->destination_slot + 1;
          }
          if (extended_run > 1) {
            uint64_t extension_runs[3] = {extended_run, extended_run,
                                          extended_run};
            size_t extension_count = 1;
            bool extension_accepted = false;

            if (extended_run > 2
                && (entry->method == ZIP_METHOD_DEFLATE
                    || entry->method == ZIP_METHOD_DEFLATE64
                    || entry->method == ZIP_METHOD_BZIP2
                    || entry->method == ZIP_METHOD_ZSTD
                    || entry->method == ZIP_METHOD_LZMA)) {
              extension_runs[0] = 2;
              extension_count = 2;
            }
            for (size_t extension_index = 0;
                 extension_index < extension_count; extension_index++) {
              const uint64_t candidate_run =
                  extension_runs[extension_index];
              int64_t extended_swap_slot = ZIP_SWAP_SLOT_UNMAPPED;

              if (!zip_reassembly_source_run_viable_indexed(
                      *candidate, state->destination_slot, candidate_run,
                      source_actual, &extended_swap_slot,
                      &mapped_blocks)) {
                continue;
              }
              memcpy(trial, baseline, (size_t)buffer_size);
              if (!zip_reassembly_apply_source_run(
                      trial, baseline, *candidate,
                      state->destination_slot, candidate_run,
                      source_actual, extended_swap_slot)) {
                continue;
              }

              uint64_t extended_failure = state->failure_offset;
              uint64_t extended_output_progress = 0;
              const bool extended_valid = zip_reassembly_verify_entry(
                  trial, state->archive_size, state, entry,
                  &extended_failure, &extended_output_progress);

              if (extended_valid
                  || (entry->method != ZIP_METHOD_BZIP2
                      && entry->method != ZIP_METHOD_ZSTD
                      && extended_failure >= trial_failure
                      && extended_output_progress
                             >= trial_output_progress
                      && (extended_failure > trial_failure
                          || extended_output_progress
                                 > trial_output_progress))) {
                trial_run_length = candidate_run;
                trial_swap_slot = extended_swap_slot;
                trial_failure = extended_failure;
                trial_output_progress = extended_output_progress;
                entry_valid = extended_valid;
                extension_accepted = true;
                break;
              }
            }
            if (!extension_accepted) {
              memcpy(trial, baseline, (size_t)buffer_size);
              if (!zip_reassembly_apply_source_run(
                      trial, baseline, *candidate,
                      state->destination_slot, trial_run_length,
                      source_actual, trial_swap_slot)) {
                continue;
              }
            }
          }
        }
      }

      bool trial_valid = false;
      uint64_t trial_entry = state->failure_entry;

      if (entry_valid || !entry
          || !zip_method_directly_verifiable(entry->method)) {
        ZipLayout trial_layout;

        memset(&trial_layout, 0, sizeof(trial_layout));
        const bool trial_structure = zip_find_layout(
            trial, state->archive_size, scalpel_state.blocksize,
            &trial_layout,
            &trial_failure, &trial_entry, &trial_valid);

        if (trial_layout.displaced_structure
            || !zip_layout_matches_state(&trial_layout, state)) {
          trial_valid = false;
        }

        zip_layout_clear(&trial_layout);
        if (!trial_structure) {
          trial_valid = false;
        }
      }

      if (trial_valid || entry_valid) {
        best_source = source_actual;
        best_swap_slot = trial_swap_slot;
        best_run_length = trial_run_length;
        best_failure = trial_failure;
        best_entry = trial_entry;
        best_valid = trial_valid;
        best_entry_valid = entry_valid;
      }
      if (trial_valid || entry_valid
          || (entry && (entry->method == ZIP_METHOD_DEFLATE
                        || entry->method == ZIP_METHOD_DEFLATE64
                        || entry->method == ZIP_METHOD_LZMA)
              && (trial_output_progress > current_output_progress
                  || (trial_output_progress == current_output_progress
                      && trial_failure > state->failure_offset)))) {
        zip_normal_scan_record(normal_scan, source_block, trial_run_length,
            trial_failure, trial_entry, trial_output_progress,
            (trial_valid ? ZIP_SCAN_VALID : 0)
            | (entry_valid ? ZIP_SCAN_ENTRY_VALID : 0));
      }
      if (!trial_valid && !entry_valid && entry
          && (entry->method == ZIP_METHOD_DEFLATE
              || entry->method == ZIP_METHOD_DEFLATE64
              || entry->method == ZIP_METHOD_LZMA)
          && (trial_output_progress > best_output_progress
              || (trial_output_progress == best_output_progress
                  && trial_failure > best_failure))) {
        best_source = source_actual;
        best_swap_slot = trial_swap_slot;
        best_run_length = trial_run_length;
        best_failure = trial_failure;
        best_entry = state->failure_entry;
        best_output_progress = trial_output_progress;
        best_valid = false;
        best_entry_valid = false;
        best_structure_progress = false;
      }
      if (best_source >= 0) {
        normal_scan->selected_source = (uint64_t)best_source;
        normal_scan->selected_run = best_run_length;
      }

      if (trial_valid || entry_valid) {
        break;
      }

    }

    bool retry_pruned = false;
    if (!anchored_repair_solved) {
      retry_pruned = zip_normal_scan_select(*candidate, state, &mapped_blocks,
          current_output_progress, &retained_best, &best_swap_slot);
      best_source = retained_best.source == UINT64_MAX
          ? -1 : (int64_t)retained_best.source;
      best_run_length = retained_best.run_length;
      best_failure = retained_best.failure;
      best_entry = retained_best.entry;
      best_output_progress = retained_best.output;
      best_valid = (retained_best.flags & ZIP_SCAN_VALID) != 0;
      best_entry_valid = (retained_best.flags & ZIP_SCAN_ENTRY_VALID) != 0;
      best_structure_progress = (retained_best.flags & ZIP_SCAN_STRUCTURE) != 0;
    }
    zip_mapped_block_index_clear(&mapped_blocks);
    zip_deflate_prefix_clear(&deflate_prefix);
    zip_apk_digest_context_clear(&apk_digest_context);
    state->scan_rank = 0;
    if (retry_pruned) {
      carve_put_state((*candidate)->carvehashkey, state);
      continue;
    }
    if (anchored_repair_solved) {
      zip_normal_scan_clear(state);
      blockvector_set_data_length((*candidate)->b, state->archive_size);
      state->destination_slot = 0;
      state->run_length = 1;
      state->broad_scan = false;
      state->broad_wrapped = false;
      state->scan_shares = 0;
      carve_put_state((*candidate)->carvehashkey, state);
      continue;
    }
    if (best_source >= 0) {
      zip_normal_scan_clear(state);
      const uint64_t committed_destination = state->destination_slot;

      zip_reassembly_commit_source_run(*candidate,
                                       state->destination_slot,
                                       best_run_length,
                                       best_source,
                                       best_swap_slot);
      state->apk_digest_entry = UINT64_MAX;
      state->apk_digest_fast_active = false;
      state->apk_digest_fast_complete = false;
      state->clone_scan_initialized = false;
      bool prefix_normalized = false;
      uint64_t structural_shift = 0;

      if (best_structure_progress && entry) {
        const int64_t expected_tail_actual =
            header_actual + (int64_t)committed_destination;

        if (best_source > expected_tail_actual) {
          structural_shift =
              (uint64_t)(best_source - expected_tail_actual);
          const uint64_t failure_slot = state->failure_offset
                                        / scalpel_state.blocksize;

          if (entry->method != ZIP_METHOD_STORED
              && failure_slot < committed_destination) {
            const uint64_t prefix_run = committed_destination
                                        - failure_slot;
            const int64_t prefix_source =
                header_actual + (int64_t)failure_slot
                + (int64_t)structural_shift;
            int64_t prefix_swap_slot = -1;

            if (zip_reassembly_source_run_viable(
                    *candidate, failure_slot, prefix_run,
                    prefix_source, &prefix_swap_slot)) {
              zip_reassembly_commit_source_run(
                  *candidate, failure_slot, prefix_run,
                  prefix_source, prefix_swap_slot);
              prefix_normalized = true;
            }
          }
        }
      }
      if (best_structure_progress && !prefix_normalized && entry
          && entry->method == ZIP_METHOD_STORED) {
        state->structure_resume_destination = committed_destination + 1;
        state->structure_destination_last = destination_last;
        state->structure_failure_offset = state->failure_offset;
        state->structure_failure_entry = state->failure_entry;
        state->stored_structure_trial = true;
      }
      if (best_structure_progress && entry
          && entry->method != ZIP_METHOD_STORED
          && targeted_scan && !state->structure_retry_active
          && !state->structure_retry_pending) {
        const uint64_t entry_first = entry->data_offset
                                     / scalpel_state.blocksize;

        if (committed_destination > entry_first) {
          state->structure_retry_first_destination = entry_first;
          state->structure_retry_next_destination =
              committed_destination - 1;
          state->structure_failure_offset = state->failure_offset;
          state->structure_failure_entry = state->failure_entry;
          state->structure_retry_pending = true;
        }
      }
      if (best_structure_progress && state->structure_retry_active) {
        state->structure_retry_active = false;
      }
      if (best_structure_progress && !prefix_normalized
          && structural_shift == 0
          && committed_destination > 0
          && entry && entry->method != ZIP_METHOD_STORED) {
        const int64_t left_actual = blockvector_get_actual_blocknumber(
            (*candidate)->b, committed_destination - 1);
        const int64_t right_actual = blockvector_get_actual_blocknumber(
            (*candidate)->b, committed_destination);

        if (left_actual >= 0 && left_actual < INT64_MAX
            && right_actual > left_actual + 1) {
          state->seam_boundary_slot = committed_destination;
          state->seam_left_actual = left_actual;
          state->seam_right_actual = right_actual;
          state->seam_variant = ZIP_SEAM_UNMODIFIED;

          // Structural metadata anchors the recovered tail. Extend that
          // trusted run backward across the seam before trying weaker
          // interpretations of the discontinuity.
          const int64_t alternate_source = right_actual - 1;
          int64_t alternate_swap_slot = -1;

          if (alternate_source >= 0
              && zip_reassembly_source_run_viable(
                     *candidate, committed_destination - 1, 1,
                     alternate_source, &alternate_swap_slot)) {
            zip_reassembly_commit_source_run(
                *candidate, committed_destination - 1, 1,
                alternate_source, alternate_swap_slot);
            state->seam_variant = ZIP_SEAM_LEFT_CONTIGUOUS;
          }
        }
      }
      blockvector_set_data_length((*candidate)->b, state->archive_size);
      state->failure_offset = best_failure;
      state->failure_entry = best_entry;
      state->destination_slot = 0;
      state->preferred_run_length = structural_shift;
      state->preferred_run_active = structural_shift > 0;
      state->preferred_destination_slot =
          state->preferred_run_active
          && structural_shift < total_blocks - committed_destination
              ? committed_destination + structural_shift
              : committed_destination;
      state->run_length = state->preferred_run_active
                              ? state->preferred_run_length : 1;
      state->broad_scan = false;
      state->broad_wrapped = false;
      state->scan_shares = 0;
      if (best_structure_progress) {
        state->structure_pending = false;
      }
      if (best_entry_valid) {
        state->seam_variant = ZIP_SEAM_NONE;
        state->stored_structure_trial = false;
        state->structure_retry_active = false;
        state->structure_retry_pending = false;
      }
      carve_put_state((*candidate)->carvehashkey, state);

      if (best_valid) {
        zip_reassembly_publish_complete(candidate, &state, trial, baseline,
                                        state->archive_size,
                                        &memory_reservation);
        return;
      }
      if (best_entry_valid) {
        continue;
      }
      continue;
    }

zip_reassembly_advance_search:
    zip_normal_scan_clear(state);
    state->scan_rank = 0;
    if (state->preferred_run_active) {
      // The physical shift gives the strongest displaced-run length. If that
      // exact interpretation fails, retain the original one-block search at
      // the same boundary before restoring the gap baseline.
      if (state->preferred_run_length > 1) {
        state->preferred_run_length = 1;
        state->run_length = 1;
        carve_put_state((*candidate)->carvehashkey, state);
        continue;
      }
      state->preferred_run_active = false;
      state->preferred_run_length = 0;
      state->preferred_destination_slot = 0;
      // Evaluate the strongest adjacent-run interpretation for every
      // restorable gap hypothesis before beginning the general two-run scan.
      if (state->gap_repair_applied
          && zip_reassembly_restore_gap_baseline(*candidate, state)) {
        state->apk_digest_entry = UINT64_MAX;
        state->apk_digest_fast_active = false;
        state->apk_digest_fast_complete = false;
        carve_put_state((*candidate)->carvehashkey, state);
        continue;
      }
      state->destination_slot = 0;
      state->run_length = 1;
      carve_put_state((*candidate)->carvehashkey, state);
      continue;
    }
    // The APK digest is an exact oracle for every supported run length. Test
    // those lengths at the current destination before advancing so a
    // two-block repair is not delayed behind the complete one-block search.
    if (state->apk_digest_fast_active && scan_all_destinations
        && state->run_length < ZIP_APK_FAST_RUN_LIMIT
        && state->run_length
               < run_last - state->destination_slot + 1) {
      state->run_length++;
      if ((*candidate)->clone
          && state->clone_destination_rank != UINT64_MAX) {
        const uint64_t ranked_destination =
            zip_reassembly_ranked_destination(
                *candidate, destination_first, destination_last,
                state->run_length, state->clone_destination_rank);

        if (ranked_destination != UINT64_MAX) {
          state->destination_slot = ranked_destination;
        }
      }
      carve_put_state((*candidate)->carvehashkey, state);
      continue;
    }
    if (state->apk_digest_fast_active && scan_all_destinations) {
      state->run_length = 1;
    }
    if (scan_all_destinations) {
      if ((*candidate)->clone) {
        const uint64_t stride = state->clone_destination_stride > 0
            ? state->clone_destination_stride : 1;

        if (state->clone_destination_rank != UINT64_MAX) {
          state->clone_destination_rank =
              stride <= UINT64_MAX - state->clone_destination_rank
                  ? state->clone_destination_rank + stride : UINT64_MAX;
          state->destination_slot = state->clone_destination_rank
                                         == UINT64_MAX
              ? UINT64_MAX
              : zip_reassembly_ranked_destination(
                    *candidate, destination_first, destination_last,
                    state->run_length, state->clone_destination_rank);
        }
        else {
          state->destination_slot =
              state->destination_slot <= destination_last
              && stride <= destination_last - state->destination_slot
                  ? state->destination_slot + stride : UINT64_MAX;
        }
      }
      else if (reverse_targeted_destinations) {
        state->destination_slot =
            state->destination_slot > destination_first
                ? state->destination_slot - 1 : UINT64_MAX;
      }
      else {
        state->destination_slot = zip_reassembly_next_destination(
            *candidate, destination_first, destination_last,
            state->destination_slot);
      }
      if (state->destination_slot == UINT64_MAX
          || state->run_length
                 > run_last - state->destination_slot + 1) {
        state->run_length = state->apk_digest_fast_active
            ? ZIP_APK_FAST_RUN_LIMIT + 1 : state->run_length + 1;
        uint64_t clone_restart = UINT64_MAX;

        if ((*candidate)->clone
            && state->clone_destination_rank != UINT64_MAX
            && !state->apk_digest_fast_active) {
          state->clone_destination_rank = (uint64_t)state->scan_shares;
          clone_restart = zip_reassembly_ranked_destination(
              *candidate, destination_first, destination_last,
              state->run_length, state->clone_destination_rank);
        }
        const bool clone_start_valid = clone_restart != UINT64_MAX;

        state->destination_slot = clone_start_valid
            ? clone_restart
            : reverse_targeted_destinations && !(*candidate)->clone
                ? destination_last
                : zip_reassembly_first_destination(
                      *candidate, destination_first, destination_last);
      }
    }
    else {
      state->run_length++;
      state->destination_slot = destination_first;
    }

    if (state->apk_digest_fast_active
        && state->run_length > ZIP_APK_FAST_RUN_LIMIT) {
      goto zip_reassembly_exhausted;
    }
    if (state->run_length
        <= run_last - state->destination_slot + 1) {
      carve_put_state((*candidate)->carvehashkey, state);
      continue;
    }

zip_reassembly_exhausted:
    zip_normal_scan_clear(state);
    if (state->apk_digest_fast_active) {
      state->apk_digest_fast_active = false;
      state->apk_digest_fast_complete = true;
      state->destination_slot = 0;
      state->run_length = 1;
      state->scan_rank = 0;
      state->broad_scan = false;
      state->broad_wrapped = false;
      state->clone_scan_initialized = false;
      state->preferred_run_active = false;
      state->preferred_run_length = 0;
      state->preferred_destination_slot = 0;
      carve_put_state((*candidate)->carvehashkey, state);
      continue;
    }
    if (state->structure_retry_pending) {
      const uint64_t retry_destination =
          state->structure_retry_next_destination;

      if (retry_destination > state->structure_retry_first_destination) {
        state->structure_retry_next_destination = retry_destination - 1;
      }
      else {
        state->structure_retry_pending = false;
      }
      state->initialized = false;
      if (!zip_reassembly_initialize_candidate(*candidate, state)) {
        free(trial);
        free(baseline);
        zip_free_carve_state((void **)&state);
        destroy_candidate(candidate);
        zip_reassembly_release_memory(&memory_reservation);
        return;
      }
      state->initialized = true;
      state->failure_offset = state->structure_failure_offset;
      state->failure_entry = state->structure_failure_entry;
      state->destination_slot = retry_destination;
      state->run_length = 1;
      state->scan_rank = 0;
      state->broad_scan = false;
      state->broad_wrapped = false;
      state->structure_pending = true;
      state->stored_structure_trial = false;
      state->scan_shares = 0;
      state->preferred_run_active = false;
      state->preferred_run_length = 0;
      state->structure_retry_destination = retry_destination;
      state->structure_retry_active = true;
      carve_put_state((*candidate)->carvehashkey, state);
      continue;
    }
    state->structure_retry_active = false;
    if (targeted_scan) {
      state->broad_scan = true;
      state->broad_wrapped = false;
      state->destination_slot = 0;
      state->run_length = 1;
      state->scan_rank = 0;
      carve_put_state((*candidate)->carvehashkey, state);
      continue;
    }
    if (state->broad_scan && !state->broad_wrapped && entry) {
      const uint64_t entry_first = entry->data_offset
                                   / scalpel_state.blocksize;
      const uint64_t failure_block = state->failure_offset
                                     / scalpel_state.blocksize;
      const uint64_t near_failure = failure_block > entry_first
                                        ? failure_block - 1
                                        : failure_block;

      if (near_failure > entry_first) {
        state->broad_wrapped = true;
        state->destination_slot = 0;
        state->run_length = 1;
        state->scan_rank = 0;
        carve_put_state((*candidate)->carvehashkey, state);
        continue;
      }
    }
    if (state->stored_structure_trial
        && state->structure_resume_destination
               <= state->structure_destination_last) {
      state->initialized = false;
      if (!zip_reassembly_initialize_candidate(*candidate, state)) {
        free(trial);
        free(baseline);
        zip_free_carve_state((void **)&state);
        destroy_candidate(candidate);
        zip_reassembly_release_memory(&memory_reservation);
        return;
      }
      state->initialized = true;
      state->failure_offset = state->structure_failure_offset;
      state->failure_entry = state->structure_failure_entry;
      state->destination_slot = state->structure_resume_destination;
      state->run_length = 1;
      state->scan_rank = 0;
      state->broad_scan = false;
      state->broad_wrapped = false;
      state->structure_pending = true;
      state->stored_structure_trial = false;
      state->seam_variant = ZIP_SEAM_NONE;
      state->scan_shares = 0;
      carve_put_state((*candidate)->carvehashkey, state);
      continue;
    }
    if (state->seam_variant == ZIP_SEAM_LEFT_CONTIGUOUS
        && state->seam_boundary_slot > 0
        && state->seam_boundary_slot < total_blocks) {
      zip_reassembly_commit_source_run(*candidate,
                                       state->seam_boundary_slot - 1, 1,
                                       state->seam_left_actual, -1);
      state->seam_variant = ZIP_SEAM_UNMODIFIED;
      state->destination_slot = 0;
      state->run_length = 1;
      state->scan_rank = 0;
      state->broad_scan = false;
      state->broad_wrapped = false;
      state->scan_shares = 0;
      carve_put_state((*candidate)->carvehashkey, state);
      continue;
    }
    if (state->seam_variant == ZIP_SEAM_UNMODIFIED
        && state->seam_boundary_slot > 0
        && state->seam_boundary_slot < total_blocks) {
      int64_t alternate_swap_slot = -1;

      if (zip_reassembly_source_run_viable(
              *candidate, state->seam_boundary_slot, 1,
              state->seam_left_actual + 1,
              &alternate_swap_slot)) {
        zip_reassembly_commit_source_run(*candidate,
                                         state->seam_boundary_slot, 1,
                                         state->seam_left_actual + 1,
                                         alternate_swap_slot);
        state->seam_variant = ZIP_SEAM_RIGHT_CONTIGUOUS;
        state->destination_slot = 0;
        state->run_length = 1;
        state->scan_rank = 0;
        state->broad_scan = false;
        state->broad_wrapped = false;
        state->scan_shares = 0;
        carve_put_state((*candidate)->carvehashkey, state);
        continue;
      }
      state->seam_variant = ZIP_SEAM_RIGHT_CONTIGUOUS;
    }
    if (state->seam_variant == ZIP_SEAM_RIGHT_CONTIGUOUS
        && state->seam_boundary_slot > 0
        && state->seam_boundary_slot < total_blocks) {
      zip_reassembly_commit_source_run(*candidate,
                                       state->seam_boundary_slot, 1,
                                       state->seam_right_actual, -1);
      state->seam_variant = ZIP_SEAM_NONE;
    }
    if (state->gap_repair_applied) {
      const bool restored = zip_reassembly_restore_gap_baseline(
          *candidate, state);

      if (scalpel_state.mode_verbose) {
        lock_fprintf(stdout,
                     "ZIP physical-gap baseline restore: restored=%d.\n",
                     restored);
      }
      if (restored) {
        carve_put_state((*candidate)->carvehashkey, state);
        continue;
      }
    }
    if (scalpel_state.write_promising) {
      uint64_t validates_to = 3;

      zip_set_partial(state->failure_offset, scalpel_state.blocksize,
                      &validates_to);
      if (validates_to < UINT64_MAX
          && validates_to + 1
                 < blockvector_get_data_length((*candidate)->b)) {
        blockvector_set_data_length((*candidate)->b, validates_to + 1);
        resize_blockvector((*candidate)->b,
                           CEILDIV(validates_to + 1,
                                   scalpel_state.blocksize));
      }
    }
    free(trial);
    free(baseline);
    zip_free_carve_state((void **)&state);
    if (scalpel_state.write_promising) {
      (*candidate)->flavor = PROMISING;
      write_candidate(candidate, false);
    }
    else {
      destroy_candidate(candidate);
    }
    zip_reassembly_release_memory(&memory_reservation);
    return;
  }
}

// Header/footer candidates may carry sequential peekahead beyond the selected
// EOCD. Defer complete ZIP validation to the candidate callback, which can
// exclude those unrelated bytes from the archive view.
//
static inline void zip_file_validate_seed(char *data,
                                          uint64_t length,
                                          bool *validates,
                                          uint64_t *validates_to,
                                          bool *promising,
                                          uint32_t needleidx,
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

  if (!zip_has_archive_header((const uint8_t *)data, length)) {
    return;
  }
  const uint64_t header_length =
      zip_read_le32((const uint8_t *)data) == ZIP_SINGLE_SEGMENT_MARKER
          ? 2 * sizeof(uint32_t) : sizeof(uint32_t);

  *validates_to = header_length - 1;
  *promising = true;
}

// Validate the candidate only through its own footer. Search peekahead remains
// available to header/footer discovery but cannot introduce a later archive
// into this candidate's ZIP parse. For a ZIP containing another ZIP, prefer
// the EOCD whose central-directory geometry is relative to the outer header.
//
static inline void zip_candidate_validate(CarveInfo *candidate,
                                          bool *validates,
                                          uint64_t *validates_to,
                                          bool *promising) {

  if (!candidate || !candidate->b || !validates || !validates_to
      || !promising || candidate->needleidx < 0
      || (uint32_t)candidate->needleidx >= scalpel_state.num_specs) {
    return;
  }

  const uint64_t available = blockvector_get_data_length(candidate->b);
  uint64_t length = blockvector_get_non_peekahead_data_length(candidate->b);

  if (length == 0 || length > available) {
    length = available;
  }

  const int64_t header_block = blockvector_get_actual_blocknumber(
      candidate->b, 0);
  const uint64_t header_in_block = candidate->start
                                   % scalpel_state.blocksize;
  SearchSpec *spec = &scalpel_state.search_specs[candidate->needleidx];

  if (header_block >= 0
      && (uint64_t)header_block
             <= (UINT64_MAX - header_in_block) / scalpel_state.blocksize) {
    const uint64_t header_actual = (uint64_t)header_block
                                   * scalpel_state.blocksize
                                   + header_in_block;
    uint64_t footer_first = 0;
    uint64_t footer_last = spec->offsets.numfooters;

    while (footer_first < footer_last) {
      const uint64_t middle = footer_first
                              + (footer_last - footer_first) / 2;

      if (spec->offsets.footers[middle] <= header_actual) {
        footer_first = middle + 1;
      }
      else {
        footer_last = middle;
      }
    }
    uint64_t fallback_length = length;
    bool fallback_set = false;
    const uint8_t *data = (const uint8_t *)
        blockvector_get_data_pointer(candidate->b);

    for (uint64_t footer_index = footer_first;
         footer_index < spec->offsets.numfooters; footer_index++) {
      const uint64_t footer_apparent = filemirror_apparent_location(
          scalpel_state.filemirror, spec->offsets.footers[footer_index]);
      uint64_t footer_end = 0;

      if (__builtin_add_overflow(
            footer_apparent,
            (uint64_t)spec->offsets.footerlens[footer_index],
            &footer_end)
          || footer_apparent < candidate->start
          || footer_end <= candidate->start) {
        continue;
      }
      const uint64_t candidate_length = footer_end - candidate->start;

      if (candidate_length > available) {
        break;
      }
      if (!fallback_set) {
        fallback_length = candidate_length;
        fallback_set = true;
      }

      ZipLayout footer_layout;

      memset(&footer_layout, 0, sizeof(footer_layout));
      const uint64_t eocd_offset = footer_apparent - candidate->start;
      const bool aligned = zip_parse_eocd(
              data, candidate_length, eocd_offset, &footer_layout)
          && !footer_layout.displaced_structure
          && zip_range_available(candidate_length,
                                 footer_layout.observed_central_offset,
                                 sizeof(uint32_t))
          && zip_read_le32(data + footer_layout.observed_central_offset)
                 == ZIP_CENTRAL_HEADER_SIGNATURE;

      zip_layout_clear(&footer_layout);
      if (aligned) {
        length = candidate_length;
        fallback_set = false;
        break;
      }
    }
    if (fallback_set) {
      length = fallback_length;
    }
  }
  zip_file_validate(blockvector_get_data_pointer(candidate->b), length,
                    validates, validates_to, promising,
                    (uint32_t)candidate->needleidx,
                    scalpel_state.blocksize, candidate->carvehashkey);

  if (*promising && !*validates && scalpel_state.blocksize > 0
      && *validates_to < UINT64_MAX && *validates_to + 1 == length
      && length < available) {
    const uint64_t remainder = length % scalpel_state.blocksize;

    if (remainder != 0) {
      const uint64_t addition = scalpel_state.blocksize - remainder;

      if (length <= UINT64_MAX - addition
          && length + addition <= available) {
        *validates_to = length + addition - 1;
      }
    }
  }
}

// Validate a ZIP or OOXML archive. A complete decision requires consistent
// EOCD, central-directory, local-header, descriptor, size, decompression, and
// CRC evidence. Encrypted members remain promising because their plaintext
// CRC cannot be checked without a key.
//
static inline void zip_file_validate(char *data,
                                     uint64_t length,
                                     bool *validates,
                                     uint64_t *validates_to,
                                     bool *promising,
                                     uint32_t needleidx,
                                     uint32_t blocksize,
                                     void *carvehashkey) {

  (void)needleidx;
  *validates = false;
  *promising = false;
  *validates_to = 0;

  if (!zip_has_archive_header((const uint8_t *)data, length)) {
    return;
  }

  const uint64_t header_length =
      zip_read_le32((const uint8_t *)data) == ZIP_SINGLE_SEGMENT_MARKER
          ? 2 * sizeof(uint32_t) : sizeof(uint32_t);

  *promising = true;
  *validates_to = header_length - 1;

  ZipLayout layout;
  uint64_t failure_offset = header_length;
  uint64_t failure_entry = UINT64_MAX;
  bool content_valid = false;

  memset(&layout, 0, sizeof(layout));
  if (!zip_find_layout((const uint8_t *)data, length, blocksize, &layout,
                       &failure_offset, &failure_entry,
                       &content_valid)) {
    zip_set_partial(failure_offset, blocksize, validates_to);
    return;
  }

  if (layout.encrypted && content_valid && !layout.displaced_structure) {
    ZipCarveState *state = zip_state_from_layout(
        &layout, layout.archive_size, UINT64_MAX, false);

    if (state) {
      carve_put_state(carvehashkey, state);
      zip_free_carve_state((void **)&state);
    }

    uint64_t retained_length = layout.archive_size;

    // ZIP metadata establishes the archive extent, but encrypted member data
    // cannot be authenticated without a key. Keep the terminal physical block
    // available to block-level reassembly while retaining PROMISING status.
    if (blocksize > 0 && retained_length % blocksize != 0) {
      const uint64_t remainder = retained_length % blocksize;
      const uint64_t addition = blocksize - remainder;

      if (retained_length <= UINT64_MAX - addition
          && retained_length + addition <= length) {
        retained_length += addition;
      }
    }
    *validates_to = retained_length - 1;
    zip_layout_clear(&layout);
    return;
  }

  if (!content_valid || layout.displaced_structure || layout.encrypted) {
    ZipCarveState *state = zip_state_from_layout(&layout, failure_offset,
                                                 failure_entry, false);

    if (state) {
      carve_put_state(carvehashkey, state);
      zip_free_carve_state((void **)&state);
    }
    zip_set_partial(failure_offset, blocksize, validates_to);
    zip_layout_clear(&layout);
    return;
  }

  *validates = true;
  *promising = false;
  *validates_to = layout.archive_size - 1;
  zip_layout_clear(&layout);
}

#endif
