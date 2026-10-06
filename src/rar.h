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

// RAR4 and RAR5 validation. RAR headers carry strong checksums and describe the
// lengths of their associated data areas. A complete candidate is accepted only
// after every structural header validates, an end-of-archive header is present,
// and member integrity is established by direct checksums or libarchive.
// Encrypted archives remain PROMISING when a password is required.
//

#ifndef SCALPEL3_RAR_H
#define SCALPEL3_RAR_H

#include "scalpel.h"

#include <archive.h>
#include <archive_entry.h>
#include <locale.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

#define RAR4_MAGIC_SIZE                 UINT64_C(7)
#define RAR5_MAGIC_SIZE                 UINT64_C(8)
#define RAR4_BASE_HEADER_SIZE           UINT64_C(7)
#define RAR5_CRC_SIZE                   UINT64_C(4)
#define RAR_MAX_VINT_SIZE               UINT64_C(10)

#define RAR4_HEADER_MARK                UINT8_C(0x72)
#define RAR4_HEADER_MAIN                UINT8_C(0x73)
#define RAR4_HEADER_FILE                UINT8_C(0x74)
#define RAR4_HEADER_COMMENT             UINT8_C(0x75)
#define RAR4_HEADER_AUTHENTICITY        UINT8_C(0x76)
#define RAR4_HEADER_SUBBLOCK            UINT8_C(0x77)
#define RAR4_HEADER_PROTECT             UINT8_C(0x78)
#define RAR4_HEADER_SIGN                UINT8_C(0x79)
#define RAR4_HEADER_NEWSUB              UINT8_C(0x7a)
#define RAR4_HEADER_END                 UINT8_C(0x7b)

#define RAR4_FLAG_LONG_BLOCK            UINT16_C(0x8000)
#define RAR4_MAIN_FLAG_VOLUME           UINT16_C(0x0001)
#define RAR4_FILE_FLAG_SPLIT_BEFORE     UINT16_C(0x0001)
#define RAR4_FILE_FLAG_SPLIT_AFTER      UINT16_C(0x0002)
#define RAR4_FILE_FLAG_PASSWORD         UINT16_C(0x0004)
#define RAR4_FILE_FLAG_LARGE            UINT16_C(0x0100)
#define RAR4_FILE_FLAG_DIRECTORY_MASK   UINT16_C(0x00e0)
#define RAR4_FILE_FLAG_DIRECTORY        UINT16_C(0x00e0)
#define RAR4_FILE_HEADER_SIZE            UINT64_C(32)
#define RAR4_FILE_METHOD_STORE           UINT8_C(0x30)

#define RAR5_BLOCK_MAIN                 UINT64_C(1)
#define RAR5_BLOCK_FILE                 UINT64_C(2)
#define RAR5_BLOCK_SERVICE              UINT64_C(3)
#define RAR5_BLOCK_ENCRYPTION           UINT64_C(4)
#define RAR5_BLOCK_END                  UINT64_C(5)

#define RAR5_HEADER_FLAG_EXTRA          UINT64_C(0x0001)
#define RAR5_HEADER_FLAG_DATA           UINT64_C(0x0002)
#define RAR5_HEADER_FLAG_SKIP_UNKNOWN   UINT64_C(0x0004)
#define RAR5_HEADER_FLAG_SPLIT_BEFORE   UINT64_C(0x0008)
#define RAR5_HEADER_FLAG_SPLIT_AFTER    UINT64_C(0x0010)
#define RAR5_MAIN_FLAG_VOLUME           UINT64_C(0x0001)
#define RAR5_END_FLAG_NEXT_VOLUME       UINT64_C(0x0001)

#define RAR5_SERVICE_FLAG_MTIME          UINT64_C(0x0002)
#define RAR5_SERVICE_FLAG_CRC32          UINT64_C(0x0004)
#define RAR5_SERVICE_FLAG_DIRECTORY      UINT64_C(0x0001)
#define RAR5_SERVICE_FLAG_UNP_UNKNOWN    UINT64_C(0x0008)
#define RAR5_SERVICE_METHOD_SHIFT        UINT64_C(7)
#define RAR5_SERVICE_METHOD_MASK         UINT64_C(0x7)
#define RAR5_FILE_EXTRA_ENCRYPTION       UINT64_C(0x01)
#define RAR5_FILE_EXTRA_REDIRECTION      UINT64_C(0x05)
#define RAR5_REDIRECTION_UNIX_SYMLINK    UINT64_C(1)
#define RAR5_REDIRECTION_FILE_COPY       UINT64_C(5)
#define RAR5_REDIRECTION_FLAG_DIRECTORY  UINT64_C(0x01)
#define RAR5_QUICK_OPEN_MAX_VINT         UINT64_C(3)
#define RAR5_RECOVERY_SHARD_PREFIX_SIZE  UINT64_C(20)
#define RAR5_MAX_HEADER_SIZE              UINT64_C(0x200000)
#define RAR_REASSEMBLY_POLL_INTERVAL      UINT64_C(256)
#define RAR_SEAM_SAMPLE_BYTES              UINT64_C(256)
#define RAR_CRC_INDEX_BUDGET              UINT64_C(67108864)
#define RAR_COMPRESSED_PROBE_WIDTH_LIMIT   UINT64_C(32)
#define RAR_RANKED_TIE_SOURCE_TRIALS       UINT64_C(1024)
#define RAR_REASSEMBLY_BUFFER_COPIES       UINT64_C(3)
#define RAR_REASSEMBLY_BLOCK_OVERHEAD      UINT64_C(128)
#define RAR_REASSEMBLY_MEMORY_DIVISOR      UINT64_C(4)
#define RAR_REASSEMBLY_FALLBACK_BUDGET     UINT64_C(536870912)
#define RAR_REASSEMBLY_WAIT_NANOSECONDS    10000000L
#define RAR_CARVE_STATE_MAGIC             UINT32_C(0x52415253)
#define RAR_CARVE_STATE_VERSION           UINT32_C(2)
#define RAR_CARVE_STATE_VERSION_LEGACY    UINT32_C(1)
#define RAR_SEARCH_GEOMETRY_INITIALIZED    UINT32_C(0x01)
#define RAR_SEARCH_RANKED_REPAIR_PENDING   UINT32_C(0x02)
#define RAR_SEARCH_RANKED_REPAIR_COMPLETE  UINT32_C(0x04)

typedef enum RarVersion {
  RAR_VERSION_UNKNOWN = 0,
  RAR_VERSION_4 = 4,
  RAR_VERSION_5 = 5
} RarVersion;

typedef enum RarStructureStatus {
  RAR_STRUCTURE_INVALID = 0,
  RAR_STRUCTURE_PARTIAL,
  RAR_STRUCTURE_COMPLETE,
  RAR_STRUCTURE_ENCRYPTED_HEADERS
} RarStructureStatus;

typedef struct RarStructureResult {
  RarVersion version;
  RarStructureStatus status;
  uint64_t archive_size;
  uint64_t complete_prefix_size;
  uint64_t prefix_validates_to;
  uint64_t header_count;
  uint64_t file_count;
  uint64_t latest_file_header_validates_to;
  uint64_t files_before_latest_file_header;
  bool seen_main;
  bool encrypted;
  bool multivolume;
  bool latest_file_header_present;
  bool all_file_data_verified;
  bool auxiliary_data_present;
  bool auxiliary_data_verified;
} RarStructureResult;

typedef struct RarHeaderInfo {
  uint64_t physical_offset;
  uint64_t logical_offset;
  uint64_t header_size;
  uint64_t data_size;
  uint64_t unpacked_size;
  uint64_t type;
  uint64_t flags;
  uint64_t method;
  uint64_t gap_blocks_after;
  uint32_t data_crc;
  bool file;
  bool directory;
  bool stored;
  bool has_data_crc;
  bool end;
} RarHeaderInfo;

typedef struct RarLayout {
  RarVersion version;
  RarHeaderInfo *headers;
  uint64_t header_count;
  uint64_t header_capacity;
  uint64_t archive_size;
  uint64_t physical_size;
  uint64_t gap_blocks;
  bool complete;
  bool implicit_end;
} RarLayout;

typedef struct RarGapRegion {
  uint64_t first_slot;
  uint64_t last_slot;
  uint64_t remove_count;
  uint64_t selection_offset;
} RarGapRegion;

typedef struct RarRemovalChoice {
  uint64_t slot;
  uint64_t confidence_sum;
  int64_t reservations;
} RarRemovalChoice;

typedef struct RarCrcSource {
  uint32_t crc;
  int64_t apparent_start;
} RarCrcSource;

typedef struct RarSourceChoice {
  int64_t apparent_start;
  uint64_t seam_score;
  uint64_t confidence_sum;
  int minimum_confidence;
  int64_t reservations;
} RarSourceChoice;

typedef struct RarDestinationChoice {
  uint64_t slot;
  uint64_t confidence_sum;
  uint64_t zero_blocks;
  uint64_t distance;
  int minimum_confidence;
} RarDestinationChoice;

typedef struct RarMappedBlock {
  int64_t apparent;
  uint64_t slot;
} RarMappedBlock;

typedef struct RarProgressScore {
  uint64_t completed_entries;
  uint64_t output_progress;
  uint64_t consumed;
} RarProgressScore;

typedef enum RarRepairScope {
  RAR_REPAIR_SCOPE_NONE = 0,
  RAR_REPAIR_SCOPE_RANKED,
  RAR_REPAIR_SCOPE_PREPASS,
  RAR_REPAIR_SCOPE_HYPOTHESIS
} RarRepairScope;

// Preserve the original physical candidate before contiguous validation trims
// it to the checksum-protected prefix. Actual block numbers survive blockmap
// changes and are converted back to the current apparent view on reassembly.
//
typedef struct RarCarveState {
  uint32_t magic;
  uint32_t version;
  uint64_t physical_length;
  uint64_t block_count;
  uint64_t archive_size;
  uint64_t physical_blocks;
  uint64_t logical_blocks;
  uint64_t selection_count;
  uint64_t gap_ordinal;
  uint64_t probe_index;
  uint64_t best_completed_entries;
  uint64_t best_output_progress;
  uint64_t best_consumed;
  uint32_t repair_pass;
  uint32_t search_initialized;
  uint32_t selection_initialized;
  uint32_t prepass_complete;
  uint32_t have_best_mapping;
  uint32_t have_compressed_recipe;
  uint32_t resume_active;
  uint32_t resume_scope;
  uint32_t resume_repair_pass;
  uint32_t resume_probe_only;
  uint64_t resume_gap_ordinal;
  uint64_t resume_probe_index;
  uint64_t resume_image_blocks;
  uint64_t resume_member_pass;
  uint64_t resume_header_index;
  uint64_t resume_destination_pass;
  uint64_t resume_chunk_start;
  uint64_t resume_width_order;
  uint64_t resume_destination_index;
  uint64_t resume_source_index;
  uint64_t resume_source_count;
  uint64_t resume_source_hash;
  RarProgressScore resume_best_progress;
  RarProgressScore resume_second_progress;
  int64_t resume_best_source;
  uint32_t resume_have_best;
  uint32_t resume_have_second;
  int64_t actual_blocks[];
} RarCarveState;

typedef struct RarCarveStateV1Header {
  uint32_t magic;
  uint32_t version;
  uint64_t physical_length;
  uint64_t block_count;
} RarCarveStateV1Header;

typedef enum RarRepairResult {
  RAR_REPAIR_NONE = 0,
  RAR_REPAIR_MATCH,
  RAR_REPAIR_PROGRESS,
  RAR_REPAIR_AMBIGUOUS,
  RAR_REPAIR_STOPPED
} RarRepairResult;

typedef enum RarMemoryReservationResult {
  RAR_MEMORY_ACQUIRED = 0,
  RAR_MEMORY_STOPPED,
  RAR_MEMORY_UNAVAILABLE
} RarMemoryReservationResult;

static _Atomic uint64_t rar_reassembly_memory_reserved = 0;
static _Atomic uint64_t rar_reassembly_memory_budget_cached = 0;

static const uint8_t rar4_magic[RAR4_MAGIC_SIZE] = {
    0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00};

static const uint8_t rar5_magic[RAR5_MAGIC_SIZE] = {
    0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00};

static const uint8_t rar5_recovery_magic[4] = {0x7b, 0x52, 0x42, 0x7d};

static const uint64_t rar_crc64_nibble_table[16] = {
    UINT64_C(0x0000000000000000), UINT64_C(0x7d9ba13851336649),
    UINT64_C(0xfb374270a266cc92), UINT64_C(0x86ace348f355aadb),
    UINT64_C(0x64b62bcaebc387a1), UINT64_C(0x192d8af2baf0e1e8),
    UINT64_C(0x9f8169ba49a54b33), UINT64_C(0xe21ac88218962d7a),
    UINT64_C(0xc96c5795d7870f42), UINT64_C(0xb4f7f6ad86b4690b),
    UINT64_C(0x325b15e575e1c3d0), UINT64_C(0x4fc0b4dd24d2a599),
    UINT64_C(0xadda7c5f3c4488e3), UINT64_C(0xd041dd676d77eeaa),
    UINT64_C(0x56ed3e2f9e224471), UINT64_C(0x2b769f17cf112238)};

static inline uint16_t rar_read_le16(const uint8_t *data);
static inline uint32_t rar_read_le32(const uint8_t *data);
static inline uint64_t rar_read_le64(const uint8_t *data);
static inline bool rar_add_u64(uint64_t left, uint64_t right,
                               uint64_t *result);
static inline bool rar_read_vint(const uint8_t *data, uint64_t available,
                                 uint64_t *value, uint64_t *encoded_size);
static inline uint32_t rar_header_crc32(const uint8_t *data,
                                        uint64_t length);
static inline uint64_t rar_recovery_crc64(const uint8_t *data,
                                          uint64_t length);
static inline locale_t rar_get_utf8_locale(void);
static inline bool rar_carve_state_size(uint64_t block_count,
                                        uint64_t selection_count,
                                        uint64_t logical_blocks,
                                        size_t *state_size);
static inline uint64_t *rar_carve_state_selection(RarCarveState *state);
static inline int64_t *rar_carve_state_best_mapping(RarCarveState *state);
static inline int64_t *rar_carve_state_recipe(RarCarveState *state);
static inline bool rar_serialize_carve_state(void **state, FILE *fp,
                                             StateSerialization mode);
static inline void *rar_clone_carve_state(const void *srcstate);
static inline void rar_free_carve_state(void **state);
static inline void rar_print_carve_state(const void *state);
static inline RarCarveState *rar_capture_carve_state(CarveInfo *candidate);
static inline void rar_structure_initialize(RarStructureResult *result);
static inline bool rar_validate_rar4_file_data(
    const uint8_t *data, uint64_t header_offset, uint64_t header_size,
    uint16_t flags, uint64_t data_offset, uint64_t data_size,
    bool data_complete, bool *content_verified);
static inline RarStructureStatus rar_parse_rar4(
    const uint8_t *data, uint64_t length, RarStructureResult *result);
static inline bool rar_validate_rar5_file_extra(
    const uint8_t *data, uint64_t extra_offset, uint64_t extra_size,
    bool *redirection, bool *encrypted);
static inline bool rar_validate_rar5_file_data(
    const uint8_t *data, uint64_t fields_offset, uint64_t fields_length,
    uint64_t extra_offset, uint64_t extra_size, uint64_t data_offset,
    uint64_t data_size, bool data_complete, bool *content_verified,
    bool *encrypted);
static inline bool rar_validate_rar5_quick_open(
    const uint8_t *data, uint64_t service_offset, uint64_t data_offset,
    uint64_t data_size);
static inline bool rar_validate_rar5_recovery_record(
    const uint8_t *data, uint64_t data_offset, uint64_t data_size);
static inline bool rar_validate_rar5_service_data(
    const uint8_t *data, uint64_t service_offset, uint64_t fields_offset,
    uint64_t fields_length, uint64_t data_offset, uint64_t data_size);
static inline RarStructureStatus rar_parse_rar5(
    const uint8_t *data, uint64_t length, RarStructureResult *result);
static inline RarStructureStatus rar_parse_structure(
    const uint8_t *data, uint64_t length, RarStructureResult *result);
static inline bool rar_parse_header(const uint8_t *data, uint64_t length,
                                    uint64_t offset, RarVersion version,
                                    RarHeaderInfo *header);
static inline void rar_layout_clear(RarLayout *layout);
static inline bool rar_discover_layout(ThreadWork *work,
                                       CarveInfo **candidate,
                                       RarCarveState *state,
                                       const uint8_t *data, uint64_t length,
                                       RarLayout *layout,
                                       uuid_string_t uuidp,
                                       uuid_string_t uuidc,
                                       uint64_t *iterations,
                                       bool *stopped);
static inline bool rar_build_gap_regions(const RarLayout *layout,
                                         RarGapRegion **regions,
                                         uint64_t *region_count,
                                         uint64_t *selection_count);
static inline void rar_initialize_gap_selection(
    const RarGapRegion *regions, uint64_t region_count,
    uint64_t *selection);
static inline int rar_compare_removal_choices(const void *left,
                                              const void *right);
static inline bool rar_initialize_ranked_gap_selection(
    const RarGapRegion *regions, uint64_t region_count,
    const int64_t *physical_mapping, uint64_t physical_blocks,
    const CarveInfo *candidate, uint64_t *selection,
    bool *strict_confidence_margin);
static inline bool rar_advance_gap_selection(
    const RarGapRegion *regions, uint64_t region_count,
    uint64_t *selection);
static inline bool rar_build_gap_mapping(
    const int64_t *physical_mapping, uint64_t physical_blocks,
    const uint64_t *selection, uint64_t selection_count,
    int64_t *logical_mapping, uint64_t logical_blocks);
static inline bool rar_reassembly_poll(ThreadWork *work,
                                       CarveInfo **candidate,
                                       RarCarveState *state,
                                       uuid_string_t uuidp,
                                       uuid_string_t uuidc,
                                       uint64_t *iterations);
static inline bool rar_reassembly_stop_requested(ThreadWork *work,
                                                 CarveInfo **candidate,
                                                 RarCarveState *state,
                                                 uuid_string_t uuidp,
                                                 uuid_string_t uuidc);
static inline uint64_t rar_reassembly_memory_budget(void);
static inline bool rar_reassembly_memory_requirement(
    uint64_t candidate_size, uint64_t *required);
static inline RarMemoryReservationResult rar_reassembly_reserve_memory(
    ThreadWork *work, CarveInfo **candidate, uint64_t candidate_size,
    uint64_t *reservation, uuid_string_t uuidp, uuid_string_t uuidc);
static inline void rar_reassembly_release_memory(uint64_t *reservation);
static inline bool rar_materialize_mapping(const int64_t *mapping,
                                           uint64_t blocks,
                                           uint64_t length,
                                           uint8_t *output);
static inline bool rar_mapping_validates(const int64_t *mapping,
                                         uint64_t blocks,
                                         uint64_t length,
                                         uint8_t *trial);
static inline void rar_commit_mapping(CarveInfo *candidate,
                                      const int64_t *mapping,
                                      uint64_t blocks, uint64_t length);
static inline int rar_compare_crc_sources(const void *left,
                                          const void *right);
static inline int rar_compare_source_choices(const void *left,
                                             const void *right);
static inline int rar_compare_source_seam_choices(const void *left,
                                                  const void *right);
static inline int rar_compare_destination_choices(const void *left,
                                                  const void *right);
static inline int rar_compare_mapped_blocks(const void *left,
                                            const void *right);
static inline int rar_compare_progress_scores(
    const RarProgressScore *left, const RarProgressScore *right);
static inline bool rar_progress_has_margin(
    const RarProgressScore *better, const RarProgressScore *other,
    uint64_t minimum_delta);
static inline int64_t rar_find_mapped_block(
    const RarMappedBlock *mapped_blocks, uint64_t block_count,
    int64_t apparent);
static inline bool rar_crc_inverse_for_len(z_off_t length,
                                           uint32_t inverse[32]);
static inline uint32_t rar_crc_apply_inverse(const uint32_t inverse[32],
                                             uint32_t value);
static inline uint64_t rar_histogram_distance(const uint8_t *left,
                                              const uint8_t *right,
                                              uint64_t length);
static inline bool rar_mapping_uses_source(const int64_t *mapping,
                                           uint64_t blocks,
                                           uint64_t destination,
                                           uint64_t width,
                                           int64_t source);
static inline RarRepairResult rar_repair_stored_members(
    ThreadWork *work, CarveInfo **candidate, const RarLayout *layout,
    int64_t *mapping, uint64_t blocks, uint8_t *trial,
    int64_t *solution, uuid_string_t uuidp, uuid_string_t uuidc,
    uint64_t *iterations, RarCarveState *state);
static inline RarRepairResult rar_repair_compressed_member(
    ThreadWork *work, CarveInfo **candidate, const RarLayout *layout,
    int64_t *mapping, uint64_t blocks, uint8_t *trial,
    int64_t *solution, uuid_string_t uuidp, uuid_string_t uuidc,
    uint64_t *iterations, bool probe_only,
    uint64_t maximum_source_trials, RarCarveState *state,
    RarRepairScope scope, uint32_t repair_pass,
    uint64_t gap_ordinal, uint64_t probe_index);
static inline RarRepairResult rar_repair_compressed_progressively(
    ThreadWork *work, CarveInfo **candidate, const RarLayout *layout,
    const int64_t *mapping, uint64_t blocks, uint8_t *trial,
    int64_t *solution, int64_t *recipe, uuid_string_t uuidp,
    uuid_string_t uuidc, uint64_t *iterations, RarCarveState *state,
    bool *have_recipe, uint64_t maximum_source_trials,
    RarRepairScope scope, uint32_t repair_pass);
static inline void rar_reassembly(ThreadWork *work, CarveInfo **candidate,
                                  uuid_string_t uuidp,
                                  uuid_string_t uuidc);
static inline bool rar_libarchive_validate(const uint8_t *data,
                                           uint64_t length,
                                           uint64_t *consumed,
                                           uint64_t *entries,
                                           uint64_t *output_progress,
                                           bool *encrypted,
                                           bool report_error);
static inline void rar_candidate_validate(CarveInfo *candidate,
                                          bool *validates,
                                          uint64_t *validates_to,
                                          bool *promising);
static inline void rar_file_validate(char *data, uint64_t length,
                                     bool *validates,
                                     uint64_t *validates_to,
                                     bool *promising, uint32_t needleidx,
                                     uint32_t blocksize,
                                     void *carvehashkey);

// Read an unsigned little-endian 16-bit integer without alignment assumptions.
//
static inline uint16_t rar_read_le16(const uint8_t *data) {

  return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
}

// Read an unsigned little-endian 32-bit integer without alignment assumptions.
//
static inline uint32_t rar_read_le32(const uint8_t *data) {

  return (uint32_t)data[0] | ((uint32_t)data[1] << 8)
         | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

// Read an unsigned little-endian 64-bit integer without alignment assumptions.
//
static inline uint64_t rar_read_le64(const uint8_t *data) {

  return (uint64_t)rar_read_le32(data)
         | ((uint64_t)rar_read_le32(data + 4) << 32);
}

// Add two archive offsets while rejecting wraparound.
//
static inline bool rar_add_u64(uint64_t left, uint64_t right,
                               uint64_t *result) {

  if (right > UINT64_MAX - left) {
    return false;
  }

  *result = left + right;
  return true;
}

// Decode a RAR5 variable-length integer from a bounded input region.
//
static inline bool rar_read_vint(const uint8_t *data, uint64_t available,
                                 uint64_t *value, uint64_t *encoded_size) {

  uint64_t result = 0;
  uint64_t i;

  for (i = 0; i < available && i < RAR_MAX_VINT_SIZE; i++) {
    uint8_t byte = data[i];

    if (i == RAR_MAX_VINT_SIZE - 1 && (byte & UINT8_C(0xfe)) != 0) {
      return false;
    }

    result |= (uint64_t)(byte & UINT8_C(0x7f)) << (i * 7);
    if ((byte & UINT8_C(0x80)) == 0) {
      *value = result;
      *encoded_size = i + 1;
      return true;
    }
  }

  return false;
}

// Calculate the standard CRC32 used by RAR4 and RAR5 archive headers.
//
static inline uint32_t rar_header_crc32(const uint8_t *data,
                                        uint64_t length) {

  uLong crc = crc32(0L, Z_NULL, 0);

  while (length > 0) {
    uInt chunk = length > UINT_MAX ? UINT_MAX : (uInt)length;
    crc = crc32(crc, data, chunk);
    data += chunk;
    length -= chunk;
  }

  return (uint32_t)crc;
}

// Calculate the reflected CRC-64/XZ used by each RAR5 recovery-record shard.
//
static inline uint64_t rar_recovery_crc64(const uint8_t *data,
                                          uint64_t length) {

  uint64_t crc = UINT64_MAX;

  while (length > 0) {
    crc ^= *data++;
    crc = (crc >> 4) ^ rar_crc64_nibble_table[crc & UINT64_C(0x0f)];
    crc = (crc >> 4) ^ rar_crc64_nibble_table[crc & UINT64_C(0x0f)];
    length--;
  }

  return crc ^ UINT64_MAX;
}

// Return a process-lifetime UTF-8 locale for the current validation thread.
// uselocale() applies it only while libarchive decodes RAR member names.
//
static inline locale_t rar_get_utf8_locale(void) {

  static _Thread_local locale_t utf8_locale = (locale_t)0;
  static _Thread_local bool locale_initialized = false;

  if (!locale_initialized) {
    static const char *locale_names[] = {
        "C.UTF-8", "en_US.UTF-8", "UTF-8", ""};

    for (size_t i = 0; i < sizeof(locale_names) / sizeof(locale_names[0]); i++) {
      utf8_locale = newlocale(LC_CTYPE_MASK, locale_names[i], (locale_t)0);
      if (utf8_locale != (locale_t)0) {
        break;
      }
    }
    locale_initialized = true;
  }

  return utf8_locale;
}

// Calculate the storage required for the original physical mapping and the
// optional reassembly selections and logical mappings.
//
static inline bool rar_carve_state_size(uint64_t block_count,
                                        uint64_t selection_count,
                                        uint64_t logical_blocks,
                                        size_t *state_size) {

  const size_t header_size = offsetof(RarCarveState, actual_blocks);
  uint64_t entries = block_count;

  if (!state_size || block_count == 0
      || selection_count > UINT64_MAX - entries) {
    return false;
  }
  entries += selection_count;
  if (logical_blocks > (UINT64_MAX - entries) / 2) {
    return false;
  }
  entries += logical_blocks * 2;
  if (entries > (SIZE_MAX - header_size) / sizeof(int64_t)) {
    return false;
  }
  *state_size = header_size + (size_t)entries * sizeof(int64_t);
  return true;
}

static inline uint64_t *rar_carve_state_selection(RarCarveState *state) {

  return state ? (uint64_t *)(state->actual_blocks + state->block_count)
               : NULL;
}

static inline int64_t *rar_carve_state_best_mapping(RarCarveState *state) {

  uint64_t *selection = rar_carve_state_selection(state);

  return selection ? (int64_t *)(selection + state->selection_count) : NULL;
}

static inline int64_t *rar_carve_state_recipe(RarCarveState *state) {

  int64_t *best = rar_carve_state_best_mapping(state);

  return best ? best + state->logical_blocks : NULL;
}

// Serialize the original RAR candidate mapping so a checkpoint restore can
// reconstruct the physical archive span that existed before prefix trimming.
//
static inline bool rar_serialize_carve_state(void **state, FILE *fp,
                                             StateSerialization mode) {

  const size_t header_size = offsetof(RarCarveState, actual_blocks);
  RarCarveState **rar_state = (RarCarveState **)state;

  if (!rar_state || !fp) {
    return false;
  }
  if (mode == SERIALIZE) {
    size_t state_size = 0;

    if (!*rar_state || (*rar_state)->magic != RAR_CARVE_STATE_MAGIC
        || (*rar_state)->version != RAR_CARVE_STATE_VERSION
        || !rar_carve_state_size((*rar_state)->block_count,
                                 (*rar_state)->selection_count,
                                 (*rar_state)->logical_blocks, &state_size)
        || fwrite(*rar_state, state_size, 1, fp) != 1) {
      perror("RAR carve state serialization");
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
    return true;
  }

  uint32_t prefix[2] = {0, 0};

  if (fread(prefix, sizeof(prefix), 1, fp) != 1
      || prefix[0] != RAR_CARVE_STATE_MAGIC
      || (prefix[1] != RAR_CARVE_STATE_VERSION
          && prefix[1] != RAR_CARVE_STATE_VERSION_LEGACY)) {
    handle_error(SCALPEL_ERROR_CHECKPOINT, "invalid RAR carve state",
                 __LINE__, __FILE__);
  }

  RarCarveState header;

  memset(&header, 0, sizeof(header));
  header.magic = prefix[0];
  header.version = RAR_CARVE_STATE_VERSION;
  if (prefix[1] == RAR_CARVE_STATE_VERSION_LEGACY) {
    RarCarveStateV1Header legacy;

    memset(&legacy, 0, sizeof(legacy));
    legacy.magic = prefix[0];
    legacy.version = prefix[1];
    if (fread((uint8_t *)&legacy + sizeof(prefix),
              sizeof(legacy) - sizeof(prefix), 1, fp) != 1) {
      handle_error(SCALPEL_ERROR_CHECKPOINT, "invalid legacy RAR state",
                   __LINE__, __FILE__);
    }
    header.physical_length = legacy.physical_length;
    header.block_count = legacy.block_count;
  }
  else if (fread((uint8_t *)&header + sizeof(prefix),
                 header_size - sizeof(prefix), 1, fp) != 1) {
    handle_error(SCALPEL_ERROR_CHECKPOINT, "invalid RAR carve state header",
                 __LINE__, __FILE__);
  }

  size_t state_size = 0;

  if (!rar_carve_state_size(header.block_count, header.selection_count,
                            header.logical_blocks, &state_size)) {
    handle_error(SCALPEL_ERROR_CHECKPOINT, "invalid RAR carve state size",
                 __LINE__, __FILE__);
  }
  *rar_state = (RarCarveState *)malloc(state_size);
  check_memory_allocation(*rar_state, __LINE__, __FILE__, "RarCarveState");
  memcpy(*rar_state, &header, header_size);
  const size_t entries = (state_size - header_size) / sizeof(int64_t);

  if (fread((*rar_state)->actual_blocks, sizeof(int64_t), entries, fp)
      != entries) {
    perror("RAR carve state block mapping deserialization");
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }
  return true;
}

// Deep-copy a variable-length RAR carve state for the global state table.
//
static inline void *rar_clone_carve_state(const void *srcstate) {

  const RarCarveState *source = (const RarCarveState *)srcstate;
  size_t state_size = 0;

  if (!source || source->magic != RAR_CARVE_STATE_MAGIC
      || source->version != RAR_CARVE_STATE_VERSION
      || !rar_carve_state_size(source->block_count, source->selection_count,
                               source->logical_blocks, &state_size)) {
    return NULL;
  }
  RarCarveState *destination = (RarCarveState *)malloc(state_size);

  check_memory_allocation(destination, __LINE__, __FILE__,
                          "RarCarveState clone");
  memcpy(destination, source, state_size);
  return destination;
}

// Release a RAR carve state returned by carve_get_state().
//
static inline void rar_free_carve_state(void **state) {

  if (!state) {
    return;
  }
  free(*state);
  *state = NULL;
}

// Print the compact RAR carve state used by checkpoint diagnostics.
//
static inline void rar_print_carve_state(const void *state) {

  const RarCarveState *rar_state = (const RarCarveState *)state;

  if (!rar_state) {
    fprintf(stdout, "NULL");
    return;
  }
  fprintf(stdout,
          "physical_length=%" PRIu64 " blocks=%" PRIu64
          " repair_pass=%u gap=%" PRIu64 " resume=%u",
          rar_state->physical_length, rar_state->block_count,
          rar_state->repair_pass, rar_state->gap_ordinal,
          rar_state->resume_active);
}

// Capture the current full candidate mapping. This is used during contiguous
// validation and also supports an F2 candidate that reaches reassembly without
// first passing through the contiguous validator.
//
static inline RarCarveState *rar_capture_carve_state(CarveInfo *candidate) {

  if (!candidate || !candidate->b || scalpel_state.blocksize == 0) {
    return NULL;
  }
  RarCarveState *existing = (RarCarveState *)carve_get_state(
      candidate->carvehashkey);

  if (existing) {
    return existing;
  }

  const uint64_t block_count = blockvector_get_num_blocks(candidate->b);
  size_t state_size = 0;

  if (!rar_carve_state_size(block_count, 0, 0, &state_size)
      || block_count > UINT64_MAX / scalpel_state.blocksize) {
    return NULL;
  }

  uint64_t physical_length = blockvector_get_non_peekahead_data_length(
      candidate->b);

  if (candidate->stop >= candidate->start
      && candidate->stop - candidate->start < UINT64_MAX) {
    const uint64_t candidate_length = candidate->stop - candidate->start + 1;

    if (candidate_length > 0
        && candidate_length <= block_count * scalpel_state.blocksize) {
      physical_length = candidate_length;
    }
  }
  if (physical_length == 0) {
    physical_length = blockvector_get_data_length(candidate->b);
  }
  if (physical_length == 0
      || physical_length > block_count * scalpel_state.blocksize) {
    return NULL;
  }

  RarCarveState *state = (RarCarveState *)malloc(state_size);

  check_memory_allocation(state, __LINE__, __FILE__, "RarCarveState");
  memset(state, 0, state_size);
  state->magic = RAR_CARVE_STATE_MAGIC;
  state->version = RAR_CARVE_STATE_VERSION;
  state->physical_length = physical_length;
  state->block_count = block_count;
  for (uint64_t slot = 0; slot < block_count; slot++) {
    state->actual_blocks[slot] = blockvector_get_actual_blocknumber(
        candidate->b, slot);
    if (state->actual_blocks[slot] < 0) {
      rar_free_carve_state((void **)&state);
      return NULL;
    }
  }
  carve_put_state(candidate->carvehashkey, state);
  return state;
}

static inline bool rar_prepare_search_state(
    RarCarveState **state, uint64_t archive_size, uint64_t physical_blocks,
    uint64_t logical_blocks, uint64_t selection_count) {

  if (!state || !*state || archive_size == 0 || physical_blocks == 0
      || logical_blocks == 0) {
    return false;
  }
  if (((*state)->search_initialized
       & RAR_SEARCH_GEOMETRY_INITIALIZED) != 0
      && (*state)->archive_size == archive_size
      && (*state)->physical_blocks == physical_blocks
      && (*state)->logical_blocks == logical_blocks
      && (*state)->selection_count == selection_count) {
    return true;
  }

  size_t state_size = 0;

  if (!rar_carve_state_size((*state)->block_count, selection_count,
                            logical_blocks, &state_size)) {
    return false;
  }
  RarCarveState *expanded = (RarCarveState *)calloc(1, state_size);

  check_memory_allocation(expanded, __LINE__, __FILE__,
                          "RAR reassembly state");
  expanded->magic = RAR_CARVE_STATE_MAGIC;
  expanded->version = RAR_CARVE_STATE_VERSION;
  expanded->physical_length = (*state)->physical_length;
  expanded->block_count = (*state)->block_count;
  expanded->archive_size = archive_size;
  expanded->physical_blocks = physical_blocks;
  expanded->logical_blocks = logical_blocks;
  expanded->selection_count = selection_count;
  expanded->search_initialized = RAR_SEARCH_GEOMETRY_INITIALIZED
                                 | RAR_SEARCH_RANKED_REPAIR_PENDING;
  memcpy(expanded->actual_blocks, (*state)->actual_blocks,
         (size_t)(expanded->block_count * sizeof(int64_t)));
  rar_free_carve_state((void **)state);
  *state = expanded;
  return true;
}

static inline bool rar_store_actual_mapping(const int64_t *mapping,
                                            uint64_t blocks,
                                            int64_t *actual_mapping) {

  if (!mapping || !actual_mapping) {
    return false;
  }
  for (uint64_t slot = 0; slot < blocks; slot++) {
    const int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, mapping[slot]);

    if (actual < 0) {
      return false;
    }
    actual_mapping[slot] = actual;
  }
  return true;
}

static inline bool rar_load_actual_mapping(const int64_t *actual_mapping,
                                           uint64_t blocks,
                                           int64_t *mapping) {

  if (!actual_mapping || !mapping) {
    return false;
  }
  for (uint64_t slot = 0; slot < blocks; slot++) {
    const int64_t actual = actual_mapping[slot];
    const int64_t apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, actual);

    if (actual < 0 || apparent < 0
        || filemirror_actual_block_covered(scalpel_state.filemirror,
                                           actual)) {
      return false;
    }
    mapping[slot] = apparent;
  }
  return true;
}

// Initialize a structural parse result before version-specific processing.
//
static inline void rar_structure_initialize(RarStructureResult *result) {

  memset(result, 0, sizeof(*result));
  result->status = RAR_STRUCTURE_INVALID;
  result->all_file_data_verified = true;
  result->auxiliary_data_verified = true;
}

// Independently verify stored RAR4 member data. libarchive does not reliably
// report checksum failures for every stored-member path.
//
static inline bool rar_validate_rar4_file_data(
    const uint8_t *data, uint64_t header_offset, uint64_t header_size,
    uint16_t flags, uint64_t data_offset, uint64_t data_size,
    bool data_complete, bool *content_verified) {

  uint64_t unpacked_size;
  uint32_t stored_crc;
  bool directory;

  *content_verified = false;

  if (header_size < RAR4_FILE_HEADER_SIZE) {
    return false;
  }

  unpacked_size = rar_read_le32(data + header_offset + 11);
  if ((flags & RAR4_FILE_FLAG_LARGE) != 0) {
    if (header_size < 40) {
      return false;
    }
    unpacked_size |= (uint64_t)rar_read_le32(data + header_offset + 36) << 32;
  }

  directory = (flags & RAR4_FILE_FLAG_DIRECTORY_MASK)
              == RAR4_FILE_FLAG_DIRECTORY;
  if (directory) {
    *content_verified = data_complete && data_size == 0;
    return *content_verified;
  }

  if (data[header_offset + 25] != RAR4_FILE_METHOD_STORE) {
    return true;
  }

  if (unpacked_size != data_size) {
    return false;
  }

  if (!data_complete) {
    return true;
  }

  stored_crc = rar_read_le32(data + header_offset + 16);
  *content_verified = rar_header_crc32(data + data_offset, data_size)
                      == stored_crc;
  return *content_verified;
}

// Parse and checksum every RAR4 archive block. Data areas are bounded here but
// are considered fully verified only after libarchive decompresses them.
//
static inline RarStructureStatus rar_parse_rar4(
    const uint8_t *data, uint64_t length, RarStructureResult *result) {

  uint64_t offset = RAR4_MAGIC_SIZE;
  bool continuous_prefix = true;

  result->version = RAR_VERSION_4;
  result->prefix_validates_to = RAR4_MAGIC_SIZE - 1;

  while (offset < length) {
    uint64_t header_end;
    uint64_t block_end;
    uint64_t data_size = 0;
    uint16_t stored_crc;
    uint16_t flags;
    uint16_t header_size;
    uint8_t type;
    bool data_complete;
    bool file_data_verified;

    if (length - offset < RAR4_BASE_HEADER_SIZE) {
      result->status = result->seen_main ? RAR_STRUCTURE_PARTIAL
                                        : RAR_STRUCTURE_INVALID;
      return result->status;
    }

    stored_crc = rar_read_le16(data + offset);
    type = data[offset + 2];
    flags = rar_read_le16(data + offset + 3);
    header_size = rar_read_le16(data + offset + 5);

    if (type < RAR4_HEADER_MARK || type > RAR4_HEADER_END
        || header_size < RAR4_BASE_HEADER_SIZE
        || !rar_add_u64(offset, header_size, &header_end)) {
      result->status = result->seen_main ? RAR_STRUCTURE_PARTIAL
                                        : RAR_STRUCTURE_INVALID;
      return result->status;
    }

    if (header_end > length) {
      result->status = result->seen_main ? RAR_STRUCTURE_PARTIAL
                                        : RAR_STRUCTURE_INVALID;
      return result->status;
    }

    if ((rar_header_crc32(data + offset + 2, header_size - 2)
         & UINT32_C(0xffff)) != stored_crc) {
      result->status = result->seen_main ? RAR_STRUCTURE_PARTIAL
                                        : RAR_STRUCTURE_INVALID;
      return result->status;
    }

    result->header_count++;

    if ((flags & RAR4_FLAG_LONG_BLOCK) != 0) {
      if (header_size < 11) {
        result->status = result->seen_main ? RAR_STRUCTURE_PARTIAL
                                          : RAR_STRUCTURE_INVALID;
        return result->status;
      }
      data_size = rar_read_le32(data + offset + 7);
    }

    if ((type == RAR4_HEADER_FILE || type == RAR4_HEADER_NEWSUB)
        && (flags & RAR4_FILE_FLAG_LARGE) != 0) {
      if (header_size < 40) {
        result->status = result->seen_main ? RAR_STRUCTURE_PARTIAL
                                          : RAR_STRUCTURE_INVALID;
        return result->status;
      }
      data_size |= (uint64_t)rar_read_le32(data + offset + 32) << 32;
    }

    if (!rar_add_u64(header_end, data_size, &block_end)) {
      result->status = RAR_STRUCTURE_PARTIAL;
      return result->status;
    }
    data_complete = block_end <= length;

    if (continuous_prefix) {
      result->prefix_validates_to = header_end - 1;
      if (data_size != 0) {
        continuous_prefix = false;
      }
    }

    if (type == RAR4_HEADER_MAIN) {
      result->seen_main = true;
      if ((flags & RAR4_MAIN_FLAG_VOLUME) != 0) {
        result->multivolume = true;
      }
    }
    else if (type == RAR4_HEADER_FILE) {
      result->latest_file_header_validates_to = header_end - 1;
      result->files_before_latest_file_header = result->file_count;
      result->latest_file_header_present = true;

      if (!rar_validate_rar4_file_data(
              data, offset, header_size, flags, header_end, data_size,
              data_complete, &file_data_verified)) {
        result->status = result->seen_main ? RAR_STRUCTURE_PARTIAL
                                          : RAR_STRUCTURE_INVALID;
        return result->status;
      }
      if (!file_data_verified) {
        result->all_file_data_verified = false;
      }

      result->file_count++;
      if ((flags & RAR4_FILE_FLAG_PASSWORD) != 0) {
        result->encrypted = true;
      }
      if ((flags & (RAR4_FILE_FLAG_SPLIT_BEFORE
                    | RAR4_FILE_FLAG_SPLIT_AFTER)) != 0) {
        result->multivolume = true;
      }
    }
    else if (type == RAR4_HEADER_END) {
      if (!result->seen_main || data_size != 0) {
        result->status = RAR_STRUCTURE_INVALID;
        return result->status;
      }
      result->archive_size = header_end;
      result->status = RAR_STRUCTURE_COMPLETE;
      return result->status;
    }

    if (!data_complete) {
      result->status = result->seen_main ? RAR_STRUCTURE_PARTIAL
                                        : RAR_STRUCTURE_INVALID;
      return result->status;
    }

    offset = block_end;
    result->complete_prefix_size = offset;
  }

  result->status = result->seen_main ? RAR_STRUCTURE_PARTIAL
                                    : RAR_STRUCTURE_INVALID;
  return result->status;
}

// Validate the boundaries of every RAR5 file extra record and recognize file
// system redirections. The enclosing file-header CRC protects each record.
//
static inline bool rar_validate_rar5_file_extra(
    const uint8_t *data, uint64_t extra_offset, uint64_t extra_size,
    bool *redirection, bool *encrypted) {

  uint64_t extra_end;

  *redirection = false;
  *encrypted = false;
  if (!rar_add_u64(extra_offset, extra_size, &extra_end)) {
    return false;
  }

  while (extra_offset < extra_end) {
    uint64_t record_size;
    uint64_t size_length;
    uint64_t record_end;
    uint64_t record_type;
    uint64_t type_length;

    if (!rar_read_vint(data + extra_offset, extra_end - extra_offset,
                       &record_size, &size_length)
        || record_size == 0) {
      return false;
    }
    extra_offset += size_length;
    if (!rar_add_u64(extra_offset, record_size, &record_end)
        || record_end > extra_end
        || !rar_read_vint(data + extra_offset, record_size, &record_type,
                          &type_length)) {
      return false;
    }
    extra_offset += type_length;

    if (record_type == RAR5_FILE_EXTRA_ENCRYPTION) {
      *encrypted = true;
    }
    else if (record_type == RAR5_FILE_EXTRA_REDIRECTION) {
      uint64_t remaining = record_end - extra_offset;
      uint64_t redirection_type;
      uint64_t redirection_flags;
      uint64_t target_size;
      uint64_t field_length;

      if (*redirection
          || !rar_read_vint(data + extra_offset, remaining,
                            &redirection_type, &field_length)) {
        return false;
      }
      extra_offset += field_length;
      remaining -= field_length;

      if (!rar_read_vint(data + extra_offset, remaining,
                         &redirection_flags, &field_length)) {
        return false;
      }
      extra_offset += field_length;
      remaining -= field_length;

      if (!rar_read_vint(data + extra_offset, remaining, &target_size,
                         &field_length)) {
        return false;
      }
      extra_offset += field_length;
      remaining -= field_length;

      if (redirection_type < RAR5_REDIRECTION_UNIX_SYMLINK
          || redirection_type > RAR5_REDIRECTION_FILE_COPY
          || (redirection_flags & ~RAR5_REDIRECTION_FLAG_DIRECTORY) != 0
          || target_size == 0 || target_size > SIZE_MAX
          || target_size != remaining
          || memchr(data + extra_offset, '\0', (size_t)target_size) != NULL) {
        return false;
      }
      *redirection = true;
    }

    extra_offset = record_end;
  }

  return extra_offset == extra_end;
}

// Parse the common RAR5 file fields and independently verify stored member
// data. Compressed members and redirections are checked by libarchive.
//
static inline bool rar_validate_rar5_file_data(
    const uint8_t *data, uint64_t fields_offset, uint64_t fields_length,
    uint64_t extra_offset, uint64_t extra_size, uint64_t data_offset,
    uint64_t data_size, bool data_complete, bool *content_verified,
    bool *encrypted) {

  uint64_t field_value;
  uint64_t field_length;
  uint64_t file_flags;
  uint64_t unpacked_size;
  uint64_t compression_info;
  uint64_t name_size;
  uint64_t method;
  uint32_t stored_crc = 0;
  bool has_crc;
  bool redirection;

  *content_verified = false;
  *encrypted = false;

  if (!rar_read_vint(data + fields_offset, fields_length, &file_flags,
                     &field_length)) {
    return false;
  }
  fields_offset += field_length;
  fields_length -= field_length;

  if (!rar_read_vint(data + fields_offset, fields_length, &unpacked_size,
                     &field_length)) {
    return false;
  }
  fields_offset += field_length;
  fields_length -= field_length;

  if (!rar_read_vint(data + fields_offset, fields_length, &field_value,
                     &field_length)) {
    return false;
  }
  fields_offset += field_length;
  fields_length -= field_length;

  if ((file_flags & RAR5_SERVICE_FLAG_MTIME) != 0) {
    if (fields_length < 4) {
      return false;
    }
    fields_offset += 4;
    fields_length -= 4;
  }

  has_crc = (file_flags & RAR5_SERVICE_FLAG_CRC32) != 0;
  if (has_crc) {
    if (fields_length < 4) {
      return false;
    }
    stored_crc = rar_read_le32(data + fields_offset);
    fields_offset += 4;
    fields_length -= 4;
  }

  if (!rar_read_vint(data + fields_offset, fields_length, &compression_info,
                     &field_length)) {
    return false;
  }
  fields_offset += field_length;
  fields_length -= field_length;

  if (!rar_read_vint(data + fields_offset, fields_length, &field_value,
                     &field_length)) {
    return false;
  }
  fields_offset += field_length;
  fields_length -= field_length;

  if (!rar_read_vint(data + fields_offset, fields_length, &name_size,
                     &field_length)) {
    return false;
  }
  fields_offset += field_length;
  fields_length -= field_length;

  if (name_size == 0 || name_size != fields_length
      || !rar_validate_rar5_file_extra(data, extra_offset, extra_size,
                                       &redirection, encrypted)) {
    return false;
  }

  if (redirection) {
    *content_verified = data_complete && data_size == 0;
    return *content_verified;
  }

  if ((file_flags & RAR5_SERVICE_FLAG_DIRECTORY) != 0) {
    *content_verified = data_complete && data_size == 0;
    return *content_verified;
  }

  method = (compression_info >> RAR5_SERVICE_METHOD_SHIFT)
           & RAR5_SERVICE_METHOD_MASK;
  if (method != 0) {
    return true;
  }

  if ((file_flags & RAR5_SERVICE_FLAG_UNP_UNKNOWN) == 0
      && unpacked_size != data_size) {
    return false;
  }

  if (!data_complete) {
    return true;
  }

  if (!has_crc) {
    *content_verified = data_size == 0;
    return true;
  }

  *content_verified = rar_header_crc32(data + data_offset, data_size)
                      == stored_crc;
  return *content_verified;
}

// Validate every Quick Open cache structure and confirm that each cached byte
// is an exact copy of the earlier archive data it references.
//
static inline bool rar_validate_rar5_quick_open(
    const uint8_t *data, uint64_t service_offset, uint64_t data_offset,
    uint64_t data_size) {

  uint64_t offset = data_offset;
  uint64_t end;
  uint64_t previous_source = 0;
  bool seen_source = false;

  if (data_size == 0 || !rar_add_u64(data_offset, data_size, &end)) {
    return false;
  }

  while (offset < end) {
    uint64_t structure_size;
    uint64_t size_length;
    uint64_t structure_start;
    uint64_t structure_end;
    uint64_t fields_offset;
    uint64_t fields_remaining;
    uint64_t flags;
    uint64_t source_distance;
    uint64_t cached_size;
    uint64_t field_length;
    uint64_t source_offset;
    uint64_t source_end;
    uint32_t stored_crc;

    if (end - offset < 5) {
      return false;
    }

    stored_crc = rar_read_le32(data + offset);
    if (!rar_read_vint(data + offset + 4, end - offset - 4,
                       &structure_size, &size_length)
        || size_length > RAR5_QUICK_OPEN_MAX_VINT
        || !rar_add_u64(offset, 4 + size_length, &structure_start)
        || !rar_add_u64(structure_start, structure_size, &structure_end)
        || structure_end > end
        || rar_header_crc32(data + offset + 4,
                            size_length + structure_size) != stored_crc) {
      return false;
    }

    fields_offset = structure_start;
    fields_remaining = structure_size;
    if (!rar_read_vint(data + fields_offset, fields_remaining, &flags,
                       &field_length)) {
      return false;
    }
    fields_offset += field_length;
    fields_remaining -= field_length;

    if (!rar_read_vint(data + fields_offset, fields_remaining,
                       &source_distance, &field_length)) {
      return false;
    }
    fields_offset += field_length;
    fields_remaining -= field_length;

    if (!rar_read_vint(data + fields_offset, fields_remaining, &cached_size,
                       &field_length)) {
      return false;
    }
    fields_offset += field_length;
    fields_remaining -= field_length;

    if (flags != 0 || cached_size != fields_remaining
        || source_distance > service_offset
        || cached_size > SIZE_MAX) {
      return false;
    }

    source_offset = service_offset - source_distance;
    if (!rar_add_u64(source_offset, cached_size, &source_end)
        || source_end > service_offset
        || (seen_source && source_offset <= previous_source)
        || memcmp(data + source_offset, data + fields_offset,
                  (size_t)cached_size) != 0) {
      return false;
    }

    previous_source = source_offset;
    seen_source = true;
    offset = structure_end;
  }

  return offset == end && seen_source;
}

// Validate every recovery-record shard using its magic, declared dimensions,
// and CRC-64/XZ. The CRC covers the shard metadata and all parity bytes.
//
static inline bool rar_validate_rar5_recovery_record(
    const uint8_t *data, uint64_t data_offset, uint64_t data_size) {

  uint64_t offset = data_offset;
  uint64_t end;
  uint64_t shard_count = 0;

  if (data_size < RAR5_RECOVERY_SHARD_PREFIX_SIZE
      || !rar_add_u64(data_offset, data_size, &end)) {
    return false;
  }

  while (offset < end) {
    uint64_t stored_crc;
    uint64_t calculated_crc;
    uint64_t shard_end;
    uint32_t shard_size;
    uint32_t header_size;

    if (end - offset < RAR5_RECOVERY_SHARD_PREFIX_SIZE
        || memcmp(data + offset, rar5_recovery_magic,
                  sizeof(rar5_recovery_magic)) != 0) {
      return false;
    }

    stored_crc = rar_read_le64(data + offset + 4);
    shard_size = rar_read_le32(data + offset + 12);
    header_size = rar_read_le32(data + offset + 16);
    if (shard_size < RAR5_RECOVERY_SHARD_PREFIX_SIZE
        || header_size < RAR5_RECOVERY_SHARD_PREFIX_SIZE
        || header_size > shard_size
        || !rar_add_u64(offset, shard_size, &shard_end)
        || shard_end > end) {
      return false;
    }

    calculated_crc = rar_recovery_crc64(data + offset + 12,
                                        shard_size - 12);
    if (calculated_crc != stored_crc) {
      return false;
    }

    shard_count++;
    offset = shard_end;
  }

  return offset == end && shard_count > 0;
}

// Verify a RAR5 service data area using the strongest integrity mechanism the
// service provides. Unknown services must carry a direct data CRC32 to qualify
// for the libarchive fallback.
//
static inline bool rar_validate_rar5_service_data(
    const uint8_t *data, uint64_t service_offset, uint64_t fields_offset,
    uint64_t fields_length, uint64_t data_offset, uint64_t data_size) {

  uint64_t field_value;
  uint64_t field_length;
  uint64_t file_flags;
  uint64_t unpacked_size;
  uint64_t compression_info;
  uint64_t name_size;
  uint64_t name_offset;
  uint64_t method;
  uint32_t stored_crc = 0;
  bool has_crc;

  if (!rar_read_vint(data + fields_offset, fields_length, &file_flags,
                     &field_length)) {
    return false;
  }
  fields_offset += field_length;
  fields_length -= field_length;

  if (!rar_read_vint(data + fields_offset, fields_length, &unpacked_size,
                     &field_length)) {
    return false;
  }
  fields_offset += field_length;
  fields_length -= field_length;

  if (!rar_read_vint(data + fields_offset, fields_length, &field_value,
                     &field_length)) {
    return false;
  }
  fields_offset += field_length;
  fields_length -= field_length;

  if ((file_flags & RAR5_SERVICE_FLAG_MTIME) != 0) {
    if (fields_length < 4) {
      return false;
    }
    fields_offset += 4;
    fields_length -= 4;
  }

  has_crc = (file_flags & RAR5_SERVICE_FLAG_CRC32) != 0;
  if (has_crc) {
    if (fields_length < 4) {
      return false;
    }
    stored_crc = rar_read_le32(data + fields_offset);
    fields_offset += 4;
    fields_length -= 4;
  }

  if (!rar_read_vint(data + fields_offset, fields_length, &compression_info,
                     &field_length)) {
    return false;
  }
  fields_offset += field_length;
  fields_length -= field_length;

  if (!rar_read_vint(data + fields_offset, fields_length, &field_value,
                     &field_length)) {
    return false;
  }
  fields_offset += field_length;
  fields_length -= field_length;

  if (!rar_read_vint(data + fields_offset, fields_length, &name_size,
                     &field_length)) {
    return false;
  }
  fields_offset += field_length;
  fields_length -= field_length;
  name_offset = fields_offset;

  method = (compression_info >> RAR5_SERVICE_METHOD_SHIFT)
           & RAR5_SERVICE_METHOD_MASK;
  if (name_size != fields_length || unpacked_size != data_size || method != 0) {
    return false;
  }

  if (name_size == 2 && memcmp(data + name_offset, "QO", 2) == 0) {
    return rar_validate_rar5_quick_open(data, service_offset, data_offset,
                                        data_size);
  }

  if (name_size == 2 && memcmp(data + name_offset, "RR", 2) == 0) {
    return rar_validate_rar5_recovery_record(data, data_offset, data_size);
  }

  return has_crc
         && rar_header_crc32(data + data_offset, data_size) == stored_crc;
}

// Parse and checksum every RAR5 archive block according to the general block
// layout. Unknown extra records remain valid because their enclosing header CRC
// and declared length provide the required structural boundary.
//
static inline RarStructureStatus rar_parse_rar5(
    const uint8_t *data, uint64_t length, RarStructureResult *result) {

  uint64_t offset = RAR5_MAGIC_SIZE;
  bool continuous_prefix = true;

  result->version = RAR_VERSION_5;
  result->prefix_validates_to = RAR5_MAGIC_SIZE - 1;

  while (offset < length) {
    uint64_t size_field_length;
    uint64_t header_size;
    uint64_t header_start;
    uint64_t header_end;
    uint64_t block_end;
    uint64_t body_offset;
    uint64_t body_remaining;
    uint64_t type;
    uint64_t type_length;
    uint64_t flags;
    uint64_t flags_length;
    uint64_t extra_size = 0;
    uint64_t data_size = 0;
    uint64_t field_value;
    uint64_t field_length;
    uint32_t stored_crc;
    bool data_complete;
    bool known_type;

    if (length - offset < RAR5_CRC_SIZE + 1) {
      result->status = result->seen_main ? RAR_STRUCTURE_PARTIAL
                                        : RAR_STRUCTURE_INVALID;
      return result->status;
    }

    stored_crc = rar_read_le32(data + offset);
    if (!rar_read_vint(data + offset + RAR5_CRC_SIZE,
                       length - offset - RAR5_CRC_SIZE,
                       &header_size, &size_field_length)
        || !rar_add_u64(offset, RAR5_CRC_SIZE + size_field_length,
                        &header_start)
        || !rar_add_u64(header_start, header_size, &header_end)) {
      result->status = result->seen_main ? RAR_STRUCTURE_PARTIAL
                                        : RAR_STRUCTURE_INVALID;
      return result->status;
    }

    if (header_size < 2 || header_end > length) {
      result->status = result->seen_main ? RAR_STRUCTURE_PARTIAL
                                        : RAR_STRUCTURE_INVALID;
      return result->status;
    }

    if (rar_header_crc32(data + offset + RAR5_CRC_SIZE,
                         size_field_length + header_size) != stored_crc) {
      result->status = result->seen_main ? RAR_STRUCTURE_PARTIAL
                                        : RAR_STRUCTURE_INVALID;
      return result->status;
    }

    body_offset = header_start;
    body_remaining = header_size;
    if (!rar_read_vint(data + body_offset, body_remaining, &type,
                       &type_length)) {
      result->status = result->seen_main ? RAR_STRUCTURE_PARTIAL
                                        : RAR_STRUCTURE_INVALID;
      return result->status;
    }
    body_offset += type_length;
    body_remaining -= type_length;

    if (!rar_read_vint(data + body_offset, body_remaining, &flags,
                       &flags_length)) {
      result->status = result->seen_main ? RAR_STRUCTURE_PARTIAL
                                        : RAR_STRUCTURE_INVALID;
      return result->status;
    }
    body_offset += flags_length;
    body_remaining -= flags_length;

    known_type = type >= RAR5_BLOCK_MAIN && type <= RAR5_BLOCK_END;
    if (!known_type && (flags & RAR5_HEADER_FLAG_SKIP_UNKNOWN) == 0) {
      result->status = result->seen_main ? RAR_STRUCTURE_PARTIAL
                                        : RAR_STRUCTURE_INVALID;
      return result->status;
    }

    if ((flags & RAR5_HEADER_FLAG_EXTRA) != 0) {
      if (!rar_read_vint(data + body_offset, body_remaining, &extra_size,
                         &field_length)) {
        result->status = result->seen_main ? RAR_STRUCTURE_PARTIAL
                                          : RAR_STRUCTURE_INVALID;
        return result->status;
      }
      body_offset += field_length;
      body_remaining -= field_length;
    }

    if ((flags & RAR5_HEADER_FLAG_DATA) != 0) {
      if (!rar_read_vint(data + body_offset, body_remaining, &data_size,
                         &field_length)) {
        result->status = result->seen_main ? RAR_STRUCTURE_PARTIAL
                                          : RAR_STRUCTURE_INVALID;
        return result->status;
      }
      body_offset += field_length;
      body_remaining -= field_length;
    }

    if (extra_size > body_remaining
        || !rar_add_u64(header_end, data_size, &block_end)) {
      result->status = result->seen_main ? RAR_STRUCTURE_PARTIAL
                                        : RAR_STRUCTURE_INVALID;
      return result->status;
    }

    data_complete = block_end <= length;

    result->header_count++;

    if (continuous_prefix) {
      result->prefix_validates_to = header_end - 1;
      if (data_size != 0) {
        continuous_prefix = false;
      }
    }

    if ((flags & (RAR5_HEADER_FLAG_SPLIT_BEFORE
                  | RAR5_HEADER_FLAG_SPLIT_AFTER)) != 0) {
      result->multivolume = true;
    }

    if (type == RAR5_BLOCK_MAIN) {
      result->seen_main = true;
      if (body_remaining > extra_size
          && rar_read_vint(data + body_offset,
                           body_remaining - extra_size,
                           &field_value, &field_length)
          && (field_value & RAR5_MAIN_FLAG_VOLUME) != 0) {
        result->multivolume = true;
      }
    }
    else if (type == RAR5_BLOCK_FILE) {
      uint64_t fields_end = header_end - extra_size;
      bool file_data_verified;
      bool file_encrypted;

      result->latest_file_header_validates_to = header_end - 1;
      result->files_before_latest_file_header = result->file_count;
      result->latest_file_header_present = true;

      if (body_offset > fields_end
          || !rar_validate_rar5_file_data(
                 data, body_offset, fields_end - body_offset, fields_end,
                 extra_size, header_end, data_size, data_complete,
                 &file_data_verified, &file_encrypted)) {
        result->status = result->seen_main ? RAR_STRUCTURE_PARTIAL
                                          : RAR_STRUCTURE_INVALID;
        return result->status;
      }
      if (!file_data_verified) {
        result->all_file_data_verified = false;
      }
      if (file_encrypted) {
        result->encrypted = true;
      }
      result->file_count++;
    }
    else if (type == RAR5_BLOCK_SERVICE && data_size > 0) {
      uint64_t fields_end = header_end - extra_size;

      result->auxiliary_data_present = true;
      if (!data_complete || body_offset > fields_end
          || !rar_validate_rar5_service_data(
                 data, offset, body_offset, fields_end - body_offset,
                 header_end, data_size)) {
        result->auxiliary_data_verified = false;
      }
    }
    else if (type == RAR5_BLOCK_ENCRYPTION) {
      result->encrypted = true;
      result->status = RAR_STRUCTURE_ENCRYPTED_HEADERS;
      return result->status;
    }
    else if (type == RAR5_BLOCK_END) {
      if (!result->seen_main || data_size != 0) {
        result->status = RAR_STRUCTURE_INVALID;
        return result->status;
      }
      if (body_remaining > extra_size
          && rar_read_vint(data + body_offset,
                           body_remaining - extra_size,
                           &field_value, &field_length)
          && (field_value & RAR5_END_FLAG_NEXT_VOLUME) != 0) {
        result->multivolume = true;
      }
      result->archive_size = header_end;
      result->status = RAR_STRUCTURE_COMPLETE;
      return result->status;
    }
    else if (!known_type) {
      result->auxiliary_data_present = true;
      if (data_size != 0) {
        result->auxiliary_data_verified = false;
      }
    }

    if (!data_complete) {
      result->status = result->seen_main ? RAR_STRUCTURE_PARTIAL
                                        : RAR_STRUCTURE_INVALID;
      return result->status;
    }

    offset = block_end;
    result->complete_prefix_size = offset;
  }

  result->status = result->seen_main ? RAR_STRUCTURE_PARTIAL
                                    : RAR_STRUCTURE_INVALID;
  return result->status;
}

// Identify the RAR generation and dispatch to its structural parser.
//
static inline RarStructureStatus rar_parse_structure(
    const uint8_t *data, uint64_t length, RarStructureResult *result) {

  rar_structure_initialize(result);

  if (!data) {
    return result->status;
  }

  if (length >= RAR5_MAGIC_SIZE
      && memcmp(data, rar5_magic, RAR5_MAGIC_SIZE) == 0) {
    return rar_parse_rar5(data, length, result);
  }

  if (length >= RAR4_MAGIC_SIZE
      && memcmp(data, rar4_magic, RAR4_MAGIC_SIZE) == 0) {
    return rar_parse_rar4(data, length, result);
  }

  return result->status;
}

// Parse one checksum-protected archive header without requiring its associated
// data area to be present or valid.
//
static inline bool rar_parse_header(const uint8_t *data, uint64_t length,
                                    uint64_t offset, RarVersion version,
                                    RarHeaderInfo *header) {

  if (!data || !header || offset >= length) {
    return false;
  }
  memset(header, 0, sizeof(*header));
  header->physical_offset = offset;

  if (version == RAR_VERSION_4) {
    if (length - offset < RAR4_BASE_HEADER_SIZE) {
      return false;
    }

    const uint16_t stored_crc = rar_read_le16(data + offset);
    const uint16_t flags = rar_read_le16(data + offset + 3);
    const uint16_t header_size = rar_read_le16(data + offset + 5);
    const uint8_t type = data[offset + 2];

    if (type < RAR4_HEADER_MARK || type > RAR4_HEADER_END
        || header_size < RAR4_BASE_HEADER_SIZE
        || header_size > length - offset
        || (rar_header_crc32(data + offset + 2, header_size - 2)
            & UINT32_C(0xffff)) != stored_crc) {
      return false;
    }

    header->header_size = header_size;
    header->type = type;
    header->flags = flags;
    header->end = type == RAR4_HEADER_END;
    if ((flags & RAR4_FLAG_LONG_BLOCK) != 0) {
      if (header_size < 11) {
        return false;
      }
      header->data_size = rar_read_le32(data + offset + 7);
    }
    if ((type == RAR4_HEADER_FILE || type == RAR4_HEADER_NEWSUB)
        && (flags & RAR4_FILE_FLAG_LARGE) != 0) {
      if (header_size < 40) {
        return false;
      }
      header->data_size |= (uint64_t)rar_read_le32(data + offset + 32)
                           << 32;
    }
    if (type == RAR4_HEADER_FILE) {
      if (header_size < RAR4_FILE_HEADER_SIZE) {
        return false;
      }
      header->file = true;
      header->unpacked_size = rar_read_le32(data + offset + 11);
      if ((flags & RAR4_FILE_FLAG_LARGE) != 0) {
        header->unpacked_size |=
            (uint64_t)rar_read_le32(data + offset + 36) << 32;
      }
      header->data_crc = rar_read_le32(data + offset + 16);
      header->has_data_crc = true;
      header->method = data[offset + 25];
      header->directory = (flags & RAR4_FILE_FLAG_DIRECTORY_MASK)
                          == RAR4_FILE_FLAG_DIRECTORY;
      header->stored = !header->directory
                       && header->method == RAR4_FILE_METHOD_STORE
                       && header->unpacked_size == header->data_size;
    }
    return true;
  }

  if (version != RAR_VERSION_5 || length - offset < RAR5_CRC_SIZE + 1) {
    return false;
  }

  uint64_t header_body_size;
  uint64_t size_length;
  uint64_t header_start;
  uint64_t header_end;
  if (!rar_read_vint(data + offset + RAR5_CRC_SIZE,
                     length - offset - RAR5_CRC_SIZE,
                     &header_body_size, &size_length)
      || header_body_size < 2 || header_body_size > RAR5_MAX_HEADER_SIZE
      || !rar_add_u64(offset, RAR5_CRC_SIZE + size_length, &header_start)
      || !rar_add_u64(header_start, header_body_size, &header_end)
      || header_end > length
      || rar_header_crc32(data + offset + RAR5_CRC_SIZE,
                          size_length + header_body_size)
             != rar_read_le32(data + offset)) {
    return false;
  }

  uint64_t cursor = header_start;
  uint64_t remaining = header_body_size;
  uint64_t field_length;
  if (!rar_read_vint(data + cursor, remaining, &header->type,
                     &field_length)) {
    return false;
  }
  cursor += field_length;
  remaining -= field_length;
  if (!rar_read_vint(data + cursor, remaining, &header->flags,
                     &field_length)) {
    return false;
  }
  cursor += field_length;
  remaining -= field_length;

  const bool known_type = header->type >= RAR5_BLOCK_MAIN
                          && header->type <= RAR5_BLOCK_END;
  if (!known_type
      && (header->flags & RAR5_HEADER_FLAG_SKIP_UNKNOWN) == 0) {
    return false;
  }

  uint64_t extra_size = 0;
  if ((header->flags & RAR5_HEADER_FLAG_EXTRA) != 0) {
    if (!rar_read_vint(data + cursor, remaining, &extra_size,
                       &field_length)) {
      return false;
    }
    cursor += field_length;
    remaining -= field_length;
  }
  if ((header->flags & RAR5_HEADER_FLAG_DATA) != 0) {
    if (!rar_read_vint(data + cursor, remaining, &header->data_size,
                       &field_length)) {
      return false;
    }
    cursor += field_length;
    remaining -= field_length;
  }
  if (extra_size > remaining) {
    return false;
  }

  header->header_size = header_end - offset;
  header->end = header->type == RAR5_BLOCK_END;
  if (header->type != RAR5_BLOCK_FILE) {
    return true;
  }

  uint64_t fields_remaining = remaining - extra_size;
  uint64_t file_flags;
  uint64_t field_value;
  uint64_t compression_info;
  uint64_t name_size;

  if (!rar_read_vint(data + cursor, fields_remaining, &file_flags,
                     &field_length)) {
    return false;
  }
  cursor += field_length;
  fields_remaining -= field_length;
  if (!rar_read_vint(data + cursor, fields_remaining,
                     &header->unpacked_size, &field_length)) {
    return false;
  }
  cursor += field_length;
  fields_remaining -= field_length;
  if (!rar_read_vint(data + cursor, fields_remaining, &field_value,
                     &field_length)) {
    return false;
  }
  cursor += field_length;
  fields_remaining -= field_length;

  if ((file_flags & RAR5_SERVICE_FLAG_MTIME) != 0) {
    if (fields_remaining < 4) {
      return false;
    }
    cursor += 4;
    fields_remaining -= 4;
  }
  if ((file_flags & RAR5_SERVICE_FLAG_CRC32) != 0) {
    if (fields_remaining < 4) {
      return false;
    }
    header->data_crc = rar_read_le32(data + cursor);
    header->has_data_crc = true;
    cursor += 4;
    fields_remaining -= 4;
  }
  if (!rar_read_vint(data + cursor, fields_remaining, &compression_info,
                     &field_length)) {
    return false;
  }
  cursor += field_length;
  fields_remaining -= field_length;
  if (!rar_read_vint(data + cursor, fields_remaining, &field_value,
                     &field_length)) {
    return false;
  }
  cursor += field_length;
  fields_remaining -= field_length;
  if (!rar_read_vint(data + cursor, fields_remaining, &name_size,
                     &field_length)) {
    return false;
  }
  cursor += field_length;
  fields_remaining -= field_length;
  if (name_size == 0 || name_size != fields_remaining) {
    return false;
  }

  header->file = true;
  header->method = (compression_info >> RAR5_SERVICE_METHOD_SHIFT)
                   & RAR5_SERVICE_METHOD_MASK;
  header->directory = (file_flags & RAR5_SERVICE_FLAG_DIRECTORY) != 0;
  header->stored = !header->directory && header->method == 0
                   && header->unpacked_size == header->data_size;
  return true;
}

static inline void rar_layout_clear(RarLayout *layout) {

  if (!layout) {
    return;
  }
  free(layout->headers);
  memset(layout, 0, sizeof(*layout));
}

static inline bool rar_reassembly_stop_requested(ThreadWork *work,
                                                 CarveInfo **candidate,
                                                 RarCarveState *state,
                                                 uuid_string_t uuidp,
                                                 uuid_string_t uuidc) {

  if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
    return true;
  }
  if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)
      && candidate && *candidate) {
    if (state) {
      carve_put_state((*candidate)->carvehashkey, state);
    }
    if (reassembly_time_to_checkpoint(work->id, *candidate, uuidp, uuidc)) {
      return true;
    }
  }
  return false;
}

// Poll long-running inner loops without placing a checkpoint check on every
// block. Outer hypothesis loops call rar_reassembly_stop_requested() directly.
//
static inline bool rar_reassembly_poll(ThreadWork *work,
                                       CarveInfo **candidate,
                                       RarCarveState *state,
                                       uuid_string_t uuidp,
                                       uuid_string_t uuidc,
                                       uint64_t *iterations) {

  (*iterations)++;
  return *iterations % RAR_REASSEMBLY_POLL_INTERVAL == 0
         && rar_reassembly_stop_requested(work, candidate, state,
                                          uuidp, uuidc);
}

// Limit simultaneous fragmented RAR materialization to a conservative share
// of physical memory. The reservation is process local and is not checkpointed.
//
static inline uint64_t rar_reassembly_memory_budget(void) {

  uint64_t budget = atomic_load_explicit(
      &rar_reassembly_memory_budget_cached, memory_order_acquire);

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

  budget = physical_memory >= RAR_REASSEMBLY_MEMORY_DIVISOR
               ? physical_memory / RAR_REASSEMBLY_MEMORY_DIVISOR
               : RAR_REASSEMBLY_FALLBACK_BUDGET;
  if (budget == 0) {
    budget = RAR_REASSEMBLY_FALLBACK_BUDGET;
  }

  uint64_t expected = 0;

  if (!atomic_compare_exchange_strong_explicit(
          &rar_reassembly_memory_budget_cached, &expected, budget,
          memory_order_release, memory_order_relaxed)) {
    budget = expected;
  }
  return budget;
}

// Estimate the peak working set for one fragmented RAR candidate. This covers
// materialized archives, mapping arrays, decoder state, and the CRC index.
//
static inline bool rar_reassembly_memory_requirement(
    uint64_t candidate_size,
    uint64_t *required) {

  if (!required || candidate_size == 0 || scalpel_state.blocksize == 0) {
    return false;
  }

  const uint64_t blocksize = scalpel_state.blocksize;
  const uint64_t total_blocks = candidate_size / blocksize
                                + (candidate_size % blocksize != 0);
  uint64_t rounded_size = 0;
  uint64_t buffer_memory = 0;
  uint64_t block_memory = 0;
  uint64_t working_memory = 0;

  if (total_blocks == 0 || total_blocks > UINT64_MAX / blocksize) {
    return false;
  }
  rounded_size = total_blocks * blocksize;
  if (__builtin_mul_overflow(rounded_size,
                             RAR_REASSEMBLY_BUFFER_COPIES,
                             &buffer_memory)
      || __builtin_mul_overflow(total_blocks,
                                RAR_REASSEMBLY_BLOCK_OVERHEAD,
                                &block_memory)
      || __builtin_add_overflow(buffer_memory, block_memory,
                                &working_memory)
      || __builtin_add_overflow(working_memory, RAR_CRC_INDEX_BUDGET,
                                required)) {
    return false;
  }
  return true;
}

// Reserve the complete working set before archive-sized buffers are created.
// Waiting workers remain responsive to checkpoints and termination requests.
//
static inline RarMemoryReservationResult rar_reassembly_reserve_memory(
    ThreadWork *work,
    CarveInfo **candidate,
    uint64_t candidate_size,
    uint64_t *reservation,
    uuid_string_t uuidp,
    uuid_string_t uuidc) {

  uint64_t required = 0;
  const uint64_t budget = rar_reassembly_memory_budget();

  if (!work || !candidate || !*candidate || !reservation) {
    return RAR_MEMORY_UNAVAILABLE;
  }
  if (*reservation != 0) {
    return RAR_MEMORY_ACQUIRED;
  }
  if (!rar_reassembly_memory_requirement(candidate_size, &required)
      || required > budget) {
    return RAR_MEMORY_UNAVAILABLE;
  }

  const struct timespec wait_time = {
      .tv_sec = 0,
      .tv_nsec = RAR_REASSEMBLY_WAIT_NANOSECONDS};

  for (;;) {
    uint64_t current = atomic_load_explicit(
        &rar_reassembly_memory_reserved, memory_order_acquire);

    if (current <= budget - required
        && atomic_compare_exchange_weak_explicit(
               &rar_reassembly_memory_reserved, &current,
               current + required, memory_order_acq_rel,
               memory_order_relaxed)) {
      *reservation = required;
      return RAR_MEMORY_ACQUIRED;
    }
    if (rar_reassembly_stop_requested(work, candidate, NULL,
                                      uuidp, uuidc)) {
      return RAR_MEMORY_STOPPED;
    }
    (void)nanosleep(&wait_time, NULL);
  }
}

// Release a process-local fragmented RAR working set reservation.
//
static inline void rar_reassembly_release_memory(uint64_t *reservation) {

  if (!reservation || *reservation == 0) {
    return;
  }
  atomic_fetch_sub_explicit(&rar_reassembly_memory_reserved,
                            *reservation, memory_order_acq_rel);
  *reservation = 0;
}

// Follow the physical header chain. Whole-block insertions shift every later
// header by a multiple of the carving block size, while each header CRC remains
// an independent anchor for the logical archive layout.
//
static inline bool rar_discover_layout(ThreadWork *work,
                                       CarveInfo **candidate,
                                       RarCarveState *state,
                                       const uint8_t *data, uint64_t length,
                                       RarLayout *layout,
                                       uuid_string_t uuidp,
                                       uuid_string_t uuidc,
                                       uint64_t *iterations,
                                       bool *stopped) {

  memset(layout, 0, sizeof(*layout));
  *stopped = false;
  if (!data || scalpel_state.blocksize == 0) {
    return false;
  }
  if (length >= RAR5_MAGIC_SIZE
      && memcmp(data, rar5_magic, RAR5_MAGIC_SIZE) == 0) {
    layout->version = RAR_VERSION_5;
  }
  else if (length >= RAR4_MAGIC_SIZE
           && memcmp(data, rar4_magic, RAR4_MAGIC_SIZE) == 0) {
    layout->version = RAR_VERSION_4;
  }
  else {
    return false;
  }

  uint64_t physical = layout->version == RAR_VERSION_5
                          ? RAR5_MAGIC_SIZE : RAR4_MAGIC_SIZE;
  uint64_t logical = physical;
  bool seen_main = false;
  bool seen_file = false;
  bool multivolume = false;

  while (physical < length) {
    RarHeaderInfo header;
    if (!rar_parse_header(data, length, physical, layout->version, &header)) {
      rar_layout_clear(layout);
      return false;
    }
    if (!seen_main) {
      const bool main_header = layout->version == RAR_VERSION_5
                                   ? header.type == RAR5_BLOCK_MAIN
                                   : header.type == RAR4_HEADER_MAIN;
      if (!main_header) {
        rar_layout_clear(layout);
        return false;
      }
      seen_main = true;
      multivolume = layout->version == RAR_VERSION_5
          ? (header.flags & RAR5_MAIN_FLAG_VOLUME) != 0
          : (header.flags & RAR4_MAIN_FLAG_VOLUME) != 0;
    }

    if (header.file) {
      seen_file = true;
      if (layout->version == RAR_VERSION_5) {
        multivolume = multivolume
                      || (header.flags & (RAR5_HEADER_FLAG_SPLIT_BEFORE
                                          | RAR5_HEADER_FLAG_SPLIT_AFTER))
                             != 0;
      }
      else {
        multivolume = multivolume
                      || (header.flags & (RAR4_FILE_FLAG_SPLIT_BEFORE
                                          | RAR4_FILE_FLAG_SPLIT_AFTER))
                             != 0;
      }
    }

    if (layout->header_count == layout->header_capacity) {
      uint64_t capacity = layout->header_capacity == 0
                              ? UINT64_C(16)
                              : layout->header_capacity * 2;
      if (capacity < layout->header_capacity
          || capacity > SIZE_MAX / sizeof(*layout->headers)) {
        rar_layout_clear(layout);
        return false;
      }
      layout->headers = (RarHeaderInfo *)realloc(
          layout->headers, (size_t)capacity * sizeof(*layout->headers));
      check_memory_allocation(layout->headers, __LINE__, __FILE__,
                              "RAR layout headers");
      layout->header_capacity = capacity;
    }

    header.logical_offset = logical;
    layout->headers[layout->header_count++] = header;
    if (!rar_add_u64(logical, header.header_size, &logical)
        || !rar_add_u64(logical, header.data_size, &logical)) {
      rar_layout_clear(layout);
      return false;
    }
    if (header.end) {
      layout->archive_size = logical;
      layout->physical_size = physical + header.header_size;
      layout->complete = true;
      return true;
    }

    uint64_t expected;
    if (!rar_add_u64(physical, header.header_size, &expected)
        || !rar_add_u64(expected, header.data_size, &expected)
        || expected >= length) {
      rar_layout_clear(layout);
      return false;
    }

    RarHeaderInfo next_header;
    uint64_t next = expected;
    if (!rar_parse_header(data, length, next, layout->version, &next_header)) {
      bool found = false;
      while (next <= UINT64_MAX - scalpel_state.blocksize) {
        next += scalpel_state.blocksize;
        if (next >= length) {
          break;
        }
        if (rar_reassembly_poll(work, candidate, state, uuidp, uuidc,
                                iterations)) {
          *stopped = true;
          rar_layout_clear(layout);
          return false;
        }
        if (rar_parse_header(data, length, next, layout->version,
                             &next_header)) {
          found = true;
          break;
        }
      }
      if (!found) {
        if (layout->version == RAR_VERSION_4 && seen_file
            && !multivolume) {
          layout->archive_size = logical;
          layout->physical_size = expected;
          layout->complete = true;
          layout->implicit_end = true;
          return true;
        }
        rar_layout_clear(layout);
        return false;
      }
    }

    const uint64_t gap_bytes = next - expected;
    if (gap_bytes % scalpel_state.blocksize != 0) {
      rar_layout_clear(layout);
      return false;
    }
    layout->headers[layout->header_count - 1].gap_blocks_after =
        gap_bytes / scalpel_state.blocksize;
    if (!rar_add_u64(layout->gap_blocks,
                     gap_bytes / scalpel_state.blocksize,
                     &layout->gap_blocks)) {
      rar_layout_clear(layout);
      return false;
    }
    physical = next;
  }

  rar_layout_clear(layout);
  return false;
}

// Convert each shift in the physical header chain into the range of whole
// blocks where the inserted blocks can occur without removing a verified
// header. Each region retains an independent combination of removed slots.
//
static inline bool rar_build_gap_regions(const RarLayout *layout,
                                         RarGapRegion **regions,
                                         uint64_t *region_count,
                                         uint64_t *selection_count) {

  if (!layout || !regions || !region_count || !selection_count
      || scalpel_state.blocksize == 0) {
    return false;
  }
  *regions = NULL;
  *region_count = 0;
  *selection_count = 0;

  for (uint64_t index = 0; index < layout->header_count; index++) {
    if (layout->headers[index].gap_blocks_after != 0) {
      (*region_count)++;
    }
  }
  if (*region_count == 0) {
    return layout->gap_blocks == 0;
  }
  if (*region_count > SIZE_MAX / sizeof(**regions)) {
    return false;
  }

  *regions = (RarGapRegion *)calloc((size_t)*region_count,
                                    sizeof(**regions));
  check_memory_allocation(*regions, __LINE__, __FILE__, "RAR gap regions");

  uint64_t region_index = 0;

  for (uint64_t index = 0; index < layout->header_count; index++) {
    const RarHeaderInfo *header = &layout->headers[index];

    if (header->gap_blocks_after == 0) {
      continue;
    }
    if (index + 1 >= layout->header_count) {
      free(*regions);
      *regions = NULL;
      return false;
    }

    uint64_t header_end;

    if (!rar_add_u64(header->physical_offset, header->header_size,
                     &header_end)) {
      free(*regions);
      *regions = NULL;
      return false;
    }
    RarGapRegion *region = &(*regions)[region_index++];

    region->first_slot = header_end / scalpel_state.blocksize;
    if (header_end % scalpel_state.blocksize != 0) {
      region->first_slot++;
    }
    const uint64_t next_header_slot =
        layout->headers[index + 1].physical_offset / scalpel_state.blocksize;

    if (next_header_slot == 0) {
      free(*regions);
      *regions = NULL;
      return false;
    }
    region->last_slot = next_header_slot - 1;
    region->remove_count = header->gap_blocks_after;
    region->selection_offset = *selection_count;
    if (region->first_slot > region->last_slot
        || region->remove_count
               > region->last_slot - region->first_slot + 1
        || region->remove_count > UINT64_MAX - *selection_count) {
      free(*regions);
      *regions = NULL;
      return false;
    }
    *selection_count += region->remove_count;
  }
  if (*selection_count != layout->gap_blocks) {
    free(*regions);
    *regions = NULL;
    return false;
  }
  return true;
}

// Begin with the lexicographically first removal combination in every region.
//
static inline void rar_initialize_gap_selection(
    const RarGapRegion *regions, uint64_t region_count,
    uint64_t *selection) {

  for (uint64_t region_index = 0; region_index < region_count;
       region_index++) {
    const RarGapRegion *region = &regions[region_index];

    for (uint64_t index = 0; index < region->remove_count; index++) {
      selection[region->selection_offset + index] =
          region->first_slot + index;
    }
  }
}

// Rank blocks least likely to belong to the archive before trying the complete
// combination space. Confidence selects the first hypothesis only; archive
// structure, decompression, and checksums still decide whether it is valid.
//
static inline int rar_compare_removal_choices(const void *left,
                                              const void *right) {

  const RarRemovalChoice *a = (const RarRemovalChoice *)left;
  const RarRemovalChoice *b = (const RarRemovalChoice *)right;

  if (a->confidence_sum != b->confidence_sum) {
    return a->confidence_sum < b->confidence_sum ? -1 : 1;
  }
  if (a->reservations != b->reservations) {
    return a->reservations > b->reservations ? -1 : 1;
  }
  if (a->slot < b->slot) {
    return -1;
  }
  if (a->slot > b->slot) {
    return 1;
  }
  return 0;
}

static inline bool rar_initialize_ranked_gap_selection(
    const RarGapRegion *regions, uint64_t region_count,
    const int64_t *physical_mapping, uint64_t physical_blocks,
    const CarveInfo *candidate, uint64_t *selection,
    bool *strict_confidence_margin) {

  RarRemovalChoice *choices = NULL;
  uint64_t maximum_width = 0;

  if (!regions || !physical_mapping || !candidate || !selection
      || !strict_confidence_margin) {
    return false;
  }
  *strict_confidence_margin = true;
  for (uint64_t region_index = 0; region_index < region_count;
       region_index++) {
    const RarGapRegion *region = &regions[region_index];

    if (region->first_slot > region->last_slot
        || region->last_slot >= physical_blocks) {
      return false;
    }
    const uint64_t width = region->last_slot - region->first_slot + 1;

    if (region->remove_count == 0 || region->remove_count > width) {
      return false;
    }
    if (width > maximum_width) {
      maximum_width = width;
    }
  }
  if (maximum_width == 0
      || maximum_width > SIZE_MAX / sizeof(*choices)) {
    return false;
  }
  choices = (RarRemovalChoice *)malloc(
      (size_t)maximum_width * sizeof(*choices));
  check_memory_allocation(choices, __LINE__, __FILE__,
                          "RAR ranked gap choices");

  for (uint64_t region_index = 0; region_index < region_count;
       region_index++) {
    const RarGapRegion *region = &regions[region_index];
    const uint64_t width = region->last_slot - region->first_slot + 1;
    const uint64_t window_count = width - region->remove_count + 1;
    uint64_t confidence_sum = 0;
    int64_t reservations = 0;

    for (uint64_t offset = 0; offset < region->remove_count; offset++) {
      const uint64_t slot = region->first_slot + offset;
      const int64_t apparent = physical_mapping[slot];

      if (apparent < 0
          || (uint64_t)apparent
                 >= filemirror_apparent_blocks(scalpel_state.filemirror)) {
        free(choices);
        return false;
      }
      const int64_t actual = filemirror_actual_blocknumber(
          scalpel_state.filemirror, apparent);

      if (actual < 0) {
        free(choices);
        return false;
      }
      confidence_sum += (uint64_t)filemirror_get_blocktype(
          scalpel_state.filemirror, actual, candidate->needleidx);
      if (scalpel_state.reservations) {
        const int64_t count = filemirror_actual_block_reserved(
            scalpel_state.filemirror, actual);

        if (count > 0 && reservations > INT64_MAX - count) {
          reservations = INT64_MAX;
        }
        else {
          reservations += count;
        }
      }
    }
    for (uint64_t window = 0; window < window_count; window++) {
      choices[window].slot = region->first_slot + window;
      choices[window].confidence_sum = confidence_sum;
      choices[window].reservations = reservations;

      if (window + 1 < window_count) {
        const uint64_t removed_slot = region->first_slot + window;
        const uint64_t added_slot = removed_slot + region->remove_count;
        const int64_t removed_apparent = physical_mapping[removed_slot];
        const int64_t added_apparent = physical_mapping[added_slot];
        const int64_t removed_actual = filemirror_actual_blocknumber(
            scalpel_state.filemirror, removed_apparent);
        const int64_t added_actual = filemirror_actual_blocknumber(
            scalpel_state.filemirror, added_apparent);

        if (removed_actual < 0 || added_actual < 0) {
          free(choices);
          return false;
        }
        confidence_sum -= (uint64_t)filemirror_get_blocktype(
            scalpel_state.filemirror, removed_actual,
            candidate->needleidx);
        confidence_sum += (uint64_t)filemirror_get_blocktype(
            scalpel_state.filemirror, added_actual,
            candidate->needleidx);
        if (scalpel_state.reservations) {
          const int64_t removed_reservations =
              filemirror_actual_block_reserved(scalpel_state.filemirror,
                                               removed_actual);
          const int64_t added_reservations =
              filemirror_actual_block_reserved(scalpel_state.filemirror,
                                               added_actual);

          if (removed_reservations > 0
              && removed_reservations <= reservations) {
            reservations -= removed_reservations;
          }
          if (added_reservations > 0
              && reservations > INT64_MAX - added_reservations) {
            reservations = INT64_MAX;
          }
          else {
            reservations += added_reservations;
          }
        }
      }
    }
    qsort(choices, (size_t)window_count, sizeof(*choices),
          rar_compare_removal_choices);
    if (scalpel_state.mode_verbose) {
      lock_fprintf(
          stdout,
          "RAR ranked gap region=%" PRIu64 " range=%" PRIu64
          "-%" PRIu64 " remove=%" PRIu64 " selected=%" PRIu64
          " confidence=%" PRIu64 " reservations=%" PRId64 ".\n",
          region_index, region->first_slot, region->last_slot,
          region->remove_count, choices[0].slot,
          choices[0].confidence_sum, choices[0].reservations);
    }
    if (window_count > 1
        && choices[0].confidence_sum >= choices[1].confidence_sum) {
      *strict_confidence_margin = false;
    }
    for (uint64_t index = 0; index < region->remove_count; index++) {
      selection[region->selection_offset + index] =
          choices[0].slot + index;
    }
  }
  free(choices);
  return true;
}

// Advance the Cartesian product of per-region block-removal combinations.
//
static inline bool rar_advance_gap_selection(
    const RarGapRegion *regions, uint64_t region_count,
    uint64_t *selection) {

  if (!regions || !selection) {
    return false;
  }
  for (uint64_t reverse_region = region_count; reverse_region > 0;
       reverse_region--) {
    const uint64_t region_index = reverse_region - 1;
    const RarGapRegion *region = &regions[region_index];

    for (uint64_t reverse_choice = region->remove_count;
         reverse_choice > 0; reverse_choice--) {
      const uint64_t choice = reverse_choice - 1;
      const uint64_t maximum = region->last_slot
                               - (region->remove_count - choice - 1);
      uint64_t *value = &selection[region->selection_offset + choice];

      if (*value >= maximum) {
        continue;
      }
      (*value)++;
      for (uint64_t following = choice + 1;
           following < region->remove_count; following++) {
        selection[region->selection_offset + following] =
            selection[region->selection_offset + following - 1] + 1;
      }
      for (uint64_t following_region = region_index + 1;
           following_region < region_count; following_region++) {
        const RarGapRegion *reset = &regions[following_region];

        for (uint64_t reset_index = 0;
             reset_index < reset->remove_count; reset_index++) {
          selection[reset->selection_offset + reset_index] =
              reset->first_slot + reset_index;
        }
      }
      return true;
    }
  }
  return false;
}

// Remove the selected physical slots and retain the remaining block order as
// one logical archive hypothesis.
//
static inline bool rar_build_gap_mapping(
    const int64_t *physical_mapping, uint64_t physical_blocks,
    const uint64_t *selection, uint64_t selection_count,
    int64_t *logical_mapping, uint64_t logical_blocks) {

  if (!physical_mapping || !logical_mapping
      || selection_count > physical_blocks
      || logical_blocks != physical_blocks - selection_count) {
    return false;
  }

  uint64_t selection_index = 0;
  uint64_t logical_slot = 0;

  for (uint64_t physical_slot = 0; physical_slot < physical_blocks;
       physical_slot++) {
    if (selection_index < selection_count
        && selection[selection_index] == physical_slot) {
      selection_index++;
      continue;
    }
    if (logical_slot >= logical_blocks) {
      return false;
    }
    logical_mapping[logical_slot++] = physical_mapping[physical_slot];
  }
  return selection_index == selection_count
         && logical_slot == logical_blocks;
}

static inline bool rar_materialize_mapping(const int64_t *mapping,
                                           uint64_t blocks,
                                           uint64_t length,
                                           uint8_t *output) {

  if (!mapping || !output || scalpel_state.blocksize == 0
      || blocks != CEILDIV(length, scalpel_state.blocksize)) {
    return false;
  }
  memset(output, 0, (size_t)(blocks * scalpel_state.blocksize));
  for (uint64_t slot = 0; slot < blocks; slot++) {
    const int64_t apparent = mapping[slot];
    if (apparent < 0
        || (uint64_t)apparent
               >= filemirror_apparent_blocks(scalpel_state.filemirror)) {
      return false;
    }
    const int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, apparent);
    uint64_t available = 0;
    const uint8_t *source = (const uint8_t *)
        filemirror_actual_block_data_pointer(scalpel_state.filemirror,
                                             actual, &available);
    if (!source || filemirror_actual_block_covered(scalpel_state.filemirror,
                                                   actual)) {
      return false;
    }
    uint64_t copy = scalpel_state.blocksize;
    if (copy > available) {
      copy = available;
    }
    memcpy(output + slot * scalpel_state.blocksize, source, (size_t)copy);
  }
  return true;
}

static inline bool rar_mapping_validates(const int64_t *mapping,
                                         uint64_t blocks,
                                         uint64_t length,
                                         uint8_t *trial) {

  bool validates = false;
  bool promising = false;
  uint64_t validates_to = 0;

  if (!rar_materialize_mapping(mapping, blocks, length, trial)) {
    return false;
  }
  rar_file_validate((char *)trial, length, &validates, &validates_to,
                    &promising, 0, scalpel_state.blocksize, NULL);
  return validates && validates_to + 1 == length;
}

static inline void rar_commit_mapping(CarveInfo *candidate,
                                      const int64_t *mapping,
                                      uint64_t blocks, uint64_t length) {

  resize_blockvector(candidate->b, blocks);
  for (uint64_t slot = 0; slot < blocks; slot++) {
    blockvector_set_apparent_blocknumber(candidate->b, slot, mapping[slot]);
  }
  normalize_blockvector(candidate->b);
  blockvector_set_data_length(candidate->b, length);
  inflate_blockvector(candidate->b);
  candidate->best_validates_to = length - 1;
  candidate->no_initial_block_extension = false;
}

static inline int rar_compare_crc_sources(const void *left,
                                          const void *right) {

  const RarCrcSource *a = (const RarCrcSource *)left;
  const RarCrcSource *b = (const RarCrcSource *)right;
  if (a->crc < b->crc) {
    return -1;
  }
  if (a->crc > b->crc) {
    return 1;
  }
  if (a->apparent_start < b->apparent_start) {
    return -1;
  }
  if (a->apparent_start > b->apparent_start) {
    return 1;
  }
  return 0;
}

// Prefer source runs with the strongest RAR classification and the least
// reservation pressure. Physical order provides a deterministic final tie.
//
static inline int rar_compare_source_choices(const void *left,
                                             const void *right) {

  const RarSourceChoice *a = (const RarSourceChoice *)left;
  const RarSourceChoice *b = (const RarSourceChoice *)right;

  if (a->minimum_confidence != b->minimum_confidence) {
    return a->minimum_confidence > b->minimum_confidence ? -1 : 1;
  }
  if (a->confidence_sum != b->confidence_sum) {
    return a->confidence_sum > b->confidence_sum ? -1 : 1;
  }
  if (a->reservations != b->reservations) {
    return a->reservations < b->reservations ? -1 : 1;
  }
  if (a->apparent_start < b->apparent_start) {
    return -1;
  }
  if (a->apparent_start > b->apparent_start) {
    return 1;
  }
  return 0;
}

// For multi-block moves, rank sources by how closely their boundary byte
// distributions match the bytes surrounding the displaced destination. This
// is only a search-order hint; complete archive validation remains decisive.
//
static inline int rar_compare_source_seam_choices(const void *left,
                                                  const void *right) {

  const RarSourceChoice *a = (const RarSourceChoice *)left;
  const RarSourceChoice *b = (const RarSourceChoice *)right;

  if (a->seam_score != b->seam_score) {
    return a->seam_score < b->seam_score ? -1 : 1;
  }
  return rar_compare_source_choices(left, right);
}

// A zero-filled run is the strongest evidence for a displaced destination,
// followed by lower RAR confidence. The decoder's consumed position orders
// equally plausible choices.
//
static inline int rar_compare_destination_choices(const void *left,
                                                  const void *right) {

  const RarDestinationChoice *a = (const RarDestinationChoice *)left;
  const RarDestinationChoice *b = (const RarDestinationChoice *)right;

  if (a->zero_blocks != b->zero_blocks) {
    return a->zero_blocks > b->zero_blocks ? -1 : 1;
  }
  if (a->minimum_confidence != b->minimum_confidence) {
    return a->minimum_confidence < b->minimum_confidence ? -1 : 1;
  }
  if (a->confidence_sum != b->confidence_sum) {
    return a->confidence_sum < b->confidence_sum ? -1 : 1;
  }
  if (a->distance != b->distance) {
    return a->distance < b->distance ? -1 : 1;
  }
  if (a->slot < b->slot) {
    return -1;
  }
  if (a->slot > b->slot) {
    return 1;
  }
  return 0;
}

static inline uint64_t rar_histogram_distance(const uint8_t *left,
                                              const uint8_t *right,
                                              uint64_t length) {

  int32_t delta[256] = {0};
  uint64_t distance = 0;

  if (!left || !right) {
    return UINT64_MAX;
  }
  for (uint64_t index = 0; index < length; index++) {
    delta[left[index]]++;
    delta[right[index]]--;
  }
  for (uint64_t value = 0; value < 256; value++) {
    distance += delta[value] < 0
        ? (uint64_t)(-delta[value]) : (uint64_t)delta[value];
  }
  return distance;
}

// Sort the blocks already used by a candidate so source membership can be
// checked without allocating an image-sized reverse map.
//
static inline int rar_compare_mapped_blocks(const void *left,
                                            const void *right) {

  const RarMappedBlock *a = (const RarMappedBlock *)left;
  const RarMappedBlock *b = (const RarMappedBlock *)right;

  if (a->apparent < b->apparent) {
    return -1;
  }
  if (a->apparent > b->apparent) {
    return 1;
  }
  if (a->slot < b->slot) {
    return -1;
  }
  if (a->slot > b->slot) {
    return 1;
  }
  return 0;
}

// Decoder progress is ordered by completed members, output from the current
// member, and finally consumed archive input.
//
static inline int rar_compare_progress_scores(
    const RarProgressScore *left, const RarProgressScore *right) {

  if (left->completed_entries != right->completed_entries) {
    return left->completed_entries > right->completed_entries ? 1 : -1;
  }
  if (left->output_progress != right->output_progress) {
    return left->output_progress > right->output_progress ? 1 : -1;
  }
  if (left->consumed != right->consumed) {
    return left->consumed > right->consumed ? 1 : -1;
  }
  return 0;
}

// A probe result is useful only when it advances by a complete member or by at
// least one input block. This rejects the few-byte decoder jitter produced by
// unrelated data while retaining the exhaustive search as a fallback.
//
static inline bool rar_progress_has_margin(
    const RarProgressScore *better, const RarProgressScore *other,
    uint64_t minimum_delta) {

  if (better->completed_entries != other->completed_entries) {
    return better->completed_entries > other->completed_entries;
  }
  if (better->output_progress < other->output_progress) {
    return false;
  }
  if (better->output_progress - other->output_progress >= minimum_delta) {
    return true;
  }
  if (better->consumed < other->consumed) {
    return false;
  }
  return better->consumed - other->consumed >= minimum_delta;
}

static inline int64_t rar_find_mapped_block(
    const RarMappedBlock *mapped_blocks, uint64_t block_count,
    int64_t apparent) {

  uint64_t lower = 0;
  uint64_t upper = block_count;

  while (lower < upper) {
    const uint64_t middle = lower + (upper - lower) / 2;

    if (mapped_blocks[middle].apparent < apparent) {
      lower = middle + 1;
    }
    else {
      upper = middle;
    }
  }
  if (lower < block_count && mapped_blocks[lower].apparent == apparent
      && mapped_blocks[lower].slot <= INT64_MAX) {
    return (int64_t)mapped_blocks[lower].slot;
  }
  return -1;
}

static inline bool rar_crc_inverse_for_len(z_off_t length,
                                           uint32_t inverse[32]) {

  uint32_t augmented[32];
  const uLong operation = crc32_combine_gen(length);

  for (int bit = 0; bit < 32; bit++) {
    augmented[bit] = (uint32_t)crc32_combine_op(
        (uLong)(UINT32_C(1) << bit), 0UL, operation);
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

static inline uint32_t rar_crc_apply_inverse(const uint32_t inverse[32],
                                             uint32_t value) {

  uint32_t result = 0;
  for (int bit = 0; bit < 32; bit++) {
    if ((value & (UINT32_C(1) << bit)) != 0) {
      result ^= inverse[bit];
    }
  }
  return result;
}

static inline bool rar_mapping_uses_source(const int64_t *mapping,
                                           uint64_t blocks,
                                           uint64_t destination,
                                           uint64_t width,
                                           int64_t source) {

  for (uint64_t source_offset = 0; source_offset < width; source_offset++) {
    const int64_t source_block = source + (int64_t)source_offset;
    for (uint64_t slot = 0; slot < blocks; slot++) {
      if (slot >= destination && slot < destination + width) {
        continue;
      }
      if (mapping[slot] == source_block) {
        return true;
      }
    }
  }
  return false;
}

// Repair displaced runs in stored members by solving the member CRC equation.
// A source run is retained only when it is the unique mapping, across every
// possible run width and destination, that restores the stored member CRC.
//
static inline RarRepairResult rar_repair_stored_members(
    ThreadWork *work, CarveInfo **candidate, const RarLayout *layout,
    int64_t *mapping, uint64_t blocks, uint8_t *trial,
    int64_t *solution, uuid_string_t uuidp, uuid_string_t uuidc,
    uint64_t *iterations, RarCarveState *state) {

  RarRepairResult result = RAR_REPAIR_NONE;
  int64_t *trial_mapping = NULL;
  int64_t *unique_mapping = NULL;
  uint32_t *member_prefix = NULL;
  bool repaired_any = false;

  if (!work || !candidate || !*candidate || !layout || !mapping || !trial
      || !solution || scalpel_state.blocksize == 0) {
    return RAR_REPAIR_NONE;
  }
  if (!rar_materialize_mapping(mapping, blocks, layout->archive_size, trial)) {
    return RAR_REPAIR_NONE;
  }

  const uint64_t blocksize = scalpel_state.blocksize;
  const uint64_t image_blocks =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  if (image_blocks == 0 || blocks > SIZE_MAX / sizeof(int64_t)
      || blocks == SIZE_MAX
      || blocks + 1 > SIZE_MAX / sizeof(uint32_t)) {
    return RAR_REPAIR_NONE;
  }

  trial_mapping = (int64_t *)malloc(
      (size_t)blocks * sizeof(*trial_mapping));
  unique_mapping = (int64_t *)malloc(
      (size_t)blocks * sizeof(*unique_mapping));
  member_prefix = (uint32_t *)malloc(
      (size_t)(blocks + 1) * sizeof(*member_prefix));

  check_memory_allocation(trial_mapping, __LINE__, __FILE__,
                          "trial_mapping");
  check_memory_allocation(unique_mapping, __LINE__, __FILE__,
                          "unique_mapping");
  check_memory_allocation(member_prefix, __LINE__, __FILE__,
                          "member_prefix");

  for (uint64_t header_index = 0;
       header_index < layout->header_count; header_index++) {
    const RarHeaderInfo *header = &layout->headers[header_index];
    if (!header->file || !header->stored || !header->has_data_crc
        || header->data_size == 0) {
      continue;
    }

    const uint64_t data_offset = header->logical_offset
                                 + header->header_size;
    uint64_t data_end;
    if (!rar_add_u64(data_offset, header->data_size, &data_end)
        || data_end > layout->archive_size) {
      goto cleanup;
    }
    if (rar_header_crc32(trial + data_offset, header->data_size)
        == header->data_crc) {
      continue;
    }

    const uint64_t destination_first = CEILDIV(data_offset, blocksize);
    const uint64_t destination_end = data_end / blocksize;
    if (destination_first >= destination_end
        || destination_end > blocks) {
      goto cleanup;
    }

    uint64_t matches = 0;
    const uint64_t maximum_width = destination_end - destination_first;
    const uint64_t overlap = maximum_width - 1;
    const uint64_t bytes_per_source = sizeof(RarCrcSource)
                                      + sizeof(uint32_t) * 2
                                      + sizeof(uint8_t) * 2;
    uint64_t overlap_bytes = 0;
    uint64_t index_capacity = 1;

    if (overlap <= UINT64_MAX / (sizeof(uint32_t) + sizeof(uint8_t))) {
      overlap_bytes = overlap * (sizeof(uint32_t) + sizeof(uint8_t));
    }
    if (bytes_per_source > 0 && overlap_bytes < RAR_CRC_INDEX_BUDGET) {
      index_capacity = (RAR_CRC_INDEX_BUDGET - overlap_bytes)
                       / bytes_per_source;
      if (index_capacity == 0) {
        index_capacity = 1;
      }
    }
    if (index_capacity > image_blocks) {
      index_capacity = image_blocks;
    }
    if (index_capacity > SIZE_MAX / sizeof(RarCrcSource)
        || index_capacity > SIZE_MAX / sizeof(uint32_t)
        || index_capacity > SIZE_MAX / sizeof(uint8_t)
        || overlap > SIZE_MAX - index_capacity
        || index_capacity + overlap > SIZE_MAX / sizeof(uint32_t)
        || index_capacity + overlap > SIZE_MAX / sizeof(uint8_t)) {
      goto cleanup;
    }

    RarCrcSource *sources = (RarCrcSource *)malloc(
        (size_t)index_capacity * sizeof(*sources));
    uint32_t *run_crcs = (uint32_t *)calloc(
        (size_t)index_capacity, sizeof(*run_crcs));
    uint8_t *run_usable = (uint8_t *)calloc(
        (size_t)index_capacity, sizeof(*run_usable));
    uint32_t *block_crcs = (uint32_t *)malloc(
        (size_t)(index_capacity + overlap) * sizeof(*block_crcs));
    uint8_t *block_usable = (uint8_t *)malloc(
        (size_t)(index_capacity + overlap) * sizeof(*block_usable));

    check_memory_allocation(sources, __LINE__, __FILE__,
                            "RAR stored CRC sources");
    check_memory_allocation(run_crcs, __LINE__, __FILE__,
                            "RAR stored run CRCs");
    check_memory_allocation(run_usable, __LINE__, __FILE__,
                            "RAR stored run usability");
    check_memory_allocation(block_crcs, __LINE__, __FILE__,
                            "RAR stored block CRCs");
    check_memory_allocation(block_usable, __LINE__, __FILE__,
                            "RAR stored block usability");

    const uLong block_operator = crc32_combine_gen((z_off_t)blocksize);
    const uint64_t initial_prefix_length =
        destination_first * blocksize - data_offset;
    const uint32_t current_member_crc = rar_header_crc32(
        trial + data_offset, header->data_size);

    member_prefix[0] = rar_header_crc32(trial + data_offset,
                                        initial_prefix_length);
    for (uint64_t boundary = 0; boundary < maximum_width; boundary++) {
      const uint64_t block_offset =
          (destination_first + boundary) * blocksize;
      const uint32_t block_crc = rar_header_crc32(
          trial + block_offset, blocksize);

      member_prefix[boundary + 1] = (uint32_t)crc32_combine_op(
          member_prefix[boundary], block_crc, block_operator);
    }

    for (uint64_t chunk_start = 0; chunk_start < image_blocks;
         chunk_start += index_capacity) {
      uint64_t chunk_end = chunk_start + index_capacity;

      if (chunk_end < chunk_start || chunk_end > image_blocks) {
        chunk_end = image_blocks;
      }
      const uint64_t chunk_count = chunk_end - chunk_start;
      uint64_t block_end = chunk_end + overlap;

      if (block_end < chunk_end || block_end > image_blocks) {
        block_end = image_blocks;
      }
      const uint64_t block_count = block_end - chunk_start;

      memset(run_crcs, 0, (size_t)chunk_count * sizeof(*run_crcs));
      memset(run_usable, 0, (size_t)chunk_count * sizeof(*run_usable));
      for (uint64_t block = 0; block < block_count; block++) {
        if (rar_reassembly_poll(work, candidate, state, uuidp, uuidc,
                                iterations)) {
          result = RAR_REPAIR_STOPPED;
          free(block_usable);
          free(block_crcs);
          free(run_usable);
          free(run_crcs);
          free(sources);
          goto cleanup;
        }
        const uint64_t apparent = chunk_start + block;
        const int64_t actual = filemirror_actual_blocknumber(
            scalpel_state.filemirror, (int64_t)apparent);
        uint64_t available = 0;
        const uint8_t *data = (const uint8_t *)
            filemirror_actual_block_data_pointer(
                scalpel_state.filemirror, actual, &available);

        block_usable[block] = 0;
        block_crcs[block] = 0;
        if (data && available >= blocksize
            && !filemirror_actual_block_covered(
                   scalpel_state.filemirror, actual)
            && filemirror_get_blocktype(
                   scalpel_state.filemirror, actual,
                   (*candidate)->needleidx) != BLOCK_CONFIDENCE_INVALID) {
          block_usable[block] = 1;
          block_crcs[block] = rar_header_crc32(data, blocksize);
        }
      }

      for (uint64_t width = 1; width <= maximum_width; width++) {
        uint64_t source_count = 0;

        for (uint64_t source = 0; source < chunk_count; source++) {
          if (source + width > block_count
              || chunk_start + source + width > image_blocks) {
            continue;
          }
          const uint64_t added = source + width - 1;

          if (width == 1) {
            run_crcs[source] = block_crcs[source];
            run_usable[source] = block_usable[source];
          }
          else {
            run_crcs[source] = (uint32_t)crc32_combine_op(
                run_crcs[source], block_crcs[added], block_operator);
            run_usable[source] = run_usable[source]
                                 && block_usable[added];
          }
          if (!run_usable[source]) {
            continue;
          }
          sources[source_count].crc = run_crcs[source];
          sources[source_count].apparent_start =
              (int64_t)(chunk_start + source);
          source_count++;
        }
        qsort(sources, (size_t)source_count, sizeof(*sources),
              rar_compare_crc_sources);

        const uint64_t run_bytes = width * blocksize;
        for (uint64_t destination = destination_first;
             destination + width <= destination_end; destination++) {
          const uint64_t destination_index =
              destination - destination_first;
          const uint64_t tail_index = destination_index + width;
          const uint64_t prefix_length =
              destination * blocksize - data_offset;
          const uint64_t suffix_offset = prefix_length + run_bytes;
          const uint64_t suffix_length = header->data_size - suffix_offset;
          const uint32_t prefix_crc = member_prefix[destination_index];
          const uLong suffix_operator = crc32_combine_gen(
              (z_off_t)suffix_length);
          const uint32_t suffix_crc = current_member_crc
              ^ (uint32_t)crc32_combine_op(
                    member_prefix[tail_index], 0UL, suffix_operator);
          const uLong prefix_operator = crc32_combine_gen(
              (z_off_t)(run_bytes + suffix_length));
          const uint32_t shifted_prefix = (uint32_t)crc32_combine_op(
              prefix_crc, 0UL, prefix_operator);
          const uint32_t required_shifted = header->data_crc
                                            ^ shifted_prefix ^ suffix_crc;
          uint32_t inverse[32];

          if (!rar_crc_inverse_for_len((z_off_t)suffix_length, inverse)) {
            continue;
          }
          const uint32_t required_crc = rar_crc_apply_inverse(
              inverse, required_shifted);
          uint64_t lower = 0;
          uint64_t upper = source_count;

          while (lower < upper) {
            const uint64_t middle = lower + (upper - lower) / 2;
            if (sources[middle].crc < required_crc) {
              lower = middle + 1;
            }
            else {
              upper = middle;
            }
          }
          for (uint64_t match = lower;
               match < source_count
               && sources[match].crc == required_crc; match++) {
            const int64_t source = sources[match].apparent_start;

            if (rar_mapping_uses_source(mapping, blocks, destination, width,
                                        source)) {
              continue;
            }
            memcpy(trial_mapping, mapping,
                   (size_t)blocks * sizeof(*trial_mapping));
            for (uint64_t offset = 0; offset < width; offset++) {
              trial_mapping[destination + offset] =
                  source + (int64_t)offset;
            }
            if (!rar_materialize_mapping(trial_mapping, blocks,
                                         layout->archive_size, trial)
                || rar_header_crc32(trial + data_offset, header->data_size)
                       != header->data_crc) {
              continue;
            }
            if (matches == 0) {
              memcpy(unique_mapping, trial_mapping,
                     (size_t)blocks * sizeof(*unique_mapping));
            }
            else if (memcmp(unique_mapping, trial_mapping,
                            (size_t)blocks * sizeof(*unique_mapping)) == 0) {
              continue;
            }
            matches++;
            if (matches > 1) {
              result = RAR_REPAIR_AMBIGUOUS;
              free(block_usable);
              free(block_crcs);
              free(run_usable);
              free(run_crcs);
              free(sources);
              goto cleanup;
            }
          }
        }
      }
    }

    free(block_usable);
    free(block_crcs);
    free(run_usable);
    free(run_crcs);
    free(sources);
    if (matches != 1) {
      goto cleanup;
    }
    memcpy(mapping, unique_mapping, (size_t)blocks * sizeof(*mapping));
    if (!rar_materialize_mapping(mapping, blocks, layout->archive_size,
                                 trial)) {
      goto cleanup;
    }
    repaired_any = true;
  }

  if (repaired_any) {
    memcpy(solution, mapping, (size_t)blocks * sizeof(*solution));
    result = RAR_REPAIR_MATCH;
  }

cleanup:
  free(member_prefix);
  free(unique_mapping);
  free(trial_mapping);
  return result;
}

static inline uint64_t rar_source_choices_hash(
    const RarSourceChoice *sources, uint64_t count) {

  uint64_t hash = UINT64_C(1469598103934665603);

  for (uint64_t index = 0; index < count; index++) {
    const uint64_t fields[] = {
        (uint64_t)sources[index].apparent_start,
        sources[index].seam_score,
        sources[index].confidence_sum,
        (uint64_t)(uint32_t)sources[index].minimum_confidence,
        (uint64_t)sources[index].reservations};

    for (size_t field = 0; field < sizeof(fields) / sizeof(fields[0]);
         field++) {
      hash ^= fields[field];
      hash *= UINT64_C(1099511628211);
    }
  }
  return hash;
}

static inline int rar_compare_resume_position(
    const RarCarveState *state, uint64_t member_pass,
    uint64_t header_index, uint64_t destination_pass,
    uint64_t chunk_start, uint64_t width_order,
    uint64_t destination_index) {

  const uint64_t current[] = {
      member_pass, header_index, destination_pass, chunk_start,
      width_order, destination_index};
  const uint64_t saved[] = {
      state->resume_member_pass, state->resume_header_index,
      state->resume_destination_pass, state->resume_chunk_start,
      state->resume_width_order, state->resume_destination_index};

  for (size_t index = 0; index < sizeof(current) / sizeof(current[0]);
       index++) {
    if (current[index] < saved[index]) {
      return -1;
    }
    if (current[index] > saved[index]) {
      return 1;
    }
  }
  return 0;
}

// Repair one displaced run inside compressed member data. libarchive's
// consumed position identifies the first destination to try, while MoDiCo
// confidence and reservation pressure only order otherwise legal sources.
// Every destination, run width, and source remains reachable, and a mapping is
// accepted only after complete archive decompression and normal validation.
//
static inline RarRepairResult rar_repair_compressed_member(
    ThreadWork *work, CarveInfo **candidate, const RarLayout *layout,
    int64_t *mapping, uint64_t blocks, uint8_t *trial,
    int64_t *solution, uuid_string_t uuidp, uuid_string_t uuidc,
    uint64_t *iterations, bool probe_only,
    uint64_t maximum_source_trials, RarCarveState *state,
    RarRepairScope scope, uint32_t repair_pass,
    uint64_t gap_ordinal, uint64_t probe_index) {

  RarRepairResult result = RAR_REPAIR_NONE;
  uint8_t *block_usable = NULL;
  uint8_t *block_confidence = NULL;
  uint8_t *run_usable = NULL;
  uint8_t *run_minimum_confidence = NULL;
  uint64_t *run_confidence_sum = NULL;
  int64_t *block_reservations = NULL;
  int64_t *run_reservations = NULL;
  RarMappedBlock *mapped_blocks = NULL;
  RarSourceChoice *sources = NULL;
  RarDestinationChoice *destinations = NULL;
  uint8_t *destination_backup = NULL;
  uint64_t consumed = 0;
  uint64_t completed_entries = 0;
  uint64_t output_progress = 0;
  uint64_t image_blocks;
  uint64_t maximum_member_width = 0;
  uint64_t index_capacity = 0;
  uint64_t block_capacity = 0;
  uint64_t source_trials = 0;
  bool resume_call = false;
  bool encrypted = false;

  if (!work || !candidate || !*candidate || !layout || !mapping || !trial
      || !solution || !state || scalpel_state.blocksize == 0
      || layout->archive_size == 0 || maximum_source_trials == 0
      || !rar_materialize_mapping(mapping, blocks, layout->archive_size,
                                  trial)) {
    return RAR_REPAIR_NONE;
  }
  if (rar_libarchive_validate(
          trial, layout->archive_size, &consumed, &completed_entries,
          &output_progress, &encrypted, false)) {
    memcpy(solution, mapping, (size_t)blocks * sizeof(*solution));
    return RAR_REPAIR_MATCH;
  }
  if (encrypted) {
    return RAR_REPAIR_NONE;
  }
  const RarProgressScore baseline_progress = {
      .completed_entries = completed_entries,
      .output_progress = output_progress,
      .consumed = consumed};

  image_blocks = filemirror_apparent_blocks(scalpel_state.filemirror);
  if (image_blocks == 0
      || blocks > SIZE_MAX / sizeof(*mapped_blocks)
      || blocks > INT64_MAX) {
    return RAR_REPAIR_NONE;
  }
  resume_call = state->resume_active
      && state->resume_scope == (uint32_t)scope
      && state->resume_repair_pass == repair_pass
      && state->resume_probe_only == (uint32_t)probe_only
      && state->resume_gap_ordinal == gap_ordinal
      && state->resume_probe_index == probe_index
      && state->resume_image_blocks == image_blocks;
  if (!resume_call) {
    state->resume_active = 1;
    state->resume_scope = (uint32_t)scope;
    state->resume_repair_pass = repair_pass;
    state->resume_probe_only = (uint32_t)probe_only;
    state->resume_gap_ordinal = gap_ordinal;
    state->resume_probe_index = probe_index;
    state->resume_image_blocks = image_blocks;
    state->resume_member_pass = UINT64_MAX;
    state->resume_header_index = UINT64_MAX;
    state->resume_destination_pass = UINT64_MAX;
    state->resume_chunk_start = UINT64_MAX;
    state->resume_width_order = UINT64_MAX;
    state->resume_destination_index = UINT64_MAX;
    state->resume_source_index = 0;
    state->resume_source_count = 0;
    state->resume_source_hash = 0;
    state->resume_best_progress = (RarProgressScore){0, 0, 0};
    state->resume_second_progress = (RarProgressScore){0, 0, 0};
    state->resume_best_source = -1;
    state->resume_have_best = 0;
    state->resume_have_second = 0;
  }

  for (uint64_t header_index = 0;
       header_index < layout->header_count; header_index++) {
    const RarHeaderInfo *header = &layout->headers[header_index];
    uint64_t data_offset;
    uint64_t data_end;

    if (!header->file || header->directory || header->stored
        || header->data_size == 0
        || !rar_add_u64(header->logical_offset, header->header_size,
                        &data_offset)
        || !rar_add_u64(data_offset, header->data_size, &data_end)
        || data_end > layout->archive_size) {
      continue;
    }
    const uint64_t destination_first = CEILDIV(
        data_offset, scalpel_state.blocksize);
    const uint64_t destination_end = data_end / scalpel_state.blocksize;

    if (destination_end > destination_first
        && destination_end - destination_first > maximum_member_width) {
      maximum_member_width = destination_end - destination_first;
    }
  }
  if (maximum_member_width == 0
      || maximum_member_width > SIZE_MAX / sizeof(*destinations)
      || maximum_member_width > SIZE_MAX / scalpel_state.blocksize) {
    return RAR_REPAIR_NONE;
  }

  const uint64_t overlap = maximum_member_width - 1;
  const uint64_t block_entry_bytes = sizeof(*block_usable)
                                     + sizeof(*block_confidence)
                                     + sizeof(*block_reservations);
  const uint64_t source_entry_bytes = block_entry_bytes
      + sizeof(*run_usable) + sizeof(*run_minimum_confidence)
      + sizeof(*run_confidence_sum) + sizeof(*run_reservations)
      + sizeof(*sources);
  uint64_t overlap_bytes = 0;

  if (block_entry_bytes == 0 || source_entry_bytes == 0) {
    return RAR_REPAIR_NONE;
  }
  if (overlap <= UINT64_MAX / block_entry_bytes) {
    overlap_bytes = overlap * block_entry_bytes;
  }
  if (overlap_bytes < RAR_CRC_INDEX_BUDGET) {
    index_capacity = (RAR_CRC_INDEX_BUDGET - overlap_bytes)
                     / source_entry_bytes;
  }
  if (index_capacity == 0) {
    index_capacity = 1;
  }
  if (index_capacity > image_blocks) {
    index_capacity = image_blocks;
  }
  if (overlap > SIZE_MAX - index_capacity) {
    return RAR_REPAIR_NONE;
  }
  block_capacity = index_capacity + overlap;
  if (block_capacity > SIZE_MAX / sizeof(*block_usable)
      || block_capacity > SIZE_MAX / sizeof(*block_confidence)
      || block_capacity > SIZE_MAX / sizeof(*block_reservations)
      || index_capacity > SIZE_MAX / sizeof(*run_usable)
      || index_capacity > SIZE_MAX / sizeof(*run_minimum_confidence)
      || index_capacity > SIZE_MAX / sizeof(*run_confidence_sum)
      || index_capacity > SIZE_MAX / sizeof(*run_reservations)
      || index_capacity > SIZE_MAX / sizeof(*sources)) {
    return RAR_REPAIR_NONE;
  }

  block_usable = (uint8_t *)calloc((size_t)block_capacity,
                                   sizeof(*block_usable));
  block_confidence = (uint8_t *)calloc((size_t)block_capacity,
                                       sizeof(*block_confidence));
  run_usable = (uint8_t *)calloc((size_t)index_capacity,
                                 sizeof(*run_usable));
  run_minimum_confidence = (uint8_t *)calloc(
      (size_t)index_capacity, sizeof(*run_minimum_confidence));
  run_confidence_sum = (uint64_t *)calloc(
      (size_t)index_capacity, sizeof(*run_confidence_sum));
  block_reservations = (int64_t *)calloc(
      (size_t)block_capacity, sizeof(*block_reservations));
  run_reservations = (int64_t *)calloc(
      (size_t)index_capacity, sizeof(*run_reservations));
  mapped_blocks = (RarMappedBlock *)malloc(
      (size_t)blocks * sizeof(*mapped_blocks));
  sources = (RarSourceChoice *)malloc(
      (size_t)index_capacity * sizeof(*sources));
  destinations = (RarDestinationChoice *)malloc(
      (size_t)maximum_member_width * sizeof(*destinations));
  destination_backup = (uint8_t *)malloc(
      (size_t)(maximum_member_width * scalpel_state.blocksize));

  check_memory_allocation(block_usable, __LINE__, __FILE__,
                          "RAR compressed block usability");
  check_memory_allocation(block_confidence, __LINE__, __FILE__,
                          "RAR compressed block confidence");
  check_memory_allocation(run_usable, __LINE__, __FILE__,
                          "RAR compressed run usability");
  check_memory_allocation(run_minimum_confidence, __LINE__, __FILE__,
                          "RAR compressed run confidence");
  check_memory_allocation(run_confidence_sum, __LINE__, __FILE__,
                          "RAR compressed confidence sums");
  check_memory_allocation(block_reservations, __LINE__, __FILE__,
                          "RAR compressed block reservations");
  check_memory_allocation(run_reservations, __LINE__, __FILE__,
                          "RAR compressed run reservations");
  check_memory_allocation(mapped_blocks, __LINE__, __FILE__,
                          "RAR compressed mapping index");
  check_memory_allocation(sources, __LINE__, __FILE__,
                          "RAR compressed source choices");
  check_memory_allocation(destinations, __LINE__, __FILE__,
                          "RAR compressed destination choices");
  check_memory_allocation(destination_backup, __LINE__, __FILE__,
                          "RAR compressed destination backup");

  for (uint64_t slot = 0; slot < blocks; slot++) {
    const int64_t apparent = mapping[slot];

    if (apparent < 0 || (uint64_t)apparent >= image_blocks) {
      goto cleanup;
    }
    mapped_blocks[slot].apparent = apparent;
    mapped_blocks[slot].slot = slot;
  }
  qsort(mapped_blocks, (size_t)blocks, sizeof(*mapped_blocks),
        rar_compare_mapped_blocks);
  for (uint64_t index = 1; index < blocks; index++) {
    if (mapped_blocks[index - 1].apparent == mapped_blocks[index].apparent) {
      goto cleanup;
    }
  }

  for (uint32_t member_pass = 0; member_pass < 2; member_pass++) {
    uint64_t file_index = 0;

    for (uint64_t header_index = 0;
         header_index < layout->header_count; header_index++) {
      const RarHeaderInfo *header = &layout->headers[header_index];

      if (!header->file || header->directory) {
        continue;
      }
      const bool preferred_member = file_index == completed_entries;
      file_index++;
      if (header->stored || header->data_size == 0
          || (member_pass == 0 && !preferred_member)
          || (member_pass == 1 && preferred_member)) {
        continue;
      }
      uint64_t data_offset;
      uint64_t data_end;
      if (!rar_add_u64(header->logical_offset, header->header_size,
                       &data_offset)
          || !rar_add_u64(data_offset, header->data_size, &data_end)
          || data_end > layout->archive_size) {
        continue;
      }
      const uint64_t destination_first = CEILDIV(
          data_offset, scalpel_state.blocksize);
      const uint64_t destination_end = data_end / scalpel_state.blocksize;

      if (destination_first >= destination_end
          || destination_end > blocks) {
        continue;
      }
      uint64_t preferred_destination = consumed / scalpel_state.blocksize;
      if (preferred_destination < destination_first) {
        preferred_destination = destination_first;
      }
      if (preferred_destination >= destination_end) {
        preferred_destination = destination_end - 1;
      }

      const uint64_t maximum_width = destination_end - destination_first;
      uint64_t preferred_width = 1;
      uint64_t zero_run = 0;

      for (uint64_t destination = destination_first;
           destination < destination_end; destination++) {
        const int64_t apparent = mapping[destination];
        const int64_t actual = filemirror_actual_blocknumber(
            scalpel_state.filemirror, apparent);

        if (actual >= 0 && filemirror_actual_block_is_zero(
                               scalpel_state.filemirror, actual)) {
          zero_run++;
          if (zero_run > preferred_width) {
            preferred_width = zero_run;
          }
        }
        else {
          zero_run = 0;
        }
      }
      if (probe_only
          && preferred_width > RAR_COMPRESSED_PROBE_WIDTH_LIMIT) {
        preferred_width = 1;
      }
      for (uint32_t destination_pass = 0; destination_pass < 2;
           destination_pass++) {
        for (uint64_t chunk_start = 0; chunk_start < image_blocks;
             chunk_start += index_capacity) {
          uint64_t chunk_end = chunk_start + index_capacity;

          if (chunk_end < chunk_start || chunk_end > image_blocks) {
            chunk_end = image_blocks;
          }
          const uint64_t chunk_count = chunk_end - chunk_start;
          uint64_t block_end = chunk_end + maximum_width - 1;

          if (block_end < chunk_end || block_end > image_blocks) {
            block_end = image_blocks;
          }
          const uint64_t block_count = block_end - chunk_start;

          memset(run_usable, 0,
                 (size_t)chunk_count * sizeof(*run_usable));
          memset(run_minimum_confidence, 0,
                 (size_t)chunk_count * sizeof(*run_minimum_confidence));
          memset(run_confidence_sum, 0,
                 (size_t)chunk_count * sizeof(*run_confidence_sum));
          memset(run_reservations, 0,
                 (size_t)chunk_count * sizeof(*run_reservations));

          for (uint64_t block = 0; block < block_count; block++) {
            if (rar_reassembly_poll(work, candidate, state, uuidp, uuidc,
                                    iterations)) {
              result = RAR_REPAIR_STOPPED;
              goto cleanup;
            }
            const uint64_t apparent = chunk_start + block;
            const int64_t actual = filemirror_actual_blocknumber(
                scalpel_state.filemirror, (int64_t)apparent);
            uint64_t available = 0;
            const uint8_t *data = (const uint8_t *)
                filemirror_actual_block_data_pointer(
                    scalpel_state.filemirror, actual, &available);

            block_usable[block] = 0;
            block_confidence[block] = 0;
            block_reservations[block] = 0;
            if (!data || available < scalpel_state.blocksize
                || filemirror_actual_block_covered(
                       scalpel_state.filemirror, actual)) {
              continue;
            }
            const BlockValidationDecision confidence =
                filemirror_get_blocktype(
                    scalpel_state.filemirror, actual,
                    (*candidate)->needleidx);

            if (confidence == BLOCK_CONFIDENCE_INVALID) {
              continue;
            }
            block_usable[block] = 1;
            block_confidence[block] = (uint8_t)confidence;
            block_reservations[block] = scalpel_state.reservations
                ? filemirror_actual_block_reserved(
                      scalpel_state.filemirror, actual) : 0;
          }

          uint64_t accumulated_width = 0;

          for (uint64_t width_order = 0; width_order < maximum_width;
               width_order++) {
            uint64_t width = width_order == 0
                ? preferred_width : width_order;

            if (width_order > 0 && width >= preferred_width) {
              width++;
            }
            uint64_t source_count = 0;
            const bool reset_run_state = width_order == 0 || width == 1;
            const uint64_t first_added = reset_run_state
                ? 0 : accumulated_width;

            for (uint64_t source = 0; source < chunk_count; source++) {
              if (source + width > block_count
                  || chunk_start + source + width > image_blocks) {
                continue;
              }
              if (reset_run_state) {
                run_usable[source] = 1;
                run_minimum_confidence[source] =
                    (uint8_t)BLOCK_CONFIDENCE_VALID;
                run_confidence_sum[source] = 0;
                run_reservations[source] = 0;
              }
              for (uint64_t added_offset = first_added;
                   added_offset < width; added_offset++) {
                const uint64_t added = source + added_offset;

                run_usable[source] = run_usable[source]
                                     && block_usable[added];
                if (block_confidence[added]
                    < run_minimum_confidence[source]) {
                  run_minimum_confidence[source] =
                      block_confidence[added];
                }
                if (UINT64_MAX - run_confidence_sum[source]
                    < block_confidence[added]) {
                  run_confidence_sum[source] = UINT64_MAX;
                }
                else {
                  run_confidence_sum[source] += block_confidence[added];
                }
                if (block_reservations[added] > 0
                    && run_reservations[source]
                           > INT64_MAX - block_reservations[added]) {
                  run_reservations[source] = INT64_MAX;
                }
                else {
                  run_reservations[source] += block_reservations[added];
                }
              }
              if (!run_usable[source]) {
                continue;
              }
              sources[source_count].apparent_start =
                  (int64_t)(chunk_start + source);
              sources[source_count].seam_score = UINT64_MAX;
              sources[source_count].confidence_sum =
                  run_confidence_sum[source];
              sources[source_count].minimum_confidence =
                  run_minimum_confidence[source];
              sources[source_count].reservations =
                  run_reservations[source];
              source_count++;
            }
            accumulated_width = width;
            qsort(sources, (size_t)source_count, sizeof(*sources),
                  rar_compare_source_choices);

            const uint64_t destination_count =
                destination_end - destination_first - width + 1;
            uint64_t preferred_start = preferred_destination;

            if (preferred_start + width > destination_end) {
              preferred_start = destination_end - width;
            }
            for (uint64_t index = 0; index < destination_count; index++) {
              const uint64_t destination = destination_first + index;
              int minimum_confidence = (int)BLOCK_CONFIDENCE_VALID;
              uint64_t confidence_sum = 0;
              uint64_t zero_blocks = 0;

              for (uint64_t offset = 0; offset < width; offset++) {
                const int64_t apparent = mapping[destination + offset];
                const int64_t actual = filemirror_actual_blocknumber(
                    scalpel_state.filemirror, apparent);
                const int confidence = apparent >= 0
                    && (uint64_t)apparent < image_blocks
                    ? (int)filemirror_get_blocktype(
                          scalpel_state.filemirror, actual,
                          (*candidate)->needleidx)
                    : (int)BLOCK_CONFIDENCE_INVALID;

                if (confidence < minimum_confidence) {
                  minimum_confidence = confidence;
                }
                confidence_sum += (uint64_t)confidence;
                if (actual >= 0 && filemirror_actual_block_is_zero(
                                       scalpel_state.filemirror, actual)) {
                  zero_blocks++;
                }
              }
              destinations[index].slot = destination;
              destinations[index].confidence_sum = confidence_sum;
              destinations[index].zero_blocks = zero_blocks;
              destinations[index].minimum_confidence = minimum_confidence;
              destinations[index].distance = destination > preferred_start
                  ? destination - preferred_start
                  : preferred_start - destination;
            }
            qsort(destinations, (size_t)destination_count,
                  sizeof(*destinations),
                  rar_compare_destination_choices);

            const uint64_t run_bytes = width * scalpel_state.blocksize;
            const uint64_t destination_begin =
                destination_pass == 0 ? 0 : 1;
            const uint64_t destination_limit = destination_pass == 0
                ? (destination_count > 0 ? 1 : 0) : destination_count;

            for (uint64_t destination_index = destination_begin;
                 destination_index < destination_limit;
                 destination_index++) {
              const uint64_t destination =
                  destinations[destination_index].slot;
              RarProgressScore width_best_progress = {0, 0, 0};
              RarProgressScore width_second_progress = {0, 0, 0};
              int64_t width_best_source = -1;
              uint64_t start_source_index = 0;
              bool have_width_best = false;
              bool have_width_second = false;
              bool seam_ordered = false;

              memcpy(destination_backup,
                     trial + destination * scalpel_state.blocksize,
                     (size_t)run_bytes);
              if (width > 1 && destination_pass == 0
                  && destination_index == 0) {
                uint64_t sample = RAR_SEAM_SAMPLE_BYTES;
                const uint64_t destination_offset =
                    destination * scalpel_state.blocksize;
                const uint64_t following_offset =
                    (destination + width) * scalpel_state.blocksize;

                if (sample > scalpel_state.blocksize) {
                  sample = scalpel_state.blocksize;
                }
                const bool have_left = destination_offset >= sample;
                const bool have_right = following_offset
                    <= layout->archive_size
                    && layout->archive_size - following_offset >= sample;

                if (sample > 0 && (have_left || have_right)) {
                  for (uint64_t source_index = 0;
                       source_index < source_count; source_index++) {
                    const int64_t source =
                        sources[source_index].apparent_start;
                    const int64_t first_actual =
                        filemirror_actual_blocknumber(
                            scalpel_state.filemirror, source);
                    const int64_t last_actual =
                        filemirror_actual_blocknumber(
                            scalpel_state.filemirror,
                            source + (int64_t)width - 1);
                    uint64_t first_available = 0;
                    uint64_t last_available = 0;
                    const uint8_t *first_data = (const uint8_t *)
                        filemirror_actual_block_data_pointer(
                            scalpel_state.filemirror, first_actual,
                            &first_available);
                    const uint8_t *last_data = (const uint8_t *)
                        filemirror_actual_block_data_pointer(
                            scalpel_state.filemirror, last_actual,
                            &last_available);
                    uint64_t seam_score = 0;

                    if (!first_data || !last_data
                        || first_available < scalpel_state.blocksize
                        || last_available < scalpel_state.blocksize) {
                      sources[source_index].seam_score = UINT64_MAX;
                      continue;
                    }
                    if (have_left) {
                      seam_score += rar_histogram_distance(
                          trial + destination_offset - sample,
                          first_data, sample);
                    }
                    if (have_right) {
                      seam_score += rar_histogram_distance(
                          last_data + scalpel_state.blocksize - sample,
                          trial + following_offset, sample);
                    }
                    sources[source_index].seam_score = seam_score;
                  }
                  qsort(sources, (size_t)source_count, sizeof(*sources),
                        rar_compare_source_seam_choices);
                  seam_ordered = true;
                }
              }
              const int resume_position = resume_call
                  ? rar_compare_resume_position(
                        state, member_pass, header_index, destination_pass,
                        chunk_start, width_order, destination_index)
                  : 1;

              if (resume_call && resume_position < 0) {
                continue;
              }
              const uint64_t source_hash = rar_source_choices_hash(
                  sources, source_count);

              if (resume_call && resume_position == 0
                  && state->resume_source_count == source_count
                  && state->resume_source_hash == source_hash
                  && state->resume_source_index <= source_count) {
                start_source_index = state->resume_source_index;
                width_best_progress = state->resume_best_progress;
                width_second_progress = state->resume_second_progress;
                width_best_source = state->resume_best_source;
                have_width_best = state->resume_have_best != 0;
                have_width_second = state->resume_have_second != 0;
              }
              else {
                state->resume_member_pass = member_pass;
                state->resume_header_index = header_index;
                state->resume_destination_pass = destination_pass;
                state->resume_chunk_start = chunk_start;
                state->resume_width_order = width_order;
                state->resume_destination_index = destination_index;
                state->resume_source_index = 0;
                state->resume_source_count = source_count;
                state->resume_source_hash = source_hash;
                state->resume_best_progress = (RarProgressScore){0, 0, 0};
                state->resume_second_progress = (RarProgressScore){0, 0, 0};
                state->resume_best_source = -1;
                state->resume_have_best = 0;
                state->resume_have_second = 0;
              }
              resume_call = false;
              for (uint64_t source_index = start_source_index;
                   source_index < source_count; source_index++) {
                state->resume_source_index = source_index;
                if (rar_reassembly_poll(work, candidate, state, uuidp, uuidc,
                                        iterations)) {
                  result = RAR_REPAIR_STOPPED;
                  goto cleanup;
                }
                const int64_t source =
                    sources[source_index].apparent_start;
                bool used_elsewhere = false;

                for (uint64_t offset = 0; offset < width; offset++) {
                  const int64_t mapped_slot = rar_find_mapped_block(
                      mapped_blocks, blocks, source + (int64_t)offset);

                  if (mapped_slot >= 0
                      && ((uint64_t)mapped_slot < destination
                          || (uint64_t)mapped_slot
                                 >= destination + width)) {
                    used_elsewhere = true;
                    break;
                  }
                }
                if (used_elsewhere) {
                  state->resume_source_index = source_index + 1;
                  continue;
                }

                for (uint64_t offset = 0; offset < width; offset++) {
                  const int64_t apparent = source + (int64_t)offset;
                  const int64_t actual = filemirror_actual_blocknumber(
                      scalpel_state.filemirror, apparent);
                  uint64_t available = 0;
                  const uint8_t *data = (const uint8_t *)
                      filemirror_actual_block_data_pointer(
                          scalpel_state.filemirror, actual, &available);

                  if (!data || available < scalpel_state.blocksize) {
                    used_elsewhere = true;
                    break;
                  }
                  memcpy(trial + (destination + offset)
                                     * scalpel_state.blocksize,
                         data, (size_t)scalpel_state.blocksize);
                }
                if (used_elsewhere) {
                  state->resume_source_index = source_index + 1;
                  continue;
                }

                uint64_t trial_consumed = 0;
                uint64_t trial_entries = 0;
                uint64_t trial_output_progress = 0;
                bool trial_encrypted = false;

                const bool trial_valid = rar_libarchive_validate(
                    trial, layout->archive_size, &trial_consumed,
                    &trial_entries, &trial_output_progress,
                    &trial_encrypted, false);
                source_trials++;

                if (!trial_encrypted) {
                  const RarProgressScore trial_progress = {
                      .completed_entries = trial_entries,
                      .output_progress = trial_output_progress,
                      .consumed = trial_consumed};
                  const int comparison = have_width_best
                      ? rar_compare_progress_scores(
                            &trial_progress, &width_best_progress)
                      : 1;

                  if (comparison > 0) {
                    if (have_width_best) {
                      width_second_progress = width_best_progress;
                      have_width_second = true;
                    }
                    width_best_progress = trial_progress;
                    width_best_source = source;
                    have_width_best = true;
                  }
                  else if (comparison == 0) {
                    width_second_progress = width_best_progress;
                    have_width_second = true;
                  }
                  else if (!have_width_second
                           || rar_compare_progress_scores(
                                  &trial_progress,
                                  &width_second_progress) > 0) {
                    width_second_progress = trial_progress;
                    have_width_second = true;
                  }
                }

                state->resume_source_index = source_index + 1;
                state->resume_best_progress = width_best_progress;
                state->resume_second_progress = width_second_progress;
                state->resume_best_source = width_best_source;
                state->resume_have_best = have_width_best ? 1U : 0U;
                state->resume_have_second = have_width_second ? 1U : 0U;

                if (trial_valid) {
                  memcpy(solution, mapping,
                         (size_t)blocks * sizeof(*solution));
                  for (uint64_t offset = 0; offset < width; offset++) {
                    solution[destination + offset] =
                        source + (int64_t)offset;
                  }
                  if (rar_mapping_validates(
                          solution, blocks, layout->archive_size, trial)) {
                    if (scalpel_state.mode_verbose) {
                      lock_fprintf(
                          stdout,
                          "RAR compressed repair matched destination=%" PRIu64
                          " width=%" PRIu64 " source=%" PRId64
                          " source_rank=%" PRIu64 "/%" PRIu64
                          " trials=%" PRIu64
                          " confidence=%d sum=%" PRIu64
                          " reservations=%" PRId64 ".\n",
                          destination, width, source, source_index + 1,
                          source_count, source_trials,
                          sources[source_index].minimum_confidence,
                          sources[source_index].confidence_sum,
                          sources[source_index].reservations);
                    }
                    result = RAR_REPAIR_MATCH;
                    goto cleanup;
                  }
                }
                if (source_trials >= maximum_source_trials) {
                  result = RAR_REPAIR_NONE;
                  goto cleanup;
                }
              }
              memcpy(trial + destination * scalpel_state.blocksize,
                     destination_backup, (size_t)run_bytes);
              if (seam_ordered) {
                qsort(sources, (size_t)source_count, sizeof(*sources),
                      rar_compare_source_choices);
              }
              if (probe_only && destination_pass == 0 && have_width_best
                  && rar_progress_has_margin(
                         &width_best_progress, &baseline_progress,
                         scalpel_state.blocksize)
                  && (!have_width_second
                      || rar_progress_has_margin(
                             &width_best_progress, &width_second_progress,
                             scalpel_state.blocksize))) {
                RarProgressScore extended_progress = width_best_progress;
                uint64_t extended_width = width;
                uint64_t extension_limit = maximum_width;

                if (extension_limit > RAR_COMPRESSED_PROBE_WIDTH_LIMIT) {
                  extension_limit = RAR_COMPRESSED_PROBE_WIDTH_LIMIT;
                }
                if (rar_materialize_mapping(
                        mapping, blocks, layout->archive_size, trial)) {
                  for (uint64_t offset = 0; offset < width; offset++) {
                    const int64_t apparent =
                        width_best_source + (int64_t)offset;
                    const int64_t actual = filemirror_actual_blocknumber(
                        scalpel_state.filemirror, apparent);
                    uint64_t available = 0;
                    const uint8_t *data = (const uint8_t *)
                        filemirror_actual_block_data_pointer(
                            scalpel_state.filemirror, actual, &available);

                    if (!data || available < scalpel_state.blocksize) {
                      break;
                    }
                    memcpy(trial + (destination + offset)
                                       * scalpel_state.blocksize,
                           data, (size_t)scalpel_state.blocksize);
                  }
                  for (uint64_t extension = width + 1;
                       extension <= extension_limit
                       && extension <= destination_end - destination
                       && extension <= image_blocks
                       && width_best_source >= 0
                       && (uint64_t)width_best_source
                              <= image_blocks - extension;
                       extension++) {
                    if (rar_reassembly_poll(work, candidate, state,
                                            uuidp, uuidc,
                                            iterations)) {
                      result = RAR_REPAIR_STOPPED;
                      goto cleanup;
                    }
                    const int64_t apparent = width_best_source
                        + (int64_t)extension - 1;
                    const int64_t mapped_slot = rar_find_mapped_block(
                        mapped_blocks, blocks, apparent);

                    if (mapped_slot >= 0
                        && ((uint64_t)mapped_slot < destination
                            || (uint64_t)mapped_slot
                                   >= destination + extension)) {
                      break;
                    }
                    const int64_t actual = filemirror_actual_blocknumber(
                        scalpel_state.filemirror, apparent);
                    uint64_t available = 0;
                    const uint8_t *data = (const uint8_t *)
                        filemirror_actual_block_data_pointer(
                            scalpel_state.filemirror, actual, &available);

                    if (!data || available < scalpel_state.blocksize
                        || filemirror_actual_block_covered(
                               scalpel_state.filemirror, actual)
                        || filemirror_get_blocktype(
                               scalpel_state.filemirror, actual,
                               (*candidate)->needleidx)
                               == BLOCK_CONFIDENCE_INVALID) {
                      break;
                    }
                    memcpy(trial + (destination + extension - 1)
                                       * scalpel_state.blocksize,
                           data, (size_t)scalpel_state.blocksize);

                    uint64_t extension_consumed = 0;
                    uint64_t extension_entries = 0;
                    uint64_t extension_output = 0;
                    bool extension_encrypted = false;
                    const bool extension_valid = rar_libarchive_validate(
                        trial, layout->archive_size, &extension_consumed,
                        &extension_entries, &extension_output,
                        &extension_encrypted, false);
                    const RarProgressScore extension_progress = {
                        .completed_entries = extension_entries,
                        .output_progress = extension_output,
                        .consumed = extension_consumed};

                    if (!extension_encrypted) {
                      const int comparison = rar_compare_progress_scores(
                          &extension_progress, &extended_progress);
                      const bool output_on_plateau =
                          extension_progress.output_progress
                              >= extended_progress.output_progress
                          || extended_progress.output_progress
                                 - extension_progress.output_progress
                                 < scalpel_state.blocksize;
                      const bool input_on_plateau =
                          extension_progress.consumed
                              >= extended_progress.consumed
                          || extended_progress.consumed
                                 - extension_progress.consumed
                                 < scalpel_state.blocksize;

                      if (comparison > 0) {
                        extended_progress = extension_progress;
                        extended_width = extension;
                      }
                      else if (extension_progress.completed_entries
                                   == extended_progress.completed_entries
                               && output_on_plateau && input_on_plateau) {
                        extended_width = extension;
                      }
                    }
                    if (extension_valid) {
                      memcpy(solution, mapping,
                             (size_t)blocks * sizeof(*solution));
                      for (uint64_t offset = 0; offset < extension; offset++) {
                        solution[destination + offset] =
                            width_best_source + (int64_t)offset;
                      }
                      if (rar_mapping_validates(
                              solution, blocks, layout->archive_size, trial)) {
                        result = RAR_REPAIR_MATCH;
                        goto cleanup;
                      }
                    }
                  }
                }
                memcpy(solution, mapping,
                       (size_t)blocks * sizeof(*solution));
                for (uint64_t offset = 0; offset < extended_width; offset++) {
                  solution[destination + offset] =
                      width_best_source + (int64_t)offset;
                }
                result = RAR_REPAIR_PROGRESS;
                goto cleanup;
              }
            }
            if (probe_only && width >= RAR_COMPRESSED_PROBE_WIDTH_LIMIT) {
              result = RAR_REPAIR_NONE;
              goto cleanup;
            }
          }
        }
      }
    }
  }

cleanup:
  free(destination_backup);
  free(destinations);
  free(sources);
  free(mapped_blocks);
  free(run_reservations);
  free(block_reservations);
  free(run_confidence_sum);
  free(run_minimum_confidence);
  free(run_usable);
  free(block_confidence);
  free(block_usable);
  return result;
}

// Apply successive decoder-backed repairs to one mapping. Each accepted
// progress step becomes the input to the next probe and is stored as actual
// block numbers so checkpoints and blockmap swaps preserve the recipe.
//
static inline RarRepairResult rar_repair_compressed_progressively(
    ThreadWork *work, CarveInfo **candidate, const RarLayout *layout,
    const int64_t *mapping, uint64_t blocks, uint8_t *trial,
    int64_t *solution, int64_t *recipe, uuid_string_t uuidp,
    uuid_string_t uuidc, uint64_t *iterations, RarCarveState *state,
    bool *have_recipe, uint64_t maximum_source_trials,
    RarRepairScope scope, uint32_t repair_pass) {

  RarRepairResult repair = RAR_REPAIR_NONE;
  bool accumulated_progress;

  if (!mapping || !solution || !recipe || !state || !have_recipe) {
    return RAR_REPAIR_NONE;
  }

  accumulated_progress = *have_recipe;
  memcpy(solution, *have_recipe ? recipe : mapping,
         (size_t)blocks * sizeof(*solution));
  for (uint64_t probe = state->probe_index; probe < blocks; probe++) {
    state->probe_index = probe;
    repair = rar_repair_compressed_member(
        work, candidate, layout, solution, blocks, trial, recipe,
        uuidp, uuidc, iterations, true, maximum_source_trials,
        state, scope, repair_pass, 0, probe);
    if (repair == RAR_REPAIR_STOPPED) {
      return repair;
    }
    state->resume_active = 0;
    state->probe_index = probe + 1;
    if (repair == RAR_REPAIR_NONE || repair == RAR_REPAIR_AMBIGUOUS) {
      break;
    }
    memcpy(solution, recipe, (size_t)blocks * sizeof(*solution));
    if (!rar_store_actual_mapping(recipe, blocks,
                                  rar_carve_state_recipe(state))) {
      return RAR_REPAIR_NONE;
    }
    state->have_compressed_recipe = 1;
    *have_recipe = true;
    if (repair == RAR_REPAIR_MATCH) {
      return repair;
    }
    accumulated_progress = true;
  }

  return accumulated_progress ? RAR_REPAIR_PROGRESS : repair;
}

// Reassemble block-aligned insertions and displaced runs without treating
// format confidence as proof. Header CRCs determine the archive geometry,
// stored-member CRCs solve displaced runs, and the normal RAR validator must
// accept the complete result before any blocks are committed.
//
static inline void rar_reassembly(ThreadWork *work, CarveInfo **candidate,
                                  uuid_string_t uuidp,
                                  uuid_string_t uuidc) {

  RarCarveState *state = NULL;
  RarLayout layout;
  RarGapRegion *regions = NULL;
  int64_t *physical_mapping = NULL;
  int64_t *mapping = NULL;
  int64_t *best_mapping = NULL;
  int64_t *repair_solution = NULL;
  int64_t *compressed_recipe = NULL;
  int64_t *solution = NULL;
  uint64_t *selection = NULL;
  uint8_t *physical_data = NULL;
  uint8_t *trial = NULL;
  uint64_t region_count = 0;
  uint64_t selection_count = 0;
  uint64_t physical_blocks = 0;
  uint64_t logical_blocks = 0;
  uint64_t iterations = 0;
  uint64_t solutions = 0;
  uint64_t best_completed_entries = 0;
  uint64_t best_output_progress = 0;
  uint64_t best_consumed = 0;
  uint64_t memory_reservation = 0;
  RarMemoryReservationResult reservation_result = RAR_MEMORY_UNAVAILABLE;
  bool strict_confidence_margin = false;
  bool have_best_mapping = false;
  bool have_compressed_recipe = false;
  bool best_mapping_invalidated = false;
  bool compressed_recipe_invalidated = false;
  bool preserve_encrypted_extent = false;
  bool stopped = false;

  memset(&layout, 0, sizeof(layout));
  if (!work || !candidate || !*candidate || !(*candidate)->b
      || scalpel_state.blocksize == 0) {
    return;
  }

  state = rar_capture_carve_state(*candidate);
  if (!state || state->magic != RAR_CARVE_STATE_MAGIC
      || state->version != RAR_CARVE_STATE_VERSION
      || state->block_count == 0
      || state->block_count > SIZE_MAX / sizeof(int64_t)
      || state->block_count > SIZE_MAX / scalpel_state.blocksize
      || state->physical_length == 0
      || state->physical_length
             > state->block_count * scalpel_state.blocksize) {
    goto no_solution;
  }

  reservation_result = rar_reassembly_reserve_memory(
      work, candidate, state->physical_length, &memory_reservation,
      uuidp, uuidc);

  if (reservation_result == RAR_MEMORY_STOPPED) {
    goto interrupted;
  }
  if (reservation_result == RAR_MEMORY_UNAVAILABLE) {
    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout,
                   "RAR candidate requires more reassembly memory than "
                   "the process budget permits.\n");
    }
    goto no_solution;
  }

  physical_mapping = (int64_t *)malloc(
      (size_t)state->block_count * sizeof(*physical_mapping));
  physical_data = (uint8_t *)malloc(
      (size_t)(state->block_count * scalpel_state.blocksize));
  check_memory_allocation(physical_mapping, __LINE__, __FILE__,
                          "RAR physical mapping");
  check_memory_allocation(physical_data, __LINE__, __FILE__,
                          "RAR physical candidate");

  // A header/footer candidate can have a speculative tail that overlaps files
  // validated by an earlier worker. Read the immutable actual blocks to find
  // the checksum-protected archive extent, then require every block inside
  // that proven extent to remain uncovered before it can be committed.
  //
  for (uint64_t slot = 0; slot < state->block_count; slot++) {
    const uint64_t offset = slot * scalpel_state.blocksize;

    if (offset >= state->physical_length) {
      break;
    }
    const int64_t actual = state->actual_blocks[slot];
    uint64_t available = 0;
    const uint8_t *data = (const uint8_t *)
        filemirror_actual_block_data_pointer(
            scalpel_state.filemirror, actual, &available);
    uint64_t copy_length = state->physical_length - offset;

    if (copy_length > scalpel_state.blocksize) {
      copy_length = scalpel_state.blocksize;
    }
    if (!data || available < copy_length) {
      goto no_solution;
    }
    memcpy(physical_data + offset, data, (size_t)copy_length);
  }
  if (!rar_discover_layout(work, candidate, state, physical_data,
                           state->physical_length, &layout, uuidp, uuidc,
                           &iterations, &stopped)) {
    if (stopped) {
      goto interrupted;
    }
    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout,
                   "RAR reassembly found no complete physical layout for "
                   "start=%" PRId64 " blocks=%" PRIu64
                   " length=%" PRIu64 ".\n",
                   state->actual_blocks[0], state->block_count,
                   state->physical_length);
    }
    goto no_solution;
  }
  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout,
                 "RAR reassembly layout: start=%" PRId64
                 " blocks=%" PRIu64 " physical=%" PRIu64
                 " archive=%" PRIu64 " gaps=%" PRIu64
                 " implicit_end=%d.\n",
                 state->actual_blocks[0], state->block_count,
                 state->physical_length, layout.archive_size,
                 layout.gap_blocks, layout.implicit_end);
  }
  if (!layout.complete || layout.archive_size == 0
      || layout.archive_size > SIZE_MAX || layout.physical_size == 0
      || layout.physical_size > state->physical_length) {
    goto no_solution;
  }
  physical_blocks = CEILDIV(layout.physical_size,
                            scalpel_state.blocksize);
  if (physical_blocks == 0 || physical_blocks > state->block_count) {
    goto no_solution;
  }
  for (uint64_t slot = 0; slot < physical_blocks; slot++) {
    const int64_t actual = state->actual_blocks[slot];
    const int64_t apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, actual);

    if (apparent < 0
        || filemirror_actual_block_covered(scalpel_state.filemirror, actual)) {
      goto no_solution;
    }
    physical_mapping[slot] = apparent;
  }

  // Data-encrypted archives retain a complete chain of CRC-protected headers.
  // If that chain is physically contiguous, its end header proves the exact
  // archive extent even though file contents cannot be checked without a
  // password. Header-encrypted archives do not expose this evidence and never
  // reach this path.
  //
  RarStructureResult encrypted_structure;

  rar_parse_structure(physical_data, layout.archive_size,
                      &encrypted_structure);
  preserve_encrypted_extent = layout.gap_blocks == 0
                              && layout.physical_size == layout.archive_size
                              && encrypted_structure.status
                                     == RAR_STRUCTURE_COMPLETE
                              && encrypted_structure.encrypted;

  free(physical_data);
  physical_data = NULL;

  logical_blocks = layout.archive_size / scalpel_state.blocksize;
  if (layout.archive_size % scalpel_state.blocksize != 0) {
    logical_blocks++;
  }
  if (logical_blocks == 0 || logical_blocks > SIZE_MAX / sizeof(int64_t)
      || logical_blocks > SIZE_MAX / scalpel_state.blocksize) {
    goto no_solution;
  }
  if (preserve_encrypted_extent) {
    rar_commit_mapping(*candidate, physical_mapping, logical_blocks,
                       layout.archive_size);
    goto no_solution;
  }
  if (!rar_build_gap_regions(&layout, &regions, &region_count,
                             &selection_count)
      || selection_count > physical_blocks
      || logical_blocks != physical_blocks - selection_count) {
    goto no_solution;
  }
  if (!rar_prepare_search_state(&state, layout.archive_size,
                                physical_blocks, logical_blocks,
                                selection_count)) {
    goto no_solution;
  }

  if (selection_count > 0) {
    if (selection_count > SIZE_MAX / sizeof(*selection)) {
      goto no_solution;
    }
    selection = (uint64_t *)malloc(
        (size_t)selection_count * sizeof(*selection));
    check_memory_allocation(selection, __LINE__, __FILE__,
                            "RAR gap selection");
  }
  mapping = (int64_t *)malloc((size_t)logical_blocks * sizeof(*mapping));
  best_mapping = (int64_t *)malloc(
      (size_t)logical_blocks * sizeof(*best_mapping));
  repair_solution = (int64_t *)malloc(
      (size_t)logical_blocks * sizeof(*repair_solution));
  compressed_recipe = (int64_t *)malloc(
      (size_t)logical_blocks * sizeof(*compressed_recipe));
  solution = (int64_t *)malloc(
      (size_t)logical_blocks * sizeof(*solution));
  trial = (uint8_t *)malloc(
      (size_t)(logical_blocks * scalpel_state.blocksize));
  check_memory_allocation(mapping, __LINE__, __FILE__, "RAR mapping");
  check_memory_allocation(best_mapping, __LINE__, __FILE__,
                          "RAR best progress mapping");
  check_memory_allocation(repair_solution, __LINE__, __FILE__,
                          "RAR repair solution");
  check_memory_allocation(compressed_recipe, __LINE__, __FILE__,
                          "RAR compressed repair recipe");
  check_memory_allocation(solution, __LINE__, __FILE__, "RAR solution");
  check_memory_allocation(trial, __LINE__, __FILE__, "RAR trial data");

  have_best_mapping = state->have_best_mapping
      && rar_load_actual_mapping(rar_carve_state_best_mapping(state),
                                 logical_blocks, best_mapping);
  best_mapping_invalidated = state->have_best_mapping
                             && !have_best_mapping;
  if (!have_best_mapping) {
    state->have_best_mapping = 0;
  }
  else {
    best_completed_entries = state->best_completed_entries;
    best_output_progress = state->best_output_progress;
    best_consumed = state->best_consumed;
  }
  have_compressed_recipe = state->have_compressed_recipe
      && rar_load_actual_mapping(rar_carve_state_recipe(state),
                                 logical_blocks, compressed_recipe);
  compressed_recipe_invalidated = state->have_compressed_recipe
                                  && !have_compressed_recipe;
  if (!have_compressed_recipe) {
    state->have_compressed_recipe = 0;
  }

  // Coverage can change while a candidate waits in the promising queue. If a
  // saved mapping used a block that is no longer available, restart only the
  // earliest search pass needed to derive replacement state.
  //
  if (best_mapping_invalidated) {
    state->repair_pass = 0;
    state->gap_ordinal = 0;
    state->probe_index = 0;
    state->best_completed_entries = 0;
    state->best_output_progress = 0;
    state->best_consumed = 0;
    state->selection_initialized = 0;
    state->prepass_complete = 0;
    state->have_compressed_recipe = 0;
    state->resume_active = 0;
    state->search_initialized |= RAR_SEARCH_RANKED_REPAIR_PENDING;
    state->search_initialized &= ~RAR_SEARCH_RANKED_REPAIR_COMPLETE;
    have_compressed_recipe = false;
  }
  else if (compressed_recipe_invalidated && state->repair_pass >= 2) {
    if (state->repair_pass > 2) {
      state->repair_pass = 2;
    }
    state->gap_ordinal = 0;
    state->probe_index = 0;
    state->selection_initialized = 0;
    state->prepass_complete = 0;
    state->resume_active = 0;
  }

  // Try the best-ranked inserted-block hypothesis before enumerating the full
  // combination space. Decoder progress and checksums remain the only
  // acceptance evidence, and failure falls through to the exhaustive search.
  //
  if ((state->search_initialized & RAR_SEARCH_RANKED_REPAIR_PENDING) != 0) {
    RarRepairResult ranked_repair = RAR_REPAIR_NONE;
    const bool have_ranked_mapping = selection_count > 0
        && rar_initialize_ranked_gap_selection(
               regions, region_count, physical_mapping, physical_blocks,
               *candidate, selection, &strict_confidence_margin)
        && rar_build_gap_mapping(physical_mapping, physical_blocks,
                                 selection, selection_count, mapping,
                                 logical_blocks);

    if (have_ranked_mapping) {
      const uint64_t ranked_source_trials = strict_confidence_margin
          ? UINT64_MAX : RAR_RANKED_TIE_SOURCE_TRIALS;
      uint64_t consumed = 0;
      uint64_t completed_entries = 0;
      uint64_t output_progress = 0;
      bool encrypted = false;

      if (rar_materialize_mapping(mapping, logical_blocks,
                                  layout.archive_size, trial)) {
        const bool content_valid = rar_libarchive_validate(
            trial, layout.archive_size, &consumed, &completed_entries,
            &output_progress, &encrypted, false);

        if (content_valid
            && rar_mapping_validates(mapping, logical_blocks,
                                     layout.archive_size, trial)) {
          memcpy(solution, mapping,
                 (size_t)logical_blocks * sizeof(*solution));
          solutions = 1;
        }
        if (!encrypted
            && (!have_best_mapping
                || completed_entries > best_completed_entries
                || (completed_entries == best_completed_entries
                    && output_progress > best_output_progress)
                || (completed_entries == best_completed_entries
                    && output_progress == best_output_progress
                    && consumed > best_consumed))) {
          memcpy(best_mapping, mapping,
                 (size_t)logical_blocks * sizeof(*best_mapping));
          if (!rar_store_actual_mapping(
                  best_mapping, logical_blocks,
                  rar_carve_state_best_mapping(state))) {
            goto no_solution;
          }
          best_completed_entries = completed_entries;
          best_output_progress = output_progress;
          best_consumed = consumed;
          state->best_completed_entries = completed_entries;
          state->best_output_progress = output_progress;
          state->best_consumed = consumed;
          state->have_best_mapping = 1;
          have_best_mapping = true;
        }
      }

      if (solutions == 0) {
        ranked_repair = rar_repair_stored_members(
            work, candidate, &layout, mapping, logical_blocks, trial,
            repair_solution, uuidp, uuidc, &iterations, state);
        if (ranked_repair == RAR_REPAIR_STOPPED) {
          goto interrupted;
        }
        if (ranked_repair == RAR_REPAIR_MATCH
            && rar_mapping_validates(repair_solution, logical_blocks,
                                     layout.archive_size, trial)) {
          memcpy(solution, repair_solution,
                 (size_t)logical_blocks * sizeof(*solution));
          solutions = 1;
        }
      }

      // A tied confidence score receives a bounded acceleration probe. If it
      // is not the right gap hypothesis, the complete search remains intact.
      if (solutions == 0) {
        ranked_repair = rar_repair_compressed_progressively(
            work, candidate, &layout, mapping, logical_blocks, trial,
            repair_solution, compressed_recipe, uuidp, uuidc, &iterations,
            state, &have_compressed_recipe, ranked_source_trials,
            RAR_REPAIR_SCOPE_RANKED, 0);
        if (ranked_repair == RAR_REPAIR_STOPPED) {
          goto interrupted;
        }
        state->resume_active = 0;
        if (ranked_repair == RAR_REPAIR_MATCH
            && rar_mapping_validates(repair_solution, logical_blocks,
                                     layout.archive_size, trial)) {
          memcpy(solution, repair_solution,
                 (size_t)logical_blocks * sizeof(*solution));
          solutions = 1;
        }
      }

      if (solutions == 0 && strict_confidence_margin) {
        memcpy(repair_solution,
               have_compressed_recipe ? compressed_recipe : mapping,
               (size_t)logical_blocks * sizeof(*repair_solution));
        ranked_repair = rar_repair_compressed_member(
            work, candidate, &layout, repair_solution, logical_blocks,
            trial, compressed_recipe, uuidp, uuidc, &iterations, false,
            UINT64_MAX, state, RAR_REPAIR_SCOPE_RANKED, 0, 0,
            UINT64_MAX);
        if (ranked_repair == RAR_REPAIR_STOPPED) {
          goto interrupted;
        }
        state->resume_active = 0;
        if (ranked_repair == RAR_REPAIR_MATCH
            && rar_mapping_validates(compressed_recipe, logical_blocks,
                                     layout.archive_size, trial)) {
          memcpy(solution, compressed_recipe,
                 (size_t)logical_blocks * sizeof(*solution));
          solutions = 1;
        }
      }
    }

    state->search_initialized &= ~RAR_SEARCH_RANKED_REPAIR_PENDING;
    state->search_initialized |= RAR_SEARCH_RANKED_REPAIR_COMPLETE;
    state->probe_index = 0;
    state->resume_active = 0;
  }

  // Test pure gap removal first, then stored and compressed displaced runs.
  // Search state is updated before every checkpointable operation so the next
  // invocation resumes the same hypothesis and decoder source trial.
  //
  for (uint32_t repair_pass = state->repair_pass;
       repair_pass < 4 && solutions == 0; repair_pass++) {
    state->repair_pass = repair_pass;

    if (repair_pass > 0 && have_best_mapping
        && !state->prepass_complete) {
      RarRepairResult repair = RAR_REPAIR_NONE;

      memcpy(mapping, best_mapping,
             (size_t)logical_blocks * sizeof(*mapping));
      if (repair_pass == 1) {
        repair = rar_repair_stored_members(
            work, candidate, &layout, mapping, logical_blocks, trial,
            repair_solution, uuidp, uuidc, &iterations, state);
      }
      else if (repair_pass == 2) {
        repair = rar_repair_compressed_progressively(
            work, candidate, &layout, mapping, logical_blocks, trial,
            repair_solution, compressed_recipe, uuidp, uuidc, &iterations,
            state, &have_compressed_recipe, UINT64_MAX,
            RAR_REPAIR_SCOPE_PREPASS, repair_pass);
      }
      else {
        repair = rar_repair_compressed_member(
            work, candidate, &layout, mapping, logical_blocks, trial,
            repair_solution, uuidp, uuidc, &iterations, false,
            UINT64_MAX, state, RAR_REPAIR_SCOPE_PREPASS,
            repair_pass, 0, 0);
        if (repair != RAR_REPAIR_STOPPED) {
          state->resume_active = 0;
        }
      }
      if (repair == RAR_REPAIR_STOPPED) {
        goto interrupted;
      }
      if (repair == RAR_REPAIR_MATCH
          && rar_mapping_validates(repair_solution, logical_blocks,
                                   layout.archive_size, trial)) {
        memcpy(solution, repair_solution,
               (size_t)logical_blocks * sizeof(*solution));
        solutions = 1;
        break;
      }
      state->prepass_complete = 1;
    }
    if (repair_pass == 2 && !have_compressed_recipe) {
      goto next_repair_pass;
    }

    if (state->selection_initialized) {
      if (selection_count > 0) {
        memcpy(selection, rar_carve_state_selection(state),
               (size_t)selection_count * sizeof(*selection));
      }
    }
    else {
      rar_initialize_gap_selection(regions, region_count, selection);
      state->gap_ordinal = 0;
      state->selection_initialized = 1;
      if (selection_count > 0) {
        memcpy(rar_carve_state_selection(state), selection,
               (size_t)selection_count * sizeof(*selection));
      }
    }
    bool have_hypothesis = true;

    while (have_hypothesis) {
      if (rar_reassembly_stop_requested(work, candidate, state,
                                        uuidp, uuidc)) {
        goto interrupted;
      }
      if (!rar_build_gap_mapping(physical_mapping, physical_blocks,
                                 selection, selection_count, mapping,
                                 logical_blocks)) {
        goto no_solution;
      }

      const int64_t *validated_mapping = mapping;
      bool validates = false;

      if (repair_pass == 0) {
        uint64_t consumed = 0;
        uint64_t completed_entries = 0;
        uint64_t output_progress = 0;
        bool encrypted = false;

        if (rar_materialize_mapping(mapping, logical_blocks,
                                    layout.archive_size, trial)) {
          const bool content_valid = rar_libarchive_validate(
              trial, layout.archive_size, &consumed, &completed_entries,
              &output_progress, &encrypted, false);

          if (content_valid) {
            validates = rar_mapping_validates(mapping, logical_blocks,
                                              layout.archive_size, trial);
          }
          if (!encrypted
              && (!have_best_mapping
                  || completed_entries > best_completed_entries
                  || (completed_entries == best_completed_entries
                      && output_progress > best_output_progress)
                  || (completed_entries == best_completed_entries
                      && output_progress == best_output_progress
                      && consumed > best_consumed))) {
            if (have_compressed_recipe
                && (!have_best_mapping
                    || memcmp(best_mapping, mapping,
                              (size_t)logical_blocks
                                  * sizeof(*best_mapping)) != 0)) {
              state->have_compressed_recipe = 0;
              state->probe_index = 0;
              state->resume_active = 0;
              have_compressed_recipe = false;
            }
            memcpy(best_mapping, mapping,
                   (size_t)logical_blocks * sizeof(*best_mapping));
            if (!rar_store_actual_mapping(
                    best_mapping, logical_blocks,
                    rar_carve_state_best_mapping(state))) {
              goto no_solution;
            }
            best_completed_entries = completed_entries;
            best_output_progress = output_progress;
            best_consumed = consumed;
            state->best_completed_entries = completed_entries;
            state->best_output_progress = output_progress;
            state->best_consumed = consumed;
            state->have_best_mapping = 1;
            have_best_mapping = true;
          }
        }
      }
      else if (repair_pass == 1) {
        const RarRepairResult repair = rar_repair_stored_members(
            work, candidate, &layout, mapping, logical_blocks, trial,
            repair_solution, uuidp, uuidc, &iterations, state);

        if (repair == RAR_REPAIR_STOPPED) {
          goto interrupted;
        }
        if (repair == RAR_REPAIR_MATCH) {
          validated_mapping = repair_solution;
          validates = rar_mapping_validates(repair_solution, logical_blocks,
                                            layout.archive_size, trial);
        }
      }
      else if (repair_pass == 2) {
        memcpy(repair_solution, mapping,
               (size_t)logical_blocks * sizeof(*repair_solution));
        for (uint64_t slot = 0; slot < logical_blocks; slot++) {
          if (compressed_recipe[slot] != best_mapping[slot]) {
            repair_solution[slot] = compressed_recipe[slot];
          }
        }
        validated_mapping = repair_solution;
        validates = rar_mapping_validates(
            repair_solution, logical_blocks, layout.archive_size, trial);
      }
      else {
        const RarRepairResult repair = rar_repair_compressed_member(
            work, candidate, &layout, mapping, logical_blocks, trial,
            repair_solution, uuidp, uuidc, &iterations, false,
            UINT64_MAX, state, RAR_REPAIR_SCOPE_HYPOTHESIS, repair_pass,
            state->gap_ordinal, 0);

        if (repair == RAR_REPAIR_STOPPED) {
          goto interrupted;
        }
        state->resume_active = 0;
        if (repair == RAR_REPAIR_MATCH) {
          validated_mapping = repair_solution;
          validates = rar_mapping_validates(repair_solution, logical_blocks,
                                            layout.archive_size, trial);
        }
      }

      if (validates) {
        if (solutions == 0) {
          memcpy(solution, validated_mapping,
                 (size_t)logical_blocks * sizeof(*solution));
          solutions = 1;
        }
        else if (memcmp(solution, validated_mapping,
                        (size_t)logical_blocks * sizeof(*solution)) != 0) {
          solutions++;
          goto no_solution;
        }
      }
      have_hypothesis = rar_advance_gap_selection(
          regions, region_count, selection);
      if (have_hypothesis) {
        state->gap_ordinal++;
        if (selection_count > 0) {
          memcpy(rar_carve_state_selection(state), selection,
                 (size_t)selection_count * sizeof(*selection));
        }
      }
    }

next_repair_pass:
    state->repair_pass = repair_pass + 1;
    state->gap_ordinal = 0;
    state->probe_index = 0;
    state->selection_initialized = 0;
    state->prepass_complete = 0;
    state->resume_active = 0;
  }

  if (solutions == 1) {
    uint64_t validates_to = 0;

    rar_commit_mapping(*candidate, solution, logical_blocks,
                       layout.archive_size);
    if (reassembly_check_validation(work->id, *candidate, &validates_to,
                                    uuidp, uuidc)) {
      rar_layout_clear(&layout);
      rar_free_carve_state((void **)&state);
      free(trial);
      free(solution);
      free(compressed_recipe);
      free(repair_solution);
      free(best_mapping);
      free(mapping);
      free(selection);
      free(regions);
      free(physical_data);
      free(physical_mapping);
      rar_reassembly_release_memory(&memory_reservation);
      write_candidate(candidate, false);
      return;
    }
  }

no_solution:
  rar_layout_clear(&layout);
  rar_free_carve_state((void **)&state);
  free(trial);
  free(solution);
  free(compressed_recipe);
  free(repair_solution);
  free(best_mapping);
  free(mapping);
  free(selection);
  free(regions);
  free(physical_data);
  free(physical_mapping);
  rar_reassembly_release_memory(&memory_reservation);
  if (!candidate || !*candidate) {
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

interrupted:
  rar_layout_clear(&layout);
  rar_free_carve_state((void **)&state);
  free(trial);
  free(solution);
  free(compressed_recipe);
  free(repair_solution);
  free(best_mapping);
  free(mapping);
  free(selection);
  free(regions);
  free(physical_data);
  free(physical_mapping);
  rar_reassembly_release_memory(&memory_reservation);
}

// Fully decompress every archive entry. libarchive performs the format-specific
// decompression, file CRC, and optional BLAKE2 integrity checks. Completed entry
// count and output progress identify the strongest partial decode; consumed input
// is retained as a weaker hint because the decoder can read ahead before failing.
//
static inline bool rar_libarchive_validate(const uint8_t *data,
                                           uint64_t length,
                                           uint64_t *consumed,
                                           uint64_t *entries,
                                           uint64_t *output_progress,
                                           bool *encrypted,
                                           bool report_error) {

  struct archive *archive;
  struct archive_entry *entry;
  const void *output;
  size_t output_size;
  la_int64_t output_offset;
  la_int64_t expected_size;
  la_int64_t position;
  locale_t validation_locale;
  locale_t previous_locale = (locale_t)0;
  int result;
  bool clean = true;

  *consumed = 0;
  *entries = 0;
  *output_progress = 0;
  *encrypted = false;

  if (length > SIZE_MAX) {
    return false;
  }

  validation_locale = rar_get_utf8_locale();
  if (validation_locale != (locale_t)0) {
    previous_locale = uselocale(validation_locale);
  }

  archive = archive_read_new();
  if (!archive) {
    if (previous_locale != (locale_t)0) {
      uselocale(previous_locale);
    }
    return false;
  }

  if (archive_read_support_filter_none(archive) != ARCHIVE_OK
      || archive_read_support_format_rar(archive) != ARCHIVE_OK
      || archive_read_support_format_rar5(archive) != ARCHIVE_OK
      || archive_read_open_memory(archive, data, (size_t)length)
             != ARCHIVE_OK) {
    archive_read_free(archive);
    if (previous_locale != (locale_t)0) {
      uselocale(previous_locale);
    }
    return false;
  }

  while ((result = archive_read_next_header(archive, &entry)) == ARCHIVE_OK) {
    *output_progress = 0;
    if (archive_entry_is_encrypted(entry) > 0) {
      *encrypted = true;
      clean = false;
      break;
    }

    expected_size = archive_entry_size(entry);
    if (!archive_entry_size_is_set(entry) || expected_size < 0) {
      clean = false;
      break;
    }

    if (archive_entry_filetype(entry) == AE_IFDIR) {
      if (expected_size != 0) {
        clean = false;
      }
      result = ARCHIVE_EOF;
    }
    else {
      while ((result = archive_read_data_block(archive, &output,
                                                &output_size,
                                                &output_offset))
             == ARCHIVE_OK) {
        (void)output;
        if (output_offset < 0
            || (uint64_t)output_offset > UINT64_MAX - output_size) {
          clean = false;
          break;
        }
        if ((uint64_t)output_offset + output_size > *output_progress) {
          *output_progress = (uint64_t)output_offset + output_size;
        }
        position = archive_filter_bytes(archive, 0);
        if (position > 0 && (uint64_t)position > *consumed) {
          *consumed = (uint64_t)position;
        }
      }
    }

    position = archive_filter_bytes(archive, 0);
    if (position > 0 && (uint64_t)position > *consumed) {
      *consumed = (uint64_t)position;
    }

    if (!clean || result != ARCHIVE_EOF
        || *output_progress != (uint64_t)expected_size) {
      clean = false;
      break;
    }

    (*entries)++;
    *output_progress = 0;
  }

  position = archive_filter_bytes(archive, 0);
  if (position > 0 && (uint64_t)position > *consumed) {
    *consumed = (uint64_t)position;
  }

  if (archive_read_has_encrypted_entries(archive) > 0) {
    *encrypted = true;
    clean = false;
  }

  if (result != ARCHIVE_EOF) {
    clean = false;
  }

  if (!clean && report_error && scalpel_state.mode_verbose) {
    const char *message = archive_error_string(archive);

    lock_fprintf(stdout,
                 "RAR libarchive validation failed: result=%d, error=%s.\n",
                 result, message ? message : "none");
  }

  archive_read_close(archive);
  archive_read_free(archive);
  if (previous_locale != (locale_t)0) {
    uselocale(previous_locale);
  }
  return clean;
}

// Validate a RAR candidate and expose conservative progress for LR fragmented
// reassembly. Confidence from MoDiCo influences block ordering in the backend;
// it is never used as acceptance evidence here.
//
static inline void rar_file_validate(char *data, uint64_t length,
                                     bool *validates,
                                     uint64_t *validates_to,
                                     bool *promising, uint32_t needleidx,
                                     uint32_t blocksize,
                                     void *carvehashkey) {

  RarStructureResult structure;
  uint64_t consumed = 0;
  uint64_t entries = 0;
  uint64_t output_progress = 0;
  bool libarchive_encrypted = false;
  bool content_valid;
  bool decodable_prefix;

  (void)needleidx;
  (void)blocksize;
  (void)carvehashkey;

  *validates = false;
  *validates_to = 0;
  *promising = false;

  if (!data || length < RAR4_MAGIC_SIZE) {
    return;
  }

  rar_parse_structure((const uint8_t *)data, length, &structure);
  if (structure.status == RAR_STRUCTURE_INVALID) {
    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout,
                   "RAR structural validation failed: length=%" PRIu64
                   " version=%d headers=%" PRIu64 " files=%" PRIu64
                   " main=%d auxiliary=%d/%d.\n",
                   length, structure.version, structure.header_count,
                   structure.file_count, structure.seen_main,
                   structure.auxiliary_data_present,
                   structure.auxiliary_data_verified);
    }
    return;
  }

  *validates_to = structure.prefix_validates_to;
  *promising = structure.seen_main
               || structure.status == RAR_STRUCTURE_ENCRYPTED_HEADERS;

  content_valid = rar_libarchive_validate((const uint8_t *)data, length,
                                          &consumed, &entries,
                                          &output_progress,
                                          &libarchive_encrypted, true);
  decodable_prefix = structure.status == RAR_STRUCTURE_PARTIAL
                     && structure.version == RAR_VERSION_4
                     && structure.complete_prefix_size > 0
                     && structure.complete_prefix_size <= length
                     && structure.file_count > 0
                     && entries == structure.file_count
                     && consumed >= structure.complete_prefix_size
                     && !structure.encrypted && !libarchive_encrypted
                     && !structure.multivolume
                     && structure.auxiliary_data_verified;
  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout,
                 "RAR validation: status=%d version=%d size=%" PRIu64
                 " prefix=%" PRIu64
                 " files=%" PRIu64 " entries=%" PRIu64
                 " filedata=%d auxiliary=%d/%d"
                 " encrypted=%d/%d multivolume=%d"
                 " libarchive=%d consumed=%" PRIu64 ".\n",
                 structure.status, structure.version, structure.archive_size,
                 structure.complete_prefix_size,
                 structure.file_count, entries,
                 structure.all_file_data_verified,
                 structure.auxiliary_data_present,
                 structure.auxiliary_data_verified, structure.encrypted,
                 libarchive_encrypted, structure.multivolume, content_valid,
                 consumed);
  }
  if (!content_valid && !libarchive_encrypted
      && structure.status == RAR_STRUCTURE_COMPLETE
      && structure.auxiliary_data_verified
      && !structure.encrypted && !structure.multivolume
      && (structure.all_file_data_verified
          || entries == structure.file_count)) {
    content_valid = true;
  }
  if (structure.latest_file_header_present
      && entries >= structure.files_before_latest_file_header
      && structure.latest_file_header_validates_to > *validates_to) {
    *validates_to = structure.latest_file_header_validates_to;
  }

  // RAR4 permits EOF immediately after the last complete archive block. A
  // fully decoded prefix ending there is a complete archive even without an
  // end marker.
  if (decodable_prefix
      && structure.complete_prefix_size - 1 > *validates_to) {
    *validates_to = structure.complete_prefix_size - 1;
  }

  // Encrypted file data cannot be checked without a password, but a complete
  // chain of checksum-protected headers still proves the archive's exact
  // extent. Preserve that complete candidate as PROMISING rather than trimming
  // it to the last independently checkable file header.
  //
  if (structure.status == RAR_STRUCTURE_COMPLETE
      && (structure.encrypted || libarchive_encrypted)
      && structure.archive_size > 0) {
    *validates_to = structure.archive_size - 1;
  }

  if (structure.status == RAR_STRUCTURE_COMPLETE && content_valid
      && !structure.encrypted && !libarchive_encrypted
      && !structure.multivolume && structure.auxiliary_data_verified
      && structure.archive_size > 0) {
    *validates = true;
    *promising = false;
    *validates_to = structure.archive_size - 1;
  }
  else if (decodable_prefix) {
    *validates_to = structure.complete_prefix_size - 1;
    *validates = true;
    *promising = false;
  }
}

// Preserve the complete physical candidate before the generic contiguous
// validator trims a promising RAR to its checksum-protected prefix.
//
static inline void rar_candidate_validate(CarveInfo *candidate,
                                          bool *validates,
                                          uint64_t *validates_to,
                                          bool *promising) {

  (void)validates_to;

  if (!candidate || !candidate->b || !validates || !promising
      || *validates || !*promising || scalpel_state.blocksize == 0) {
    return;
  }
  RarCarveState *state = rar_capture_carve_state(candidate);

  rar_free_carve_state((void **)&state);
}

#endif
