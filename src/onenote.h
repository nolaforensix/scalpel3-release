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

#if !defined(SCALPEL_ONENOTE_H)
#define SCALPEL_ONENOTE_H

#include "scalpel.h"
#include "png.h"
#include "zip.h"

#include <limits.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#define ONENOTE_HEADER_SIZE UINT64_C(1024)
#define ONENOTE_MINIMUM_PACKAGE_SIZE UINT64_C(72)
#define ONENOTE_EXPECTED_LENGTH_OFFSET UINT64_C(196)
#define ONENOTE_ROOT_REFERENCE_OFFSET UINT64_C(172)
#define ONENOTE_PACKAGE_END_SIZE UINT64_C(4)
#define ONENOTE_FSS_MAXIMUM_DEPTH 128u
#define ONENOTE_FSS_ANY_OBJECT UINT16_MAX
#define ONENOTE_FSS_DATA_ELEMENT UINT16_C(0x01)
#define ONENOTE_FSS_DATA_ELEMENT_PACKAGE UINT16_C(0x15)
#define ONENOTE_FSS_ONENOTE_PACKAGING UINT16_C(0x7a)
#define ONENOTE_HASHED_REFERENCE_NODE UINT32_C(0x0c2)
#define ONENOTE_FILE_DATA_STORE_REFERENCE_NODE UINT32_C(0x094)
#define ONENOTE_READ_ONLY_REFERENCE_NODE UINT32_C(0x0c4)
#define ONENOTE_READ_ONLY_LARGE_REFERENCE_NODE UINT32_C(0x0c5)
#define ONENOTE_CHUNK_TERMINATOR_NODE UINT32_C(0x0ff)
#define ONENOTE_FILE_DATA_HEADER_SIZE UINT64_C(36)
#define ONENOTE_FILE_DATA_FOOTER_SIZE UINT64_C(16)
#define ONENOTE_PROPERTY_MAXIMUM_DEPTH 64u
#define ONENOTE_REASSEMBLY_SEAM_BYTES 256u
#define ONENOTE_REASSEMBLY_SEAM_BUFFER 640u
#define ONENOTE_REASSEMBLY_EXHAUSTIVE_GAP_BLOCKS 16u
#define ONENOTE_CARVE_STATE_MAGIC UINT32_C(0x4f4e5333)
#define ONENOTE_CARVE_STATE_VERSION UINT32_C(8)

typedef enum OneNoteKind {
  ONENOTE_KIND_NONE = 0,
  ONENOTE_KIND_SECTION,
  ONENOTE_KIND_TOC
} OneNoteKind;

typedef enum OneNoteStorage {
  ONENOTE_STORAGE_NONE = 0,
  ONENOTE_STORAGE_REVISION,
  ONENOTE_STORAGE_PACKAGE,
  ONENOTE_STORAGE_EMBEDDED_PACKAGE
} OneNoteStorage;

typedef enum OneNoteCachedValidation {
  ONENOTE_CACHED_FILE_DATA = 1,
  ONENOTE_CACHED_PROPERTY_SET
} OneNoteCachedValidation;

typedef struct OneNoteSummary {
  OneNoteKind kind;
  OneNoteStorage storage;
  uint64_t extent;
  uint64_t verified_to;
  uint64_t failure_offset;
  uint64_t failure_start;
  uint64_t failure_end;
  uint64_t authenticated_references;
  uint64_t integrity_references;
  uint64_t structural_references;
  bool no_memory;
} OneNoteSummary;

typedef struct OneNoteFSSObject {
  uint16_t type;
  uint64_t data_length;
  bool compound;
} OneNoteFSSObject;

typedef struct OneNoteReference {
  uint64_t offset;
  uint64_t size;
} OneNoteReference;

typedef struct OneNoteIntegrityCacheEntry {
  OneNoteReference reference;
  uint64_t failure_start;
  uint64_t failure_end;
  uint64_t structural_evidence;
  OneNoteCachedValidation validation;
  bool valid;
  bool integrity_evidence;
} OneNoteIntegrityCacheEntry;

typedef struct OneNoteZipProbe {
  ZipStateEntry entry;
  ZipDeflatePrefix prefix;
  uint64_t payload_offset;
  uint64_t payload_length;
  uint64_t baseline_failure;
  uint64_t baseline_output_distance;
  uint64_t patch_start;
  uint64_t patch_end;
  bool available;
  bool baseline_output_comparable;
  bool prefix_attempted;
} OneNoteZipProbe;

typedef struct OneNoteTargetPriority {
  uint64_t slot;
  uint64_t uniformity;
} OneNoteTargetPriority;

typedef struct OneNoteNodeCount {
  uint32_t list_id;
  uint32_t count;
} OneNoteNodeCount;

typedef struct OneNoteListIdentity {
  uint32_t list_id;
  uint64_t first_offset;
} OneNoteListIdentity;

typedef struct OneNoteFragmentIdentity {
  uint32_t list_id;
  uint32_t sequence;
  uint64_t offset;
} OneNoteFragmentIdentity;

typedef struct OneNoteRevisionState {
  const uint8_t *data;
  uint64_t length;
  uint64_t expected_length;
  OneNoteKind kind;
  OneNoteNodeCount *node_counts;
  uint64_t node_count_count;
  uint64_t node_count_capacity;
  OneNoteNodeCount *pending_counts;
  uint64_t pending_count;
  uint64_t pending_capacity;
  OneNoteReference *list_queue;
  uint64_t list_queue_count;
  uint64_t list_queue_capacity;
  OneNoteListIdentity *lists;
  uint64_t list_count;
  uint64_t list_capacity;
  OneNoteFragmentIdentity *fragments;
  uint64_t fragment_count;
  uint64_t fragment_capacity;
  OneNoteReference *transaction_fragments;
  uint64_t transaction_fragment_count;
  uint64_t transaction_fragment_capacity;
  OneNoteIntegrityCacheEntry *integrity_cache;
  uint64_t integrity_cache_count;
  uint64_t integrity_cache_capacity;
  OneNoteZipProbe zip_probe;
  EVP_MD_CTX *md5_context;
  uint64_t failure_offset;
  uint64_t failure_start;
  uint64_t failure_end;
  uint64_t authenticated_references;
  uint64_t integrity_references;
  uint64_t structural_references;
  uint64_t trial_start;
  uint64_t trial_end;
  uint64_t searched_end;
  bool trial_active;
  bool no_memory;
} OneNoteRevisionState;

typedef struct OneNoteRecoveryScore {
  OneNoteSummary summary;
  uint64_t overlapping_suffix_blocks;
  uint64_t contiguous_pairs;
  uint64_t seam_cost;
  uint64_t content_seam_cost;
  uint64_t reservations;
  uint64_t zip_output_distance;
  uint64_t run_start;
  uint64_t run_length;
  int64_t source;
  bool complete;
  bool found;
  bool zip_output_comparable;
  bool exact_run_boundaries;
} OneNoteRecoveryScore;

typedef enum OneNoteSearchPhase {
  ONENOTE_SEARCH_NONE = 0,
  ONENOTE_SEARCH_INTERIOR_SPANS = 1,
  ONENOTE_SEARCH_INTERIOR_SPANS_COMPLETE
} OneNoteSearchPhase;

typedef struct OneNoteAlignment {
  int64_t actual;
  uint64_t slot;
} OneNoteAlignment;

typedef enum OneNoteRepairPhase {
  ONENOTE_REPAIR_NONE = 0,
  ONENOTE_REPAIR_RUNS,
  ONENOTE_REPAIR_SUFFIXES,
  ONENOTE_REPAIR_ZERO_GAP,
  ONENOTE_REPAIR_ZERO_ISLAND,
  ONENOTE_REPAIR_PACKAGE_GAP,
  ONENOTE_REPAIR_PACKAGE_TAIL,
  ONENOTE_REPAIR_BOUNDARIES,
  ONENOTE_REPAIR_ZIP_SOURCES,
  ONENOTE_REPAIR_ZIP_EXTENSION,
  ONENOTE_REPAIR_ALIGNMENTS,
  ONENOTE_REPAIR_ANCHOR
} OneNoteRepairPhase;

typedef struct OneNoteRepairSearch {
  uint32_t phase;
  uint32_t pass;
  uint64_t run_length;
  uint64_t run_start;
  uint64_t next_source;
  uint64_t searched_end;
  uint64_t view;
  OneNoteRecoveryScore best;
  OneNoteRecoveryScore weak;
  OneNoteRecoveryScore local_best;
} OneNoteRepairSearch;

typedef struct OneNoteCarveState {
  uint32_t magic;
  uint32_t version;
  uint32_t phase;
  uint32_t reserved;
  uint64_t block_count;
  uint64_t data_length;
  uint64_t mapping_hash;
  uint64_t span_start;
  uint64_t run_start;
  uint64_t run_end;
  uint64_t overlapping_suffix_blocks;
  uint64_t reservations;
  uint64_t alignment_count;
  uint32_t progress_valid;
  uint32_t exact_run_boundaries;
  uint64_t span_view;
  OneNoteRepairSearch repair;
  OneNoteAlignment *alignments;
} OneNoteCarveState;

static inline uint32_t onenote_read_le32(const uint8_t *data);
static inline uint64_t onenote_read_le64(const uint8_t *data);
static inline uint32_t onenote_read_be32(const uint8_t *data);
static inline OneNoteKind onenote_file_kind(const uint8_t *data,
                                            uint64_t length);
static inline bool onenote_embedded_package_offset(
    const uint8_t *data, uint64_t length, uint64_t *offset);
static inline OneNoteStorage onenote_storage_kind(const uint8_t *data,
                                                  uint64_t length);
static inline bool onenote_range_available(uint64_t length,
                                           uint64_t offset,
                                           uint64_t size);
static inline bool onenote_exguid_size(const uint8_t *data, uint64_t length,
                                       uint64_t *size);
static inline bool onenote_compact_u64_read(const uint8_t *data,
                                            uint64_t length,
                                            uint64_t *cursor,
                                            uint64_t *value);
static inline bool onenote_fss_header_read(const uint8_t *data,
                                           uint64_t length,
                                           uint64_t *cursor,
                                           OneNoteFSSObject *object);
static inline bool onenote_fss_end_read(const uint8_t *data,
                                        uint64_t length,
                                        uint64_t *cursor,
                                        uint16_t *type);
static inline bool onenote_fss_object_validate(const uint8_t *data,
                                               uint64_t length,
                                               uint64_t *cursor,
                                               uint16_t expected_type,
                                               bool require_compound,
                                               uint32_t depth);
static inline bool onenote_package_extent_validate(const uint8_t *data,
                                                   uint64_t length,
                                                   OneNoteKind kind,
                                                   uint64_t *extent);
static inline bool onenote_revision_reserve(void **items,
                                            uint64_t item_size,
                                            uint64_t needed,
                                            uint64_t *capacity);
static inline bool onenote_reference_is_nil_or_zero(
    OneNoteReference reference);
static inline bool onenote_revision_range_validate(
    OneNoteRevisionState *state, OneNoteReference reference);
static inline bool onenote_revision_node_count_set(
    OneNoteRevisionState *state, uint32_t list_id, uint32_t count);
static inline bool onenote_revision_node_count_get(
    const OneNoteRevisionState *state, uint32_t list_id, uint32_t *count);
static inline bool onenote_revision_queue_list(
    OneNoteRevisionState *state, OneNoteReference reference);
static inline bool onenote_revision_record_list(
    OneNoteRevisionState *state, uint32_t list_id, uint64_t first_offset);
static inline bool onenote_revision_record_fragment(
    OneNoteRevisionState *state, uint32_t list_id, uint32_t sequence,
    uint64_t offset);
static inline bool onenote_revision_md5_matches(
    OneNoteRevisionState *state, OneNoteReference reference,
    const uint8_t expected[16]);
static inline void onenote_revision_failure_set(
    OneNoteRevisionState *state, uint64_t first, uint64_t last);
static inline bool onenote_revision_integrity_cache_get(
    OneNoteRevisionState *state, OneNoteReference reference,
    OneNoteCachedValidation validation, bool *valid);
static inline void onenote_revision_integrity_cache_put(
    OneNoteRevisionState *state, OneNoteReference reference,
    OneNoteCachedValidation validation, bool valid,
    bool integrity_evidence, uint64_t structural_evidence);
static inline void onenote_revision_zip_probe_clear(
    OneNoteRevisionState *state);
static inline void onenote_revision_zip_probe_record(
    OneNoteRevisionState *state, uint64_t payload_offset,
    uint64_t payload_length, uint64_t failure_offset,
    uint64_t failure_entry, const ZipLayout *layout);
static inline bool onenote_revision_zip_probe_trial(
    OneNoteRevisionState *state, const uint8_t *data,
    uint64_t trial_start, uint64_t trial_end,
    bool *valid, uint64_t *failure_offset,
    bool *output_comparable, uint64_t *output_distance);
static inline bool onenote_revision_property_advance(
    OneNoteRevisionState *state, uint64_t *cursor, uint64_t limit,
    uint64_t size);
static inline bool onenote_revision_object_stream_skip(
    OneNoteRevisionState *state, uint64_t *cursor, uint64_t limit,
    bool *extended_streams_present, bool *osid_stream_not_present,
    uint64_t *structural_evidence);
static inline bool onenote_revision_property_set_read(
    OneNoteRevisionState *state, uint64_t *cursor, uint64_t limit,
    uint32_t depth, uint64_t *structural_evidence);
static inline bool onenote_revision_object_property_set_validate(
    OneNoteRevisionState *state, OneNoteReference reference);
static inline bool onenote_revision_png_validate(
    OneNoteRevisionState *state, const uint8_t *payload,
    uint64_t payload_length, uint64_t payload_offset);
static inline bool onenote_revision_file_data_validate(
    OneNoteRevisionState *state, OneNoteReference reference);
static inline bool onenote_revision_node_definition_validate(
    OneNoteKind kind, uint32_t node_id, uint32_t base_type,
    uint32_t cb_format);
static inline bool onenote_revision_node_reference_read(
    const uint8_t *data, uint64_t limit, uint64_t *cursor,
    uint32_t stp_format, uint32_t cb_format, OneNoteReference *reference);
static inline bool onenote_revision_transaction_log_validate(
    OneNoteRevisionState *state, OneNoteReference first,
    uint32_t transaction_count);
static inline bool onenote_revision_file_node_list_validate(
    OneNoteRevisionState *state, OneNoteReference first);
static inline bool onenote_revision_free_chunk_list_validate(
    OneNoteRevisionState *state, OneNoteReference first);
static inline void onenote_revision_state_release(
    OneNoteRevisionState *state);
static inline bool onenote_revision_header_validate(const uint8_t *data,
                                                    uint64_t length,
                                                    OneNoteKind kind,
                                                    OneNoteSummary *summary,
                                                    OneNoteRevisionState *workspace);
static inline bool onenote_package_header_validate(const uint8_t *data,
                                                   uint64_t length,
                                                   OneNoteKind kind,
                                                   OneNoteSummary *summary);
static inline bool onenote_parse(const uint8_t *data, uint64_t length,
                                 OneNoteKind required_kind,
                                 OneNoteSummary *summary);
static inline bool onenote_parse_with_workspace(
    const uint8_t *data, uint64_t length, OneNoteKind required_kind,
    OneNoteSummary *summary, OneNoteRevisionState *workspace);
static inline char *onenote_header_discovery_kind(
    char *base, uint64_t offset, uint64_t remaining, char **matchpos,
    uint32_t *matchlen, OneNoteKind required_kind);
static inline char *onenote_section_header_discovery(
    char *base, uint64_t offset, uint64_t remaining, char **matchpos,
    uint32_t *matchlen, uint32_t blocksize);
static inline char *onenote_toc_header_discovery(
    char *base, uint64_t offset, uint64_t remaining, char **matchpos,
    uint32_t *matchlen, uint32_t blocksize);
static inline char *onenote_footer_discovery_kind(
    char *base, uint64_t offset, uint64_t remaining, char **matchpos,
    uint32_t *matchlen, OneNoteKind required_kind);
static inline char *onenote_section_footer_discovery(
    char *base, uint64_t offset, uint64_t remaining, char **matchpos,
    uint32_t *matchlen, uint32_t blocksize);
static inline char *onenote_toc_footer_discovery(
    char *base, uint64_t offset, uint64_t remaining, char **matchpos,
    uint32_t *matchlen, uint32_t blocksize);
static inline void onenote_file_validate_kind(
    char *data, uint64_t length, bool *validates, uint64_t *validates_to,
    bool *promising, OneNoteKind required_kind);
static inline void onenote_section_file_validate(
    char *data, uint64_t length, bool *validates, uint64_t *validates_to,
    bool *promising, uint32_t needleidx, uint32_t blocksize,
    void *carvehashkey);
static inline void onenote_toc_file_validate(
    char *data, uint64_t length, bool *validates, uint64_t *validates_to,
    bool *promising, uint32_t needleidx, uint32_t blocksize,
    void *carvehashkey);
static inline void onenote_candidate_validate(CarveInfo *candidate,
                                              bool *validates,
                                              uint64_t *validates_to,
                                              bool *promising);
static inline bool onenote_serialize_carve_state(
    void **state, FILE *fp, StateSerialization mode);
static inline void *onenote_clone_carve_state(const void *srcstate);
static inline void onenote_free_carve_state(void **state);
static inline size_t onenote_sizeof_carve_state(const void *state);
static inline void onenote_print_carve_state(const void *state);
static inline uint64_t onenote_reassembly_mapping_hash(
    const int64_t *mapping, uint64_t block_count);
static inline void onenote_reassembly_remember_alignment(
    OneNoteCarveState *state, int64_t actual, uint64_t slot);
static inline OneNoteCarveState *onenote_reassembly_progress_state(
    CarveInfo *candidate, const int64_t *mapping, uint64_t block_count,
    uint64_t data_length);
static inline void onenote_reassembly_restore_progress(
    CarveInfo *candidate, const int64_t *mapping, uint64_t block_count,
    uint64_t data_length, OneNoteRecoveryScore *current,
    int64_t **displacements, uint64_t *count, uint64_t *capacity);
static inline void onenote_reassembly_commit_progress(
    CarveInfo *candidate, const int64_t *mapping, uint64_t block_count,
    uint64_t data_length, const OneNoteRecoveryScore *current,
    const OneNoteRecoveryScore *placement, bool new_alignment);
static inline uint64_t onenote_reassembly_span_view(
    const int64_t *mapping, uint64_t block_count);
static inline bool onenote_reassembly_score_valid(
    const OneNoteRecoveryScore *score, uint64_t block_count);
static inline uint64_t onenote_reassembly_search_view(uint64_t end);
static inline uint64_t onenote_reassembly_search_scope(
    const OneNoteCarveState *state, const OneNoteRepairSearch *search);
static inline OneNoteRepairSearch onenote_reassembly_load_search(
    CarveInfo *candidate);
static inline bool onenote_reassembly_search_poll(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, OneNoteRepairSearch *search,
    const OneNoteRevisionState *workspace);
static inline bool onenote_reassembly_search_zero(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, uint8_t *trial_data, const int64_t *mapping,
    uint8_t *used, uint64_t block_count, uint64_t data_length,
    OneNoteKind kind, uint64_t failure_start_slot, uint64_t failure_end_slot,
    const OneNoteRecoveryScore *current, OneNoteRecoveryScore *best,
    OneNoteRevisionState *workspace, OneNoteRepairSearch *search);
static inline bool onenote_reassembly_search_zip(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, uint8_t *trial_data, const int64_t *mapping,
    uint8_t *used, uint64_t block_count, uint64_t data_length,
    OneNoteKind kind, uint64_t failure_start_slot, uint64_t failure_end_slot,
    const OneNoteRecoveryScore *current, OneNoteRecoveryScore *best,
    OneNoteRevisionState *workspace, OneNoteRepairSearch *search);
static inline bool onenote_reassembly_search_boundaries(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, uint8_t *trial_data, const int64_t *mapping,
    uint8_t *used, uint64_t block_count, uint64_t data_length,
    OneNoteKind kind, const OneNoteRecoveryScore *current,
    OneNoteRecoveryScore *best, const int64_t *displacements,
    uint64_t displacement_count, OneNoteRevisionState *workspace,
    OneNoteRepairSearch *search);
static inline bool onenote_reassembly_search_alignments(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, uint8_t *trial_data, const int64_t *mapping,
    uint8_t *used, uint64_t block_count, uint64_t data_length,
    OneNoteKind kind, uint64_t failure_start_slot, uint64_t failure_end_slot,
    uint64_t failure_slot, const OneNoteRecoveryScore *current,
    OneNoteRecoveryScore *best, const int64_t *displacements,
    uint64_t displacement_count, OneNoteRevisionState *workspace,
    OneNoteRepairSearch *search);
static inline bool onenote_reassembly_search_runs(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, uint8_t *trial_data, const int64_t *mapping,
    uint8_t *used, uint64_t block_count, uint64_t data_length,
    OneNoteKind kind, uint64_t failure_start, uint64_t failure_end,
    uint64_t failure_slot, const OneNoteRecoveryScore *current,
    OneNoteRecoveryScore *best, OneNoteRecoveryScore *weak,
    OneNoteRevisionState *workspace, OneNoteRepairSearch *search);
static inline bool onenote_reassembly_poll(ThreadWork *work,
                                           CarveInfo **candidate,
                                           uuid_string_t uuidp,
                                           uuid_string_t uuidc);
static inline bool onenote_reassembly_copy_block(uint8_t *destination,
                                                 int64_t apparent);
static inline bool onenote_reassembly_materialize(uint8_t *data,
                                                  const int64_t *mapping,
                                                  uint64_t block_count);
static inline uint64_t onenote_reassembly_uniformity(
    const uint8_t *data, uint64_t length);
static inline bool onenote_reassembly_score_better(
    const OneNoteRecoveryScore *trial,
    const OneNoteRecoveryScore *best);
static inline bool onenote_reassembly_parser_progress(
    const OneNoteRecoveryScore *current, const OneNoteSummary *summary,
    bool complete, bool zip_output_comparable,
    uint64_t zip_output_distance);
static inline bool onenote_reassembly_evidence_progress(
    const OneNoteRecoveryScore *current,
    const OneNoteRecoveryScore *trial);
static inline void onenote_reassembly_score_layout(
    const uint8_t *data, const int64_t *mapping, uint64_t block_count,
    uint64_t run_start, uint64_t run_length, int64_t source,
    OneNoteRecoveryScore *score);
static inline uint64_t onenote_reassembly_content_seam_cost(
    const uint8_t *data, uint64_t block_count);
static inline bool onenote_reassembly_try_run(
    uint8_t *trial_data, const int64_t *mapping, const uint8_t *used,
    uint64_t block_count, uint64_t data_length, OneNoteKind kind,
    uint64_t run_start, uint64_t run_length, int64_t source,
    const OneNoteRecoveryScore *current, OneNoteRecoveryScore *best,
    bool restore_data, OneNoteRecoveryScore *observed,
    OneNoteRevisionState *workspace, bool confirm_progress);
static inline void onenote_reassembly_probe_run(
    uint8_t *trial_data, const int64_t *mapping, const uint8_t *used,
    uint64_t block_count, uint64_t data_length, OneNoteKind kind,
    uint64_t run_start, uint64_t run_length, int64_t source,
    const OneNoteRecoveryScore *current, OneNoteRecoveryScore *strong,
    OneNoteRecoveryScore *weak, bool restore_data,
    OneNoteRevisionState *workspace);
static inline bool onenote_reassembly_try_alignment(
    uint8_t *trial_data, const int64_t *mapping, uint8_t *used,
    uint64_t block_count, uint64_t data_length, OneNoteKind kind,
    uint64_t failure_start, uint64_t failure_end,
    uint64_t failure_slot, int64_t failure_source,
    const OneNoteRecoveryScore *current, OneNoteRecoveryScore *best,
    OneNoteRecoveryScore *observed, OneNoteRevisionState *workspace,
    bool confirm_progress);
static inline void onenote_reassembly_apply_run(
    CarveInfo *candidate, int64_t *mapping, uint8_t *used,
    uint8_t *trial_data, const OneNoteRecoveryScore *recovery);
static inline void onenote_reassembly_preserve_run(
    CarveInfo **candidate, const int64_t *mapping, uint64_t block_count,
    uint64_t data_length, const OneNoteRecoveryScore *recovery);
static inline void onenote_reassembly_preserve_mapping(
    CarveInfo **candidate, const int64_t *mapping,
    const int64_t *alternative, uint64_t block_count,
    uint64_t data_length);
static inline bool onenote_reassembly_preserve_interior_spans(
    ThreadWork *work, CarveInfo **candidate,
    uuid_string_t uuidp, uuid_string_t uuidc, uint8_t *trial_data,
    const int64_t *mapping, uint8_t *used, uint64_t block_count,
    uint64_t data_length, OneNoteKind kind,
    const OneNoteRecoveryScore *current,
    OneNoteRevisionState *workspace);
static inline void onenote_package_reassembly(
    ThreadWork *work, CarveInfo **candidate,
    uuid_string_t uuidp, uuid_string_t uuidc);
static inline void onenote_reassembly(ThreadWork *work,
                                      CarveInfo **candidate,
                                      uuid_string_t uuidp,
                                      uuid_string_t uuidc);

static const uint8_t ONENOTE_SECTION_GUID[16] = {
  0xe4, 0x52, 0x5c, 0x7b, 0x8c, 0xd8, 0xa7, 0x4d,
  0xae, 0xb1, 0x53, 0x78, 0xd0, 0x29, 0x96, 0xd3
};

static const uint8_t ONENOTE_TOC_GUID[16] = {
  0xa1, 0x2f, 0xff, 0x43, 0xd9, 0xef, 0x76, 0x4c,
  0x9e, 0xe2, 0x10, 0xea, 0x57, 0x22, 0x76, 0x5f
};

static const uint8_t ONENOTE_REVISION_GUID[16] = {
  0x3f, 0xdd, 0x9a, 0x10, 0x1b, 0x91, 0xf5, 0x49,
  0xa5, 0xd0, 0x17, 0x91, 0xed, 0xc8, 0xae, 0xd8
};

static const uint8_t ONENOTE_PACKAGE_GUID[16] = {
  0x2f, 0xe9, 0x8d, 0x63, 0xd4, 0xa6, 0xc1, 0x4b,
  0x9a, 0x36, 0xb3, 0xfc, 0x25, 0x11, 0xa5, 0xb7
};

static const uint8_t ONENOTE_SECTION_SCHEMA_GUID[16] = {
  0xb4, 0x7c, 0x93, 0x1f, 0x6f, 0xb2, 0x5f, 0x44,
  0xb9, 0xf8, 0x17, 0xe2, 0x01, 0x60, 0xe4, 0x61
};

static const uint8_t ONENOTE_TOC_SCHEMA_GUID[16] = {
  0x38, 0xfd, 0xdb, 0xe4, 0xc7, 0xe5, 0x8b, 0x40,
  0xa8, 0xa1, 0x0e, 0x7b, 0x42, 0x1e, 0x1f, 0x5f
};

static const uint8_t ONENOTE_FILE_NODE_MAGIC[8] = {
  0xc4, 0xf4, 0xf7, 0xf5, 0xb1, 0x7a, 0x56, 0xa4
};

static const uint8_t ONENOTE_FILE_NODE_FOOTER[8] = {
  0x4b, 0xba, 0x33, 0x82, 0xc3, 0x15, 0xc2, 0x8b
};

static const uint8_t ONENOTE_FILE_DATA_HEADER_GUID[16] = {
  0xe7, 0x16, 0xe3, 0xbd, 0x65, 0x26, 0x11, 0x45,
  0xa4, 0xc4, 0x8d, 0x4d, 0x0b, 0x7a, 0x9e, 0xac
};

static const uint8_t ONENOTE_FILE_DATA_FOOTER_GUID[16] = {
  0x22, 0xa7, 0xfb, 0x71, 0x79, 0x0f, 0x0b, 0x4a,
  0xbb, 0x13, 0x89, 0x92, 0x56, 0x42, 0x6b, 0x24
};

static const uint8_t ONENOTE_PNG_SIGNATURE[8] = {
  0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a
};

static inline uint32_t onenote_read_le32(const uint8_t *data) {

  return (uint32_t)data[0]
         | ((uint32_t)data[1] << 8)
         | ((uint32_t)data[2] << 16)
         | ((uint32_t)data[3] << 24);
}

static inline uint64_t onenote_read_le64(const uint8_t *data) {

  return (uint64_t)onenote_read_le32(data)
         | ((uint64_t)onenote_read_le32(data + 4) << 32);
}

static inline uint32_t onenote_read_be32(const uint8_t *data) {

  return ((uint32_t)data[0] << 24)
         | ((uint32_t)data[1] << 16)
         | ((uint32_t)data[2] << 8)
         | (uint32_t)data[3];
}

// Some OneDrive files retain a revision-store header and place the active
// FSSHTTPB package immediately after the first transaction-log fragment.
static inline bool onenote_embedded_package_offset(
    const uint8_t *data, uint64_t length, uint64_t *offset) {

  if (!data || !offset || length < ONENOTE_HEADER_SIZE
      || memcmp(data + 48, ONENOTE_REVISION_GUID,
                sizeof(ONENOTE_REVISION_GUID)) != 0
      || onenote_read_le64(data + ONENOTE_EXPECTED_LENGTH_OFFSET) != 0) {
    return false;
  }
  for (uint64_t index = 32; index < 48; index++) {
    if (data[index] != 0) {
      return false;
    }
  }

  const uint64_t transaction_offset = onenote_read_le64(data + 160);
  const uint64_t transaction_length = onenote_read_le32(data + 168);

  if (transaction_offset > length
      || transaction_length > length - transaction_offset) {
    return false;
  }
  const uint64_t package_offset = transaction_offset + transaction_length;

  if (package_offset > length || length - package_offset < 64
      || memcmp(data + package_offset + 48, ONENOTE_PACKAGE_GUID,
                sizeof(ONENOTE_PACKAGE_GUID)) != 0) {
    return false;
  }
  *offset = package_offset;
  return true;
}

static inline OneNoteKind onenote_file_kind(const uint8_t *data,
                                            uint64_t length) {

  if (!data || length < 64) {
    return ONENOTE_KIND_NONE;
  }
  if (memcmp(data, ONENOTE_SECTION_GUID, sizeof(ONENOTE_SECTION_GUID)) == 0) {
    if (memcmp(data + 48, ONENOTE_PACKAGE_GUID,
               sizeof(ONENOTE_PACKAGE_GUID)) == 0) {
      const uint64_t schema_limit = length < 160 ? length : 160;

      for (uint64_t offset = 64;
           offset + sizeof(ONENOTE_SECTION_SCHEMA_GUID) <= schema_limit;
           offset++) {
        if (memcmp(data + offset, ONENOTE_SECTION_SCHEMA_GUID,
                   sizeof(ONENOTE_SECTION_SCHEMA_GUID)) == 0) {
          return ONENOTE_KIND_SECTION;
        }
        if (memcmp(data + offset, ONENOTE_TOC_SCHEMA_GUID,
                   sizeof(ONENOTE_TOC_SCHEMA_GUID)) == 0) {
          return ONENOTE_KIND_TOC;
        }
      }
      return ONENOTE_KIND_NONE;
    }
    return ONENOTE_KIND_SECTION;
  }
  if (memcmp(data, ONENOTE_TOC_GUID, sizeof(ONENOTE_TOC_GUID)) == 0) {
    return ONENOTE_KIND_TOC;
  }
  return ONENOTE_KIND_NONE;
}

static inline OneNoteStorage onenote_storage_kind(const uint8_t *data,
                                                  uint64_t length) {

  if (!data || length < 64) {
    return ONENOTE_STORAGE_NONE;
  }
  if (memcmp(data + 48, ONENOTE_REVISION_GUID,
             sizeof(ONENOTE_REVISION_GUID)) == 0) {
    uint64_t package_offset = 0;

    if (onenote_embedded_package_offset(data, length, &package_offset)) {
      return ONENOTE_STORAGE_EMBEDDED_PACKAGE;
    }
    return ONENOTE_STORAGE_REVISION;
  }
  if (memcmp(data + 48, ONENOTE_PACKAGE_GUID,
             sizeof(ONENOTE_PACKAGE_GUID)) == 0) {
    return ONENOTE_STORAGE_PACKAGE;
  }
  return ONENOTE_STORAGE_NONE;
}

static inline bool onenote_range_available(uint64_t length,
                                           uint64_t offset,
                                           uint64_t size) {

  return offset <= length && size <= length - offset;
}

static inline bool onenote_exguid_size(const uint8_t *data, uint64_t length,
                                       uint64_t *size) {

  if (!data || !size || length == 0) {
    return false;
  }
  if (data[0] == 0) {
    *size = 1;
    return true;
  }
  if ((data[0] & 0x07u) == 0x04u) {
    *size = 17;
  } else if ((data[0] & 0x3fu) == 0x20u) {
    *size = 18;
  } else if ((data[0] & 0x7fu) == 0x40u) {
    *size = 19;
  } else if (data[0] == 0x80u) {
    *size = 21;
  } else {
    return false;
  }
  return *size <= length;
}

static inline bool onenote_compact_u64_read(const uint8_t *data,
                                            uint64_t length,
                                            uint64_t *cursor,
                                            uint64_t *value) {

  if (!data || !cursor || !value || *cursor >= length) {
    return false;
  }

  const uint8_t first = data[*cursor];

  if (first == 0) {
    *value = 0;
    (*cursor)++;
    return true;
  }

  uint32_t width = 0;

  for (uint32_t bit = 0; bit < 7; bit++) {
    if ((first & (uint8_t)(1u << bit)) != 0) {
      width = bit + 1;
      break;
    }
  }
  if (width != 0) {
    if (!onenote_range_available(length, *cursor, width)) {
      return false;
    }

    uint64_t encoded = 0;

    for (uint32_t index = 0; index < width; index++) {
      encoded |= (uint64_t)data[*cursor + index] << (index * 8);
    }
    *value = encoded >> width;
    *cursor += width;
    return true;
  }
  if (!onenote_range_available(length, *cursor, 9)) {
    return false;
  }
  *value = onenote_read_le64(data + *cursor + 1);
  *cursor += 9;
  return true;
}

static inline bool onenote_fss_header_read(const uint8_t *data,
                                           uint64_t length,
                                           uint64_t *cursor,
                                           OneNoteFSSObject *object) {

  if (!data || !cursor || !object || *cursor >= length) {
    return false;
  }

  const uint8_t header_type = data[*cursor] & 0x03u;

  if (header_type == 0) {
    if (!onenote_range_available(length, *cursor, 2)) {
      return false;
    }

    const uint16_t encoded = (uint16_t)data[*cursor]
        | ((uint16_t)data[*cursor + 1] << 8);

    object->compound = (encoded & 0x04u) != 0;
    object->type = (encoded >> 3) & 0x3fu;
    object->data_length = encoded >> 9;
    *cursor += 2;
    return true;
  }
  if (header_type != 2
      || !onenote_range_available(length, *cursor, 4)) {
    return false;
  }

  const uint32_t encoded = onenote_read_le32(data + *cursor);

  object->compound = (encoded & 0x04u) != 0;
  object->type = (uint16_t)((encoded >> 3) & 0x3fffu);
  object->data_length = encoded >> 17;
  *cursor += 4;
  if (object->data_length == 0x7fffu
      && !onenote_compact_u64_read(data, length, cursor,
                                   &object->data_length)) {
    return false;
  }
  return true;
}

static inline bool onenote_fss_end_read(const uint8_t *data,
                                        uint64_t length,
                                        uint64_t *cursor,
                                        uint16_t *type) {

  if (!data || !cursor || !type || *cursor >= length) {
    return false;
  }

  const uint8_t header_type = data[*cursor] & 0x03u;

  if (header_type == 1) {
    *type = data[*cursor] >> 2;
    (*cursor)++;
    return true;
  }
  if (header_type != 3
      || !onenote_range_available(length, *cursor, 2)) {
    return false;
  }

  *type = ((uint16_t)data[*cursor]
           | ((uint16_t)data[*cursor + 1] << 8)) >> 2;
  *cursor += 2;
  return true;
}

// Walk one FSSHTTPB stream object. Object lengths skip opaque payload bytes,
// while compound objects recursively validate their matching end records.
//
static inline bool onenote_fss_object_validate(const uint8_t *data,
                                               uint64_t length,
                                               uint64_t *cursor,
                                               uint16_t expected_type,
                                               bool require_compound,
                                               uint32_t depth) {

  if (!data || !cursor || depth >= ONENOTE_FSS_MAXIMUM_DEPTH) {
    return false;
  }

  OneNoteFSSObject object;

  if (!onenote_fss_header_read(data, length, cursor, &object)
      || (expected_type != ONENOTE_FSS_ANY_OBJECT
          && object.type != expected_type)
      || (require_compound && !object.compound)
      || !onenote_range_available(length, *cursor, object.data_length)) {
    return false;
  }
  *cursor += object.data_length;
  if (!object.compound) {
    return true;
  }

  while (*cursor < length) {
    uint64_t end_cursor = *cursor;
    uint16_t end_type = 0;

    if (onenote_fss_end_read(data, length, &end_cursor, &end_type)) {
      if (end_type != object.type) {
        return false;
      }
      *cursor = end_cursor;
      return true;
    }
    if (!onenote_fss_object_validate(data, length, cursor,
                                     ONENOTE_FSS_ANY_OBJECT, false,
                                     depth + 1)) {
      return false;
    }
  }
  return false;
}

// Validate the nested OneNotePackaging and DataElementPackage structures and
// return the exact end of the package stream.
//
static inline bool onenote_package_extent_validate(const uint8_t *data,
                                                   uint64_t length,
                                                   OneNoteKind kind,
                                                   uint64_t *extent) {

  if (!data || !extent || length < ONENOTE_MINIMUM_PACKAGE_SIZE
      || onenote_read_le32(data + 64) != 0
      || onenote_file_kind(data, length) != kind) {
    return false;
  }

  uint64_t cursor = 68;
  OneNoteFSSObject packaging;

  if (!onenote_fss_header_read(data, length, &cursor, &packaging)
      || packaging.type != ONENOTE_FSS_ONENOTE_PACKAGING
      || !packaging.compound
      || !onenote_range_available(length, cursor, packaging.data_length)) {
    return false;
  }

  uint64_t storage_index_size = 0;

  if (!onenote_exguid_size(data + cursor, packaging.data_length,
                           &storage_index_size)
      || packaging.data_length != storage_index_size + 16) {
    return false;
  }

  const uint8_t *expected_schema = kind == ONENOTE_KIND_SECTION
      ? ONENOTE_SECTION_SCHEMA_GUID : ONENOTE_TOC_SCHEMA_GUID;

  if (memcmp(data + cursor + storage_index_size, expected_schema, 16) != 0) {
    return false;
  }
  cursor += packaging.data_length;

  OneNoteFSSObject package;

  if (!onenote_fss_header_read(data, length, &cursor, &package)
      || package.type != ONENOTE_FSS_DATA_ELEMENT_PACKAGE
      || !package.compound || package.data_length != 1
      || !onenote_range_available(length, cursor, 1)
      || data[cursor] != 0) {
    return false;
  }
  cursor++;

  while (cursor < length) {
    uint64_t end_cursor = cursor;
    uint16_t end_type = 0;

    if (onenote_fss_end_read(data, length, &end_cursor, &end_type)) {
      if (end_type != ONENOTE_FSS_DATA_ELEMENT_PACKAGE) {
        return false;
      }
      cursor = end_cursor;
      break;
    }
    if (!onenote_fss_object_validate(data, length, &cursor,
                                     ONENOTE_FSS_DATA_ELEMENT, true, 0)) {
      return false;
    }
  }

  uint16_t end_type = 0;

  if (!onenote_fss_end_read(data, length, &cursor, &end_type)
      || end_type != ONENOTE_FSS_ONENOTE_PACKAGING) {
    return false;
  }
  *extent = cursor;
  return true;
}

static inline bool onenote_revision_reserve(void **items,
                                            uint64_t item_size,
                                            uint64_t needed,
                                            uint64_t *capacity) {

  if (!items || !capacity || item_size == 0) {
    return false;
  }
  if (needed <= *capacity) {
    return true;
  }

  uint64_t new_capacity = *capacity == 0 ? 16 : *capacity;

  while (new_capacity < needed) {
    if (new_capacity > UINT64_MAX / 2) {
      return false;
    }
    new_capacity *= 2;
  }
  if (new_capacity > SIZE_MAX / item_size) {
    return false;
  }

  void *grown = realloc(*items, (size_t)(new_capacity * item_size));

  if (!grown) {
    return false;
  }
  *items = grown;
  *capacity = new_capacity;
  return true;
}

static inline bool onenote_reference_is_nil_or_zero(
    OneNoteReference reference) {

  return reference.size == 0
         && (reference.offset == 0
             || reference.offset == UINT64_MAX);
}

static inline bool onenote_revision_range_validate(
    OneNoteRevisionState *state, OneNoteReference reference) {

  if (!state || reference.offset > state->expected_length
      || reference.size > state->expected_length - reference.offset
      || reference.offset > state->length
      || reference.size > state->length - reference.offset) {
    return false;
  }
  return true;
}

static inline bool onenote_revision_node_count_set(
    OneNoteRevisionState *state, uint32_t list_id, uint32_t count) {

  if (!state) {
    return false;
  }
  for (uint64_t index = 0; index < state->node_count_count; index++) {
    if (state->node_counts[index].list_id == list_id) {
      state->node_counts[index].count = count;
      return true;
    }
  }
  if (!onenote_revision_reserve(
          (void **)&state->node_counts, sizeof(*state->node_counts),
          state->node_count_count + 1, &state->node_count_capacity)) {
    state->no_memory = true;
    return false;
  }
  state->node_counts[state->node_count_count].list_id = list_id;
  state->node_counts[state->node_count_count].count = count;
  state->node_count_count++;
  return true;
}

static inline bool onenote_revision_node_count_get(
    const OneNoteRevisionState *state, uint32_t list_id, uint32_t *count) {

  if (!state || !count) {
    return false;
  }
  for (uint64_t index = 0; index < state->node_count_count; index++) {
    if (state->node_counts[index].list_id == list_id) {
      *count = state->node_counts[index].count;
      return true;
    }
  }
  return false;
}

static inline bool onenote_revision_queue_list(
    OneNoteRevisionState *state, OneNoteReference reference) {

  if (!state || onenote_reference_is_nil_or_zero(reference)
      || !onenote_revision_range_validate(state, reference)) {
    return false;
  }
  if (!onenote_revision_reserve(
          (void **)&state->list_queue, sizeof(*state->list_queue),
          state->list_queue_count + 1, &state->list_queue_capacity)) {
    state->no_memory = true;
    return false;
  }
  state->list_queue[state->list_queue_count++] = reference;
  return true;
}

static inline bool onenote_revision_record_list(
    OneNoteRevisionState *state, uint32_t list_id, uint64_t first_offset) {

  if (!state) {
    return false;
  }
  for (uint64_t index = 0; index < state->list_count; index++) {
    if (state->lists[index].list_id == list_id
        || state->lists[index].first_offset == first_offset) {
      return false;
    }
  }
  if (!onenote_revision_reserve(
          (void **)&state->lists, sizeof(*state->lists),
          state->list_count + 1, &state->list_capacity)) {
    state->no_memory = true;
    return false;
  }
  state->lists[state->list_count].list_id = list_id;
  state->lists[state->list_count].first_offset = first_offset;
  state->list_count++;
  return true;
}

static inline bool onenote_revision_record_fragment(
    OneNoteRevisionState *state, uint32_t list_id, uint32_t sequence,
    uint64_t offset) {

  if (!state) {
    return false;
  }
  for (uint64_t index = 0; index < state->fragment_count; index++) {
    if (state->fragments[index].offset == offset
        || (state->fragments[index].list_id == list_id
            && state->fragments[index].sequence == sequence)) {
      return false;
    }
  }
  if (!onenote_revision_reserve(
          (void **)&state->fragments, sizeof(*state->fragments),
          state->fragment_count + 1, &state->fragment_capacity)) {
    state->no_memory = true;
    return false;
  }
  state->fragments[state->fragment_count].list_id = list_id;
  state->fragments[state->fragment_count].sequence = sequence;
  state->fragments[state->fragment_count].offset = offset;
  state->fragment_count++;
  return true;
}

static inline bool onenote_revision_md5_matches(
    OneNoteRevisionState *state, OneNoteReference reference,
    const uint8_t expected[16]) {

  if (!state || !expected
      || !onenote_revision_range_validate(state, reference)) {
    return false;
  }
  if (!state->md5_context) {
    state->md5_context = EVP_MD_CTX_new();
    if (!state->md5_context) {
      state->no_memory = true;
      return false;
    }
  }

  uint8_t digest[EVP_MAX_MD_SIZE];
  unsigned int digest_length = 0;

  if (EVP_DigestInit_ex(state->md5_context, EVP_md5(), NULL) != 1
      || EVP_DigestUpdate(state->md5_context,
                          state->data + reference.offset,
                          (size_t)reference.size) != 1
      || EVP_DigestFinal_ex(state->md5_context, digest,
                            &digest_length) != 1
      || digest_length != 16) {
    return false;
  }
  return memcmp(digest, expected, 16) == 0;
}

static inline void onenote_revision_failure_set(
    OneNoteRevisionState *state, uint64_t first, uint64_t last) {

  if (!state) {
    return;
  }
  if (last < first) {
    last = first;
  }
  state->failure_start = first;
  state->failure_end = last;
  state->failure_offset = first + (last - first) / 2;
}

static inline bool onenote_revision_integrity_cache_get(
    OneNoteRevisionState *state, OneNoteReference reference,
    OneNoteCachedValidation validation, bool *valid) {

  if (!state || !valid || reference.size == 0
      || reference.offset > UINT64_MAX - reference.size) {
    return false;
  }

  const uint64_t reference_end = reference.offset + reference.size - 1;

  if (state->trial_active && reference.offset <= state->trial_end
      && reference_end >= state->trial_start) {
    return false;
  }

  for (uint64_t index = 0; index < state->integrity_cache_count; index++) {
    const OneNoteIntegrityCacheEntry *entry =
        &state->integrity_cache[index];

    if (entry->reference.offset != reference.offset
        || entry->reference.size != reference.size
        || entry->validation != validation) {
      continue;
    }
    *valid = entry->valid;
    if (entry->valid) {
      state->integrity_references += entry->integrity_evidence;
      state->structural_references += entry->structural_evidence;
    }
    else {
      onenote_revision_failure_set(
          state, entry->failure_start, entry->failure_end);
    }
    return true;
  }
  return false;
}

static inline void onenote_revision_integrity_cache_put(
    OneNoteRevisionState *state, OneNoteReference reference,
    OneNoteCachedValidation validation, bool valid,
    bool integrity_evidence, uint64_t structural_evidence) {

  if (!state || reference.size == 0
      || reference.offset > UINT64_MAX - reference.size) {
    return;
  }

  const uint64_t reference_end = reference.offset + reference.size - 1;

  if (state->trial_active && reference.offset <= state->trial_end
      && reference_end >= state->trial_start) {
    return;
  }

  uint64_t index = 0;

  for (; index < state->integrity_cache_count; index++) {
    if (state->integrity_cache[index].reference.offset == reference.offset
        && state->integrity_cache[index].reference.size == reference.size
        && state->integrity_cache[index].validation == validation) {
      break;
    }
  }
  if (index == state->integrity_cache_count) {
    if (!onenote_revision_reserve(
            (void **)&state->integrity_cache,
            sizeof(*state->integrity_cache),
            state->integrity_cache_count + 1,
            &state->integrity_cache_capacity)) {
      return;
    }
    state->integrity_cache_count++;
  }

  OneNoteIntegrityCacheEntry *entry = &state->integrity_cache[index];

  entry->reference = reference;
  entry->failure_start = state->failure_start;
  entry->failure_end = state->failure_end;
  entry->structural_evidence = structural_evidence;
  entry->validation = validation;
  entry->valid = valid;
  entry->integrity_evidence = integrity_evidence;
}

static inline void onenote_revision_zip_probe_clear(
    OneNoteRevisionState *state) {

  if (!state) {
    return;
  }
  zip_deflate_prefix_clear(&state->zip_probe.prefix);
  memset(&state->zip_probe, 0, sizeof(state->zip_probe));
}

// Retain only the geometry needed to test the failing DEFLATE member. A
// successful probe remains subject to complete ZIP and OneNote validation.
//
static inline void onenote_revision_zip_probe_record(
    OneNoteRevisionState *state, uint64_t payload_offset,
    uint64_t payload_length, uint64_t failure_offset,
    uint64_t failure_entry, const ZipLayout *layout) {

  if (!state || state->trial_active || !layout || !layout->entries
      || failure_entry >= layout->entry_count
      || payload_offset > state->length
      || payload_length > state->length - payload_offset) {
    return;
  }

  const ZipEntry *source = &layout->entries[failure_entry];

  if (source->encrypted || !source->geometry_known
      || source->method != ZIP_METHOD_DEFLATE
      || source->compressed_size == 0
      || source->data_offset > payload_length
      || source->compressed_size > payload_length - source->data_offset) {
    return;
  }

  onenote_revision_zip_probe_clear(state);
  OneNoteZipProbe *probe = &state->zip_probe;

  probe->entry.local_offset = source->local_offset;
  probe->entry.observed_local_offset = source->observed_local_offset;
  probe->entry.compressed_size = source->compressed_size;
  probe->entry.uncompressed_size = source->uncompressed_size;
  probe->entry.data_offset = source->data_offset;
  probe->entry.range_end = source->range_end;
  probe->entry.crc32 = source->crc32;
  probe->entry.flags = source->flags;
  probe->entry.method = source->method;
  probe->entry.encrypted = source->encrypted;
  probe->entry.geometry_known = source->geometry_known;
  probe->payload_offset = payload_offset;
  probe->payload_length = payload_length;
  uint64_t decoder_failure = source->data_offset;
  uint64_t output_progress = 0;

  (void)zip_verify_deflate_entry(
      state->data + payload_offset, source,
      &decoder_failure, &output_progress);
  const uint64_t compressed_end = source->data_offset
                                  + source->compressed_size;

  if (decoder_failure >= compressed_end) {
    probe->baseline_output_comparable = true;
    probe->baseline_output_distance = output_progress
        > source->uncompressed_size
            ? output_progress - source->uncompressed_size
            : source->uncompressed_size - output_progress;
  }
  if (failure_offset >= payload_length) {
    failure_offset = payload_length - 1;
  }
  probe->baseline_failure = payload_offset + failure_offset;
  probe->available = true;
}

// Resume from a cached inflate prefix and test only the modified portion of
// the failing member plus its unchanged suffix. This is a rejection filter;
// it never substitutes for validation of the complete container.
//
static inline bool onenote_revision_zip_probe_trial(
    OneNoteRevisionState *state, const uint8_t *data,
    uint64_t trial_start, uint64_t trial_end,
    bool *valid, uint64_t *failure_offset,
    bool *output_comparable, uint64_t *output_distance) {

  if (valid) {
    *valid = false;
  }
  if (output_comparable) {
    *output_comparable = false;
  }
  if (output_distance) {
    *output_distance = UINT64_MAX;
  }
  if (!state || !data || !valid || !failure_offset
      || !output_comparable || !output_distance
      || !state->zip_probe.available || trial_end < trial_start
      || trial_end == UINT64_MAX) {
    return false;
  }

  OneNoteZipProbe *probe = &state->zip_probe;
  const uint64_t entry_start = probe->payload_offset
                               + probe->entry.data_offset;
  const uint64_t entry_end = entry_start
                             + probe->entry.compressed_size;
  const uint64_t trial_limit = trial_end + 1;
  const uint64_t overlap_start = trial_start > entry_start
                                     ? trial_start : entry_start;
  const uint64_t overlap_end = trial_limit < entry_end
                                   ? trial_limit : entry_end;

  if (overlap_start >= overlap_end) {
    return false;
  }

  const uint64_t patch_start = overlap_start - probe->payload_offset;
  const uint64_t patch_end = overlap_end - probe->payload_offset;

  if (!probe->prefix_attempted || probe->patch_start != patch_start) {
    zip_deflate_prefix_clear(&probe->prefix);
    probe->patch_start = patch_start;
    probe->prefix_attempted = true;
    (void)zip_deflate_prefix_initialize(
        data + probe->payload_offset, &probe->entry,
        patch_start, patch_end, &probe->prefix);
  }
  probe->patch_end = patch_end;
  if (!probe->prefix.initialized) {
    return false;
  }

  z_stream stream;

  memset(&stream, 0, sizeof(stream));
  if (inflateCopy(&stream, &probe->prefix.stream) != Z_OK) {
    return false;
  }

  const uint8_t *payload = data + probe->payload_offset;
  uLong crc = probe->prefix.crc;
  uint64_t patch_consumed = 0;
  uint64_t suffix_consumed = 0;
  const uint64_t member_end = probe->entry.data_offset
                              + probe->entry.compressed_size;
  ZipInflateFeedResult result = zip_deflate_feed(
      &stream, payload + patch_start, patch_end - patch_start,
      &crc, &patch_consumed);
  uint64_t relative_failure = patch_start + patch_consumed;

  if (result == ZIP_INFLATE_NEEDS_INPUT) {
    result = zip_deflate_feed(
        &stream, payload + patch_end, member_end - patch_end,
        &crc, &suffix_consumed);
    relative_failure = patch_end + suffix_consumed;
  }

  const uint64_t produced = stream.total_out;

  if (result == ZIP_INFLATE_ENDED && relative_failure == member_end) {
    *output_comparable = true;
    *output_distance = produced > probe->entry.uncompressed_size
        ? produced - probe->entry.uncompressed_size
        : probe->entry.uncompressed_size - produced;
    *valid = *output_distance == 0
             && (uint32_t)crc == probe->entry.crc32;
  }
  if (relative_failure >= probe->payload_length) {
    relative_failure = probe->payload_length - 1;
  }
  *failure_offset = probe->payload_offset + relative_failure;
  (void)inflateEnd(&stream);
  return true;
}

static inline bool onenote_revision_property_advance(
    OneNoteRevisionState *state, uint64_t *cursor, uint64_t limit,
    uint64_t size) {

  if (!state || !cursor || *cursor > limit || size > limit - *cursor) {
    if (state && cursor) {
      const uint64_t first = *cursor < limit
                                 ? *cursor
                                 : limit == 0 ? 0 : limit - 1;
      const uint64_t last = limit > first ? limit - 1 : first;

      onenote_revision_failure_set(state, first, last);
    }
    return false;
  }
  *cursor += size;
  return true;
}

static inline bool onenote_revision_object_stream_skip(
    OneNoteRevisionState *state, uint64_t *cursor, uint64_t limit,
    bool *extended_streams_present, bool *osid_stream_not_present,
    uint64_t *structural_evidence) {

  if (!state || !cursor || !extended_streams_present
      || !osid_stream_not_present || !structural_evidence
      || !onenote_revision_property_advance(state, cursor, limit, 4)) {
    return false;
  }

  const uint32_t header = onenote_read_le32(state->data + *cursor - 4);
  const uint64_t count = header & UINT32_C(0x00ffffff);

  *extended_streams_present = (header & UINT32_C(0x40000000)) != 0;
  *osid_stream_not_present = (header & UINT32_C(0x80000000)) != 0;
  if (count > (limit - *cursor) / 4) {
    onenote_revision_failure_set(
        state, *cursor - 4, limit == 0 ? 0 : limit - 1);
    return false;
  }
  if (!onenote_revision_property_advance(
          state, cursor, limit, count * 4)) {
    return false;
  }
  *structural_evidence += count + 1;
  return true;
}

// Parse the recursive property grammar used by object declarations. Bounds are
// checked before every read so malformed vector lengths identify the referenced
// object that reassembly must repair.
//
static inline bool onenote_revision_property_set_read(
    OneNoteRevisionState *state, uint64_t *cursor, uint64_t limit,
    uint32_t depth, uint64_t *structural_evidence) {

  if (!state || !cursor || !structural_evidence
      || depth > ONENOTE_PROPERTY_MAXIMUM_DEPTH
      || !onenote_revision_property_advance(state, cursor, limit, 2)) {
    return false;
  }

  const uint64_t property_count =
      (uint64_t)(state->data[*cursor - 2]
                 | ((uint16_t)state->data[*cursor - 1] << 8));
  const uint64_t property_ids = *cursor;

  if (property_count > (limit - *cursor) / 4
      || !onenote_revision_property_advance(
             state, cursor, limit, property_count * 4)) {
    return false;
  }

  for (uint64_t index = 0; index < property_count; index++) {
    const uint64_t property_position = property_ids + index * 4;
    const uint32_t property_id = onenote_read_le32(
        state->data + property_position);
    const uint32_t property_type = (property_id >> 26) & 0x1fu;
    uint64_t count = 0;

    switch (property_type) {
      case 0x01:
      case 0x02:
      case 0x08:
      case 0x0a:
      case 0x0c:
        break;
      case 0x03:
        if (!onenote_revision_property_advance(
                state, cursor, limit, 1)) {
          return false;
        }
        break;
      case 0x04:
        if (!onenote_revision_property_advance(
                state, cursor, limit, 2)) {
          return false;
        }
        break;
      case 0x05:
      case 0x09:
      case 0x0b:
      case 0x0d:
        if (!onenote_revision_property_advance(
                state, cursor, limit, 4)) {
          return false;
        }
        break;
      case 0x06:
        if (!onenote_revision_property_advance(
                state, cursor, limit, 8)) {
          return false;
        }
        break;
      case 0x07:
        if (!onenote_revision_property_advance(
                state, cursor, limit, 4)) {
          return false;
        }
        count = onenote_read_le32(state->data + *cursor - 4);
        if (!onenote_revision_property_advance(
                state, cursor, limit, count)) {
          return false;
        }
        break;
      case 0x10:
        if (!onenote_revision_property_advance(
                state, cursor, limit, 8)) {
          return false;
        }
        count = onenote_read_le32(state->data + *cursor - 8);
        if (count > (limit - *cursor) / 2) {
          onenote_revision_failure_set(
              state, *cursor - 8, limit == 0 ? 0 : limit - 1);
          return false;
        }
        for (uint64_t nested = 0; nested < count; nested++) {
          if (!onenote_revision_property_set_read(
                  state, cursor, limit, depth + 1,
                  structural_evidence)) {
            return false;
          }
        }
        break;
      case 0x11:
        if (!onenote_revision_property_set_read(
                state, cursor, limit, depth + 1,
                structural_evidence)) {
          return false;
        }
        break;
      default:
        onenote_revision_failure_set(
            state, property_position, property_position + 3);
        return false;
    }
  }
  *structural_evidence += property_count + 1;
  return true;
}

static inline bool onenote_revision_object_property_set_validate(
    OneNoteRevisionState *state, OneNoteReference reference) {

  if (!state || onenote_reference_is_nil_or_zero(reference)
      || !onenote_revision_range_validate(state, reference)) {
    return false;
  }

  bool cached_valid = false;

  if (onenote_revision_integrity_cache_get(
          state, reference, ONENOTE_CACHED_PROPERTY_SET, &cached_valid)) {
    return cached_valid;
  }

  uint64_t cursor = reference.offset;
  const uint64_t limit = reference.offset + reference.size;
  uint64_t structural_evidence = 0;
  bool extended_streams_present = false;
  bool osid_stream_not_present = false;
  bool valid = onenote_revision_object_stream_skip(
      state, &cursor, limit, &extended_streams_present,
      &osid_stream_not_present, &structural_evidence);

  if (valid && !osid_stream_not_present) {
    valid = onenote_revision_object_stream_skip(
        state, &cursor, limit, &extended_streams_present,
        &osid_stream_not_present, &structural_evidence);
    if (valid && extended_streams_present) {
      valid = onenote_revision_object_stream_skip(
          state, &cursor, limit, &extended_streams_present,
          &osid_stream_not_present, &structural_evidence);
    }
  }
  if (valid) {
    valid = onenote_revision_property_set_read(
        state, &cursor, limit, 0, &structural_evidence);
  }

  if (valid) {
    structural_evidence++;
    state->structural_references += structural_evidence;
  }
  onenote_revision_integrity_cache_put(
      state, reference, ONENOTE_CACHED_PROPERTY_SET, valid, false,
      valid ? structural_evidence : 0);
  return valid;
}

// Validate every PNG chunk checksum before applying the full PNG structural
// and inflate checks. A failed checksum identifies the complete chunk as the
// logical range that reassembly must repair.
//
static inline bool onenote_revision_png_validate(
    OneNoteRevisionState *state, const uint8_t *payload,
    uint64_t payload_length, uint64_t payload_offset) {

  if (!state || !payload || payload_length < sizeof(ONENOTE_PNG_SIGNATURE)
      || memcmp(payload, ONENOTE_PNG_SIGNATURE,
                sizeof(ONENOTE_PNG_SIGNATURE)) != 0) {
    return false;
  }

  uint64_t cursor = sizeof(ONENOTE_PNG_SIGNATURE);
  bool have_iend = false;

  while (cursor < payload_length) {
    if (payload_length - cursor < 12) {
      onenote_revision_failure_set(
          state, payload_offset + cursor,
          payload_offset + payload_length - 1);
      return false;
    }

    const uint64_t chunk_length = onenote_read_be32(payload + cursor);

    if (chunk_length > payload_length - cursor - 12) {
      onenote_revision_failure_set(
          state, payload_offset + cursor,
          payload_offset + payload_length - 1);
      return false;
    }

    const uint64_t chunk_end = cursor + chunk_length + 12;
    const uint32_t stored_crc = onenote_read_be32(
        payload + cursor + chunk_length + 8);
    const uint32_t computed_crc = zip_crc32(
        payload + cursor + 4, chunk_length + 4);

    if (stored_crc != computed_crc) {
      onenote_revision_failure_set(
          state, payload_offset + cursor,
          payload_offset + chunk_end - 1);
      return false;
    }
    if (memcmp(payload + cursor + 4, "IEND", 4) == 0) {
      have_iend = chunk_length == 0;
      cursor = chunk_end;
      break;
    }
    cursor = chunk_end;
  }

  uint64_t validates_to = 0;

  if (!have_iend || cursor != payload_length
      || !png_try_complete_contiguous(
             (char *)payload, payload_length, &validates_to)) {
    onenote_revision_failure_set(
        state, payload_offset,
        payload_offset + payload_length - 1);
    return false;
  }
  state->integrity_references++;
  return true;
}

// Validate the container around an embedded file and use checksums and format
// structure from recognized payloads as stronger content evidence.
//
static inline bool onenote_revision_file_data_validate(
    OneNoteRevisionState *state, OneNoteReference reference) {

  if (!state || reference.size < ONENOTE_FILE_DATA_HEADER_SIZE
                                 + ONENOTE_FILE_DATA_FOOTER_SIZE
      || !onenote_revision_range_validate(state, reference)) {
    return false;
  }

  const uint8_t *object = state->data + reference.offset;

  onenote_revision_failure_set(state, reference.offset, reference.offset);
  if (memcmp(object, ONENOTE_FILE_DATA_HEADER_GUID,
             sizeof(ONENOTE_FILE_DATA_HEADER_GUID)) != 0) {
    return false;
  }

  const uint64_t payload_length = onenote_read_le64(object + 16);
  uint64_t payload_end = 0;

  if (onenote_read_le32(object + 24) != 0
      || onenote_read_le64(object + 28) != 0
      || __builtin_add_overflow(ONENOTE_FILE_DATA_HEADER_SIZE,
                                payload_length, &payload_end)
      || payload_end > UINT64_MAX - 7) {
    return false;
  }

  const uint64_t footer_offset = (payload_end + 7) & ~UINT64_C(7);
  uint64_t object_size = 0;

  if (__builtin_add_overflow(footer_offset,
                             ONENOTE_FILE_DATA_FOOTER_SIZE,
                             &object_size)
      || object_size != reference.size) {
    return false;
  }

  onenote_revision_failure_set(
      state, reference.offset + footer_offset,
      reference.offset + footer_offset);
  if (memcmp(object + footer_offset, ONENOTE_FILE_DATA_FOOTER_GUID,
             sizeof(ONENOTE_FILE_DATA_FOOTER_GUID)) != 0) {
    return false;
  }

  const uint8_t *payload = object + ONENOTE_FILE_DATA_HEADER_SIZE;
  const uint64_t payload_offset = reference.offset
                                  + ONENOTE_FILE_DATA_HEADER_SIZE;
  const bool png_payload = payload_length >= sizeof(ONENOTE_PNG_SIGNATURE)
      && memcmp(payload, ONENOTE_PNG_SIGNATURE,
                sizeof(ONENOTE_PNG_SIGNATURE)) == 0;
  const bool zip_payload = !png_payload
                           && zip_has_archive_header(
                                  payload, payload_length);

  if (png_payload || zip_payload) {
    bool cached_valid = false;

    if (onenote_revision_integrity_cache_get(
            state, reference, ONENOTE_CACHED_FILE_DATA,
            &cached_valid)) {
      return cached_valid;
    }
  }

  if (png_payload) {
    const bool valid = onenote_revision_png_validate(
        state, payload, payload_length, payload_offset);

    onenote_revision_integrity_cache_put(
        state, reference, ONENOTE_CACHED_FILE_DATA, valid, valid, 0);
    return valid;
  }
  if (zip_payload) {
    ZipLayout layout = {0};
    uint64_t zip_failure = 0;
    uint64_t zip_failure_entry = UINT64_MAX;
    uint64_t zip_failure_start = UINT64_MAX;
    uint64_t zip_failure_end = 0;
    bool content_valid = false;
    const bool layout_found = zip_find_layout(
        payload, payload_length, (uint32_t)scalpel_state.blocksize,
        &layout, &zip_failure, &zip_failure_entry, &content_valid);

    if (layout_found && !content_valid) {
      onenote_revision_zip_probe_record(
          state, payload_offset, payload_length, zip_failure,
          zip_failure_entry, &layout);
      if (zip_failure_entry < layout.entry_count) {
        const ZipEntry *entry = &layout.entries[zip_failure_entry];
        uint64_t compressed_end = 0;

        if (!__builtin_add_overflow(entry->data_offset,
                                    entry->compressed_size,
                                    &compressed_end)
            && compressed_end > entry->data_offset
            && compressed_end <= payload_length
            && zip_failure >= compressed_end) {
          zip_failure_start = entry->data_offset;
          zip_failure_end = compressed_end - 1;
        }
      }
    }
    zip_layout_clear(&layout);
    if (!layout_found || !content_valid) {
      if (payload_length != 0 && zip_failure >= payload_length) {
        zip_failure = payload_length - 1;
      }
      if (zip_failure_end < zip_failure_start) {
        zip_failure_start = zip_failure;
        zip_failure_end = zip_failure;
      }
      onenote_revision_failure_set(
          state, payload_offset + zip_failure_start,
          payload_offset + zip_failure_end);
      state->failure_offset = payload_offset + zip_failure;
      onenote_revision_integrity_cache_put(
          state, reference, ONENOTE_CACHED_FILE_DATA, false, false, 0);
      return false;
    }
    state->integrity_references++;
    onenote_revision_integrity_cache_put(
        state, reference, ONENOTE_CACHED_FILE_DATA, true, true, 0);
  }
  return true;
}

static inline bool onenote_revision_node_definition_validate(
    OneNoteKind kind, uint32_t node_id, uint32_t base_type,
    uint32_t cb_format) {

  if (base_type > 2 || (base_type == 0 && cb_format != 0)) {
    return false;
  }

  uint32_t expected_base = UINT32_MAX;
  bool allowed = true;

  switch (node_id) {
    case 0x004:
    case 0x00c:
    case 0x014:
    case 0x01c:
    case 0x024:
    case 0x028:
    case 0x05c:
    case 0x08c:
    case ONENOTE_CHUNK_TERMINATOR_NODE:
      expected_base = 0;
      break;
    case 0x008:
    case 0x010:
      expected_base = 2;
      break;
    case 0x084:
      expected_base = 1;
      break;
    case 0x01b:
    case 0x021:
    case 0x025:
    case 0x026:
    case 0x059:
      expected_base = 0;
      allowed = kind == ONENOTE_KIND_TOC;
      break;
    case 0x02d:
    case 0x02e:
    case 0x041:
    case 0x042:
      expected_base = 1;
      allowed = kind == ONENOTE_KIND_TOC;
      break;
    case 0x01e:
    case 0x01f:
    case 0x022:
    case 0x05a:
    case 0x05d:
    case 0x072:
    case 0x073:
    case 0x0b4:
    case 0x0b8:
      expected_base = 0;
      allowed = kind == ONENOTE_KIND_SECTION;
      break;
    case 0x07c:
    case 0x094:
    case 0x0a4:
    case 0x0a5:
    case ONENOTE_HASHED_REFERENCE_NODE:
    case ONENOTE_READ_ONLY_REFERENCE_NODE:
    case ONENOTE_READ_ONLY_LARGE_REFERENCE_NODE:
      expected_base = 1;
      allowed = kind == ONENOTE_KIND_SECTION;
      break;
    case 0x090:
    case 0x0b0:
      expected_base = 2;
      allowed = kind == ONENOTE_KIND_SECTION;
      break;
    default:
      break;
  }
  return allowed
         && (expected_base == UINT32_MAX || base_type == expected_base);
}

static inline bool onenote_revision_node_reference_read(
    const uint8_t *data, uint64_t limit, uint64_t *cursor,
    uint32_t stp_format, uint32_t cb_format, OneNoteReference *reference) {

  if (!data || !cursor || !reference) {
    return false;
  }
  switch (stp_format) {
    case 0:
      if (!onenote_range_available(limit, *cursor, 8)) {
        return false;
      }
      reference->offset = onenote_read_le64(data + *cursor);
      *cursor += 8;
      break;
    case 1:
      if (!onenote_range_available(limit, *cursor, 4)) {
        return false;
      }
      reference->offset = onenote_read_le32(data + *cursor);
      *cursor += 4;
      break;
    case 2:
      if (!onenote_range_available(limit, *cursor, 2)) {
        return false;
      }
      reference->offset = (uint64_t)(data[*cursor]
                                     | ((uint16_t)data[*cursor + 1] << 8))
                          * 8;
      *cursor += 2;
      break;
    case 3:
      if (!onenote_range_available(limit, *cursor, 4)) {
        return false;
      }
      reference->offset = (uint64_t)onenote_read_le32(data + *cursor) * 8;
      *cursor += 4;
      break;
    default:
      return false;
  }

  switch (cb_format) {
    case 0:
      if (!onenote_range_available(limit, *cursor, 4)) {
        return false;
      }
      reference->size = onenote_read_le32(data + *cursor);
      *cursor += 4;
      break;
    case 1:
      if (!onenote_range_available(limit, *cursor, 8)) {
        return false;
      }
      reference->size = onenote_read_le64(data + *cursor);
      *cursor += 8;
      break;
    case 2:
      if (!onenote_range_available(limit, *cursor, 1)) {
        return false;
      }
      reference->size = (uint64_t)data[*cursor] * 8;
      (*cursor)++;
      break;
    case 3:
      if (!onenote_range_available(limit, *cursor, 2)) {
        return false;
      }
      reference->size = (uint64_t)(data[*cursor]
                                   | ((uint16_t)data[*cursor + 1] << 8))
                        * 8;
      *cursor += 2;
      break;
    default:
      return false;
  }
  return true;
}

static inline bool onenote_revision_transaction_log_validate(
    OneNoteRevisionState *state, OneNoteReference first,
    uint32_t transaction_count) {

  if (!state || transaction_count == 0
      || onenote_reference_is_nil_or_zero(first)) {
    return false;
  }

  OneNoteReference current = first;
  uint32_t committed = 0;
  bool valid = true;

  while (committed < transaction_count) {
    onenote_revision_failure_set(state, current.offset, current.offset);
    if (onenote_reference_is_nil_or_zero(current)
        || current.size < 12
        || !onenote_revision_range_validate(state, current)) {
      valid = false;
      break;
    }
    for (uint64_t index = 0;
         index < state->transaction_fragment_count; index++) {
      if (state->transaction_fragments[index].offset == current.offset) {
        valid = false;
        break;
      }
    }
    if (!valid) {
      break;
    }
    if (!onenote_revision_reserve(
            (void **)&state->transaction_fragments,
            sizeof(*state->transaction_fragments),
            state->transaction_fragment_count + 1,
            &state->transaction_fragment_capacity)) {
      state->no_memory = true;
      valid = false;
      break;
    }
    state->transaction_fragments[state->transaction_fragment_count++] =
        current;
    const uint64_t entry_count = (current.size - 12) / 8;
    uint64_t cursor = current.offset;
    const uint64_t entry_end = cursor + entry_count * 8;

    while (cursor < entry_end && committed < transaction_count) {
      onenote_revision_failure_set(state, cursor, cursor);
      const uint32_t source = onenote_read_le32(state->data + cursor);
      const uint32_t value = onenote_read_le32(state->data + cursor + 4);

      cursor += 8;
      if (source == 1) {
        if (state->pending_count == 0) {
          valid = false;
          break;
        }
        for (uint64_t index = 0; index < state->pending_count; index++) {
          if (!onenote_revision_node_count_set(
                  state, state->pending_counts[index].list_id,
                  state->pending_counts[index].count)) {
            valid = false;
            break;
          }
        }
        if (!valid) {
          break;
        }
        state->pending_count = 0;
        committed++;
        continue;
      }
      if (source == 0
          || !onenote_revision_reserve(
                 (void **)&state->pending_counts,
                 sizeof(*state->pending_counts), state->pending_count + 1,
                 &state->pending_capacity)) {
        state->no_memory = source != 0;
        valid = false;
        break;
      }
      state->pending_counts[state->pending_count].list_id = source;
      state->pending_counts[state->pending_count].count = value;
      state->pending_count++;
    }
    if (valid) {
      state->structural_references++;
    }
    if (!valid || committed == transaction_count) {
      break;
    }
    onenote_revision_failure_set(state, entry_end, entry_end);
    current.offset = onenote_read_le64(state->data + entry_end);
    current.size = onenote_read_le32(state->data + entry_end + 8);
  }

  return valid && committed == transaction_count;
}

static inline bool onenote_revision_file_node_list_validate(
    OneNoteRevisionState *state, OneNoteReference first) {

  if (!state || onenote_reference_is_nil_or_zero(first)) {
    return false;
  }

  OneNoteReference current = first;
  uint32_t expected_list_id = 0;
  uint32_t expected_sequence = 0;
  uint32_t remaining_nodes = 0;
  bool has_node_count = false;

  while (!onenote_reference_is_nil_or_zero(current)) {
    onenote_revision_failure_set(state, current.offset, current.offset);
    if (current.size < 36
        || !onenote_revision_range_validate(state, current)) {
      return false;
    }

    const uint8_t *fragment = state->data + current.offset;
    const uint32_t list_id = onenote_read_le32(fragment + 8);
    const uint32_t sequence = onenote_read_le32(fragment + 12);

    if (onenote_read_le64(fragment) != UINT64_C(0xa4567ab1f5f7f4c4)
        || list_id <= 1 || sequence != expected_sequence
        || (expected_sequence > 0 && list_id != expected_list_id)
        || !onenote_revision_record_fragment(
               state, list_id, sequence, current.offset)) {
      return false;
    }
    if (expected_sequence == 0) {
      expected_list_id = list_id;
      has_node_count = onenote_revision_node_count_get(
          state, list_id, &remaining_nodes);
      if (!onenote_revision_record_list(state, list_id, first.offset)) {
        return false;
      }
    }

    const uint64_t next_offset = current.offset + current.size - 20;
    const uint64_t footer_offset = current.offset + current.size - 8;

    onenote_revision_failure_set(state, footer_offset, footer_offset);
    if (onenote_read_le64(state->data + footer_offset)
        != UINT64_C(0x8bc215c38233ba4b)) {
      return false;
    }

    OneNoteReference next = {
      .offset = onenote_read_le64(state->data + next_offset),
      .size = onenote_read_le32(state->data + next_offset + 8)
    };
    uint64_t cursor = current.offset + 16;
    bool terminated = false;

    while (cursor + 4 <= next_offset) {
      onenote_revision_failure_set(state, cursor, cursor);
      if (has_node_count && remaining_nodes == 0) {
        break;
      }

      const uint32_t descriptor = onenote_read_le32(state->data + cursor);
      const uint32_t node_id = descriptor & 0x3ffu;

      if (node_id == 0) {
        if (descriptor != 0) {
          return false;
        }
        cursor += 4;
        continue;
      }

      const uint32_t node_size = (descriptor >> 10) & 0x1fffu;
      const uint32_t stp_format = (descriptor >> 23) & 0x03u;
      const uint32_t cb_format = (descriptor >> 25) & 0x03u;
      const uint32_t base_type = (descriptor >> 27) & 0x0fu;
      const uint32_t reserved = descriptor >> 31;
      const uint64_t node_end = cursor + node_size;

      if (node_size < 4 || node_end > next_offset || reserved != 1
          || !onenote_revision_node_definition_validate(
                 state->kind, node_id, base_type, cb_format)
          || (node_id == ONENOTE_CHUNK_TERMINATOR_NODE
              && node_size != 4)) {
        return false;
      }

      OneNoteReference node_reference = {0};
      uint64_t body = cursor + 4;

      if (base_type != 0) {
        if (!onenote_revision_node_reference_read(
                state->data, node_end, &body, stp_format, cb_format,
                &node_reference)) {
          return false;
        }
        if (!onenote_reference_is_nil_or_zero(node_reference)) {
          if (!onenote_revision_range_validate(state, node_reference)) {
            return false;
          }
          state->structural_references++;
        }
        if (base_type == 2) {
          if (!onenote_revision_queue_list(state, node_reference)) {
            return false;
          }
        }
      }

      if (node_id == ONENOTE_HASHED_REFERENCE_NODE) {
        onenote_revision_failure_set(
            state, node_reference.offset, node_reference.offset);
        if (onenote_reference_is_nil_or_zero(node_reference)
            || body + 16 > node_end
            || !onenote_revision_md5_matches(
                   state, node_reference, state->data + body)) {
          return false;
        }
        state->authenticated_references++;
      }
      else if (node_id == ONENOTE_FILE_DATA_STORE_REFERENCE_NODE) {
        onenote_revision_failure_set(
            state, node_reference.offset, node_reference.offset);
        if (onenote_reference_is_nil_or_zero(node_reference)
            || node_end - body != 16
            || !onenote_revision_file_data_validate(
                   state, node_reference)) {
          return false;
        }
      }
      else if (node_id == ONENOTE_READ_ONLY_REFERENCE_NODE
               || node_id == ONENOTE_READ_ONLY_LARGE_REFERENCE_NODE) {
        if (node_size < 20) {
          return false;
        }
        if (!onenote_reference_is_nil_or_zero(node_reference)
            && onenote_revision_md5_matches(
                   state, node_reference, state->data + node_end - 16)) {
          state->authenticated_references++;
        }
      }

      const bool property_set_reference = node_id == 0x02d
          || node_id == 0x02e || node_id == 0x041 || node_id == 0x042
          || node_id == 0x0a4 || node_id == 0x0a5
          || node_id == ONENOTE_HASHED_REFERENCE_NODE
          || node_id == ONENOTE_READ_ONLY_REFERENCE_NODE
          || node_id == ONENOTE_READ_ONLY_LARGE_REFERENCE_NODE;

      if (property_set_reference
          && !onenote_revision_object_property_set_validate(
                 state, node_reference)) {
        return false;
      }

      cursor = node_end;
      if (node_id == ONENOTE_CHUNK_TERMINATOR_NODE) {
        terminated = true;
        break;
      }
      if (has_node_count) {
        remaining_nodes--;
      }
    }

    state->structural_references++;
    if (has_node_count && remaining_nodes == 0) {
      break;
    }
    if (terminated && onenote_reference_is_nil_or_zero(next)) {
      return false;
    }
    if (onenote_reference_is_nil_or_zero(next)) {
      break;
    }
    current = next;
    expected_sequence++;
  }

  return !has_node_count || remaining_nodes == 0;
}

static inline bool onenote_revision_free_chunk_list_validate(
    OneNoteRevisionState *state, OneNoteReference first) {

  if (!state || onenote_reference_is_nil_or_zero(first)) {
    return true;
  }

  OneNoteReference current = first;
  uint64_t fragments = 0;

  while (!onenote_reference_is_nil_or_zero(current)) {
    onenote_revision_failure_set(state, current.offset, current.offset);
    if (current.size < 16 || (current.size - 16) % 16 != 0
        || !onenote_revision_range_validate(state, current)) {
      return false;
    }
    if (fragments++ > state->expected_length / 16) {
      return false;
    }

    const uint8_t *fragment = state->data + current.offset;
    OneNoteReference next = {
      .offset = onenote_read_le64(fragment + 4),
      .size = onenote_read_le32(fragment + 12)
    };
    const uint64_t free_count = (current.size - 16) / 16;

    for (uint64_t index = 0; index < free_count; index++) {
      OneNoteReference free_reference = {
        .offset = onenote_read_le64(fragment + 16 + index * 16),
        .size = onenote_read_le64(fragment + 24 + index * 16)
      };

      if (!onenote_reference_is_nil_or_zero(free_reference)
          && !onenote_revision_range_validate(state, free_reference)) {
        return false;
      }
    }
    state->structural_references++;
    current = next;
  }
  return true;
}

static inline void onenote_revision_state_release(
    OneNoteRevisionState *state) {

  if (!state) {
    return;
  }
  onenote_revision_zip_probe_clear(state);
  EVP_MD_CTX_free(state->md5_context);
  free(state->integrity_cache);
  free(state->fragments);
  free(state->lists);
  free(state->list_queue);
  free(state->pending_counts);
  free(state->node_counts);
  free(state->transaction_fragments);
  memset(state, 0, sizeof(*state));
}

// Validate the committed transaction log and every reachable file node list.
// Stored MD5 values authenticate hashed chunks when the format provides them.
//
static inline bool onenote_revision_header_validate(const uint8_t *data,
                                                    uint64_t length,
                                                    OneNoteKind kind,
                                                    OneNoteSummary *summary,
                                                    OneNoteRevisionState *workspace) {

  if (!data || !summary || length < ONENOTE_HEADER_SIZE) {
    return false;
  }

  const uint32_t expected_version = kind == ONENOTE_KIND_SECTION ? 42u : 27u;

  for (uint64_t offset = 64; offset < 80; offset += sizeof(uint32_t)) {
    if (onenote_read_le32(data + offset) != expected_version) {
      return false;
    }
  }
  if (onenote_read_le32(data + 96) == 0
      || onenote_read_le32(data + 100) != 0) {
    return false;
  }

  const uint64_t expected_length = onenote_read_le64(
      data + ONENOTE_EXPECTED_LENGTH_OFFSET);

  if (expected_length < ONENOTE_HEADER_SIZE || expected_length > length) {
    summary->verified_to = ONENOTE_HEADER_SIZE - 1;
    return false;
  }

  OneNoteRevisionState local_state = {0};
  OneNoteRevisionState *state = workspace ? workspace : &local_state;

  if (!state->trial_active) {
    onenote_revision_zip_probe_clear(state);
  }
  state->data = data;
  state->length = length;
  state->expected_length = expected_length;
  state->kind = kind;
  state->node_count_count = 0;
  state->pending_count = 0;
  state->list_queue_count = 0;
  state->list_count = 0;
  state->fragment_count = 0;
  state->transaction_fragment_count = 0;
  onenote_revision_failure_set(
      state, ONENOTE_HEADER_SIZE, ONENOTE_HEADER_SIZE);
  state->authenticated_references = 0;
  state->integrity_references = 0;
  state->structural_references = 0;
  state->no_memory = false;
  const OneNoteReference transaction_log = {
    .offset = onenote_read_le64(data + 160),
    .size = onenote_read_le32(data + 168)
  };
  const OneNoteReference hashed_chunks = {
    .offset = onenote_read_le64(data + 148),
    .size = onenote_read_le32(data + 156)
  };
  const OneNoteReference root = {
    .offset = onenote_read_le64(data + ONENOTE_ROOT_REFERENCE_OFFSET),
    .size = onenote_read_le32(data + ONENOTE_ROOT_REFERENCE_OFFSET + 8)
  };
  const OneNoteReference free_chunks = {
    .offset = onenote_read_le64(data + 184),
    .size = onenote_read_le32(data + 192)
  };

  bool valid = onenote_revision_transaction_log_validate(
      state, transaction_log, onenote_read_le32(data + 96));

  if (valid && !onenote_reference_is_nil_or_zero(hashed_chunks)) {
    valid = onenote_revision_queue_list(state, hashed_chunks);
  }
  if (valid) {
    valid = onenote_revision_queue_list(state, root);
  }
  for (uint64_t index = 0;
       valid && index < state->list_queue_count; index++) {
    valid = onenote_revision_file_node_list_validate(
        state, state->list_queue[index]);
  }
  if (valid) {
    valid = onenote_revision_free_chunk_list_validate(state, free_chunks);
  }
  for (uint64_t index = 0;
       valid && index < state->node_count_count; index++) {
    bool found = false;

    for (uint64_t list_index = 0;
         list_index < state->list_count; list_index++) {
      if (state->lists[list_index].list_id
          == state->node_counts[index].list_id) {
        found = true;
        break;
      }
    }
    valid = found;
  }

  if (valid && !state->no_memory) {
    summary->extent = expected_length;
    summary->verified_to = expected_length - 1;
    onenote_revision_failure_set(
        state, expected_length - 1, expected_length - 1);
  }
  else {
    summary->verified_to = ONENOTE_HEADER_SIZE - 1;
  }
  summary->failure_offset = state->failure_offset;
  summary->failure_start = state->failure_start;
  summary->failure_end = state->failure_end;
  summary->authenticated_references = state->authenticated_references;
  summary->integrity_references = state->integrity_references;
  summary->structural_references = state->structural_references;
  summary->no_memory = state->no_memory;
  if (!workspace) {
    onenote_revision_state_release(state);
  }
  return valid;
}

// Validate the package-store header and its nested FSSHTTPB stream. The
// reserved zero tail used by some producers is not part of the package stream.
//
static inline bool onenote_package_header_validate(const uint8_t *data,
                                                   uint64_t length,
                                                   OneNoteKind kind,
                                                   OneNoteSummary *summary) {

  if (!data || !summary
      || !onenote_package_extent_validate(data, length, kind,
                                          &summary->extent)) {
    return false;
  }
  summary->verified_to = summary->extent - 1;
  return true;
}

static inline bool onenote_parse_with_workspace(
    const uint8_t *data, uint64_t length, OneNoteKind required_kind,
    OneNoteSummary *summary, OneNoteRevisionState *workspace) {

  if (!summary) {
    return false;
  }
  memset(summary, 0, sizeof(*summary));

  const OneNoteKind kind = onenote_file_kind(data, length);
  const OneNoteStorage storage = onenote_storage_kind(data, length);

  summary->kind = kind;
  summary->storage = storage;
  if (kind == ONENOTE_KIND_NONE || kind != required_kind
      || storage == ONENOTE_STORAGE_NONE) {
    return false;
  }
  if (storage == ONENOTE_STORAGE_REVISION) {
    return onenote_revision_header_validate(
        data, length, kind, summary, workspace);
  }
  if (storage == ONENOTE_STORAGE_EMBEDDED_PACKAGE) {
    uint64_t package_offset = 0;

    if (!onenote_embedded_package_offset(data, length, &package_offset)) {
      return false;
    }
    const uint8_t *package = data + package_offset;
    const uint64_t package_length = length - package_offset;
    const OneNoteKind package_kind = onenote_file_kind(
        package, package_length);
    OneNoteSummary package_summary = {0};

    if (package_kind == ONENOTE_KIND_NONE
        || !onenote_package_header_validate(
               package, package_length, package_kind, &package_summary)) {
      return false;
    }
    summary->extent = package_offset + package_summary.extent;
    summary->verified_to = summary->extent - 1;
    return true;
  }
  return onenote_package_header_validate(data, length, kind, summary);
}

static inline bool onenote_parse(const uint8_t *data, uint64_t length,
                                 OneNoteKind required_kind,
                                 OneNoteSummary *summary) {

  return onenote_parse_with_workspace(
      data, length, required_kind, summary, NULL);
}

static inline char *onenote_header_discovery_kind(
    char *base, uint64_t offset, uint64_t remaining, char **matchpos,
    uint32_t *matchlen, OneNoteKind required_kind) {

  if (!base || !matchpos || !matchlen) {
    return NULL;
  }
  *matchpos = NULL;
  *matchlen = 16;

  const uint8_t *region = (const uint8_t *)base + offset;
  uint64_t searched = 0;

  while (searched + 64 <= remaining) {
    const size_t search_length = (size_t)(remaining - searched - 63);
    const uint8_t *section_candidate = memchr(
        region + searched, ONENOTE_SECTION_GUID[0], search_length);
    const uint8_t *toc_candidate = required_kind == ONENOTE_KIND_TOC
        ? memchr(region + searched, ONENOTE_TOC_GUID[0], search_length)
        : NULL;
    const uint8_t *candidate = section_candidate;

    if (!candidate || (toc_candidate && toc_candidate < candidate)) {
      candidate = toc_candidate;
    }

    if (!candidate) {
      break;
    }
    const uint64_t position = (uint64_t)(candidate - region);

    if (onenote_file_kind(candidate, remaining - position) == required_kind
        && onenote_storage_kind(candidate, remaining - position)
               != ONENOTE_STORAGE_NONE) {
      *matchpos = (char *)candidate;
      return NULL;
    }
    searched = position + 1;
  }
  return NULL;
}

static inline char *onenote_section_header_discovery(
    char *base, uint64_t offset, uint64_t remaining, char **matchpos,
    uint32_t *matchlen, uint32_t blocksize) {

  (void)blocksize;
  return onenote_header_discovery_kind(base, offset, remaining, matchpos,
                                       matchlen, ONENOTE_KIND_SECTION);
}

static inline char *onenote_toc_header_discovery(
    char *base, uint64_t offset, uint64_t remaining, char **matchpos,
    uint32_t *matchlen, uint32_t blocksize) {

  (void)blocksize;
  return onenote_header_discovery_kind(base, offset, remaining, matchpos,
                                       matchlen, ONENOTE_KIND_TOC);
}

// Discover one exact revision-store end or package-stream terminator by first
// locating its corresponding header. This avoids matching package terminators
// that occur as ordinary payload bytes.
//
static inline char *onenote_footer_discovery_kind(
    char *base, uint64_t offset, uint64_t remaining, char **matchpos,
    uint32_t *matchlen, OneNoteKind required_kind) {

  if (!base || !matchpos || !matchlen) {
    return NULL;
  }
  *matchpos = NULL;
  *matchlen = 1;

  char *header = NULL;
  uint32_t header_length = 0;

  onenote_header_discovery_kind(base, offset, remaining, &header,
                                &header_length, required_kind);
  if (!header) {
    return NULL;
  }

  const uint64_t header_position = (uint64_t)(header - (base + offset));
  const uint64_t available = remaining - header_position;
  const uint8_t *bytes = (const uint8_t *)header;
  const OneNoteStorage storage = onenote_storage_kind(bytes, available);

  if (storage == ONENOTE_STORAGE_REVISION
      && available >= ONENOTE_HEADER_SIZE) {
    const uint64_t expected = onenote_read_le64(
        bytes + ONENOTE_EXPECTED_LENGTH_OFFSET);

    if (expected >= ONENOTE_HEADER_SIZE && expected <= available) {
      *matchpos = header + expected - 1;
      return NULL;
    }
  }
  if (storage == ONENOTE_STORAGE_PACKAGE) {
    uint64_t package_extent = 0;

    if (onenote_package_extent_validate(bytes, available, required_kind,
                                        &package_extent)) {
      *matchpos = header + package_extent - ONENOTE_PACKAGE_END_SIZE;
      *matchlen = (uint32_t)ONENOTE_PACKAGE_END_SIZE;
      return NULL;
    }
  }
  if (storage == ONENOTE_STORAGE_EMBEDDED_PACKAGE) {
    OneNoteSummary summary = {0};

    if (onenote_parse(bytes, available, required_kind, &summary)) {
      *matchpos = header + summary.extent - ONENOTE_PACKAGE_END_SIZE;
      *matchlen = (uint32_t)ONENOTE_PACKAGE_END_SIZE;
      return NULL;
    }
  }
  return NULL;
}

static inline char *onenote_section_footer_discovery(
    char *base, uint64_t offset, uint64_t remaining, char **matchpos,
    uint32_t *matchlen, uint32_t blocksize) {

  (void)blocksize;
  return onenote_footer_discovery_kind(base, offset, remaining, matchpos,
                                       matchlen, ONENOTE_KIND_SECTION);
}

static inline char *onenote_toc_footer_discovery(
    char *base, uint64_t offset, uint64_t remaining, char **matchpos,
    uint32_t *matchlen, uint32_t blocksize) {

  (void)blocksize;
  return onenote_footer_discovery_kind(base, offset, remaining, matchpos,
                                       matchlen, ONENOTE_KIND_TOC);
}

static inline void onenote_file_validate_kind(
    char *data, uint64_t length, bool *validates, uint64_t *validates_to,
    bool *promising, OneNoteKind required_kind) {

  if (!validates || !validates_to || !promising) {
    return;
  }
  *validates = false;
  *validates_to = 0;
  *promising = false;

  OneNoteSummary summary;

  if (onenote_parse((const uint8_t *)data, length, required_kind, &summary)) {
    *validates = true;
    *validates_to = summary.verified_to;
    return;
  }
  if (summary.kind == required_kind && summary.storage != ONENOTE_STORAGE_NONE) {
    *promising = true;
    *validates_to = summary.verified_to;
  }
}

static inline void onenote_section_file_validate(
    char *data, uint64_t length, bool *validates, uint64_t *validates_to,
    bool *promising, uint32_t needleidx, uint32_t blocksize,
    void *carvehashkey) {

  (void)needleidx;
  (void)blocksize;
  (void)carvehashkey;
  onenote_file_validate_kind(data, length, validates, validates_to,
                             promising, ONENOTE_KIND_SECTION);
}

static inline void onenote_toc_file_validate(
    char *data, uint64_t length, bool *validates, uint64_t *validates_to,
    bool *promising, uint32_t needleidx, uint32_t blocksize,
    void *carvehashkey) {

  (void)needleidx;
  (void)blocksize;
  (void)carvehashkey;
  onenote_file_validate_kind(data, length, validates, validates_to,
                             promising, ONENOTE_KIND_TOC);
}

// OneNote stores can contain opaque object payloads without independent
// authenticators. A complete structural parse therefore remains PROMISING.
//
static inline void onenote_candidate_validate(CarveInfo *candidate,
                                              bool *validates,
                                              uint64_t *validates_to,
                                              bool *promising) {

  (void)validates_to;

  if (!candidate || !candidate->b || !validates || !promising
      || !*validates) {
    return;
  }
  *validates = false;
  *promising = true;
}

static inline bool onenote_reassembly_score_valid(
    const OneNoteRecoveryScore *score, uint64_t block_count) {

  const bool *flags[] = {&score->summary.no_memory, &score->complete,
                        &score->found, &score->zip_output_comparable,
                        &score->exact_run_boundaries};

  for (size_t index = 0; index < sizeof(flags) / sizeof(flags[0]); index++) {
    unsigned char value;

    memcpy(&value, flags[index], sizeof(value));
    if (value > 1) {
      return false;
    }
  }
  return !score->found
         || (score->source >= 0 && score->run_start > 0
             && score->run_start < block_count && score->run_length > 0
             && score->run_length <= block_count - score->run_start);
}

static inline bool onenote_carve_state_valid(
    const OneNoteCarveState *state) {

  if (!state || state->magic != ONENOTE_CARVE_STATE_MAGIC
      || state->version != ONENOTE_CARVE_STATE_VERSION
      || state->phase > ONENOTE_SEARCH_INTERIOR_SPANS_COMPLETE
      || state->reserved != 0 || state->block_count == 0
      || state->data_length == 0 || state->progress_valid > 1
      || state->exact_run_boundaries > 1
      || state->overlapping_suffix_blocks > state->block_count
      || state->alignment_count > SIZE_MAX / sizeof(*state->alignments)
      || (state->alignment_count != 0 && !state->alignments)
      || (state->progress_valid == 0
          && (state->alignment_count != 0 || state->exact_run_boundaries
              || state->overlapping_suffix_blocks != 0))) {
    return false;
  }
  for (uint64_t index = 0; index < state->alignment_count; index++) {
    if (state->alignments[index].actual < 0
        || state->alignments[index].slot >= state->block_count) {
      return false;
    }
  }
  const OneNoteRepairSearch *search = &state->repair;

  if (!onenote_reassembly_score_valid(&search->best, state->block_count)
      || !onenote_reassembly_score_valid(&search->weak, state->block_count)
      || !onenote_reassembly_score_valid(&search->local_best, state->block_count)
      || search->phase > ONENOTE_REPAIR_ANCHOR
      || (search->phase != ONENOTE_REPAIR_NONE
          && (!state->progress_valid || search->pass > 1
              || search->run_start == 0
              || search->run_start > state->block_count
              || (search->phase != ONENOTE_REPAIR_ZERO_GAP
                  && search->phase != ONENOTE_REPAIR_PACKAGE_GAP
                  && search->phase != ONENOTE_REPAIR_BOUNDARIES
                  && search->phase != ONENOTE_REPAIR_ZIP_EXTENSION
                  && (search->run_start == state->block_count
                      || search->run_length == 0
                      || search->run_length
                             > state->block_count - search->run_start))
              || (search->phase == ONENOTE_REPAIR_ZIP_EXTENSION
                  && (search->run_start == state->block_count
                      || search->run_length < 2
                      || search->run_length > state->block_count - search->run_start + 1
                      || !search->local_best.found
                      || !search->local_best.zip_output_comparable))
              || (search->phase == ONENOTE_REPAIR_BOUNDARIES
                  && (search->run_start == state->block_count
                      || search->run_length == 0
                      || (search->pass == 0
                          && search->run_length >= search->run_start)
                      || (search->pass == 1
                          && search->run_length > state->block_count - search->run_start)
                      || search->next_source > state->alignment_count + 1))
              || search->searched_end == 0 || search->searched_end > INT64_MAX
              || ((search->phase == ONENOTE_REPAIR_ZIP_SOURCES
                   || search->phase == ONENOTE_REPAIR_ZIP_EXTENSION)
                  && search->local_best.found
                  && ((uint64_t)search->local_best.source >= search->searched_end
                      || search->local_best.run_start != search->run_start
                      || (search->phase == ONENOTE_REPAIR_ZIP_EXTENSION
                          && search->local_best.run_length != search->run_length - 1)))
              || ((search->phase == ONENOTE_REPAIR_RUNS
                   || search->phase == ONENOTE_REPAIR_ZERO_ISLAND
                   || search->phase == ONENOTE_REPAIR_ZIP_SOURCES)
                  && search->next_source > search->searched_end)
              || (search->phase == ONENOTE_REPAIR_ALIGNMENTS
                  && search->next_source > state->alignment_count + 1)
              || (search->phase == ONENOTE_REPAIR_ANCHOR
                  && (search->next_source > 2 || !search->best.found))
              || (search->phase == ONENOTE_REPAIR_SUFFIXES
                  && search->next_source > search->run_length)
              || (search->phase == ONENOTE_REPAIR_PACKAGE_TAIL
                  && search->next_source
                         < state->block_count - search->run_length)))) {
    return false;
  }
  if (state->phase == ONENOTE_SEARCH_NONE) {
    return state->progress_valid != 0;
  }
  if (state->block_count < 3) {
    return false;
  }
  if (state->phase == ONENOTE_SEARCH_INTERIOR_SPANS_COMPLETE) {
    return true;
  }
  return state->span_start > 0
         && state->span_start < state->block_count - 1
         && state->run_start > 0
         && state->run_start < state->block_count
         && state->run_end > state->run_start
         && state->run_end <= state->block_count;
}

static inline bool onenote_serialize_carve_state(
    void **state, FILE *fp, StateSerialization mode) {

  OneNoteCarveState **onenote_state = (OneNoteCarveState **)state;

  if (!onenote_state || !fp) {
    return false;
  }
  if (mode == SERIALIZE) {
    if (!onenote_carve_state_valid(*onenote_state)
        || fwrite(*onenote_state,
                  offsetof(OneNoteCarveState, alignments), 1, fp) != 1
        || ((*onenote_state)->alignment_count != 0
            && fwrite((*onenote_state)->alignments,
                      sizeof(*(*onenote_state)->alignments),
                      (size_t)(*onenote_state)->alignment_count, fp)
                   != (*onenote_state)->alignment_count)) {
      handle_error(SCALPEL_ERROR_CHECKPOINT,
                   "invalid OneNote carve state", __LINE__, __FILE__);
    }
    return true;
  }

  OneNoteCarveState *restored = calloc(1, sizeof(*restored));
  check_memory_allocation(restored, __LINE__, __FILE__,
                          "OneNote carve state");
  const size_t legacy_size = offsetof(OneNoteCarveState,
                                      overlapping_suffix_blocks);
  const size_t extra_size = offsetof(OneNoteCarveState, alignments)
                           - offsetof(OneNoteCarveState, repair);
  const size_t v2_size = offsetof(OneNoteCarveState, repair) - legacy_size;
  bool valid = fread(restored, legacy_size, 1, fp) == 1
               && restored->magic == ONENOTE_CARVE_STATE_MAGIC
               && (restored->version == 1 || restored->version == 2
                   || restored->version == 3 || restored->version == 4
                   || restored->version == 5 || restored->version == 6
                   || restored->version == 7
                   || restored->version == ONENOTE_CARVE_STATE_VERSION);

  if (valid && restored->version >= 2) {
    valid = fread((uint8_t *)restored + legacy_size, v2_size, 1, fp) == 1
            && restored->alignment_count
                   <= SIZE_MAX / sizeof(*restored->alignments);
    if (valid && restored->version >= 3) {
      valid = fread(&restored->repair, extra_size, 1, fp) == 1;
    }
    if (valid && restored->alignment_count != 0) {
      restored->alignments = malloc((size_t)restored->alignment_count
                                    * sizeof(*restored->alignments));
      check_memory_allocation(restored->alignments, __LINE__, __FILE__,
                              "OneNote saved alignments");
      valid = fread(restored->alignments, sizeof(*restored->alignments),
                    (size_t)restored->alignment_count, fp)
              == restored->alignment_count;
    }
  }
  restored->version = ONENOTE_CARVE_STATE_VERSION;
  if (!valid || !onenote_carve_state_valid(restored)) {
    onenote_free_carve_state((void **)&restored);
    handle_error(SCALPEL_ERROR_CHECKPOINT,
                 "invalid OneNote carve state", __LINE__, __FILE__);
    return false;
  }
  *onenote_state = restored;
  return true;
}

static inline void *onenote_clone_carve_state(const void *srcstate) {

  const OneNoteCarveState *source = (const OneNoteCarveState *)srcstate;

  if (!onenote_carve_state_valid(source)) {
    return NULL;
  }
  OneNoteCarveState *clone = malloc(sizeof(*clone));
  check_memory_allocation(clone, __LINE__, __FILE__,
                          "OneNote carve state clone");
  memcpy(clone, source, sizeof(*clone));
  clone->alignments = NULL;
  if (source->alignment_count != 0) {
    clone->alignments = malloc((size_t)source->alignment_count
                              * sizeof(*clone->alignments));
    check_memory_allocation(clone->alignments, __LINE__, __FILE__,
                            "OneNote alignment clone");
    memcpy(clone->alignments, source->alignments,
           (size_t)source->alignment_count * sizeof(*clone->alignments));
  }
  return clone;
}

static inline void onenote_free_carve_state(void **state) {

  if (state) {
    if (*state) {
      free(((OneNoteCarveState *)*state)->alignments);
    }
    free(*state);
    *state = NULL;
  }
}

static inline size_t onenote_sizeof_carve_state(const void *state) {

  (void)state;
  return 0;
}

static inline void onenote_print_carve_state(const void *state) {

  const OneNoteCarveState *onenote_state =
      (const OneNoteCarveState *)state;

  if (!onenote_state) {
    fprintf(stdout, "NULL");
    return;
  }
  fprintf(stdout,
          "phase=%" PRIu32 " span=%" PRIu64 " run=%" PRIu64
          " end=%" PRIu64,
          onenote_state->phase, onenote_state->span_start,
          onenote_state->run_start, onenote_state->run_end);
}

static inline void onenote_store_carve_state(
    CarveInfo *candidate, const OneNoteCarveState *state) {

  carve_put_state(candidate ? candidate->carvehashkey : NULL, (void *)state);
}

static inline uint64_t onenote_reassembly_mapping_hash(
    const int64_t *mapping, uint64_t block_count) {

  uint64_t hash = UINT64_C(1469598103934665603);

  for (uint64_t slot = 0; slot < block_count; slot++) {
    const int64_t actual = mapping[slot] < 0
        ? -1
        : filemirror_actual_blocknumber(scalpel_state.filemirror,
                                        mapping[slot]);

    hash ^= (uint64_t)actual;
    hash *= UINT64_C(1099511628211);
    hash ^= slot;
    hash *= UINT64_C(1099511628211);
  }
  return hash;
}

// Keep a physical witness for each learned alignment. Apparent positions can
// change when a checkpoint removes blocks recovered by another candidate.
//
static inline void onenote_reassembly_remember_alignment(
    OneNoteCarveState *state, int64_t actual, uint64_t slot) {

  if (!state || actual < 0 || slot >= state->block_count) {
    return;
  }
  if (state->alignment_count >= SIZE_MAX / sizeof(*state->alignments)) {
    handle_error(SCALPEL_GENERAL_ABORT, "OneNote alignment table overflow",
                 __LINE__, __FILE__);
    return;
  }
  OneNoteAlignment *alignments = realloc(
      state->alignments,
      (size_t)(state->alignment_count + 1) * sizeof(*alignments));
  check_memory_allocation(alignments, __LINE__, __FILE__,
                          "OneNote saved alignments");
  state->alignments = alignments;
  state->alignments[state->alignment_count++] =
      (OneNoteAlignment){.actual = actual, .slot = slot};
}

// Load progress only for the same committed physical mapping and extent.
//
static inline OneNoteCarveState *onenote_reassembly_progress_state(
    CarveInfo *candidate, const int64_t *mapping, uint64_t block_count,
    uint64_t data_length) {

  OneNoteCarveState *state = (OneNoteCarveState *)carve_get_state(
      candidate->carvehashkey);
  const uint64_t hash = onenote_reassembly_mapping_hash(mapping, block_count);

  if (!onenote_carve_state_valid(state)
      || state->block_count != block_count || state->data_length != data_length
      || state->mapping_hash != hash) {
    onenote_free_carve_state((void **)&state);
    state = calloc(1, sizeof(*state));
    check_memory_allocation(state, __LINE__, __FILE__,
                            "OneNote committed progress");
    state->magic = ONENOTE_CARVE_STATE_MAGIC;
    state->version = ONENOTE_CARVE_STATE_VERSION;
    state->block_count = block_count;
    state->data_length = data_length;
    state->mapping_hash = hash;
  }
  return state;
}

// Restore decisions made while committing the current mapping. Parser scratch
// is rebuilt independently; these learned alignments and guards are not scratch.
//
static inline void onenote_reassembly_restore_progress(
    CarveInfo *candidate, const int64_t *mapping, uint64_t block_count,
    uint64_t data_length, OneNoteRecoveryScore *current,
    int64_t **displacements, uint64_t *count, uint64_t *capacity) {

  OneNoteCarveState *state = onenote_reassembly_progress_state(
      candidate, mapping, block_count, data_length);
  if (state->progress_valid) {
    current->overlapping_suffix_blocks = state->overlapping_suffix_blocks;
    current->exact_run_boundaries = state->exact_run_boundaries != 0;
    current->reservations = state->reservations;
  }
  else {
    state->progress_valid = 1;
    state->reservations = current->reservations;
    onenote_reassembly_remember_alignment(
        state, filemirror_actual_blocknumber(scalpel_state.filemirror,
                                             mapping[0]), 0);
  }

  for (uint64_t index = 0; index < state->alignment_count; index++) {
    const OneNoteAlignment *alignment = &state->alignments[index];
    const int64_t apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, alignment->actual);

    if (apparent < 0 || alignment->slot > INT64_MAX
        || filemirror_actual_block_covered(scalpel_state.filemirror,
                                          alignment->actual)) {
      continue;
    }
    const int64_t displacement = apparent - (int64_t)alignment->slot;
    bool known = false;

    for (uint64_t prior = 0; prior < *count; prior++) {
      if ((*displacements)[prior] == displacement) {
        known = true;
        break;
      }
    }
    if (known) {
      continue;
    }
    if (*count == *capacity) {
      if (*capacity > SIZE_MAX / sizeof(**displacements) / 2) {
        handle_error(SCALPEL_GENERAL_ABORT, "OneNote displacement table overflow",
                     __LINE__, __FILE__);
        break;
      }
      *capacity *= 2;
      *displacements = realloc(*displacements,
                                (size_t)*capacity * sizeof(**displacements));
      check_memory_allocation(*displacements, __LINE__, __FILE__,
                              "OneNote restored displacements");
    }
    (*displacements)[(*count)++] = displacement;
  }
  onenote_store_carve_state(candidate, state);
  onenote_free_carve_state((void **)&state);
}

// Saving a new committed mapping invalidates only the boundary search for the
// previous mapping. Preserve every learned alignment, including older ones.
//
static inline void onenote_reassembly_commit_progress(
    CarveInfo *candidate, const int64_t *mapping, uint64_t block_count,
    uint64_t data_length, const OneNoteRecoveryScore *current,
    const OneNoteRecoveryScore *placement, bool new_alignment) {

  OneNoteCarveState *state = (OneNoteCarveState *)carve_get_state(
      candidate->carvehashkey);

  if (!onenote_carve_state_valid(state)) {
    onenote_free_carve_state((void **)&state);
    state = calloc(1, sizeof(*state));
    check_memory_allocation(state, __LINE__, __FILE__,
                            "OneNote committed progress");
    state->magic = ONENOTE_CARVE_STATE_MAGIC;
    state->version = ONENOTE_CARVE_STATE_VERSION;
    state->block_count = block_count;
    onenote_reassembly_remember_alignment(
        state, filemirror_actual_blocknumber(scalpel_state.filemirror,
                                             mapping[0]), 0);
  }
  state->block_count = block_count;
  state->data_length = data_length;
  state->mapping_hash = onenote_reassembly_mapping_hash(mapping, block_count);
  state->phase = ONENOTE_SEARCH_NONE;
  state->span_start = state->run_start = state->run_end = state->span_view = 0;
  state->progress_valid = 1;
  state->overlapping_suffix_blocks = current->overlapping_suffix_blocks;
  state->exact_run_boundaries = current->exact_run_boundaries ? 1 : 0;
  state->reservations = current->reservations;
  memset(&state->repair, 0, sizeof(state->repair));
  if (new_alignment) {
    onenote_reassembly_remember_alignment(
        state, filemirror_actual_blocknumber(scalpel_state.filemirror,
                                             placement->source),
        placement->run_start);
  }
  onenote_store_carve_state(candidate, state);
  onenote_free_carve_state((void **)&state);
}

// The span cursor depends on the blocks reachable through its two apparent
// alignments, not on unrelated coverage elsewhere in the image.
//
static inline uint64_t onenote_reassembly_span_view(
    const int64_t *mapping, uint64_t block_count) {

  uint64_t hash = UINT64_C(1469598103934665603);
  const uint64_t image_blocks = filemirror_apparent_blocks(
      scalpel_state.filemirror);

  for (uint64_t start = 1; start + 1 < block_count;) {
    const int64_t inner = mapping[start] - (int64_t)start;
    uint64_t end = start + 1;

    while (end < block_count && mapping[end] - (int64_t)end == inner) {
      end++;
    }
    if (end == block_count) {
      break;
    }
    const int64_t outer = mapping[start - 1] - (int64_t)(start - 1);

    if (outer == mapping[end] - (int64_t)end && outer != inner) {
      hash = (hash ^ start) * UINT64_C(1099511628211);
      hash = (hash ^ end) * UINT64_C(1099511628211);
      for (uint32_t side = 0; side < 2; side++) {
        const int64_t displacement = side ? inner : outer;

        for (uint64_t slot = 1; slot < block_count; slot++) {
          int64_t actual = -1;

          if (displacement >= -(int64_t)slot
              && displacement <= INT64_MAX - (int64_t)slot) {
            const int64_t apparent = displacement + (int64_t)slot;

            if ((uint64_t)apparent < image_blocks) {
              actual = filemirror_actual_blocknumber(scalpel_state.filemirror,
                                                     apparent);
            }
          }
          hash = (hash ^ (uint64_t)actual) * UINT64_C(1099511628211);
          const bool covered = actual >= 0
              && filemirror_actual_block_covered(scalpel_state.filemirror,
                                                 actual);

          hash = (hash ^ (uint64_t)covered) * UINT64_C(1099511628211);
        }
      }
    }
    start = end;
  }
  return hash;
}

// Honor kill-queue and checkpoint requests without imposing voluntary yields.
//
static inline bool onenote_reassembly_poll(ThreadWork *work,
                                           CarveInfo **candidate,
                                           uuid_string_t uuidp,
                                           uuid_string_t uuidc) {

  if (!work || !candidate || !*candidate
      || reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
    return true;
  }
  if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)
      && reassembly_time_to_checkpoint(work->id, *candidate, uuidp, uuidc)) {
    return true;
  }
  return false;
}

// These searches enumerate apparent runs. Retain their cursor only while the
// tested source prefix still names the same available physical blocks.
//
static inline uint64_t onenote_reassembly_search_view(uint64_t end) {

  uint64_t hash = UINT64_C(1469598103934665603);
  const uint64_t blocks = filemirror_apparent_blocks(scalpel_state.filemirror);
  const uint64_t count = end < blocks ? end : blocks;

  for (uint64_t index = 0; index < count; index++) {
    const int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, (int64_t)index);
    const bool covered = actual < 0
        || filemirror_actual_block_covered(scalpel_state.filemirror, actual);

    hash = (hash ^ (uint64_t)actual) * UINT64_C(1099511628211);
    hash = (hash ^ (uint64_t)covered) * UINT64_C(1099511628211);
  }
  return (hash ^ count) * UINT64_C(1099511628211);
}

// Boundary refinements also depend on the learned alignment list. A removed
// witness can change its filtered indices even outside the scanned source prefix.
//
static inline uint64_t onenote_reassembly_search_scope(
    const OneNoteCarveState *state, const OneNoteRepairSearch *search) {

  uint64_t hash = onenote_reassembly_search_view(search->searched_end);

  if (search->phase == ONENOTE_REPAIR_BOUNDARIES
      || search->phase == ONENOTE_REPAIR_ALIGNMENTS) {
    for (uint64_t index = 0; index < state->alignment_count; index++) {
      const OneNoteAlignment *alignment = &state->alignments[index];
      const int64_t apparent = filemirror_apparent_blocknumber(
          scalpel_state.filemirror, alignment->actual);
      const bool covered = filemirror_actual_block_covered(
          scalpel_state.filemirror, alignment->actual);

      hash = (hash ^ (uint64_t)apparent) * UINT64_C(1099511628211);
      hash = (hash ^ (uint64_t)covered) * UINT64_C(1099511628211);
    }
  }
  return hash;
}

static inline OneNoteRepairSearch onenote_reassembly_load_search(
    CarveInfo *candidate) {

  OneNoteRepairSearch search = {0};
  OneNoteCarveState *state = (OneNoteCarveState *)carve_get_state(
      candidate->carvehashkey);

  if (onenote_carve_state_valid(state)
      && state->repair.phase != ONENOTE_REPAIR_NONE
      && state->repair.view
             == onenote_reassembly_search_scope(state, &state->repair)) {
    search = state->repair;
  }
  onenote_free_carve_state((void **)&state);
  return search;
}

static inline bool onenote_reassembly_search_poll(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, OneNoteRepairSearch *search,
    const OneNoteRevisionState *workspace) {

  if (candidate && *candidate
      && atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
    OneNoteCarveState *state = (OneNoteCarveState *)carve_get_state(
        (*candidate)->carvehashkey);

    if (onenote_carve_state_valid(state)) {
      search->searched_end = workspace->searched_end;
      search->view = onenote_reassembly_search_scope(state, search);
      state->repair = *search;
      onenote_store_carve_state(*candidate, state);
    }
    onenote_free_carve_state((void **)&state);
  }
  return onenote_reassembly_poll(work, candidate, uuidp, uuidc);
}

// Copy one apparent image block into a zero-padded destination block.
//
static inline bool onenote_reassembly_copy_block(uint8_t *destination,
                                                 int64_t apparent) {

  const uint64_t image_blocks = filemirror_apparent_blocks(
      scalpel_state.filemirror);

  if (!destination || apparent < 0 || (uint64_t)apparent >= image_blocks) {
    return false;
  }

  const int64_t actual = filemirror_actual_blocknumber(
      scalpel_state.filemirror, apparent);
  uint64_t available = 0;
  const char *source = filemirror_actual_block_data_pointer(
      scalpel_state.filemirror, actual, &available);

  if (!source) {
    return false;
  }
  if (available > scalpel_state.blocksize) {
    available = scalpel_state.blocksize;
  }
  memcpy(destination, source, available);
  if (available < scalpel_state.blocksize) {
    memset(destination + available, 0,
           scalpel_state.blocksize - available);
  }
  return true;
}

// Materialize a complete trial mapping once; individual trials patch and
// restore only the run under consideration.
//
static inline bool onenote_reassembly_materialize(uint8_t *data,
                                                  const int64_t *mapping,
                                                  uint64_t block_count) {

  if (!data || !mapping) {
    return false;
  }
  for (uint64_t slot = 0; slot < block_count; slot++) {
    if (!onenote_reassembly_copy_block(
            data + slot * (uint64_t)scalpel_state.blocksize,
            mapping[slot])) {
      return false;
    }
  }
  return true;
}

// Rank statistically uniform blocks first when a checksum identifies a broad
// compressed range. This affects search order only; every slot remains in the
// exhaustive fallback.
//
static inline uint64_t onenote_reassembly_uniformity(
    const uint8_t *data, uint64_t length) {

  if (!data || length == 0) {
    return UINT64_MAX;
  }

  uint64_t counts[UINT8_MAX + 1] = {0};

  for (uint64_t offset = 0; offset < length; offset++) {
    counts[data[offset]]++;
  }

  uint64_t sum = 0;

  for (uint64_t value = 0; value <= UINT8_MAX; value++) {
    uint64_t square = 0;

    if (__builtin_mul_overflow(counts[value], counts[value], &square)
        || __builtin_add_overflow(sum, square, &sum)) {
      return UINT64_MAX;
    }
  }
  return sum;
}

// Rank parser progress first. Physical continuity and reservation pressure
// only break ties between trials with identical format evidence.
//
static inline bool onenote_reassembly_score_better(
    const OneNoteRecoveryScore *trial,
    const OneNoteRecoveryScore *best) {

  if (!trial || !trial->found) {
    return false;
  }
  if (!best || !best->found) {
    return true;
  }
  if (trial->complete != best->complete) {
    return trial->complete;
  }
  if (!trial->complete
      && trial->overlapping_suffix_blocks
             != best->overlapping_suffix_blocks) {
    return trial->overlapping_suffix_blocks
           > best->overlapping_suffix_blocks;
  }
  if (trial->summary.authenticated_references
      != best->summary.authenticated_references) {
    return trial->summary.authenticated_references
           > best->summary.authenticated_references;
  }
  if (trial->summary.integrity_references
      != best->summary.integrity_references) {
    return trial->summary.integrity_references
           > best->summary.integrity_references;
  }
  if (trial->summary.structural_references
      != best->summary.structural_references) {
    return trial->summary.structural_references
           > best->summary.structural_references;
  }
  if (trial->zip_output_comparable && best->zip_output_comparable
      && trial->zip_output_distance != best->zip_output_distance) {
    return trial->zip_output_distance < best->zip_output_distance;
  }
  if (trial->summary.failure_offset != best->summary.failure_offset) {
    return trial->summary.failure_offset > best->summary.failure_offset;
  }
  if (trial->content_seam_cost != best->content_seam_cost) {
    return trial->content_seam_cost < best->content_seam_cost;
  }
  if (trial->contiguous_pairs != best->contiguous_pairs) {
    return trial->contiguous_pairs > best->contiguous_pairs;
  }
  if (trial->seam_cost != best->seam_cost) {
    return trial->seam_cost < best->seam_cost;
  }
  if (trial->reservations != best->reservations) {
    return trial->reservations < best->reservations;
  }
  if (trial->run_length != best->run_length) {
    return trial->run_length < best->run_length;
  }
  return trial->source < best->source;
}

static inline bool onenote_reassembly_parser_progress(
    const OneNoteRecoveryScore *current, const OneNoteSummary *summary,
    bool complete, bool zip_output_comparable,
    uint64_t zip_output_distance) {

  if (!current || !summary) {
    return false;
  }
  if (current->complete) {
    return complete;
  }
  return complete
         || (zip_output_comparable && current->zip_output_comparable
             && zip_output_distance < current->zip_output_distance)
         || summary->authenticated_references
                > current->summary.authenticated_references
         || (summary->authenticated_references
                 == current->summary.authenticated_references
             && summary->integrity_references
                    > current->summary.integrity_references)
         || (summary->authenticated_references
                 == current->summary.authenticated_references
             && summary->integrity_references
                    == current->summary.integrity_references
             && summary->structural_references
                    > current->summary.structural_references)
         || (summary->authenticated_references
                 == current->summary.authenticated_references
             && summary->integrity_references
                    == current->summary.integrity_references
             && summary->structural_references
                    == current->summary.structural_references
             && summary->failure_offset
                    > current->summary.failure_offset);
}

// Distinguish independent format evidence from a parser cursor that merely
// moved farther through unauthenticated bytes. Cursor movement is useful for
// locating a displaced run, but is not by itself strong enough to commit one
// arbitrary block from that run.
//
static inline bool onenote_reassembly_evidence_progress(
    const OneNoteRecoveryScore *current,
    const OneNoteRecoveryScore *trial) {

  if (!current || !trial || !trial->found) {
    return false;
  }
  return trial->complete
         || (trial->zip_output_comparable && current->zip_output_comparable
             && trial->zip_output_distance < current->zip_output_distance)
         || trial->summary.authenticated_references
                > current->summary.authenticated_references
         || (trial->summary.authenticated_references
                 == current->summary.authenticated_references
             && trial->summary.integrity_references
                    > current->summary.integrity_references)
         || (trial->summary.authenticated_references
                 == current->summary.authenticated_references
             && trial->summary.integrity_references
                    == current->summary.integrity_references
             && trial->summary.structural_references
                    > current->summary.structural_references);
}

// Score the physical layout of a trial. Compression is used only across
// discontinuities and only as a tiebreaker after complete format validation.
//
static inline void onenote_reassembly_score_layout(
    const uint8_t *data, const int64_t *mapping, uint64_t block_count,
    uint64_t run_start, uint64_t run_length, int64_t source,
    OneNoteRecoveryScore *score) {

  if (!data || !mapping || !score) {
    return;
  }

  const uint64_t blocksize = scalpel_state.blocksize;
  uint8_t seam[2 * ONENOTE_REASSEMBLY_SEAM_BYTES];
  uint8_t compressed[ONENOTE_REASSEMBLY_SEAM_BUFFER];

  score->contiguous_pairs = 0;
  score->reservations = 0;
  score->seam_cost = 0;

  for (uint64_t slot = 0; slot < block_count; slot++) {
    const int64_t apparent = run_length > 0 && slot >= run_start
                                 && slot < run_start + run_length
                                 ? source + (int64_t)(slot - run_start)
                                 : mapping[slot];
    const int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, apparent);

    if (scalpel_state.reservations && actual >= 0) {
      const int64_t reservations = filemirror_actual_block_reserved(
          scalpel_state.filemirror, actual);

      if (reservations > 0) {
        score->reservations += (uint64_t)reservations;
      }
    }
    if (slot == 0) {
      continue;
    }
    const int64_t previous = run_length > 0 && slot - 1 >= run_start
                                 && slot - 1 < run_start + run_length
                                 ? source + (int64_t)(slot - 1 - run_start)
                                 : mapping[slot - 1];

    if (apparent == previous + 1) {
      score->contiguous_pairs++;
      continue;
    }
    if (!score->complete) {
      continue;
    }
    if (blocksize < ONENOTE_REASSEMBLY_SEAM_BYTES) {
      score->seam_cost = UINT64_MAX;
      continue;
    }

    memcpy(seam,
           data + slot * blocksize - ONENOTE_REASSEMBLY_SEAM_BYTES,
           ONENOTE_REASSEMBLY_SEAM_BYTES);
    memcpy(seam + ONENOTE_REASSEMBLY_SEAM_BYTES,
           data + slot * blocksize,
           ONENOTE_REASSEMBLY_SEAM_BYTES);

    uLongf compressed_length = sizeof(compressed);
    const int result = compress2(compressed, &compressed_length,
                                 seam, sizeof(seam), Z_BEST_SPEED);

    if (result != Z_OK
        || score->seam_cost > UINT64_MAX - compressed_length) {
      score->seam_cost = UINT64_MAX;
    }
    else {
      score->seam_cost += compressed_length;
    }
  }
}

// Measure byte continuity at every logical block boundary. This is used only
// when strict parser evidence ties between structured gap hypotheses.
//
static inline uint64_t onenote_reassembly_content_seam_cost(
    const uint8_t *data, uint64_t block_count) {

  const uint64_t blocksize = scalpel_state.blocksize;

  if (!data || block_count < 2
      || blocksize < ONENOTE_REASSEMBLY_SEAM_BYTES) {
    return UINT64_MAX;
  }

  uint8_t seam[2 * ONENOTE_REASSEMBLY_SEAM_BYTES];
  uint8_t compressed[ONENOTE_REASSEMBLY_SEAM_BUFFER];
  uint64_t cost = 0;

  for (uint64_t slot = 1; slot < block_count; slot++) {
    memcpy(seam,
           data + slot * blocksize - ONENOTE_REASSEMBLY_SEAM_BYTES,
           ONENOTE_REASSEMBLY_SEAM_BYTES);
    memcpy(seam + ONENOTE_REASSEMBLY_SEAM_BYTES,
           data + slot * blocksize,
           ONENOTE_REASSEMBLY_SEAM_BYTES);

    uLongf compressed_length = sizeof(compressed);
    const int result = compress2(compressed, &compressed_length,
                                 seam, sizeof(seam), Z_BEST_SPEED);

    if (result != Z_OK || cost > UINT64_MAX - compressed_length) {
      return UINT64_MAX;
    }
    cost += compressed_length;
  }
  return cost;
}

// Test one contiguous source run in one logical slot range. The caller clears
// the current target blocks from 'used', so any remaining set bit represents
// a collision with a block outside the replacement range. Exhaustive callers
// can defer restoring the same logical run until all source trials finish.
//
static inline bool onenote_reassembly_try_run(
    uint8_t *trial_data, const int64_t *mapping, const uint8_t *used,
    uint64_t block_count, uint64_t data_length, OneNoteKind kind,
    uint64_t run_start, uint64_t run_length, int64_t source,
    const OneNoteRecoveryScore *current, OneNoteRecoveryScore *best,
    bool restore_data, OneNoteRecoveryScore *observed,
    OneNoteRevisionState *workspace, bool confirm_progress) {

  const uint64_t image_blocks = filemirror_apparent_blocks(
      scalpel_state.filemirror);
  const uint64_t blocksize = scalpel_state.blocksize;

  if (!trial_data || !mapping || !used || !current || !best
      || run_start == 0 || run_length == 0
      || run_start > block_count
      || run_length > block_count - run_start
      || source < 0 || (uint64_t)source > image_blocks
      || run_length > image_blocks - (uint64_t)source) {
    return false;
  }

  if (workspace && workspace->searched_end < (uint64_t)source + run_length) {
    workspace->searched_end = (uint64_t)source + run_length;
  }

  bool changed = false;

  for (uint64_t offset = 0; offset < run_length; offset++) {
    const uint64_t apparent = (uint64_t)source + offset;

    if ((used[apparent >> 3] & (uint8_t)(1u << (apparent & 7u))) != 0) {
      return false;
    }
    const int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, (int64_t)apparent);

    // Revision stores can legitimately contain allocated all-zero ranges.
    // Their physical blocks remain valid choices when they are uncovered.
    if (actual < 0
        || filemirror_actual_block_covered(scalpel_state.filemirror,
                                           actual)) {
      return false;
    }
    changed = changed || mapping[run_start + offset] != (int64_t)apparent;
  }
  if (!changed) {
    return false;
  }

  bool copied = true;

  for (uint64_t offset = 0; offset < run_length; offset++) {
    copied = onenote_reassembly_copy_block(
        trial_data + (run_start + offset) * blocksize,
        source + (int64_t)offset);
    if (!copied) {
      break;
    }
  }

  OneNoteSummary summary = {0};
  bool complete = false;
  bool reject_without_full_parse = false;
  bool zip_output_comparable = false;
  uint64_t zip_output_distance = UINT64_MAX;

  if (copied) {
    if (workspace) {
      workspace->trial_start = run_start * blocksize;
      workspace->trial_end = (run_start + run_length) * blocksize - 1;
      if (workspace->trial_end >= data_length) {
        workspace->trial_end = data_length - 1;
      }
      bool zip_valid = false;
      uint64_t zip_failure = 0;
      const bool zip_probe_used = onenote_revision_zip_probe_trial(
          workspace, trial_data, workspace->trial_start,
          workspace->trial_end, &zip_valid, &zip_failure,
          &zip_output_comparable, &zip_output_distance);

      reject_without_full_parse = zip_probe_used && !zip_valid;
      if (reject_without_full_parse) {
        summary = current->summary;
        summary.failure_offset = zip_failure;
      }
    }
    if (!reject_without_full_parse) {
      if (workspace) {
        workspace->trial_active = true;
      }
      complete = onenote_parse_with_workspace(
          trial_data, data_length, kind, &summary, workspace);
      if (workspace) {
        workspace->trial_active = false;
      }
    }
  }
  bool parser_progress = onenote_reassembly_parser_progress(
      current, &summary, complete, zip_output_comparable,
      zip_output_distance);

  // Cached references cheaply reject most trials. Confirm every apparent
  // improvement with independent parser state before allowing it to change the
  // candidate, since modified pointer structures can invalidate indirect cache
  // dependencies outside the replaced byte range.
  if (copied && parser_progress && confirm_progress) {
    OneNoteRevisionState confirmation = {0};
    OneNoteSummary confirmed_summary = {0};
    const bool confirmed_complete = onenote_parse_with_workspace(
        trial_data, data_length, kind, &confirmed_summary, &confirmation);
    const bool confirmed_zip_comparable =
        confirmation.zip_probe.baseline_output_comparable;
    const uint64_t confirmed_zip_distance = confirmed_zip_comparable
        ? confirmation.zip_probe.baseline_output_distance : UINT64_MAX;

    onenote_revision_state_release(&confirmation);
    summary = confirmed_summary;
    complete = confirmed_complete;
    zip_output_comparable = confirmed_zip_comparable;
    zip_output_distance = confirmed_zip_distance;
    parser_progress = onenote_reassembly_parser_progress(
        current, &summary, complete, zip_output_comparable,
        zip_output_distance);
  }

  OneNoteRecoveryScore trial = {
    .summary = summary,
    .run_start = run_start,
    .run_length = run_length,
    .source = source,
    .complete = complete,
    .found = true,
    .zip_output_comparable = zip_output_comparable,
    .zip_output_distance = zip_output_distance
  };

  // A physical gap shifts a suffix forward while retaining most of the blocks
  // already associated with the candidate. Prefer that independently parsed,
  // minimal repair over an incomplete graft from an unrelated distant file.
  // Complete format validation remains the strongest result.
  if (!complete
      && current->summary.authenticated_references == 0
      && current->summary.integrity_references == 0
      && block_count <= ONENOTE_REASSEMBLY_EXHAUSTIVE_GAP_BLOCKS
      && run_start + run_length == block_count
      && mapping[run_start - 1] >= 0
      && mapping[run_start - 1] < INT64_MAX) {
    const uint64_t expected_source =
        (uint64_t)mapping[run_start - 1] + 1;

    if ((uint64_t)source > expected_source) {
      const uint64_t shift = (uint64_t)source - expected_source;

      if (shift < run_length) {
        trial.overlapping_suffix_blocks = run_length - shift;
      }
    }
  }
  const bool score_required = parser_progress || observed;

  if (copied && score_required) {
    onenote_reassembly_score_layout(
        trial_data, mapping, block_count, run_start, run_length, source,
        &trial);
    if (complete) {
      trial.content_seam_cost = onenote_reassembly_content_seam_cost(
          trial_data, block_count);
    }
  }

  if (restore_data) {
    for (uint64_t offset = 0; offset < run_length; offset++) {
      if (!onenote_reassembly_copy_block(
              trial_data + (run_start + offset) * blocksize,
              mapping[run_start + offset])) {
        copied = false;
        break;
      }
    }
  }
  if (!copied || summary.no_memory) {
    return false;
  }
  if (observed) {
    *observed = trial;
  }

  bool progressed = false;

  if (current->complete) {
    progressed = parser_progress
                 && (trial.content_seam_cost
                         < current->content_seam_cost
                     || (trial.content_seam_cost
                             == current->content_seam_cost
                         && trial.contiguous_pairs
                                > current->contiguous_pairs)
                     || (trial.content_seam_cost
                             == current->content_seam_cost
                         && trial.contiguous_pairs
                                == current->contiguous_pairs
                         && trial.seam_cost < current->seam_cost)
                     || (trial.content_seam_cost
                             == current->content_seam_cost
                         && trial.contiguous_pairs
                                == current->contiguous_pairs
                         && trial.seam_cost == current->seam_cost
                         && trial.reservations < current->reservations));
  }
  else {
    progressed = parser_progress;
  }
  if (!progressed) {
    return false;
  }

  if (onenote_reassembly_score_better(&trial, best)) {
    *best = trial;
  }
  return true;
}

// Probe with reusable parser state, but independently confirm any trial that
// improves format evidence or minimally shifts an overlapping physical suffix.
// Other cursor-only movement is retained as a last-resort hypothesis and
// cannot preempt stronger evidence.
//
static inline void onenote_reassembly_probe_run(
    uint8_t *trial_data, const int64_t *mapping, const uint8_t *used,
    uint64_t block_count, uint64_t data_length, OneNoteKind kind,
    uint64_t run_start, uint64_t run_length, int64_t source,
    const OneNoteRecoveryScore *current, OneNoteRecoveryScore *strong,
    OneNoteRecoveryScore *weak, bool restore_data,
    OneNoteRevisionState *workspace) {

  if (!current || !strong || !weak) {
    return;
  }

  OneNoteRecoveryScore observed = {0};
  OneNoteRecoveryScore probe_best = {0};

  const bool parser_advanced = onenote_reassembly_try_run(
      trial_data, mapping, used, block_count, data_length, kind,
      run_start, run_length, source, current, &probe_best,
      restore_data, &observed, workspace, false);

  if (!parser_advanced && observed.overlapping_suffix_blocks == 0) {
    return;
  }
  const bool format_evidence = onenote_reassembly_evidence_progress(
      current, &observed);
  const bool overlapping_suffix =
      observed.overlapping_suffix_blocks
      > current->overlapping_suffix_blocks;

  if (!format_evidence && !overlapping_suffix) {
    if (onenote_reassembly_score_better(&observed, weak)) {
      *weak = observed;
    }
    return;
  }

  OneNoteRecoveryScore confirmed = {0};
  OneNoteRecoveryScore confirmed_best = {0};

  onenote_reassembly_try_run(
      trial_data, mapping, used, block_count, data_length, kind,
      run_start, run_length, source, current, &confirmed_best,
      restore_data, &confirmed, workspace, true);
  if ((onenote_reassembly_evidence_progress(current, &confirmed)
       || confirmed.overlapping_suffix_blocks
              > current->overlapping_suffix_blocks)
      && onenote_reassembly_score_better(&confirmed, strong)) {
    *strong = confirmed;
  }
}

// Expand an aligned replacement until none of its source blocks remain owned
// by a logical slot outside the replacement. A physical gap shifts an entire
// suffix, so this closure identifies the first legal trial directly instead of
// testing every shorter run that is guaranteed to collide.
//
static inline bool onenote_reassembly_try_alignment(
    uint8_t *trial_data, const int64_t *mapping, uint8_t *used,
    uint64_t block_count, uint64_t data_length, OneNoteKind kind,
    uint64_t failure_start, uint64_t failure_end,
    uint64_t failure_slot, int64_t failure_source,
    const OneNoteRecoveryScore *current, OneNoteRecoveryScore *best,
    OneNoteRecoveryScore *observed, OneNoteRevisionState *workspace,
    bool confirm_progress) {

  if (!trial_data || !mapping || !used || !current || !best
      || failure_source < 0 || failure_slot >= block_count
      || failure_slot > INT64_MAX || failure_start > failure_slot
      || failure_end < failure_slot || failure_end >= block_count) {
    return false;
  }

  uint64_t run_start = failure_start == 0 ? failure_slot : failure_start;
  uint64_t run_end = failure_end + 1;

  if (run_start == 0 || run_start >= run_end || run_start > INT64_MAX) {
    return false;
  }

  const int64_t logical_failure = (int64_t)failure_slot;
  const int64_t displacement = failure_source >= logical_failure
                                   ? failure_source - logical_failure
                                   : -(logical_failure - failure_source);
  const uint64_t image_blocks = filemirror_apparent_blocks(
      scalpel_state.filemirror);

  bool expanded = false;
  int64_t source_start = -1;

  do {
    expanded = false;
    if (run_start > INT64_MAX
        || displacement < -(int64_t)run_start
        || displacement > INT64_MAX - (int64_t)run_start) {
      return false;
    }
    source_start = displacement + (int64_t)run_start;
    const uint64_t run_length = run_end - run_start;

    if (source_start < 0 || (uint64_t)source_start > image_blocks
        || run_length > image_blocks - (uint64_t)source_start) {
      return false;
    }
    const uint64_t source_end = (uint64_t)source_start + run_length;

    for (uint64_t slot = 0; slot < block_count; slot++) {
      if (slot >= run_start && slot < run_end) {
        continue;
      }
      const int64_t apparent = mapping[slot];

      if (apparent < source_start || (uint64_t)apparent >= source_end) {
        continue;
      }
      if (slot == 0) {
        return false;
      }
      if (slot < run_start) {
        run_start = slot;
      }
      else {
        run_end = slot + 1;
      }
      expanded = true;
    }
  } while (expanded);

  for (uint64_t slot = run_start; slot < run_end; slot++) {
    const uint64_t apparent = (uint64_t)mapping[slot];

    used[apparent >> 3] &= (uint8_t)~(1u << (apparent & 7u));
  }
  const bool advanced = onenote_reassembly_try_run(
      trial_data, mapping, used, block_count, data_length, kind,
      run_start, run_end - run_start, source_start, current, best,
      true, observed, workspace, confirm_progress);

  for (uint64_t slot = run_start; slot < run_end; slot++) {
    const uint64_t apparent = (uint64_t)mapping[slot];

    used[apparent >> 3] |= (uint8_t)(1u << (apparent & 7u));
  }
  return advanced;
}

// Commit one proven replacement run to the candidate and synchronize its byte
// view immediately so progress survives a checkpoint.
//
static inline void onenote_reassembly_apply_run(
    CarveInfo *candidate, int64_t *mapping, uint8_t *used,
    uint8_t *trial_data, const OneNoteRecoveryScore *recovery) {

  if (!candidate || !candidate->b || !mapping || !used || !trial_data
      || !recovery || !recovery->found) {
    return;
  }

  const uint64_t blocksize = scalpel_state.blocksize;

  for (uint64_t offset = 0; offset < recovery->run_length; offset++) {
    const uint64_t slot = recovery->run_start + offset;
    const uint64_t old_apparent = (uint64_t)mapping[slot];

    used[old_apparent >> 3] &= (uint8_t)~(1u << (old_apparent & 7u));
  }
  for (uint64_t offset = 0; offset < recovery->run_length; offset++) {
    const uint64_t slot = recovery->run_start + offset;
    const int64_t apparent = recovery->source + (int64_t)offset;

    mapping[slot] = apparent;
    used[(uint64_t)apparent >> 3]
        |= (uint8_t)(1u << ((uint64_t)apparent & 7u));
    blockvector_set_apparent_blocknumber(candidate->b, slot, apparent);
    onenote_reassembly_copy_block(trial_data + slot * blocksize, apparent);
  }
  inflate_blockvector(candidate->b);
}

// Preserve a complete byte-level alternative without changing the active
// search mapping. Revision stores can have several equally supported layouts.
//
static inline void onenote_reassembly_preserve_run(
    CarveInfo **candidate, const int64_t *mapping, uint64_t block_count,
    uint64_t data_length, const OneNoteRecoveryScore *recovery) {

  if (!candidate || !*candidate || !(*candidate)->b || !mapping
      || !recovery || !recovery->complete || !recovery->found
      || recovery->run_start > block_count
      || recovery->run_length > block_count - recovery->run_start) {
    return;
  }

  const CarveInfoFlavor original_flavor = (*candidate)->flavor;

  for (uint64_t offset = 0; offset < recovery->run_length; offset++) {
    blockvector_set_apparent_blocknumber(
        (*candidate)->b, recovery->run_start + offset,
        recovery->source + (int64_t)offset);
  }
  inflate_blockvector((*candidate)->b);
  blockvector_set_data_length((*candidate)->b, data_length);
  (*candidate)->flavor = PROMISING;
  write_candidate(candidate, true);

  for (uint64_t offset = 0; offset < recovery->run_length; offset++) {
    const uint64_t slot = recovery->run_start + offset;

    blockvector_set_apparent_blocknumber((*candidate)->b, slot,
                                         mapping[slot]);
  }
  inflate_blockvector((*candidate)->b);
  blockvector_set_data_length((*candidate)->b, data_length);
  (*candidate)->flavor = original_flavor;
}

// Write one complete alternative mapping and restore the active mapping before
// returning to the search.
//
static inline void onenote_reassembly_preserve_mapping(
    CarveInfo **candidate, const int64_t *mapping,
    const int64_t *alternative, uint64_t block_count,
    uint64_t data_length) {

  if (!candidate || !*candidate || !(*candidate)->b || !mapping
      || !alternative) {
    return;
  }

  const CarveInfoFlavor original_flavor = (*candidate)->flavor;

  for (uint64_t slot = 0; slot < block_count; slot++) {
    blockvector_set_apparent_blocknumber((*candidate)->b, slot,
                                         alternative[slot]);
  }
  inflate_blockvector((*candidate)->b);
  blockvector_set_data_length((*candidate)->b, data_length);
  (*candidate)->flavor = PROMISING;
  write_candidate(candidate, true);

  for (uint64_t slot = 0; slot < block_count; slot++) {
    blockvector_set_apparent_blocknumber((*candidate)->b, slot,
                                         mapping[slot]);
  }
  inflate_blockvector((*candidate)->b);
  blockvector_set_data_length((*candidate)->b, data_length);
  (*candidate)->flavor = original_flavor;
}

// Retain every structurally complete boundary for an interior physical
// alignment bracketed by the same outer alignment. OneNote revision stores
// can leave both ends of an out-of-order run opaque, so parser progress can
// identify the correct source alignment without identifying either boundary.
// This exhaustive output is performed only when the operator explicitly
// requests PROMISING files.
//
static inline bool onenote_reassembly_preserve_interior_spans(
    ThreadWork *work, CarveInfo **candidate,
    uuid_string_t uuidp, uuid_string_t uuidc, uint8_t *trial_data,
    const int64_t *mapping, uint8_t *used, uint64_t block_count,
    uint64_t data_length, OneNoteKind kind,
    const OneNoteRecoveryScore *current,
    OneNoteRevisionState *workspace) {

  if (!scalpel_state.write_promising || !work || !candidate || !*candidate
      || !trial_data || !mapping || !used || !current
      || !current->complete || block_count < 3
      || block_count > INT64_MAX) {
    return false;
  }

  const uint64_t mapping_hash = onenote_reassembly_mapping_hash(
      mapping, block_count);
  OneNoteCarveState *state = (OneNoteCarveState *)carve_get_state(
      (*candidate)->carvehashkey);

  if (!onenote_carve_state_valid(state)
      || state->block_count != block_count
      || state->data_length != data_length
      || state->mapping_hash != mapping_hash) {
    onenote_free_carve_state((void **)&state);
    state = calloc(1, sizeof(*state));
    check_memory_allocation(state, __LINE__, __FILE__,
                            "OneNote interior-span resume state");
    state->magic = ONENOTE_CARVE_STATE_MAGIC;
    state->version = ONENOTE_CARVE_STATE_VERSION;
    state->phase = ONENOTE_SEARCH_INTERIOR_SPANS;
    state->block_count = block_count;
    state->data_length = data_length;
    state->mapping_hash = mapping_hash;
  }
  const uint64_t span_view = onenote_reassembly_span_view(mapping, block_count);

  if (state->phase == ONENOTE_SEARCH_NONE || state->span_view != span_view) {
    state->phase = ONENOTE_SEARCH_INTERIOR_SPANS;
    state->span_view = span_view;
    state->span_start = 1;
    state->run_start = 1;
    state->run_end = 2;
  }
  if (state->phase == ONENOTE_SEARCH_INTERIOR_SPANS_COMPLETE) {
    onenote_free_carve_state((void **)&state);
    return false;
  }

  int64_t *baseline = malloc((size_t)block_count * sizeof(*baseline));
  check_memory_allocation(baseline, __LINE__, __FILE__,
                          "OneNote interior-span baseline");
  int64_t *alternative = malloc(
      (size_t)block_count * sizeof(*alternative));
  check_memory_allocation(alternative, __LINE__, __FILE__,
                          "OneNote interior-span alternative");

  for (uint64_t slot = 0; slot < block_count; slot++) {
    const uint64_t apparent = (uint64_t)mapping[slot];

    used[apparent >> 3] &= (uint8_t)~(1u << (apparent & 7u));
  }

  const uint64_t image_blocks = filemirror_apparent_blocks(
      scalpel_state.filemirror);
  const uint64_t blocksize = scalpel_state.blocksize;
  uint64_t attempts = 0;
  uint64_t span_start = state->span_start;
  bool resume_active = true;

  while (span_start < block_count - 1 && *candidate) {
    const int64_t inner_displacement = mapping[span_start]
                                       - (int64_t)span_start;
    uint64_t span_end = span_start + 1;

    while (span_end < block_count
           && mapping[span_end] - (int64_t)span_end
                  == inner_displacement) {
      span_end++;
    }
    if (span_end == block_count) {
      break;
    }

    const int64_t before = mapping[span_start - 1]
                           - (int64_t)(span_start - 1);
    const int64_t after = mapping[span_end] - (int64_t)span_end;

    if (before == after && before != inner_displacement) {
      memcpy(baseline, mapping,
             (size_t)block_count * sizeof(*baseline));
      bool baseline_valid = true;

      for (uint64_t slot = span_start; slot < span_end; slot++) {
        if (before < -(int64_t)slot
            || before > INT64_MAX - (int64_t)slot) {
          baseline_valid = false;
          break;
        }
        baseline[slot] = before + (int64_t)slot;
      }

      uint64_t first_run_start = resume_active ? state->run_start : 1;

      if (first_run_start == 0 || first_run_start >= span_end) {
        first_run_start = 1;
        resume_active = false;
      }
      for (uint64_t run_start = first_run_start;
           baseline_valid && run_start < span_end && *candidate;
           run_start++) {
        memcpy(alternative, baseline,
               (size_t)block_count * sizeof(*alternative));
        if (!onenote_reassembly_materialize(
                trial_data, alternative, block_count)) {
          continue;
        }

        uint64_t first_run_end = run_start + 1;

        if (resume_active && run_start == state->run_start
            && state->run_end > run_start
            && state->run_end <= block_count) {
          first_run_end = state->run_end;
        }
        bool prefix_available = true;
        for (uint64_t slot = run_start;
             slot + 1 < first_run_end; slot++) {
          if (inner_displacement < -(int64_t)slot
              || inner_displacement > INT64_MAX - (int64_t)slot) {
            prefix_available = false;
            break;
          }
          const int64_t apparent = inner_displacement + (int64_t)slot;

          alternative[slot] = apparent;
          if (!onenote_reassembly_copy_block(
                  trial_data + slot * blocksize, apparent)) {
            prefix_available = false;
            break;
          }
        }
        if (!prefix_available) {
          resume_active = false;
          continue;
        }

        for (uint64_t run_end = first_run_end;
             run_end <= block_count && *candidate; run_end++) {
          const uint64_t slot = run_end - 1;

          if (inner_displacement < -(int64_t)slot
              || inner_displacement > INT64_MAX - (int64_t)slot) {
            break;
          }
          const int64_t apparent = inner_displacement + (int64_t)slot;

          alternative[slot] = apparent;
          if (!onenote_reassembly_copy_block(
                  trial_data + slot * blocksize, apparent)) {
            break;
          }
          if (run_end <= span_start) {
            continue;
          }

          bool valid_mapping = true;
          uint64_t marked = 0;
          uint64_t dirty_first = block_count;
          uint64_t dirty_last = 0;

          for (uint64_t index = 0; index < block_count; index++) {
            const int64_t selected = alternative[index];

            if (selected != mapping[index]) {
              if (dirty_first == block_count) {
                dirty_first = index;
              }
              dirty_last = index;
            }

            if (selected < 0 || (uint64_t)selected >= image_blocks) {
              valid_mapping = false;
              break;
            }
            const uint64_t selected_u64 = (uint64_t)selected;
            const int64_t actual = filemirror_actual_blocknumber(
                scalpel_state.filemirror, selected);

            if ((used[selected_u64 >> 3]
                 & (uint8_t)(1u << (selected_u64 & 7u))) != 0
                || actual < 0
                || filemirror_actual_block_covered(
                       scalpel_state.filemirror, actual)) {
              valid_mapping = false;
              break;
            }
            used[selected_u64 >> 3]
                |= (uint8_t)(1u << (selected_u64 & 7u));
            marked++;
          }

          OneNoteSummary summary = {0};
          bool complete = false;

          if (valid_mapping) {
            if (workspace && dirty_first < block_count) {
              workspace->trial_start = dirty_first * blocksize;
              workspace->trial_end = (dirty_last + 1) * blocksize - 1;
              if (workspace->trial_end >= data_length) {
                workspace->trial_end = data_length - 1;
              }
              workspace->trial_active = true;
            }
            complete = onenote_parse_with_workspace(
                trial_data, data_length, kind, &summary, workspace);
            if (workspace) {
              workspace->trial_active = false;
            }
          }

          for (uint64_t index = 0; index < marked; index++) {
            const uint64_t selected = (uint64_t)alternative[index];

            used[selected >> 3]
                &= (uint8_t)~(1u << (selected & 7u));
          }
          if (complete) {
            onenote_reassembly_preserve_mapping(
                candidate, mapping, alternative, block_count, data_length);
          }

          attempts++;
          if ((attempts & UINT64_C(0xff)) == 0) {
            uint64_t next_span_start = span_start;
            uint64_t next_run_start = run_start;
            uint64_t next_run_end = run_end + 1;

            if (next_run_end > block_count) {
              next_run_start++;
              next_run_end = next_run_start + 1;
              if (next_run_start >= span_end) {
                next_span_start = span_end;
                next_run_start = 1;
                next_run_end = 2;
              }
            }
            if (next_span_start >= block_count - 1) {
              state->phase = ONENOTE_SEARCH_INTERIOR_SPANS_COMPLETE;
              state->span_start = 0;
              state->run_start = 0;
              state->run_end = 0;
            }
            else {
              state->phase = ONENOTE_SEARCH_INTERIOR_SPANS;
              state->span_start = next_span_start;
              state->run_start = next_run_start;
              state->run_end = next_run_end;
            }
            onenote_store_carve_state(*candidate, state);
            for (uint64_t index = 0; index < block_count; index++) {
              const uint64_t selected = (uint64_t)mapping[index];

              used[selected >> 3]
                  |= (uint8_t)(1u << (selected & 7u));
            }
            onenote_reassembly_materialize(
                trial_data, mapping, block_count);
            if (onenote_reassembly_poll(
                    work, candidate, uuidp, uuidc)) {
              free(alternative);
              free(baseline);
              onenote_free_carve_state((void **)&state);
              return true;
            }
            for (uint64_t index = 0; index < block_count; index++) {
              const uint64_t selected = (uint64_t)mapping[index];

              used[selected >> 3]
                  &= (uint8_t)~(1u << (selected & 7u));
            }
          }
        }
        resume_active = false;
      }
    }
    resume_active = false;
    span_start = span_end;
  }

  for (uint64_t slot = 0; slot < block_count; slot++) {
    const uint64_t apparent = (uint64_t)mapping[slot];

    used[apparent >> 3] |= (uint8_t)(1u << (apparent & 7u));
  }
  onenote_reassembly_materialize(trial_data, mapping, block_count);
  state->phase = ONENOTE_SEARCH_INTERIOR_SPANS_COMPLETE;
  state->span_start = 0;
  state->run_start = 0;
  state->run_end = 0;
  onenote_store_carve_state(*candidate, state);
  onenote_free_carve_state((void **)&state);
  free(alternative);
  free(baseline);
  return false;
}

// Keep zero-gap and displaced zero-island trials across a checkpoint.
//
static inline bool onenote_reassembly_search_zero(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, uint8_t *trial_data, const int64_t *mapping,
    uint8_t *used, uint64_t block_count, uint64_t data_length,
    OneNoteKind kind, uint64_t failure_start_slot, uint64_t failure_end_slot,
    const OneNoteRecoveryScore *current, OneNoteRecoveryScore *best,
    OneNoteRevisionState *workspace, OneNoteRepairSearch *search) {

  const uint64_t image_blocks = filemirror_apparent_blocks(scalpel_state.filemirror);
  const uint64_t blocksize = scalpel_state.blocksize;
  uint64_t attempts = 0;
  bool resume_island = search->phase == ONENOTE_REPAIR_ZERO_ISLAND;

  // A physical gap commonly appears as one or more mapped zero blocks
  // followed by the displaced suffix. Test that complete suffix directly;
  // strict parser progress is still required before it can be committed.
  // Valid allocated zero ranges remain untouched when this hypothesis does
  // not improve the parse, and the general search below remains available.
  if ((search->phase == ONENOTE_REPAIR_NONE
       || search->phase == ONENOTE_REPAIR_ZERO_GAP)
      && !current->complete && block_count > 1) {
    for (uint64_t gap_start = search->phase == ONENOTE_REPAIR_ZERO_GAP
                                 ? search->run_start : 1;
         gap_start < block_count && *candidate && !best->complete;
         gap_start++) {
      const int64_t gap_actual = filemirror_actual_blocknumber(
          scalpel_state.filemirror, mapping[gap_start]);

      if (gap_actual < 0
          || !filemirror_actual_block_is_zero(
                 scalpel_state.filemirror, gap_actual)) {
        continue;
      }

      uint64_t zero_blocks = 1;

      while (zero_blocks < block_count - gap_start) {
        const int64_t actual = filemirror_actual_blocknumber(
            scalpel_state.filemirror,
            mapping[gap_start + zero_blocks]);

        if (actual < 0
            || !filemirror_actual_block_is_zero(
                   scalpel_state.filemirror, actual)) {
          break;
        }
        zero_blocks++;
      }

      const uint64_t run_length = block_count - gap_start;

      if (mapping[gap_start] >= 0
          && zero_blocks <= (uint64_t)(INT64_MAX - mapping[gap_start])) {
        for (uint64_t offset = 0; offset < run_length; offset++) {
          const uint64_t apparent =
              (uint64_t)mapping[gap_start + offset];

          used[apparent >> 3]
              &= (uint8_t)~(1u << (apparent & 7u));
        }

        OneNoteRecoveryScore gap_best = {0};

        onenote_reassembly_try_run(
            trial_data, mapping, used, block_count, data_length, kind,
            gap_start, run_length,
            mapping[gap_start] + (int64_t)zero_blocks,
            current, &gap_best, true, NULL, workspace, true);
        if (onenote_reassembly_score_better(&gap_best, best)) {
          *best = gap_best;
        }

        for (uint64_t offset = 0; offset < run_length; offset++) {
          const uint64_t apparent =
              (uint64_t)mapping[gap_start + offset];

          used[apparent >> 3]
              |= (uint8_t)(1u << (apparent & 7u));
        }
      }

      attempts++;
      *search = (OneNoteRepairSearch){
        .phase = ONENOTE_REPAIR_ZERO_GAP,
        .run_start = gap_start + zero_blocks, .best = *best
      };
      if (onenote_reassembly_search_poll(
              work, candidate, uuidp, uuidc, search, workspace)) {
        return true;
      }
      gap_start += zero_blocks - 1;
    }
    memset(search, 0, sizeof(*search));
  }

  // An out-of-order run commonly leaves a fixed-size zero island at its
  // logical position. Test islands near the parser's failure range first,
  // then the remaining islands before expanding the general search. Parser
  // failures can surface well after the displaced run that caused them.
  // Strict format evidence remains the acceptance criterion.
  if ((search->phase == ONENOTE_REPAIR_NONE
       || search->phase == ONENOTE_REPAIR_ZERO_ISLAND)
      && !current->complete && !best->complete
      && failure_start_slot > 0
      && failure_start_slot <= failure_end_slot) {
    for (uint32_t zero_pass = resume_island ? search->pass : 0;
         zero_pass < 2 && *candidate && !best->complete; zero_pass++) {
      for (uint64_t zero_start = resume_island ? search->run_start : 1;
           zero_start < block_count && *candidate && !best->complete;
           zero_start++) {
        const int64_t zero_actual = filemirror_actual_blocknumber(
            scalpel_state.filemirror, mapping[zero_start]);

        if (zero_actual < 0
            || !filemirror_actual_block_is_zero(
                   scalpel_state.filemirror, zero_actual)) {
          continue;
        }

        uint64_t zero_blocks = 1;

        while (zero_blocks < block_count - zero_start) {
          const int64_t actual = filemirror_actual_blocknumber(
              scalpel_state.filemirror,
              mapping[zero_start + zero_blocks]);

          if (actual < 0
              || !filemirror_actual_block_is_zero(
                     scalpel_state.filemirror, actual)) {
            break;
          }
          zero_blocks++;
        }
        const uint64_t zero_end = zero_start + zero_blocks - 1;

        const bool intersects_failure = zero_end >= failure_start_slot
                                        && zero_start <= failure_end_slot;

        if ((zero_pass == 0) != intersects_failure) {
          zero_start += zero_blocks - 1;
          continue;
        }

        bool contiguous_target = true;
        const uint64_t target_start = (uint64_t)mapping[zero_start];

        for (uint64_t offset = 1; offset < zero_blocks; offset++) {
          if (mapping[zero_start + offset]
              != mapping[zero_start] + (int64_t)offset) {
            contiguous_target = false;
            break;
          }
        }
        if (!contiguous_target) {
          zero_start += zero_blocks - 1;
          continue;
        }
        const uint64_t target_end = target_start + zero_blocks;

        for (uint64_t offset = 0; offset < zero_blocks; offset++) {
          const uint64_t apparent =
              (uint64_t)mapping[zero_start + offset];

          used[apparent >> 3]
              &= (uint8_t)~(1u << (apparent & 7u));
        }

        OneNoteRecoveryScore zero_best = resume_island
            ? search->local_best : (OneNoteRecoveryScore){0};
        OneNoteRecoveryScore zero_weak = resume_island
            ? search->weak : (OneNoteRecoveryScore){0};
        const uint64_t final_source = image_blocks - zero_blocks;

        for (uint64_t source = resume_island ? search->next_source : 0;
             source <= final_source && *candidate && !zero_best.complete;
             source++) {
          // A displaced run has a distinct physical source. Overlapping
          // suffix shifts are evaluated by the zero-gap path above.
          if (source < target_end
              && source + zero_blocks > target_start) {
            continue;
          }
          onenote_reassembly_probe_run(
              trial_data, mapping, used, block_count, data_length, kind,
              zero_start, zero_blocks, (int64_t)source, current,
              &zero_best, &zero_weak, false, workspace);

          attempts++;
          if ((attempts & UINT64_C(0xff)) == 0) {
            *search = (OneNoteRepairSearch){
              .phase = ONENOTE_REPAIR_ZERO_ISLAND, .pass = zero_pass,
              .run_start = zero_start, .run_length = zero_blocks,
              .next_source = source + 1, .best = *best,
              .weak = zero_weak, .local_best = zero_best
            };
            if (onenote_reassembly_search_poll(
                    work, candidate, uuidp, uuidc, search, workspace)) {
              return true;
            }
          }
        }

        resume_island = false;
        bool restored = true;

        for (uint64_t offset = 0; offset < zero_blocks; offset++) {
          if (!onenote_reassembly_copy_block(
                  trial_data + (zero_start + offset) * blocksize,
                  mapping[zero_start + offset])) {
            restored = false;
            break;
          }
        }
        for (uint64_t offset = 0; offset < zero_blocks; offset++) {
          const uint64_t apparent =
              (uint64_t)mapping[zero_start + offset];

          used[apparent >> 3]
              |= (uint8_t)(1u << (apparent & 7u));
        }
        if (!restored) {
          destroy_candidate(candidate);
          return true;
        }
        if (zero_best.complete) {
          zero_best.exact_run_boundaries = true;
        }
        if (onenote_reassembly_score_better(&zero_best, best)) {
          *best = zero_best;
        }
        zero_start += zero_blocks - 1;
      }
    }
    memset(search, 0, sizeof(*search));
  }

  return false;
}

// Resume embedded ZIP source ranking and extension without repeating completed
// decompression trials. Preferred sources remain tentative until full validation.
//
static inline bool onenote_reassembly_search_zip(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, uint8_t *trial_data, const int64_t *mapping,
    uint8_t *used, uint64_t block_count, uint64_t data_length,
    OneNoteKind kind, uint64_t failure_start_slot, uint64_t failure_end_slot,
    const OneNoteRecoveryScore *current, OneNoteRecoveryScore *best,
    OneNoteRevisionState *workspace, OneNoteRepairSearch *search) {

  const uint64_t image_blocks = filemirror_apparent_blocks(
      scalpel_state.filemirror);
  const uint64_t blocksize = scalpel_state.blocksize;
  bool resume_sources = search->phase == ONENOTE_REPAIR_ZIP_SOURCES;
  bool resume_extension = search->phase == ONENOTE_REPAIR_ZIP_EXTENSION;
  uint64_t attempts = 0;

  if ((search->phase != ONENOTE_REPAIR_NONE
       && !resume_sources && !resume_extension)
      || current->complete || !current->zip_output_comparable
      || failure_start_slot == 0 || failure_start_slot > failure_end_slot) {
    return false;
  }
  const uint64_t priority_count = failure_end_slot - failure_start_slot + 1;

  if (priority_count > SIZE_MAX / sizeof(OneNoteTargetPriority)) {
    return false;
  }
  OneNoteTargetPriority *priorities = malloc(
      (size_t)priority_count * sizeof(*priorities));
  check_memory_allocation(priorities, __LINE__, __FILE__,
                          "OneNote ZIP target priorities");

  for (uint64_t index = 0; index < priority_count; index++) {
    const uint64_t slot = failure_start_slot + index;

    priorities[index].slot = slot;
    priorities[index].uniformity = onenote_reassembly_uniformity(
        trial_data + slot * blocksize, blocksize);
  }
  for (uint64_t index = 1; index < priority_count; index++) {
    const OneNoteTargetPriority value = priorities[index];
    uint64_t destination = index;

    while (destination > 0
           && (value.uniformity < priorities[destination - 1].uniformity
               || (value.uniformity == priorities[destination - 1].uniformity
                   && value.slot < priorities[destination - 1].slot))) {
      priorities[destination] = priorities[destination - 1];
      destination--;
    }
    priorities[destination] = value;
  }

  uint64_t first_priority = 0;

  if (resume_sources || resume_extension) {
    while (first_priority < priority_count
           && priorities[first_priority].slot != search->run_start) {
      first_priority++;
    }
    if (first_priority == priority_count) {
      first_priority = 0;
      resume_sources = false;
      resume_extension = false;
      memset(search, 0, sizeof(*search));
    }
  }

  for (uint64_t priority = first_priority;
       priority < priority_count && *candidate && !best->complete;
       priority++) {
    const uint64_t run_start = priorities[priority].slot;
    const uint64_t old_apparent = (uint64_t)mapping[run_start];

    used[old_apparent >> 3] &= (uint8_t)~(1u << (old_apparent & 7u));

    OneNoteRecoveryScore preferred = resume_sources || resume_extension
                                        ? search->local_best
                                        : (OneNoteRecoveryScore){0};
    uint64_t preferred_source = preferred.found
                                   ? (uint64_t)preferred.source : 0;

    if (!resume_extension) {
      for (uint64_t source = resume_sources ? search->next_source : 0;
           source < image_blocks && *candidate && !best->complete; source++) {
        OneNoteRecoveryScore source_best = {0};
        OneNoteRecoveryScore observed = {0};

        const bool advanced = onenote_reassembly_try_run(
            trial_data, mapping, used, block_count, data_length, kind,
            run_start, 1, (int64_t)source, current, &source_best,
            true, &observed, workspace, true);

        if (advanced && observed.complete) {
          *best = observed;
          break;
        }
        if (advanced && observed.zip_output_comparable
            && observed.zip_output_distance < current->zip_output_distance) {
          if (!preferred.found
              || observed.zip_output_distance < preferred.zip_output_distance
              || (observed.zip_output_distance == preferred.zip_output_distance
                  && onenote_reassembly_score_better(&observed, &preferred))) {
            preferred = observed;
            preferred_source = source;
          }
        }

        attempts++;
        if ((attempts & UINT64_C(0xff)) == 0) {
          *search = (OneNoteRepairSearch){
            .phase = ONENOTE_REPAIR_ZIP_SOURCES,
            .run_start = run_start, .run_length = 1,
            .next_source = source + 1, .best = *best,
            .local_best = preferred
          };
          if (onenote_reassembly_search_poll(
                  work, candidate, uuidp, uuidc, search, workspace)) {
            used[old_apparent >> 3] |= (uint8_t)(1u << (old_apparent & 7u));
            free(priorities);
            return true;
          }
        }
      }
    }
    if (!best->complete && preferred.found) {
      uint64_t prior_distance = preferred.zip_output_distance;
      uint64_t maximum_length = failure_end_slot - run_start + 1;

      if (maximum_length > block_count - run_start) {
        maximum_length = block_count - run_start;
      }
      if (maximum_length > image_blocks - preferred_source) {
        maximum_length = image_blocks - preferred_source;
      }

      const uint64_t first_length = resume_extension ? search->run_length : 2;
      uint64_t cleared = first_length - 1;

      for (uint64_t offset = 1; offset < cleared; offset++) {
        const uint64_t apparent = (uint64_t)mapping[run_start + offset];

        used[apparent >> 3] &= (uint8_t)~(1u << (apparent & 7u));
      }
      for (uint64_t run_length = first_length;
           run_length <= maximum_length && *candidate; run_length++) {
        const uint64_t slot = run_start + run_length - 1;
        const uint64_t apparent = (uint64_t)mapping[slot];

        used[apparent >> 3] &= (uint8_t)~(1u << (apparent & 7u));
        cleared = run_length;

        OneNoteRecoveryScore extended_best = {0};
        OneNoteRecoveryScore extended = {0};
        const bool extension_advanced = onenote_reassembly_try_run(
            trial_data, mapping, used, block_count, data_length, kind,
            run_start, run_length, (int64_t)preferred_source,
            current, &extended_best, true, &extended, workspace, true);

        if (extension_advanced && extended.complete) {
          *best = extended;
          break;
        }
        if (!extension_advanced || !extended.zip_output_comparable
            || extended.zip_output_distance >= prior_distance) {
          break;
        }
        prior_distance = extended.zip_output_distance;
        *search = (OneNoteRepairSearch){
          .phase = ONENOTE_REPAIR_ZIP_EXTENSION,
          .run_start = run_start, .run_length = run_length + 1,
          .best = *best, .local_best = extended
        };
        if (onenote_reassembly_search_poll(
                work, candidate, uuidp, uuidc, search, workspace)) {
          for (uint64_t offset = 0; offset < cleared; offset++) {
            const uint64_t restored = (uint64_t)mapping[run_start + offset];

            used[restored >> 3] |= (uint8_t)(1u << (restored & 7u));
          }
          free(priorities);
          return true;
        }
      }

      for (uint64_t offset = 1; offset < cleared; offset++) {
        const uint64_t apparent = (uint64_t)mapping[run_start + offset];

        used[apparent >> 3] |= (uint8_t)(1u << (apparent & 7u));
      }
    }

    used[old_apparent >> 3] |= (uint8_t)(1u << (old_apparent & 7u));
    resume_sources = false;
    resume_extension = false;
    memset(search, 0, sizeof(*search));
  }
  free(priorities);
  return false;
}

// Continue boundary alternatives after earlier complete placements.
//
static inline bool onenote_reassembly_search_boundaries(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, uint8_t *trial_data, const int64_t *mapping,
    uint8_t *used, uint64_t block_count, uint64_t data_length,
    OneNoteKind kind, const OneNoteRecoveryScore *current,
    OneNoteRecoveryScore *best, const int64_t *displacements,
    uint64_t displacement_count, OneNoteRevisionState *workspace,
    OneNoteRepairSearch *search) {

  uint64_t attempts = 0;
  bool resuming = search->phase == ONENOTE_REPAIR_BOUNDARIES;

  // Once the format is complete, only refine boundaries between physical
  // alignments that previously advanced the parser. This can recover opaque
  // edge blocks without admitting unrelated source regions merely because
  // they happen to improve a byte-continuity heuristic.
  if ((search->phase == ONENOTE_REPAIR_NONE
       || search->phase == ONENOTE_REPAIR_BOUNDARIES) && current->complete) {
    if (!resuming && onenote_reassembly_preserve_interior_spans(
            work, candidate, uuidp, uuidc, trial_data, mapping, used,
            block_count, data_length, kind, current,
            workspace)) {
      return true;
    }
    for (uint64_t boundary = resuming ? search->run_start : 1;
         boundary < block_count && *candidate; boundary++) {
      if (mapping[boundary] == mapping[boundary - 1] + 1) {
        continue;
      }

      for (uint32_t side = resuming ? search->pass : 0; side < 2; side++) {
        const uint64_t maximum_length = side == 0
                                            ? boundary - 1
                                            : block_count - boundary;

        for (uint64_t run_length = resuming ? search->run_length : 1;
             run_length <= maximum_length && *candidate; run_length++) {
          const uint64_t run_start = side == 0
                                         ? boundary - run_length
                                         : boundary;

          for (uint64_t offset = 0; offset < run_length; offset++) {
            const uint64_t apparent =
                (uint64_t)mapping[run_start + offset];

            used[apparent >> 3]
                &= (uint8_t)~(1u << (apparent & 7u));
          }

          if (run_start <= INT64_MAX) {
            const int64_t logical_start = (int64_t)run_start;

            for (uint64_t index = resuming ? search->next_source : 0;
                 index < displacement_count && *candidate; index++) {
              if (displacements[index]
                  <= INT64_MAX - logical_start) {
                OneNoteRecoveryScore observed = {0};

                onenote_reassembly_try_run(
                    trial_data, mapping, used, block_count, data_length,
                    kind, run_start, run_length,
                    displacements[index] + logical_start, current, best,
                    true, &observed, workspace, true);
                if (observed.complete
                    && (observed.content_seam_cost
                            == current->content_seam_cost)
                    && scalpel_state.write_promising) {
                  onenote_reassembly_preserve_run(
                      candidate, mapping, block_count, data_length,
                      &observed);
                }
              }
              attempts++;
              if ((attempts & UINT64_C(0xff)) == 0) {
                *search = (OneNoteRepairSearch){
                  .phase = ONENOTE_REPAIR_BOUNDARIES, .pass = side,
                  .run_start = boundary, .run_length = run_length,
                  .next_source = index + 1, .best = *best
                };
                if (onenote_reassembly_search_poll(
                        work, candidate, uuidp, uuidc, search, workspace)) {
                  return true;
                }
              }
            }
          }
          resuming = false;

          for (uint64_t offset = 0; offset < run_length; offset++) {
            const uint64_t apparent =
                (uint64_t)mapping[run_start + offset];

            used[apparent >> 3]
                |= (uint8_t)(1u << (apparent & 7u));
          }
        }
      }
    }
    memset(search, 0, sizeof(*search));
  }

  return false;
}

// Retain alignment trials and the tentative anchor while testing longer runs.
// Each completed trial is saved only if a checkpoint actually requests a yield.
//
static inline bool onenote_reassembly_search_alignments(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, uint8_t *trial_data, const int64_t *mapping,
    uint8_t *used, uint64_t block_count, uint64_t data_length,
    OneNoteKind kind, uint64_t failure_start_slot, uint64_t failure_end_slot,
    uint64_t failure_slot, const OneNoteRecoveryScore *current,
    OneNoteRecoveryScore *best, const int64_t *displacements,
    uint64_t displacement_count, OneNoteRevisionState *workspace,
    OneNoteRepairSearch *search) {

  uint64_t attempts = 0;

  if ((search->phase == ONENOTE_REPAIR_NONE
       || search->phase == ONENOTE_REPAIR_ALIGNMENTS)
      && !current->complete
      && (!best->complete || search->phase == ONENOTE_REPAIR_ALIGNMENTS)
      && failure_slot > 0 && failure_slot <= INT64_MAX) {
    const int64_t logical_slot = (int64_t)failure_slot;

    for (uint64_t index = search->phase == ONENOTE_REPAIR_ALIGNMENTS
                              ? search->next_source : 0;
         index < displacement_count && *candidate; index++) {
      if (displacements[index] >= -logical_slot
          && displacements[index] <= INT64_MAX - logical_slot) {
        onenote_reassembly_try_alignment(
            trial_data, mapping, used, block_count, data_length, kind,
            failure_start_slot, failure_end_slot, failure_slot,
            displacements[index] + logical_slot, current, best,
            NULL, workspace, true);
      }
      *search = (OneNoteRepairSearch){
        .phase = ONENOTE_REPAIR_ALIGNMENTS, .run_start = failure_slot,
        .run_length = 1, .next_source = index + 1, .best = *best
      };
      if (onenote_reassembly_search_poll(
              work, candidate, uuidp, uuidc, search, workspace)) {
        return true;
      }
    }
    memset(search, 0, sizeof(*search));
  }

  bool resuming = search->phase == ONENOTE_REPAIR_ANCHOR;

  if ((search->phase == ONENOTE_REPAIR_NONE || resuming)
      && best->found && !current->complete
      && !onenote_reassembly_evidence_progress(current, best)) {
    const OneNoteRecoveryScore anchor = *best;
    OneNoteRecoveryScore expanded = resuming
        ? search->local_best : (OneNoteRecoveryScore){0};
    bool evidence_found = expanded.found;

    for (uint64_t run_length = resuming ? search->run_length : 2;
         run_length < block_count && *candidate && !evidence_found;
         run_length++) {
      uint64_t first_start = failure_start_slot >= run_length - 1
                                 ? failure_start_slot - run_length + 1 : 1;
      uint64_t final_start = failure_end_slot;
      const uint64_t maximum_start = block_count - run_length;

      if (first_start == 0) {
        first_start = 1;
      }
      if (final_start > maximum_start) {
        final_start = maximum_start;
      }
      if (first_start > final_start) {
        continue;
      }

      for (uint64_t run_start = resuming ? search->run_start : first_start;
           run_start <= final_start && *candidate && !evidence_found;
           run_start++) {
        for (uint64_t offset = 0; offset < run_length; offset++) {
          const uint64_t apparent = (uint64_t)mapping[run_start + offset];

          used[apparent >> 3] &= (uint8_t)~(1u << (apparent & 7u));
        }

        int64_t sources[2] = {anchor.source, -1};

        if (failure_slot >= run_start
            && failure_slot - run_start <= INT64_MAX
            && anchor.source >= (int64_t)(failure_slot - run_start)) {
          sources[1] = anchor.source - (int64_t)(failure_slot - run_start);
        }
        for (uint32_t source_index = resuming ? (uint32_t)search->next_source : 0;
             source_index < 2 && *candidate && !evidence_found;
             source_index++) {
          if (sources[source_index] < 0
              || (source_index == 1 && sources[1] == sources[0])) {
            continue;
          }

          OneNoteRecoveryScore observed = {0};
          OneNoteRecoveryScore source_best = {0};

          onenote_reassembly_try_run(
              trial_data, mapping, used, block_count, data_length, kind,
              run_start, run_length, sources[source_index], current,
              &source_best, true, &observed, workspace, false);
          if (onenote_reassembly_evidence_progress(current, &observed)) {
            OneNoteRecoveryScore confirmed = {0};
            OneNoteRecoveryScore confirmed_best = {0};

            onenote_reassembly_try_run(
                trial_data, mapping, used, block_count, data_length, kind,
                run_start, run_length, sources[source_index], current,
                &confirmed_best, true, &confirmed, workspace, true);
            if (onenote_reassembly_evidence_progress(current, &confirmed)
                && onenote_reassembly_score_better(&confirmed, &expanded)) {
              expanded = confirmed;
              evidence_found = true;
            }
          }
          attempts++;
          if ((attempts & UINT64_C(0xff)) == 0) {
            *search = (OneNoteRepairSearch){
              .phase = ONENOTE_REPAIR_ANCHOR, .run_start = run_start,
              .run_length = run_length, .next_source = source_index + 1,
              .best = anchor, .local_best = expanded
            };
            if (onenote_reassembly_search_poll(
                    work, candidate, uuidp, uuidc, search, workspace)) {
              for (uint64_t offset = 0; offset < run_length; offset++) {
                const uint64_t apparent = (uint64_t)mapping[run_start + offset];

                used[apparent >> 3] |= (uint8_t)(1u << (apparent & 7u));
              }
              return true;
            }
          }
        }
        resuming = false;

        for (uint64_t offset = 0; offset < run_length; offset++) {
          const uint64_t apparent = (uint64_t)mapping[run_start + offset];

          used[apparent >> 3] |= (uint8_t)(1u << (apparent & 7u));
        }
      }
    }

    if (evidence_found) {
      *best = expanded;
    }
    else {
      memset(best, 0, sizeof(*best));
    }
    memset(search, 0, sizeof(*search));
  }
  return false;
}

// Resume exhaustive run and small-suffix scans with their earlier best trials.
// Temporary bytes and the used bitmap are rebuilt on entry; only the caller
// commits a repair to the candidate.
//
static inline bool onenote_reassembly_search_runs(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, uint8_t *trial_data, const int64_t *mapping,
    uint8_t *used, uint64_t block_count, uint64_t data_length,
    OneNoteKind kind, uint64_t failure_start, uint64_t failure_end,
    uint64_t failure_slot, const OneNoteRecoveryScore *current,
    OneNoteRecoveryScore *best, OneNoteRecoveryScore *weak,
    OneNoteRevisionState *workspace, OneNoteRepairSearch *search) {

  const uint64_t image_blocks = filemirror_apparent_blocks(scalpel_state.filemirror);
  const uint64_t blocksize = scalpel_state.blocksize;
  uint64_t attempts = 0;
  bool resume_runs = search->phase == ONENOTE_REPAIR_RUNS;
  bool resume_suffix = search->phase == ONENOTE_REPAIR_SUFFIXES;

  for (uint32_t pass = resume_runs ? search->pass : 0;
       !resume_suffix && !current->complete && pass < 2 && !best->found; pass++) {
    if (pass == 0 && failure_slot == 0) {
      continue;
    }
    if (pass == 1 && best->found) {
      break;
    }
    for (uint64_t run_length = resume_runs ? search->run_length : 1;
         run_length < block_count && !best->found; run_length++) {
      uint64_t first_start = 1;
      uint64_t final_start = block_count - run_length;

      if (pass == 0) {
        first_start = failure_start >= run_length - 1
                          ? failure_start - run_length + 1 : 1;
        if (first_start == 0) {
          first_start = 1;
        }
        final_start = failure_end < final_start
                          ? failure_end : final_start;
        if (first_start > final_start) {
          continue;
        }
      }

      OneNoteRecoveryScore length_best = resume_runs
          ? search->local_best : (OneNoteRecoveryScore){0};

      for (uint64_t run_start = resume_runs ? search->run_start : first_start;
           run_start <= final_start && *candidate; run_start++) {
        for (uint64_t offset = 0; offset < run_length; offset++) {
          const uint64_t apparent = (uint64_t)mapping[run_start + offset];

          used[apparent >> 3]
              &= (uint8_t)~(1u << (apparent & 7u));
        }

        int64_t preferred[2] = {-1, -1};

        preferred[0] = mapping[run_start - 1] + 1;
        if (run_start + run_length < block_count) {
          preferred[1] = mapping[run_start + run_length]
                         - (int64_t)run_length;
        }
        for (uint32_t index = 0; !resume_runs && index < 2; index++) {
          if (preferred[index] >= 0
              && (index == 0 || preferred[index] != preferred[0])) {
            onenote_reassembly_probe_run(
                trial_data, mapping, used, block_count, data_length, kind,
                run_start, run_length, preferred[index], current,
                &length_best, weak, false, workspace);
          }
        }

        const uint64_t final_source = image_blocks - run_length;

        for (uint64_t source = resume_runs ? search->next_source : 0;
             source <= final_source && *candidate; source++) {
          if ((int64_t)source != preferred[0]
              && (int64_t)source != preferred[1]) {
            onenote_reassembly_probe_run(
                trial_data, mapping, used, block_count, data_length, kind,
                run_start, run_length, (int64_t)source, current,
                &length_best, weak, false, workspace);
          }
          attempts++;
          if ((attempts & UINT64_C(0xff)) == 0) {
            *search = (OneNoteRepairSearch){
              .phase = ONENOTE_REPAIR_RUNS, .pass = pass,
              .run_length = run_length, .run_start = run_start,
              .next_source = source + 1, .best = *best, .weak = *weak,
              .local_best = length_best
            };
            if (onenote_reassembly_search_poll(
                    work, candidate, uuidp, uuidc, search, workspace)) {
              return true;
            }
          }
        }

        resume_runs = false;

        bool restored = true;

        for (uint64_t offset = 0; offset < run_length; offset++) {
          if (!onenote_reassembly_copy_block(
                  trial_data + (run_start + offset) * blocksize,
                  mapping[run_start + offset])) {
            restored = false;
            break;
          }
        }
        if (!restored) {
          destroy_candidate(candidate);
          return true;
        }

        for (uint64_t offset = 0; offset < run_length; offset++) {
          const uint64_t apparent = (uint64_t)mapping[run_start + offset];

          used[apparent >> 3]
              |= (uint8_t)(1u << (apparent & 7u));
        }
      }
      if (onenote_reassembly_score_better(&length_best, best)) {
        *best = length_best;
      }
    }
  }

  // Exhaustively test forward shifts from every suffix boundary in small
  // candidates. A gap can otherwise remain invisible when another displaced
  // run determines the failure cursor. Larger candidates retain the
  // parser-directed search without paying for repeated full-file parses.
  if (!current->complete && !best->complete && block_count > 2
      && block_count <= ONENOTE_REASSEMBLY_EXHAUSTIVE_GAP_BLOCKS) {
    OneNoteRecoveryScore suffix_best = resume_suffix
        ? search->local_best : (OneNoteRecoveryScore){0};

    for (uint64_t run_start = resume_suffix ? search->run_start : 1;
         run_start < block_count && *candidate
         && !suffix_best.complete; run_start++) {
      const uint64_t run_length = block_count - run_start;

      for (uint64_t offset = 0; offset < run_length; offset++) {
        const uint64_t apparent =
            (uint64_t)mapping[run_start + offset];

        used[apparent >> 3]
            &= (uint8_t)~(1u << (apparent & 7u));
      }

      const int64_t previous = mapping[run_start - 1];

      if (previous >= 0 && previous < INT64_MAX) {
        const uint64_t expected_source = (uint64_t)previous + 1;

        for (uint64_t shift = resume_suffix ? search->next_source : 1;
             shift < run_length && *candidate
             && !suffix_best.complete; shift++) {
          if (expected_source > (uint64_t)INT64_MAX - shift) {
            break;
          }
          onenote_reassembly_probe_run(
              trial_data, mapping, used, block_count, data_length, kind,
              run_start, run_length,
              (int64_t)(expected_source + shift), current,
              &suffix_best, weak, false, workspace);

          attempts++;
          if ((attempts & UINT64_C(0xff)) == 0) {
            *search = (OneNoteRepairSearch){
              .phase = ONENOTE_REPAIR_SUFFIXES,
              .run_length = run_length, .run_start = run_start,
              .next_source = shift + 1, .best = *best, .weak = *weak,
              .local_best = suffix_best
            };
            if (onenote_reassembly_search_poll(
                    work, candidate, uuidp, uuidc, search, workspace)) {
              return true;
            }
          }
        }
      }

      resume_suffix = false;

      bool restored = true;

      for (uint64_t offset = 0; offset < run_length; offset++) {
        if (!onenote_reassembly_copy_block(
                trial_data + (run_start + offset) * blocksize,
                mapping[run_start + offset])) {
          restored = false;
          break;
        }
      }
      for (uint64_t offset = 0; offset < run_length; offset++) {
        const uint64_t apparent =
            (uint64_t)mapping[run_start + offset];

        used[apparent >> 3]
            |= (uint8_t)(1u << (apparent & 7u));
      }
      if (!restored) {
        destroy_candidate(candidate);
        return true;
      }
    }
    if (onenote_reassembly_score_better(&suffix_best, best)) {
      *best = suffix_best;
    }
  }


  memset(search, 0, sizeof(*search));
  return false;
}

// Package stores are sequential FSSHTTPB streams. A physical zero-block gap
// can therefore be repaired by removing the zero island, shifting the mapped
// suffix left, and continuing the same physical run until its authenticated
// terminator. The replacement is accepted only when the complete package
// parser authenticates the resulting stream.
//
static inline void onenote_package_reassembly(
    ThreadWork *work, CarveInfo **candidate,
    uuid_string_t uuidp, uuid_string_t uuidc) {

  if (!work || !candidate || !*candidate || !(*candidate)->b) {
    return;
  }

  BlockVector *blockvector = (*candidate)->b;
  const uint64_t block_count = blockvector_get_num_blocks(blockvector);
  const uint64_t blocksize = scalpel_state.blocksize;
  const uint64_t image_blocks = filemirror_apparent_blocks(
      scalpel_state.filemirror);
  const uint8_t *current_data = (const uint8_t *)
      blockvector_get_data_pointer(blockvector);
  const uint64_t current_length = blockvector_get_data_length(blockvector);
  const OneNoteKind kind = onenote_file_kind(current_data, current_length);
  OneNoteSummary summary = {0};

  if (onenote_parse(current_data, current_length, kind, &summary)) {
    blockvector_set_data_length(blockvector, summary.extent);
    if (scalpel_state.write_promising) {
      (*candidate)->flavor = PROMISING;
      write_candidate(candidate, false);
    }
    else {
      destroy_candidate(candidate);
    }
    return;
  }
  if (block_count < 2 || blocksize == 0
      || block_count > SIZE_MAX / sizeof(int64_t)
      || block_count > SIZE_MAX / blocksize
      || image_blocks == 0) {
    if (scalpel_state.write_promising) {
      (*candidate)->flavor = PROMISING;
      write_candidate(candidate, false);
    }
    else {
      destroy_candidate(candidate);
    }
    return;
  }

  int64_t *mapping = malloc((size_t)block_count * sizeof(*mapping));
  check_memory_allocation(mapping, __LINE__, __FILE__,
                          "OneNote package mapping");

  for (uint64_t slot = 0; slot < block_count; slot++) {
    mapping[slot] = blockvector_get_apparent_blocknumber(
        blockvector, slot);
  }

  bool contiguous = mapping[0] >= 0;

  for (uint64_t slot = 1; slot < block_count && contiguous; slot++) {
    contiguous = mapping[slot] == mapping[slot - 1] + 1;
  }
  if (!contiguous) {
    free(mapping);
    if (scalpel_state.write_promising) {
      (*candidate)->flavor = PROMISING;
      write_candidate(candidate, false);
    }
    else {
      destroy_candidate(candidate);
    }
    return;
  }

  OneNoteCarveState *state = onenote_reassembly_progress_state(
      *candidate, mapping, block_count, current_length);
  state->progress_valid = 1;
  onenote_store_carve_state(*candidate, state);
  onenote_free_carve_state((void **)&state);
  OneNoteRepairSearch search = onenote_reassembly_load_search(*candidate);
  OneNoteRevisionState workspace = {.searched_end = search.searched_end};
  const uint64_t max_file_blocks = 1
      + (UINT64_C(4294967296) - 1) / blocksize;
  const uint64_t capacity_limit = image_blocks < max_file_blocks
      ? image_blocks : max_file_blocks;

  if ((search.phase != ONENOTE_REPAIR_PACKAGE_GAP
       && search.phase != ONENOTE_REPAIR_PACKAGE_TAIL)
      || search.next_source > capacity_limit
      || search.next_source > SIZE_MAX / sizeof(int64_t)
      || search.next_source > SIZE_MAX / blocksize) {
    memset(&search, 0, sizeof(search));
  }
  for (uint64_t slot = 0; slot < block_count; slot++) {
    if (workspace.searched_end < (uint64_t)mapping[slot] + 1) {
      workspace.searched_end = (uint64_t)mapping[slot] + 1;
    }
  }
  bool resume_tail = search.phase == ONENOTE_REPAIR_PACKAGE_TAIL;
  uint64_t trial_capacity = resume_tail && search.next_source > block_count
      ? search.next_source : block_count;
  int64_t *trial_mapping = malloc(
      (size_t)trial_capacity * sizeof(*trial_mapping));
  check_memory_allocation(trial_mapping, __LINE__, __FILE__,
                          "OneNote package trial mapping");
  uint8_t *trial_data = malloc((size_t)trial_capacity * blocksize);
  check_memory_allocation(trial_data, __LINE__, __FILE__,
                          "OneNote package trial data");
  bool recovered = false;

  for (uint64_t gap_start = search.phase == ONENOTE_REPAIR_NONE
                                 ? 1 : search.run_start;
       gap_start < block_count && *candidate && !recovered;
       gap_start++) {
    const int64_t gap_actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, mapping[gap_start]);

    if (gap_actual < 0
        || !filemirror_actual_block_is_zero(
               scalpel_state.filemirror, gap_actual)) {
      continue;
    }

    uint64_t zero_blocks = 1;

    while (zero_blocks < block_count - gap_start) {
      const int64_t actual = filemirror_actual_blocknumber(
          scalpel_state.filemirror, mapping[gap_start + zero_blocks]);

      if (actual < 0
          || !filemirror_actual_block_is_zero(
                 scalpel_state.filemirror, actual)) {
        break;
      }
      zero_blocks++;
    }
    if (zero_blocks == block_count - gap_start) {
      break;
    }

    const uint64_t trial_blocks = block_count - zero_blocks;
    bool copied = true;

    if (resume_tail && search.run_length != zero_blocks) {
      resume_tail = false;
    }
    const uint64_t restored_blocks = resume_tail
        ? search.next_source : trial_blocks;

    for (uint64_t slot = 0; slot < restored_blocks; slot++) {
      if (slot < trial_blocks) {
        const uint64_t source_slot = slot < gap_start
            ? slot : slot + zero_blocks;

        trial_mapping[slot] = mapping[source_slot];
      }
      else {
        const uint64_t delta = slot - trial_blocks + 1;

        if (delta > (uint64_t)(INT64_MAX - mapping[block_count - 1])) {
          copied = false;
          break;
        }
        trial_mapping[slot] = mapping[block_count - 1] + (int64_t)delta;
      }
      if (!onenote_reassembly_copy_block(
              trial_data + slot * blocksize, trial_mapping[slot])) {
        copied = false;
        break;
      }
    }

    OneNoteSummary trial_summary = {0};
    uint64_t materialized_blocks = restored_blocks;

    if (copied && !resume_tail) {
      recovered = onenote_parse(
          trial_data, materialized_blocks * blocksize, kind, &trial_summary);
    }

    const uint64_t next_delta = materialized_blocks - trial_blocks + 1;
    int64_t next_apparent = next_delta
            > (uint64_t)(INT64_MAX - mapping[block_count - 1])
        ? -1 : mapping[block_count - 1] + (int64_t)next_delta;
    resume_tail = false;

    while (copied && !recovered && next_apparent >= 0
           && (uint64_t)next_apparent < image_blocks
           && materialized_blocks < capacity_limit) {
      if (materialized_blocks == trial_capacity) {
        uint64_t new_capacity = trial_capacity > capacity_limit / 2
            ? capacity_limit : trial_capacity * 2;

        if (new_capacity <= trial_capacity
            || new_capacity > SIZE_MAX / sizeof(*trial_mapping)
            || new_capacity > SIZE_MAX / blocksize) {
          break;
        }

        int64_t *grown_mapping = realloc(
            trial_mapping, (size_t)new_capacity * sizeof(*trial_mapping));
        check_memory_allocation(grown_mapping, __LINE__, __FILE__,
                                "grown OneNote package trial mapping");
        trial_mapping = grown_mapping;

        uint8_t *grown_data = realloc(
            trial_data, (size_t)new_capacity * blocksize);
        check_memory_allocation(grown_data, __LINE__, __FILE__,
                                "grown OneNote package trial data");
        trial_data = grown_data;
        trial_capacity = new_capacity;
      }

      trial_mapping[materialized_blocks] = next_apparent;
      copied = onenote_reassembly_copy_block(
          trial_data + materialized_blocks * blocksize, next_apparent);
      if (!copied) {
        break;
      }
      materialized_blocks++;

      const uint64_t scan_start = (materialized_blocks - 1) * blocksize;
      const uint64_t marker_start = scan_start == 0 ? 0 : scan_start - 1;
      const uint64_t scan_end = materialized_blocks * blocksize;
      bool possible_end = false;

      for (uint64_t offset = marker_start;
           offset + 1 < scan_end && !possible_end; offset++) {
        possible_end = trial_data[offset] == 0xeb
                       && trial_data[offset + 1] == 0x01;
      }
      if (possible_end) {
        recovered = onenote_parse(
            trial_data, materialized_blocks * blocksize,
            kind, &trial_summary);
      }

      if (workspace.searched_end < (uint64_t)next_apparent + 1) {
        workspace.searched_end = (uint64_t)next_apparent + 1;
      }
      search = (OneNoteRepairSearch){
        .phase = ONENOTE_REPAIR_PACKAGE_TAIL, .run_start = gap_start,
        .run_length = zero_blocks, .next_source = materialized_blocks
      };
      if (!recovered
          && onenote_reassembly_search_poll(
                 work, candidate, uuidp, uuidc, &search, &workspace)) {
        free(trial_data);
        free(trial_mapping);
        free(mapping);
        return;
      }
      next_apparent++;
    }

    if (recovered) {
      const uint64_t recovered_blocks = 1
          + (trial_summary.extent - 1) / blocksize;

      if (recovered_blocks > materialized_blocks) {
        recovered = false;
        continue;
      }
      resize_blockvector(blockvector, recovered_blocks);
      for (uint64_t slot = 0; slot < recovered_blocks; slot++) {
        blockvector_set_apparent_blocknumber(
            blockvector, slot, trial_mapping[slot]);
      }
      inflate_blockvector(blockvector);
      blockvector_set_data_length(blockvector, trial_summary.extent);
      break;
    }

    search = (OneNoteRepairSearch){
      .phase = ONENOTE_REPAIR_PACKAGE_GAP,
      .run_start = gap_start + zero_blocks
    };
    if (onenote_reassembly_search_poll(
            work, candidate, uuidp, uuidc, &search, &workspace)) {
      free(trial_data);
      free(trial_mapping);
      free(mapping);
      return;
    }
    gap_start += zero_blocks - 1;
  }

  free(trial_data);
  free(trial_mapping);
  free(mapping);

  if (!*candidate) {
    return;
  }
  if (scalpel_state.write_promising) {
    (*candidate)->flavor = PROMISING;
    write_candidate(candidate, false);
  }
  else {
    destroy_candidate(candidate);
  }
}

// Recover revision stores by repairing the smallest logical run implicated by
// the strict parser. Format evidence, including stored MD5 values, must advance
// before a trial is committed. If the implicated range is ambiguous, the same
// exhaustive search is applied to every non-header slot. Checkpoint requests
// preserve every committed improvement in the blockvector.
//
static inline void onenote_reassembly(ThreadWork *work,
                                      CarveInfo **candidate,
                                      uuid_string_t uuidp,
                                      uuid_string_t uuidc) {

  if (!work || !candidate || !*candidate || !(*candidate)->b
      || scalpel_state.blocksize == 0) {
    if (candidate && *candidate) {
      destroy_candidate(candidate);
    }
    return;
  }

  (*candidate)->chopped = false;
  inflate_blockvector((*candidate)->b);

  BlockVector *blockvector = (*candidate)->b;
  const uint64_t existing_blocks = blockvector_get_num_blocks(blockvector);
  const uint64_t existing_length = blockvector_get_data_length(blockvector);
  const uint8_t *existing_data = (const uint8_t *)
      blockvector_get_data_pointer(blockvector);

  const OneNoteStorage storage = onenote_storage_kind(
      existing_data, existing_length);

  if (storage == ONENOTE_STORAGE_PACKAGE
      || storage == ONENOTE_STORAGE_EMBEDDED_PACKAGE) {
    onenote_package_reassembly(work, candidate, uuidp, uuidc);
    return;
  }
  if (!existing_data || existing_blocks == 0
      || existing_length < ONENOTE_HEADER_SIZE
      || storage != ONENOTE_STORAGE_REVISION) {
    if (scalpel_state.write_promising) {
      (*candidate)->flavor = PROMISING;
      write_candidate(candidate, false);
    }
    else {
      destroy_candidate(candidate);
    }
    return;
  }

  const OneNoteKind kind = onenote_file_kind(existing_data, existing_length);
  const uint64_t data_length = onenote_read_le64(
      existing_data + ONENOTE_EXPECTED_LENGTH_OFFSET);
  const uint64_t blocksize = scalpel_state.blocksize;

  if (kind == ONENOTE_KIND_NONE || data_length < ONENOTE_HEADER_SIZE
      || data_length > scalpel_state.search_specs[(*candidate)->needleidx]
                           .MAXIMUMSIZE
      || data_length > UINT64_MAX - (blocksize - 1)) {
    destroy_candidate(candidate);
    return;
  }

  const uint64_t block_count = CEILDIV(data_length, blocksize);
  const uint64_t image_blocks = filemirror_apparent_blocks(
      scalpel_state.filemirror);
  const uint64_t used_size_64 = image_blocks / 8
                                + (image_blocks % 8 != 0);

  if (block_count == 0 || block_count > image_blocks
      || block_count > SIZE_MAX / sizeof(int64_t)
      || block_count > SIZE_MAX / blocksize
      || used_size_64 > SIZE_MAX) {
    destroy_candidate(candidate);
    return;
  }

  const int64_t first_apparent = blockvector_get_apparent_blocknumber(
      blockvector, 0);

  if (first_apparent < 0
      || (uint64_t)first_apparent >= image_blocks) {
    destroy_candidate(candidate);
    return;
  }

  resize_blockvector(blockvector, block_count);
  int64_t *mapping = malloc((size_t)block_count * sizeof(*mapping));
  check_memory_allocation(mapping, __LINE__, __FILE__,
                          "OneNote reassembly mapping");

  const size_t used_size = (size_t)used_size_64;
  uint8_t *used = calloc(used_size, 1);
  check_memory_allocation(used, __LINE__, __FILE__,
                          "OneNote reassembly used-block bitmap");

  bool mapping_valid = true;

  for (uint64_t slot = 0; slot < block_count; slot++) {
    int64_t apparent = slot < existing_blocks
                           ? blockvector_get_apparent_blocknumber(
                                 blockvector, slot)
                           : -1;

    if (apparent < 0) {
      if ((uint64_t)first_apparent + slot >= image_blocks) {
        mapping_valid = false;
        break;
      }
      apparent = first_apparent + (int64_t)slot;
      blockvector_set_apparent_blocknumber(blockvector, slot, apparent);
    }
    if ((uint64_t)apparent >= image_blocks
        || (used[(uint64_t)apparent >> 3]
            & (uint8_t)(1u << ((uint64_t)apparent & 7u))) != 0) {
      mapping_valid = false;
      break;
    }
    mapping[slot] = apparent;
    used[(uint64_t)apparent >> 3]
        |= (uint8_t)(1u << ((uint64_t)apparent & 7u));
  }

  const uint64_t materialized_length = block_count * blocksize;
  uint8_t *trial_data = NULL;

  if (mapping_valid) {
    trial_data = malloc((size_t)materialized_length);
    check_memory_allocation(trial_data, __LINE__, __FILE__,
                            "OneNote reassembly trial data");
    mapping_valid = onenote_reassembly_materialize(
        trial_data, mapping, block_count);
  }
  if (!mapping_valid) {
    free(trial_data);
    free(used);
    free(mapping);
    destroy_candidate(candidate);
    return;
  }

  blockvector_set_data_length(blockvector, data_length);
  inflate_blockvector(blockvector);

  OneNoteRevisionState parser_workspace = {0};
  OneNoteRecoveryScore current = {0};
  current.complete = onenote_parse_with_workspace(
      trial_data, data_length, kind, &current.summary, &parser_workspace);
  current.found = true;
  current.zip_output_comparable =
      parser_workspace.zip_probe.baseline_output_comparable;
  current.zip_output_distance =
      parser_workspace.zip_probe.baseline_output_distance;
  onenote_reassembly_score_layout(
      trial_data, mapping, block_count, 0, 0, -1, &current);
  current.content_seam_cost = onenote_reassembly_content_seam_cost(
      trial_data, block_count);

  uint64_t displacement_capacity = 8;
  uint64_t displacement_count = 1;
  int64_t *displacements = malloc(
      (size_t)displacement_capacity * sizeof(*displacements));
  check_memory_allocation(displacements, __LINE__, __FILE__,
                          "OneNote source displacements");
  displacements[0] = first_apparent;
  onenote_reassembly_restore_progress(
      *candidate, mapping, block_count, data_length, &current,
      &displacements, &displacement_count, &displacement_capacity);
  OneNoteRepairSearch search = onenote_reassembly_load_search(*candidate);
  parser_workspace.searched_end = search.searched_end;

  while (*candidate && !current.summary.no_memory) {
    OneNoteRecoveryScore best = search.best;

    for (uint64_t slot = 0; slot < block_count; slot++) {
      if (mapping[slot] >= 0
          && parser_workspace.searched_end < (uint64_t)mapping[slot] + 1) {
        parser_workspace.searched_end = (uint64_t)mapping[slot] + 1;
      }
    }
    uint64_t failure_slot = current.summary.failure_offset / blocksize;
    uint64_t failure_start_slot = current.summary.failure_start / blocksize;
    uint64_t failure_end_slot = current.summary.failure_end / blocksize;

    if (failure_slot >= block_count) {
      failure_slot = block_count - 1;
    }
    if (failure_start_slot >= block_count
        || failure_end_slot < failure_start_slot) {
      failure_start_slot = failure_slot;
      failure_end_slot = failure_slot;
    }
    else if (failure_end_slot >= block_count) {
      failure_end_slot = block_count - 1;
    }

    if (onenote_reassembly_search_zero(
            work, candidate, uuidp, uuidc, trial_data, mapping, used,
            block_count, data_length, kind, failure_start_slot,
            failure_end_slot, &current, &best, &parser_workspace, &search)) {
      onenote_revision_state_release(&parser_workspace);
      free(displacements);
      free(trial_data);
      free(used);
      free(mapping);
      return;
    }

    if (onenote_reassembly_search_zip(
            work, candidate, uuidp, uuidc, trial_data, mapping, used,
            block_count, data_length, kind, failure_start_slot,
            failure_end_slot, &current, &best, &parser_workspace, &search)) {
      onenote_revision_state_release(&parser_workspace);
      free(displacements);
      free(trial_data);
      free(used);
      free(mapping);
      return;
    }

    if (current.complete && current.exact_run_boundaries) {
      break;
    }

    if (onenote_reassembly_search_boundaries(
            work, candidate, uuidp, uuidc, trial_data, mapping, used,
            block_count, data_length, kind, &current, &best, displacements,
            displacement_count, &parser_workspace, &search)) {
      onenote_revision_state_release(&parser_workspace);
      free(displacements);
      free(trial_data);
      free(used);
      free(mapping);
      return;
    }

    if (onenote_reassembly_search_alignments(
            work, candidate, uuidp, uuidc, trial_data, mapping, used,
            block_count, data_length, kind, failure_start_slot,
            failure_end_slot, failure_slot, &current, &best, displacements,
            displacement_count, &parser_workspace, &search)) {
      onenote_revision_state_release(&parser_workspace);
      free(displacements);
      free(trial_data);
      free(used);
      free(mapping);
      return;
    }

    OneNoteRecoveryScore weak = search.weak;

    if (onenote_reassembly_search_runs(
            work, candidate, uuidp, uuidc, trial_data, mapping, used,
            block_count, data_length, kind, failure_start_slot,
            failure_end_slot, failure_slot, &current, &best, &weak,
            &parser_workspace, &search)) {
      onenote_revision_state_release(&parser_workspace);
      free(displacements);
      free(trial_data);
      free(used);
      free(mapping);
      return;
    }

    if (!best.found && weak.found && *candidate) {
      for (uint64_t offset = 0; offset < weak.run_length; offset++) {
        const uint64_t apparent =
            (uint64_t)mapping[weak.run_start + offset];

        used[apparent >> 3]
            &= (uint8_t)~(1u << (apparent & 7u));
      }

      OneNoteRecoveryScore confirmed = {0};
      OneNoteRecoveryScore confirmed_best = {0};

      onenote_reassembly_try_run(
          trial_data, mapping, used, block_count, data_length, kind,
          weak.run_start, weak.run_length, weak.source, &current,
          &confirmed_best, true, &confirmed, &parser_workspace, true);
      for (uint64_t offset = 0; offset < weak.run_length; offset++) {
        const uint64_t apparent =
            (uint64_t)mapping[weak.run_start + offset];

        used[apparent >> 3]
            |= (uint8_t)(1u << (apparent & 7u));
      }
      if (onenote_reassembly_parser_progress(
              &current, &confirmed.summary, confirmed.complete,
              confirmed.zip_output_comparable,
              confirmed.zip_output_distance)) {
        best = confirmed;
      }
    }

    if (!best.found || !*candidate) {
      break;
    }
    bool new_alignment = false;

    if (best.run_start <= INT64_MAX) {
      const int64_t displacement = best.source - (int64_t)best.run_start;
      bool known = false;

      for (uint64_t index = 0; index < displacement_count; index++) {
        if (displacements[index] == displacement) {
          known = true;
          break;
        }
      }
      if (!known) {
        if (displacement_count == displacement_capacity) {
          const uint64_t new_capacity = displacement_capacity * 2;

          if (new_capacity < displacement_capacity
              || new_capacity > SIZE_MAX / sizeof(*displacements)) {
            onenote_revision_state_release(&parser_workspace);
            free(displacements);
            free(trial_data);
            free(used);
            free(mapping);
            handle_error(SCALPEL_GENERAL_ABORT,
                         "OneNote displacement table overflow",
                         __LINE__, __FILE__);
          }
          int64_t *new_displacements = realloc(
              displacements,
              (size_t)new_capacity * sizeof(*displacements));
          check_memory_allocation(new_displacements, __LINE__, __FILE__,
                                  "OneNote source displacements");
          displacements = new_displacements;
          displacement_capacity = new_capacity;
        }
        displacements[displacement_count++] = displacement;
        new_alignment = true;
      }
    }
    onenote_reassembly_apply_run(*candidate, mapping, used, trial_data,
                                 &best);
    blockvector_set_data_length((*candidate)->b, data_length);
    parser_workspace.integrity_cache_count = 0;

    // Cursor-only progress cannot reopen an already-tested speculative gap.
    const uint64_t overlapping_suffix_blocks =
        current.overlapping_suffix_blocks > best.overlapping_suffix_blocks
            ? current.overlapping_suffix_blocks
            : best.overlapping_suffix_blocks;

    current = best;
    current.overlapping_suffix_blocks = overlapping_suffix_blocks;
    OneNoteSummary refreshed = {0};

    current.complete = onenote_parse_with_workspace(
        trial_data, data_length, kind, &refreshed, &parser_workspace);
    current.summary = refreshed;
    current.zip_output_comparable =
        parser_workspace.zip_probe.baseline_output_comparable;
    current.zip_output_distance =
        parser_workspace.zip_probe.baseline_output_distance;

    onenote_reassembly_commit_progress(
        *candidate, mapping, block_count, data_length, &current, &best,
        new_alignment);
    parser_workspace.searched_end = 0;

    // Preserve each structurally complete reconstruction before optional
    // boundary refinement because opaque ranges can leave several defensible
    // byte-level alternatives.
    if (current.complete && scalpel_state.write_promising) {
      blockvector_set_data_length((*candidate)->b, current.summary.extent);
      (*candidate)->flavor = PROMISING;
      write_candidate(candidate, true);
    }

    if (onenote_reassembly_poll(work, candidate, uuidp, uuidc)) {
      onenote_revision_state_release(&parser_workspace);
      free(displacements);
      free(trial_data);
      free(used);
      free(mapping);
      return;
    }
  }

  onenote_revision_state_release(&parser_workspace);
  free(displacements);
  free(trial_data);
  free(used);
  free(mapping);

  if (!*candidate) {
    return;
  }
  if (current.complete) {
    blockvector_set_data_length((*candidate)->b, current.summary.extent);
    if (scalpel_state.write_promising) {
      (*candidate)->flavor = PROMISING;
      write_candidate(candidate, false);
    }
    else {
      destroy_candidate(candidate);
    }
    return;
  }
  if (scalpel_state.write_promising) {
    (*candidate)->flavor = PROMISING;
    write_candidate(candidate, false);
  }
  else {
    destroy_candidate(candidate);
  }
}

#endif
