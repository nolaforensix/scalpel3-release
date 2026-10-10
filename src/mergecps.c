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
#define SCALPEL3_EXTERNAL 1
#include <sys/types.h>  // must precede roaring.h on macOS to ensure BSD types (u_int etc.) are defined
#include "roaring.h"
#include "scalpel.h"
#include "scalpelsimd.h"
#include "colors.h"
#include "prioque.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#define MERGECPS_BANNER_STRING \
  "MergeCPs v%s -- Merges two scalpel3 checkpoints.", SCALPEL_VERSION

// Global for linkage
ScalpelState merged_state;

typedef struct {
  uint64_t offset;
  size_t len;
  bool deposited;
} HeaderEntry;

typedef struct {
  uint64_t offset;
  size_t len;
} FooterEntry;

// Per-spec opaque blobs for carve_state and block_state passthrough
typedef struct {
  void   *carve_blob;
  size_t  carve_size;
  void   *block_blob;
  size_t  block_size;
} SpecBlob;

typedef struct {
  unsigned char key[CARVE_HASH_KEY_SIZE];
  unsigned int source;
} CandidateStateSource;

typedef struct {
  unsigned char identity[sizeof(uuid_t) * 2];
} CandidateIdentity;

typedef struct {
  const unsigned char *key;
  const unsigned char *record;
  size_t size;
  size_t key_size;
  unsigned int source;
} StateRecord;

// function prototypes for local functions
static int compare_footers(const void *a, const void *b);
static int compare_headers(const void *a, const void *b);
static void mergecps_logo(void);
static void usage(void);
static void merge_global_counters(ScalpelState *state1, ScalpelState *state2);
static void merge_search_spec(SearchSpec *sm, SearchSpec *s1, SearchSpec *s2);
static void merge_blocktypes(unsigned char **btm, unsigned char **bt1, unsigned char **bt2, uint64_t numblocks, uint32_t num_specs);
static void merge_promising_queues(Queue *qm, const char *path1, const char *path2,
                                   CandidateStateSource **sources, size_t *source_count);
static int compare_candidate_identity(const void *a, const void *b);
static int compare_candidate_state_source(const void *a, const void *b);
static int compare_state_records(const void *a, const void *b);
static size_t read_state_records(const void *blob, size_t size, size_t key_size,
                                 unsigned int source, StateRecord **records);
static void merge_state_blob(void **output, size_t *output_size,
                             const void *left, size_t left_size, const void *right, size_t right_size,
                             size_t key_size, const CandidateStateSource *sources, size_t source_count);
static SpecBlob *read_checkpoint_state(ScalpelState *state, char *path);
static uint64_t get_numblocks_from_blockmap(const char *blockmap_path);
static void write_merged_checkpoint(const char *out_dir, uint64_t numblocks, unsigned char **btm, Queue *qm, uint64_t sequence_number, SpecBlob *blobs);
static bool parent_directory(const char *path, char *parent, size_t parent_size);

#define CHECK_IO(cond, msg)                                                                                                \
  if (! (cond)) {                                                                                                          \
    fprintf(stderr, "At line %d in source file %s:\n", __LINE__, __FILE__);                                                \
    fprintf(stderr, "Checkpoint integrity failure: %s. Aborting.\n", msg);                                                 \
    exit(1);                                                                                                               \
  }


///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// imported serialization functions--if scalpel3's serialized state layouts //
// change, these functions and types MUST be updated to match. Transactional //
// checkpoint format operations are shared through common.c.                 //
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

// function prototypes for local copies of scalpel3 functions
static bool best_choices_element_serialization(void **element, int64_t *priority, FILE *fp, StateSerialization mode);
static void filemirror_serialize_blockclassification_data(
    uint64_t numblocks, unsigned char **blocktype, StateSerialization mode,
    char *filename, ScalpelState *state);
static void init_blockvector(void *state, BlockVector **b, uint64_t num_blocks, bool disable_reservations);
static void memset_uint64_t_local(uint64_t *dest, uint64_t val, size_t count);
static bool promising_queue_element_serialization(void **element, int64_t *priority, FILE *fp, StateSerialization mode);
static void scalpel_state_serialization(ScalpelState *state, StateSerialization mode, char *filename, SpecBlob *blobs);
static void seq_read_blockvector(void *state, BlockVector **b, FILE *fp);
static void seq_write_blockvector(BlockVector *b, FILE *fp);

typedef struct BlockVector {
  char *data;                     // data corresponding to valid apparent
                                  // block numbers when actual blocks are not adjacent
  char *seqdata;                  // data corresponding to valid apparent
                                  // block numbers when actual blocks are adjacent
  uint64_t numblocks;             // # of blocks in block vector
  int64_t *apparent_blocknumber;  // vector of block numbers adjusted
                                  // to ignore covered blocks
  bool *valid;                    // true if data in corresponding
                                  // block is valid
  int64_t *actual_blocknumber;    // vector of actual block numbers in
                                  // file being mirrored
  uint64_t length;                // length of 'data' in blockvector
  roaring64_bitmap_t **choices;   // array of bitmaps representing
                                  // possible suitable block numbers for each block
  FileMirror *filemirror;         // associated file mirror
  uint64_t malloc_length;         // number of blocks accomodated by
                                  // current memory allocation
  bool ignore_reservations;       // if true, don't perform reservation operations
} BlockVector;

// Helper functions
static void init_blockvector(void *state, BlockVector **b, uint64_t num_blocks, bool disable_reservations) {

  (void)state;
  (void)disable_reservations;

  *b = calloc(1, sizeof(BlockVector));
  check_memory_allocation(*b, __LINE__, __FILE__, "b");

  (*b)->numblocks = num_blocks;
  (*b)->malloc_length = num_blocks;

  (*b)->actual_blocknumber = calloc(num_blocks, sizeof(int64_t));
  check_memory_allocation((*b)->actual_blocknumber, __LINE__, __FILE__, "b->actual_blocknumber");

  (*b)->apparent_blocknumber = calloc(num_blocks, sizeof(int64_t));
  check_memory_allocation((*b)->apparent_blocknumber, __LINE__, __FILE__, "b->apparent_blocknumber");

  (*b)->valid = calloc(num_blocks, sizeof(bool));
  check_memory_allocation((*b)->valid, __LINE__, __FILE__, "b->valid");

  (*b)->ignore_reservations = true;
}


static void memset_uint64_t_local(uint64_t *dest, uint64_t val, size_t count) {

  for (size_t i = 0; i < count; i++) {
    dest[i] = val;
  }
}


static uint64_t checkpoint_get_sequence(const CheckpointSelection *checkpoint1,
                                        const CheckpointSelection *checkpoint2) {

  uint64_t sequence_number = checkpoint1->manifest.sequence_number
                                 > checkpoint2->manifest.sequence_number
                             ? checkpoint1->manifest.sequence_number
                             : checkpoint2->manifest.sequence_number;

  CHECK_IO(sequence_number < UINT64_MAX, "checkpoint sequence overflow");
  return sequence_number + 1U;
}


static void seq_read_blockvector(void *state, BlockVector **b, FILE *fp) {

  uint64_t i;
  int64_t index = 0;
  uint64_t num_blocks = 0;
  char *serialized_bitmap;
  size_t serialized_length;

  CHECK_IO(fread(&num_blocks, sizeof(num_blocks), 1, fp) == 1, "numblocks");

  init_blockvector(state, b, num_blocks, false);

  for (i = 0; i < num_blocks; i++) {
    CHECK_IO(fread(&((*b)->apparent_blocknumber[i]), sizeof((*b)->apparent_blocknumber[i]), 1, fp) == 1, "apparent_blocknumber");
    CHECK_IO(fread(&((*b)->actual_blocknumber[i]), sizeof((*b)->actual_blocknumber[i]), 1, fp) == 1, "actual_blocknumber");
  }

  CHECK_IO(fread(&((*b)->length), sizeof((*b)->length), 1, fp) == 1, "length");
  CHECK_IO(fread(&index, sizeof(index), 1, fp) == 1, "index");

  if (index >= 0) {
    (*b)->choices = (roaring64_bitmap_t **)calloc((*b)->malloc_length, sizeof(roaring64_bitmap_t *));
    check_memory_allocation((*b)->choices, __LINE__, __FILE__, "b->choices");
    memset_uint64_t_local((uint64_t *)(*b)->choices, 0, (*b)->numblocks);
  }

  while (index >= 0) {
    if ((uint64_t)index >= (*b)->numblocks) {
      fprintf(stderr, "At line %d in source file %s:\n", __LINE__, __FILE__);
      fprintf(stderr, "Checkpoint integrity failure: invalid choices index. Aborting.\n");
      exit(1);
    }

    CHECK_IO(fread(&serialized_length, sizeof(serialized_length), 1, fp) == 1, "choices serialized_length");

    serialized_bitmap = malloc(serialized_length);
    check_memory_allocation(serialized_bitmap, __LINE__, __FILE__, "b->choices");

    CHECK_IO(fread(serialized_bitmap, serialized_length, 1, fp) == 1, "choices serialized_bitmap");

    (*b)->choices[index] = roaring64_bitmap_portable_deserialize_safe(serialized_bitmap, serialized_length);
    free(serialized_bitmap);

    if (! roaring64_bitmap_internal_validate((*b)->choices[index], NULL)) {
      fprintf(stderr, "At line %d in source file %s:\n", __LINE__, __FILE__);
      fprintf(stderr, "Checkpoint integrity failure: invalid bitmap. Aborting.\n");
      exit(1);
    }

    CHECK_IO(fread(&index, sizeof(index), 1, fp) == 1, "choices next index");
  }

  CHECK_IO(fread(&(*b)->ignore_reservations, sizeof(bool), 1, fp) == 1, "ignore_reservations");
}


static void seq_write_blockvector(BlockVector *b, FILE *fp) {

  int64_t i;
  char *serialized_bitmap;
  size_t serialized_length;

  CHECK_IO(fwrite(&b->numblocks, sizeof(b->numblocks), 1, fp) == 1, "numblocks");

  for (i = 0; i < (int64_t)b->numblocks; i++) {
    CHECK_IO(fwrite(&b->apparent_blocknumber[i], sizeof(b->apparent_blocknumber[i]), 1, fp) == 1, "apparent_blocknumber");
    CHECK_IO(fwrite(&b->actual_blocknumber[i], sizeof(b->actual_blocknumber[i]), 1, fp) == 1, "actual_blocknumber");
  }

  CHECK_IO(fwrite(&b->length, sizeof(b->length), 1, fp) == 1, "length");

  if (b->choices) {
    for (i = 0; i < (int64_t)b->numblocks; i++) {
      if (b->choices[i]) {
        CHECK_IO(fwrite(&i, sizeof(i), 1, fp) == 1, "choices index");

        serialized_length = roaring64_bitmap_portable_size_in_bytes(b->choices[i]);
        CHECK_IO(fwrite(&serialized_length, sizeof(serialized_length), 1, fp) == 1, "choices serialized_length");

        serialized_bitmap = malloc(serialized_length);
        check_memory_allocation(serialized_bitmap, __LINE__, __FILE__, "b->choices");

        roaring64_bitmap_portable_serialize(b->choices[i], serialized_bitmap);

        CHECK_IO(fwrite(serialized_bitmap, serialized_length, 1, fp) == 1, "choices serialized_bitmap");

        free(serialized_bitmap);
      }
    }
  }

  i = -1;
  CHECK_IO(fwrite(&i, sizeof(i), 1, fp) == 1, "choices terminal index");
  CHECK_IO(fwrite(&b->ignore_reservations, sizeof(bool), 1, fp) == 1, "ignore_reservations");
}


static void filemirror_serialize_blockclassification_data(
    uint64_t numblocks, unsigned char **blocktype, StateSerialization mode,
    char *filename, ScalpelState *state) {

  FILE *fp;
  char magic[BLOCKCLASSIFICATION_MAGIC_SIZE];
  uint32_t version = BLOCKCLASSIFICATION_VERSION;
  uint32_t num_specs = state->num_specs;
  uint64_t blocksize = state->blocksize;

  if (mode == SERIALIZE) {
    unlink(filename);
  }

  fp = fopen(filename, mode == SERIALIZE ? "wb" : "rb");
  CHECK_IO(fp != NULL, "blockclassification open");

  if (mode == SERIALIZE) {
    CHECK_IO(fwrite(BLOCKCLASSIFICATION_MAGIC, 1,
                    BLOCKCLASSIFICATION_MAGIC_SIZE, fp)
                 == BLOCKCLASSIFICATION_MAGIC_SIZE,
             "blockclassification magic");
    CHECK_IO(fwrite(&version, sizeof(version), 1, fp) == 1,
             "blockclassification version");
    CHECK_IO(fwrite(&blocksize, sizeof(blocksize), 1, fp) == 1,
             "blockclassification blocksize");
    CHECK_IO(fwrite(&numblocks, sizeof(numblocks), 1, fp) == 1,
             "blockclassification block count");
    CHECK_IO(fwrite(&num_specs, sizeof(num_specs), 1, fp) == 1,
             "blockclassification type count");

    for (uint32_t j = 0; j < num_specs; j++) {
      uint32_t filetype_len = (uint32_t)strlen(state->search_specs[j].FILETYPE);

      CHECK_IO(filetype_len > 0 && filetype_len < MAX_STRING_LENGTH,
               "blockclassification file type length");
      CHECK_IO(fwrite(&filetype_len, sizeof(filetype_len), 1, fp) == 1,
               "blockclassification file type length");
      CHECK_IO(fwrite(state->search_specs[j].FILETYPE, 1, filetype_len, fp)
                   == filetype_len,
               "blockclassification file type");
    }
  }
  else {
    uint32_t stored_version;
    uint32_t stored_num_specs;
    uint64_t stored_blocksize;
    uint64_t stored_numblocks;

    CHECK_IO(fread(magic, 1, sizeof(magic), fp) == sizeof(magic)
                 && memcmp(magic, BLOCKCLASSIFICATION_MAGIC, sizeof(magic)) == 0,
             "blockclassification magic");
    CHECK_IO(fread(&stored_version, sizeof(stored_version), 1, fp) == 1
                 && stored_version == BLOCKCLASSIFICATION_VERSION,
             "blockclassification version");
    CHECK_IO(fread(&stored_blocksize, sizeof(stored_blocksize), 1, fp) == 1
                 && stored_blocksize == blocksize,
             "blockclassification blocksize");
    CHECK_IO(fread(&stored_numblocks, sizeof(stored_numblocks), 1, fp) == 1
                 && stored_numblocks == numblocks,
             "blockclassification block count");
    CHECK_IO(fread(&stored_num_specs, sizeof(stored_num_specs), 1, fp) == 1
                 && stored_num_specs == num_specs,
             "blockclassification type count");

    for (uint32_t j = 0; j < num_specs; j++) {
      char filetype[MAX_STRING_LENGTH];
      uint32_t filetype_len;

      CHECK_IO(fread(&filetype_len, sizeof(filetype_len), 1, fp) == 1
                   && filetype_len > 0 && filetype_len < sizeof(filetype),
               "blockclassification file type length");
      CHECK_IO(fread(filetype, 1, filetype_len, fp) == filetype_len,
               "blockclassification file type");
      filetype[filetype_len] = '\0';
      if (state->search_specs[j].MASTER
          && state->search_specs[j].FILETYPE[0] == '\0') {
        memcpy(state->search_specs[j].FILETYPE, filetype, filetype_len + 1);
      }
      else {
        CHECK_IO(strcmp(filetype, state->search_specs[j].FILETYPE) == 0,
                 "blockclassification file type mapping");
      }
    }
  }

  for (uint32_t j = 0; j < num_specs; j++) {
    size_t processed = mode == SERIALIZE
                           ? fwrite(blocktype[j], 1, numblocks, fp)
                           : fread(blocktype[j], 1, numblocks, fp);
    CHECK_IO(processed == numblocks, "blockclassification column");
  }

  CHECK_IO(mode == SERIALIZE ? checkpoint_durable_close(fp) : fclose(fp) == 0,
           "blockclassification close");
}



static bool best_choices_element_serialization(void **element, int64_t *priority, FILE *fp, StateSerialization mode) {

  size_t (*fb)(void *, size_t, size_t, FILE *) = mode == SERIALIZE ? (size_t (*)(void *, size_t, size_t, FILE *))fwrite : (size_t (*)(void *, size_t, size_t, FILE *))fread;
  void *slot = *element;

  CHECK_IO(fb(priority, sizeof(*priority), 1, fp) == 1, "best_choices priority");

  if (mode == SERIALIZE) {
    int64_t *block = (int64_t *)slot;
    CHECK_IO(fb(block, sizeof(*block), 1, fp) == 1, "best_choices block");
  }
  else {
    int64_t *buf = (int64_t *)calloc(1, sizeof(int64_t));
    if (! buf) {
      fprintf(stderr, "Memory allocation failed.\n");
      exit(1);
    }

    CHECK_IO(fb(buf, sizeof(*buf), 1, fp) == 1, "best_choices block");
    *element = buf;
  }

  return true;
}


static bool promising_queue_element_serialization(void **element, int64_t *priority, FILE *fp, StateSerialization mode) {

  size_t (*fb)(void *, size_t, size_t, FILE *) = mode == SERIALIZE ? (size_t (*)(void *, size_t, size_t, FILE *))fwrite : (size_t (*)(void *, size_t, size_t, FILE *))fread;
  void *slot = *element;
  CarveInfo *c;
  CarveInfo **tmp = (CarveInfo **)slot;

  if (mode == SERIALIZE) {
    c = *tmp;
  }
  else {
    c = calloc(1, sizeof(CarveInfo));
    if (! c) {
      fprintf(stderr, "Memory allocation failed.\n");
      exit(1);
    }
    *tmp = c;
  }

  CHECK_IO(fb(priority, sizeof(*priority), 1, fp) == 1, "promising priority");
  CHECK_IO(fb(&(c->workload), sizeof(c->workload), 1, fp) == 1, "promising workload");
  CHECK_IO(fb(&(c->needleidx), sizeof(c->needleidx), 1, fp) == 1, "promising needleidx");

  if (mode == SERIALIZE) {
    seq_write_blockvector(c->b, fp);
  }
  else {
    seq_read_blockvector(NULL, &(c->b), fp);
  }

  CHECK_IO(fb(&(c->chopped), sizeof(c->chopped), 1, fp) == 1, "promising chopped");
  CHECK_IO(fb(&(c->cloned), sizeof(c->cloned), 1, fp) == 1, "promising cloned");
  CHECK_IO(fb(&(c->clone), sizeof(c->clone), 1, fp) == 1, "promising clone");
  CHECK_IO(fb(&(c->deposited), sizeof(c->deposited), 1, fp) == 1, "promising deposited");
  CHECK_IO(fb(&(c->partial_artifact_written), sizeof(c->partial_artifact_written), 1, fp) == 1, "promising partial_artifact_written");
  CHECK_IO(fb(&(c->qposition), sizeof(c->qposition), 1, fp) == 1, "promising qposition");
  CHECK_IO(fb(&(c->flavor), sizeof(c->flavor), 1, fp) == 1, "promising flavor");
  CHECK_IO(fb(&(c->best_validates_to), sizeof(c->best_validates_to), 1, fp) == 1, "promising best_validates_to");
  CHECK_IO(fb(&(c->newblock), sizeof(c->newblock), 1, fp) == 1, "promising newblock");
  CHECK_IO(fb(&(c->block_choice_start), sizeof(c->block_choice_start), 1, fp) == 1, "promising block_choice_start");
  CHECK_IO(fb(&(c->no_initial_block_extension), sizeof(c->no_initial_block_extension), 1, fp) == 1, "promising no_initial_block_extension");
  CHECK_IO(fb(&(c->fastpath), sizeof(c->fastpath), 1, fp) == 1, "promising fastpath");

  static const uint64_t PQ_BEST_MAGIC = 0xB35DB3357A17CAFEULL;

  if (mode == SERIALIZE) {
    CHECK_IO(fwrite(&PQ_BEST_MAGIC, sizeof(PQ_BEST_MAGIC), 1, fp) == 1, "pq_best_magic write");
  }
  else {
    uint64_t chk = 0;
    CHECK_IO(fread(&chk, sizeof(chk), 1, fp) == 1, "pq_best_magic read");
    if (chk != PQ_BEST_MAGIC) {
      fprintf(stderr, "At line %d in source file %s:\n", __LINE__, __FILE__);
      fprintf(stderr, "Checkpoint integrity failure: PQ_BEST_MAGIC mismatch (got 0x%016llx). Aborting.\n", (unsigned long long)chk);
      exit(1);
    }
  }

  if (mode == SERIALIZE) {
    if (! serialize_queue(c->best_choices, best_choices_element_serialization, fp)) {
      fprintf(stderr, "At line %d in source file %s:\n", __LINE__, __FILE__);
      fprintf(stderr, "Checkpoint integrity failure: serialize promising choices. Aborting.\n");
      exit(1);
    }
  }
  else {
    c->best_choices = malloc(sizeof(Queue));
    if (! c->best_choices) {
      fprintf(stderr, "Memory allocation failed.\n");
      exit(1);
    }

    init_queue(c->best_choices, sizeof(int64_t), true, NULL, true);

    if (! deserialize_queue(c->best_choices, best_choices_element_serialization, false, fp)) {
      fprintf(stderr, "At line %d in source file %s:\n", __LINE__, __FILE__);
      fprintf(stderr, "Checkpoint integrity failure: deserialize promising choices. Aborting.\n");
      exit(1);
    }
  }

  CHECK_IO(fb(c->binuuid, sizeof(c->binuuid), 1, fp) == 1, "promising binuuid");
  CHECK_IO(fb(c->clone_binuuid, sizeof(c->clone_binuuid), 1, fp) == 1, "promising clone_binuuid");
  CHECK_IO(fb(c->carvehashkey, sizeof(c->carvehashkey), 1, fp) == 1, "promising carvehashkey");

  if (mode == DESERIALIZE) {
    // needleidx comes from the checkpoint; bound it before indexing search_specs.
    if (c->needleidx < 0 || (uint32_t)c->needleidx >= merged_state.num_specs) {
      fprintf(stderr, "At line %d in source file %s:\n", __LINE__, __FILE__);
      fprintf(stderr, "Checkpoint integrity failure: promising needleidx %d out of range (num_specs %u). Aborting.\n",
              c->needleidx, merged_state.num_specs);
      exit(1);
    }
    c->filetype = merged_state.search_specs[c->needleidx].FILETYPE;
    c->searchtype = merged_state.search_specs[c->needleidx].SEARCHTYPE;
  }

  return true;
}


static void scalpel_state_serialization(ScalpelState *state, StateSerialization mode, char *filename, SpecBlob *blobs) {

  FILE *fp;
  uint32_t i, j;
  uint64_t validated_files, files_written, backtracked;
  size_t (*fb)(void *, size_t, size_t, FILE *) = mode == SERIALIZE ? (size_t (*)(void *, size_t, size_t, FILE *))fwrite : (size_t (*)(void *, size_t, size_t, FILE *))fread;

  if (mode == SERIALIZE) {
    unlink(filename);
  }

  fp = fopen(filename, mode == SERIALIZE ? "wb" : "rb");
  if (! fp) {
    fprintf(stderr, "At line %d in source file %s:\n", __LINE__, __FILE__);
    fprintf(stderr, "Checkpoint integrity failure: scalpel_state open (%s). Aborting.\n", filename);
    exit(1);
  }

  CHECK_IO(fb(state->sha256, sizeof(state->sha256), 1, fp) == 1, "sha256");

  CHECK_IO(fb(state->image_pathname, 1, PATH_MAX, fp) == PATH_MAX, "image_pathname");
  CHECK_IO(fb(state->blockmap_pathname, 1, PATH_MAX, fp) == PATH_MAX, "blockmap_pathname");
  CHECK_IO(fb(&(state->blocksize), sizeof(state->blocksize), 1, fp) == 1, "blocksize");
  CHECK_IO(fb(&(state->num_specs), sizeof(state->num_specs), 1, fp) == 1, "num_specs");

  if (mode == DESERIALIZE) {
    state->search_specs = realloc(state->search_specs, sizeof(SearchSpec) * (state->num_specs + 1));
    check_memory_allocation(state->search_specs, __LINE__, __FILE__, "state->search_specs");
    // MASTER bodies are omitted; their flag, name and original index are saved.
    memset(state->search_specs, 0, sizeof(SearchSpec) * (state->num_specs + 1));
  }

  CHECK_IO(fb(&(state->longest_footer), sizeof(state->longest_footer), 1, fp) == 1, "longest_footer");
  CHECK_IO(fb(&(state->largest_maxfilesize), sizeof(state->largest_maxfilesize), 1, fp) == 1, "largest_maxfilesize");

  if (mode == SERIALIZE) {
    validated_files = atomic_load_explicit(&(state->validated_files), memory_order_acquire);
    files_written = atomic_load_explicit(&(state->files_written), memory_order_acquire);
  }

  CHECK_IO(fb(&(files_written), sizeof(files_written), 1, fp) == 1, "files_written");
  CHECK_IO(fb(&(validated_files), sizeof(validated_files), 1, fp) == 1, "validated_files");

  if (mode == DESERIALIZE) {
    atomic_init(&(state->validated_files), validated_files);
    atomic_init(&(state->files_written), files_written);
  }

  CHECK_IO(fb(&(state->candidates), sizeof(state->candidates), 1, fp) == 1, "candidates");
  CHECK_IO(fb(&(state->chopped), sizeof(state->chopped), 1, fp) == 1, "chopped");
  CHECK_IO(fb(&(state->reduce_aggressive_allocation), sizeof(state->reduce_aggressive_allocation), 1, fp) == 1, "reduce_aggressive_allocation");
  CHECK_IO(fb(&(state->write_blockvectors), sizeof(state->write_blockvectors), 1, fp) == 1, "write_blockvectors");
  CHECK_IO(fb(&(state->write_promising), sizeof(state->write_promising), 1, fp) == 1, "write_promising");
  CHECK_IO(fb(&(state->organize_subdirectories), sizeof(state->organize_subdirectories), 1, fp) == 1, "organize_subdirectories");
  CHECK_IO(fb(&(state->max_search_threads), sizeof(state->max_search_threads), 1, fp) == 1, "max_search_threads");
  CHECK_IO(fb(&(state->max_validation_threads), sizeof(state->max_validation_threads), 1, fp) == 1, "max_validation_threads");
  CHECK_IO(fb(&(state->max_reassembly_threads), sizeof(state->max_reassembly_threads), 1, fp) == 1, "max_reassembly_threads");
  CHECK_IO(fb(&(state->max_filemirror_threads), sizeof(state->max_filemirror_threads), 1, fp) == 1, "max_filemirror_threads");
  CHECK_IO(fb(&(state->share_reassembly), sizeof(state->share_reassembly), 1, fp) == 1, "share_reassembly");
  CHECK_IO(fb(&(state->contig_header_reuse), sizeof(state->contig_header_reuse), 1, fp) == 1, "contig_header_reuse");
  CHECK_IO(fb(&(state->no_defrag), sizeof(state->no_defrag), 1, fp) == 1, "no_defrag");
  CHECK_IO(fb(&(state->backtrack), sizeof(state->backtrack), 1, fp) == 1, "backtrack");
  CHECK_IO(fb(&(state->start_block), sizeof(state->start_block), 1, fp) == 1, "start_block");
  CHECK_IO(fb(&(state->end_block), sizeof(state->end_block), 1, fp) == 1, "end_block");
  CHECK_IO(fb(&(state->reservations), sizeof(state->reservations), 1, fp) == 1, "reservations");
  CHECK_IO(fb(&(state->memory_profiling), sizeof(state->memory_profiling), 1, fp) == 1, "memory_profiling");
  CHECK_IO(fb(&(state->disable_shadow_peeking), sizeof(state->disable_shadow_peeking), 1, fp) == 1, "disable_shadow_peeking");
  CHECK_IO(fb(&(state->disable_backtrace), sizeof(state->disable_backtrace), 1, fp) == 1, "disable_backtrace");
  CHECK_IO(fb(&(state->prioritize_types), sizeof(state->prioritize_types), 1, fp) == 1, "prioritize_types");
  CHECK_IO(fb(&(state->write_inprogress), sizeof(state->write_inprogress), 1, fp) == 1, "write_inprogress");
  CHECK_IO(fb(&(state->gallop_factor), sizeof(state->gallop_factor), 1, fp) == 1, "gallop_factor");
  CHECK_IO(fb(&(state->gallop_limit), sizeof(state->gallop_limit), 1, fp) == 1, "gallop_limit");
  CHECK_IO(fb(&(state->current_priority), sizeof(state->current_priority), 1, fp) == 1, "current_priority");
  CHECK_IO(fb(&(state->block_validation_complete), sizeof(state->block_validation_complete), 1, fp) == 1, "block_validation_complete");
  CHECK_IO(fb(&(state->contiguous_recovery_complete), sizeof(state->contiguous_recovery_complete), 1, fp) == 1, "contiguous_recovery_complete");
  CHECK_IO(fb(&(state->F1_initiated), sizeof(state->F1_initiated), 1, fp) == 1, "F1_initiated");
  CHECK_IO(fb(&(state->F2_initiated), sizeof(state->F2_initiated), 1, fp) == 1, "F2_initiated");
  CHECK_IO(fb(&(state->modico_requested), sizeof(state->modico_requested), 1, fp) == 1, "modico_requested");
  CHECK_IO(checkpoint_modico_serialization(state, fp, mode), "MoDiCo checkpoint metadata");

  for (i = 0; i < state->num_specs; i++) {
    CHECK_IO(fb(&(state->search_specs[i].MASTER), sizeof(state->search_specs[i].MASTER), 1, fp) == 1, "spec MASTER");
    CHECK_IO(fb(state->search_specs[i].FILETYPE, MAX_STRING_LENGTH, 1, fp) == 1, "spec FILETYPE");
    CHECK_IO(memchr(state->search_specs[i].FILETYPE, '\0', MAX_STRING_LENGTH), "spec FILETYPE terminator");
    CHECK_IO(fb(&(state->search_specs[i].mastertype), sizeof(state->search_specs[i].mastertype), 1, fp) == 1, "spec mastertype");

    if (state->search_specs[i].MASTER) {
      continue;
    }

    CHECK_IO(fb(&(state->search_specs[i].CASESENSITIVE), sizeof(state->search_specs[i].CASESENSITIVE), 1, fp) == 1, "spec CASESENSITIVE");
    CHECK_IO(fb(&(state->search_specs[i].MAXIMUMSIZE), sizeof(state->search_specs[i].MAXIMUMSIZE), 1, fp) == 1, "spec MAXIMUMSIZE");
    CHECK_IO(fb(&(state->search_specs[i].MINIMUMSIZE), sizeof(state->search_specs[i].MINIMUMSIZE), 1, fp) == 1, "spec MINIMUMSIZE");
    CHECK_IO(fb(state->search_specs[i].HEADER, MAX_STRING_LENGTH, 1, fp) == 1, "spec HEADER");
    CHECK_IO(fb(state->search_specs[i].begin, MAX_STRING_LENGTH, 1, fp) == 1, "spec begin");
    CHECK_IO(fb(&(state->search_specs[i].beginlength), sizeof(state->search_specs[i].beginlength), 1, fp) == 1, "spec beginlength");
    CHECK_IO(fb(&(state->search_specs[i].begin_is_RE), sizeof(state->search_specs[i].begin_is_RE), 1, fp) == 1, "spec begin_is_RE");
    CHECK_IO(fb(state->search_specs[i].FOOTER, MAX_STRING_LENGTH, 1, fp) == 1, "spec FOOTER");
    CHECK_IO(fb(state->search_specs[i].end, MAX_STRING_LENGTH, 1, fp) == 1, "spec end");
    CHECK_IO(fb(&(state->search_specs[i].endlength), sizeof(state->search_specs[i].endlength), 1, fp) == 1, "spec endlength");
    CHECK_IO(fb(&(state->search_specs[i].end_is_RE), sizeof(state->search_specs[i].end_is_RE), 1, fp) == 1, "spec end_is_RE");
    CHECK_IO(fb(&(state->search_specs[i].SEARCHTYPE), sizeof(state->search_specs[i].SEARCHTYPE), 1, fp) == 1, "spec SEARCHTYPE");
    CHECK_IO(fb(&(state->search_specs[i].PRIORITY), sizeof(state->search_specs[i].PRIORITY), 1, fp) == 1, "spec PRIORITY");
    CHECK_IO(fb(&(state->search_specs[i].NO_DEFRAG), sizeof(state->search_specs[i].NO_DEFRAG), 1, fp) == 1, "spec NO_DEFRAG");
    CHECK_IO(fb(&(state->search_specs[i].BLOCKVALIDATIONSCOPE),
                sizeof(state->search_specs[i].BLOCKVALIDATIONSCOPE), 1, fp)
                 == 1,
             "spec BLOCKVALIDATIONSCOPE");
    if (state->search_specs[i].BLOCKVALIDATIONSCOPE
            != BLOCK_VALIDATION_ALWAYS
        && state->search_specs[i].BLOCKVALIDATIONSCOPE
               != BLOCK_VALIDATION_REASSEMBLY_ONLY
        && state->search_specs[i].BLOCKVALIDATIONSCOPE
               != BLOCK_VALIDATION_DISABLED) {
      fprintf(stderr,
              "Checkpoint contains an invalid block validation disposition "
              "for file type \"%s\". Aborting.\n",
              state->search_specs[i].FILETYPE);
      exit(1);
    }

    // carve_state blob (size-prefixed by carve.c; passthrough via SpecBlob)
    {
      uint64_t blob_size = 0;
      if (mode == SERIALIZE) {
        blob_size = blobs ? blobs[i].carve_size : 0;
        CHECK_IO(fwrite(&blob_size, sizeof(blob_size), 1, fp) == 1, "carve_state blob_size write");
        if (blob_size > 0) {
          CHECK_IO(fwrite(blobs[i].carve_blob, 1, blob_size, fp) == blob_size, "carve_state blob write");
        }
      }
      else {
        CHECK_IO(fread(&blob_size, sizeof(blob_size), 1, fp) == 1, "carve_state blob_size read");
        if (blobs) {
          blobs[i].carve_size = blob_size;
          blobs[i].carve_blob = blob_size > 0 ? malloc(blob_size) : NULL;
          if (blob_size > 0) {
            if (! blobs[i].carve_blob) { fprintf(stderr, "Memory allocation failed.\n"); exit(1); }
            CHECK_IO(fread(blobs[i].carve_blob, 1, blob_size, fp) == blob_size, "carve_state blob read");
          }
        }
        else {
          if (blob_size > 0 && fseek(fp, (long)blob_size, SEEK_CUR) != 0) {
            fprintf(stderr, "At line %d in source file %s:\n", __LINE__, __FILE__);
            fprintf(stderr, "Checkpoint integrity failure: carve_state blob skip. Aborting.\n");
            exit(1);
          }
        }
      }
      state->search_specs[i].carve_state = NULL;
    }

    // block_state blob (size-prefixed by carve.c; passthrough via SpecBlob)
    {
      uint64_t blob_size = 0;
      if (mode == SERIALIZE) {
        blob_size = blobs ? blobs[i].block_size : 0;
        CHECK_IO(fwrite(&blob_size, sizeof(blob_size), 1, fp) == 1, "block_state blob_size write");
        if (blob_size > 0) {
          CHECK_IO(fwrite(blobs[i].block_blob, 1, blob_size, fp) == blob_size, "block_state blob write");
        }
      }
      else {
        CHECK_IO(fread(&blob_size, sizeof(blob_size), 1, fp) == 1, "block_state blob_size read");
        if (blobs) {
          blobs[i].block_size = blob_size;
          blobs[i].block_blob = blob_size > 0 ? malloc(blob_size) : NULL;
          if (blob_size > 0) {
            if (! blobs[i].block_blob) { fprintf(stderr, "Memory allocation failed.\n"); exit(1); }
            CHECK_IO(fread(blobs[i].block_blob, 1, blob_size, fp) == blob_size, "block_state blob read");
          }
        }
        else {
          if (blob_size > 0 && fseek(fp, (long)blob_size, SEEK_CUR) != 0) {
            fprintf(stderr, "At line %d in source file %s:\n", __LINE__, __FILE__);
            fprintf(stderr, "Checkpoint integrity failure: block_state blob skip. Aborting.\n");
            exit(1);
          }
        }
      }
      state->search_specs[i].block_state = NULL;
    }

    CHECK_IO(fb(&(state->search_specs[i].per_pass_candidates), sizeof(state->search_specs[i].per_pass_candidates), 1, fp) == 1, "spec per_pass_candidates");
    CHECK_IO(fb(&(state->search_specs[i].candidates), sizeof(state->search_specs[i].candidates), 1, fp) == 1, "spec candidates");
    CHECK_IO(fb(&(state->search_specs[i].chopped), sizeof(state->search_specs[i].chopped), 1, fp) == 1, "spec chopped");

    if (mode == SERIALIZE) {
      validated_files = atomic_load_explicit(&(state->search_specs[i].validated_files), memory_order_acquire);
    }

    CHECK_IO(fb(&(validated_files), sizeof(validated_files), 1, fp) == 1, "spec validated_files");

    if (mode == DESERIALIZE) {
      atomic_init(&(state->search_specs[i].validated_files), validated_files);
    }

    if (mode == SERIALIZE) {
      backtracked = atomic_load_explicit(&(state->search_specs[i].backtracked), memory_order_acquire);
    }

    CHECK_IO(fb(&(backtracked), sizeof(backtracked), 1, fp) == 1, "spec backtracked");

    if (mode == DESERIALIZE) {
      atomic_init(&(state->search_specs[i].backtracked), backtracked);
    }

    CHECK_IO(fb(&(state->search_specs[i].offsets.numheaders), sizeof(state->search_specs[i].offsets.numheaders), 1, fp) == 1, "spec numheaders");
    CHECK_IO(fb(&(state->search_specs[i].offsets.numfooters), sizeof(state->search_specs[i].offsets.numfooters), 1, fp) == 1, "spec numfooters");

    if (mode == DESERIALIZE) {
      if (state->search_specs[i].offsets.numheaders > 0) {
        state->search_specs[i].offsets.headers = malloc(state->search_specs[i].offsets.numheaders * sizeof(uint64_t));
        check_memory_allocation(state->search_specs[i].offsets.headers, __LINE__, __FILE__, "headers");
        state->search_specs[i].offsets.headerlens = malloc(state->search_specs[i].offsets.numheaders * sizeof(size_t));
        check_memory_allocation(state->search_specs[i].offsets.headerlens, __LINE__, __FILE__, "headerlens");
        state->search_specs[i].offsets.deposited = malloc(state->search_specs[i].offsets.numheaders * sizeof(bool));
        check_memory_allocation(state->search_specs[i].offsets.deposited, __LINE__, __FILE__, "deposited");
      }
      else {
        state->search_specs[i].offsets.headers = NULL;
        state->search_specs[i].offsets.headerlens = NULL;
        state->search_specs[i].offsets.deposited = NULL;
      }

      if (state->search_specs[i].offsets.numfooters > 0) {
        state->search_specs[i].offsets.footers = malloc(state->search_specs[i].offsets.numfooters * sizeof(uint64_t));
        check_memory_allocation(state->search_specs[i].offsets.footers, __LINE__, __FILE__, "footers");
        state->search_specs[i].offsets.footerlens = malloc(state->search_specs[i].offsets.numfooters * sizeof(size_t));
        check_memory_allocation(state->search_specs[i].offsets.footerlens, __LINE__, __FILE__, "footerlens");
      }
      else {
        state->search_specs[i].offsets.footers = NULL;
        state->search_specs[i].offsets.footerlens = NULL;
      }
    }

    for (j = 0; j < state->search_specs[i].offsets.numheaders; j++) {
      CHECK_IO(fb(&(state->search_specs[i].offsets.headers[j]), sizeof(uint64_t), 1, fp) == 1, "spec header offset");
      CHECK_IO(fb(&(state->search_specs[i].offsets.headerlens[j]), sizeof(size_t), 1, fp) == 1, "spec header length");
      CHECK_IO(fb(&(state->search_specs[i].offsets.deposited[j]), sizeof(bool), 1, fp) == 1, "spec header deposited");
    }

    for (j = 0; j < state->search_specs[i].offsets.numfooters; j++) {
      CHECK_IO(fb(&(state->search_specs[i].offsets.footers[j]), sizeof(uint64_t), 1, fp) == 1, "spec footer offset");
      CHECK_IO(fb(&(state->search_specs[i].offsets.footerlens[j]), sizeof(size_t), 1, fp) == 1, "spec footer length");
    }
  }

  CHECK_IO(mode == SERIALIZE ? checkpoint_durable_close(fp) : fclose(fp) == 0,
           "scalpel_state close");
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// END IMPORTED TYPES AND FUNCTIONS
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

static void mergecps_logo(void) {

  char *logo[] = {
      "\n", "\n",
      " ............................................................\n",
      ".   __  __ ______ _____   _____ ______ _____ _____   _____   .\n",
      ".  |  \\/  |  ____|  __ \\ / ____|  ____/ ____|  __ \\ / ____|  .\n",
      ".  | \\  / | |__  | |__) | |  __| |__ | |    | |__) | (___    .\n",
      ".  | |\\/| |  __| |  _  /| | |_ |  __|| |    |  ___/ \\___ \\   .\n",
      ".  | |  | | |____| | \\ \\| |__| | |___| |____| |     ____) |  .\n",
      ".  |_|  |_|______|_|  \\_\\\\_____|______\\_____|_|    |_____/   .\n",
      " ............................................................\n",
      ""};

  size_t j;
  size_t len;
  int i = 0;

  if (get_terminal_width() < 64) {
    return;
  }

  while (logo[i][0]) {
    len = strlen(logo[i]);
    for (j = 0; j < len; j++) {
      if (isspace(logo[i][j]) || i < 3 || i > 8 || j < 2 || j > 60) {
        fprintf(stdout, "%s", BLACK);
      }
      else {
        fprintf(stdout, "%s%s", BOLD, LOGOP);
      }

      fputc(logo[i][j], stdout);
      fprintf(stdout, "%s", BLACK);
    }
    i++;
  }

  fputc('\n', stdout);
}


static void usage(void) {
  fprintf(stderr, "Usage: mergecps checkpoint_dir1 checkpoint_dir2 output_dir\n");
  exit(1);
}


static int compare_headers(const void *a, const void *b) {

  HeaderEntry *h1 = (HeaderEntry *)a;
  HeaderEntry *h2 = (HeaderEntry *)b;

  if (h1->offset < h2->offset) {
    return -1;
  }

  if (h1->offset > h2->offset) {
    return 1;
  }

  if (h1->len < h2->len) {
    return -1;
  }

  if (h1->len > h2->len) {
    return 1;
  }

  return 0;
}


static int compare_footers(const void *a, const void *b) {

  FooterEntry *f1 = (FooterEntry *)a;
  FooterEntry *f2 = (FooterEntry *)b;

  if (f1->offset < f2->offset) {
    return -1;
  }

  if (f1->offset > f2->offset) {
    return 1;
  }

  if (f1->len < f2->len) {
    return -1;
  }

  if (f1->len > f2->len) {
    return 1;
  }

  return 0;
}


static void merge_global_counters(ScalpelState *state1, ScalpelState *state2) {

  atomic_init(&merged_state.files_written, atomic_load_explicit(&state1->files_written, memory_order_acquire) + atomic_load_explicit(&state2->files_written, memory_order_acquire));
  atomic_init(&merged_state.validated_files, atomic_load_explicit(&state1->validated_files, memory_order_acquire) + atomic_load_explicit(&state2->validated_files, memory_order_acquire));

  merged_state.candidates = state1->candidates + state2->candidates;
  merged_state.chopped = state1->chopped + state2->chopped;
  merged_state.block_validation_complete = state1->block_validation_complete || state2->block_validation_complete;
  merged_state.contiguous_recovery_complete = false;
  merged_state.F1_initiated = state1->F1_initiated || state2->F1_initiated;
  merged_state.F2_initiated = false;

  merged_state.start_block = (state1->start_block < state2->start_block) ? state1->start_block : state2->start_block;
  merged_state.end_block = (state1->end_block > state2->end_block) ? state1->end_block : state2->end_block;

  if (state2->longest_footer > merged_state.longest_footer) {
    merged_state.longest_footer = state2->longest_footer;
  }

  if (state2->largest_maxfilesize > merged_state.largest_maxfilesize) {
    merged_state.largest_maxfilesize = state2->largest_maxfilesize;
  }
}


static void merge_search_spec(SearchSpec *sm, SearchSpec *s1, SearchSpec *s2) {

  // A master's identity is retained even though its unused runtime body is omitted.
  if (s1->MASTER) {
    sm->MASTER = true;
    sm->mastertype = s1->mastertype;
    memcpy(sm->FILETYPE, s1->FILETYPE, sizeof(sm->FILETYPE));
    return;
  }

  memcpy(sm, s1, sizeof(SearchSpec));

  // Sum per-spec counters
  sm->per_pass_candidates = s1->per_pass_candidates + s2->per_pass_candidates;
  sm->candidates = s1->candidates + s2->candidates;
  sm->chopped = s1->chopped + s2->chopped;
  atomic_init(&sm->validated_files, atomic_load_explicit(&s1->validated_files, memory_order_acquire) + atomic_load_explicit(&s2->validated_files, memory_order_acquire));
  atomic_init(&sm->backtracked, atomic_load_explicit(&s1->backtracked, memory_order_acquire) + atomic_load_explicit(&s2->backtracked, memory_order_acquire));

  // Merge headers
  uint64_t total_h = s1->offsets.numheaders + s2->offsets.numheaders;
  sm->offsets.numheaders = 0;
  sm->offsets.headers = NULL;
  sm->offsets.headerlens = NULL;
  sm->offsets.deposited = NULL;

  if (total_h > 0) {
    HeaderEntry *temp_h = calloc(total_h, sizeof(HeaderEntry));

    for (uint64_t j = 0; j < s1->offsets.numheaders; j++) {
      temp_h[j].offset = s1->offsets.headers[j];
      temp_h[j].len = s1->offsets.headerlens[j];
      temp_h[j].deposited = s1->offsets.deposited[j];
    }

    for (uint64_t j = 0; j < s2->offsets.numheaders; j++) {
      temp_h[s1->offsets.numheaders + j].offset = s2->offsets.headers[j];
      temp_h[s1->offsets.numheaders + j].len = s2->offsets.headerlens[j];
      temp_h[s1->offsets.numheaders + j].deposited = s2->offsets.deposited[j];
    }

    qsort(temp_h, total_h, sizeof(HeaderEntry), compare_headers);

    sm->offsets.numheaders = 1;
    for (uint64_t j = 1; j < total_h; j++) {
      if (temp_h[j].offset != temp_h[j - 1].offset || temp_h[j].len != temp_h[j - 1].len) {
        sm->offsets.numheaders++;
      }
    }

    sm->offsets.headers = malloc(sm->offsets.numheaders * sizeof(uint64_t));
    sm->offsets.headerlens = malloc(sm->offsets.numheaders * sizeof(size_t));
    sm->offsets.deposited = malloc(sm->offsets.numheaders * sizeof(bool));

    uint64_t cur = 0;
    for (uint64_t j = 0; j < total_h; j++) {
      if (j > 0 && temp_h[j].offset == temp_h[j - 1].offset && temp_h[j].len == temp_h[j - 1].len) {
        if (temp_h[j].deposited) {
          sm->offsets.deposited[cur - 1] = 1;
        }
        continue;
      }

      sm->offsets.headers[cur] = temp_h[j].offset;
      sm->offsets.headerlens[cur] = temp_h[j].len;
      sm->offsets.deposited[cur] = temp_h[j].deposited;
      cur++;
    }
    free(temp_h);
  }

  // Merge footers
  uint64_t total_f = s1->offsets.numfooters + s2->offsets.numfooters;
  sm->offsets.numfooters = 0;
  sm->offsets.footers = NULL;
  sm->offsets.footerlens = NULL;

  if (total_f > 0) {
    FooterEntry *temp_f = calloc(total_f, sizeof(FooterEntry));

    for (uint64_t j = 0; j < s1->offsets.numfooters; j++) {
      temp_f[j].offset = s1->offsets.footers[j];
      temp_f[j].len = s1->offsets.footerlens[j];
    }

    for (uint64_t j = 0; j < s2->offsets.numfooters; j++) {
      temp_f[s1->offsets.numfooters + j].offset = s2->offsets.footers[j];
      temp_f[s1->offsets.numfooters + j].len = s2->offsets.footerlens[j];
    }

    qsort(temp_f, total_f, sizeof(FooterEntry), compare_footers);

    sm->offsets.numfooters = 1;
    for (uint64_t j = 1; j < total_f; j++) {
      if (temp_f[j].offset != temp_f[j - 1].offset || temp_f[j].len != temp_f[j - 1].len) {
        sm->offsets.numfooters++;
      }
    }

    sm->offsets.footers = malloc(sm->offsets.numfooters * sizeof(uint64_t));
    sm->offsets.footerlens = malloc(sm->offsets.numfooters * sizeof(size_t));

    uint64_t cur = 0;
    for (uint64_t k = 0; k < total_f; k++) {
      if (k > 0 && temp_f[k].offset == temp_f[k - 1].offset && temp_f[k].len == temp_f[k - 1].len) {
        continue;
      }

      sm->offsets.footers[cur] = temp_f[k].offset;
      sm->offsets.footerlens[cur] = temp_f[k].len;
      cur++;
    }
    free(temp_f);
  }
}


static void merge_blocktypes(unsigned char **btm, unsigned char **bt1, unsigned char **bt2, uint64_t numblocks, uint32_t num_specs) {

  // column-major: merge each file type's column as the element-wise max of the two inputs.
  for (uint32_t j = 0; j < num_specs; j++) {
    for (uint64_t i = 0; i < numblocks; i++) {
      btm[j][i] = (bt1[j][i] > bt2[j][i]) ? bt1[j][i] : bt2[j][i];
    }
  }
}


static int compare_candidate_identity(const void *a, const void *b) {
  return memcmp(((const CandidateIdentity *)a)->identity,
                ((const CandidateIdentity *)b)->identity, sizeof(CandidateIdentity));
}


static int compare_candidate_state_source(const void *a, const void *b) {
  return memcmp(((const CandidateStateSource *)a)->key,
                ((const CandidateStateSource *)b)->key, CARVE_HASH_KEY_SIZE);
}


// Keep each candidate's origin, including when its chosen input has no saved state.
// A clone has its own identity and must not be deduplicated against its parent.
static void merge_promising_queues(Queue *qm, const char *path1, const char *path2,
                                   CandidateStateSource **sources, size_t *source_count) {

  Queue q1, q2;

  init_queue(&q1, sizeof(CarveInfo *), true, NULL, false);
  init_queue(&q2, sizeof(CarveInfo *), true, NULL, false);

  FILE *fq1 = fopen(path1, "rb");
  if (! fq1) {
    perror(path1);
    exit(1);
  }

  CHECK_IO(deserialize_queue(&q1, promising_queue_element_serialization, true, fq1), "first queue");
  fclose(fq1);

  FILE *fq2 = fopen(path2, "rb");
  if (! fq2) {
    perror(path2);
    exit(1);
  }

  CHECK_IO(deserialize_queue(&q2, promising_queue_element_serialization, true, fq2), "second queue");
  fclose(fq2);

  // Collect both UUIDs for O(log N) duplicate detection.
  size_t q1_count = 0;
  size_t q2_count = 0;

  rewind_queue(&q1);
  while (! end_of_queue(&q1)) {
    q1_count++;
    next_element(&q1);
  }

  rewind_queue(&q2);
  while (! end_of_queue(&q2)) {
    q2_count++;
    next_element(&q2);
  }
  CHECK_IO(q1_count <= SIZE_MAX - q2_count
               && q1_count + q2_count < SIZE_MAX / sizeof(**sources), "queue sizes");
  CandidateIdentity *identities = calloc(q1_count + 1, sizeof(*identities));
  check_memory_allocation(identities, __LINE__, __FILE__, "candidate identities");
  *sources = calloc(q1_count + q2_count + 1, sizeof(**sources));
  check_memory_allocation(*sources, __LINE__, __FILE__, "candidate state origins");
  *source_count = 0;

  rewind_queue(&q1);
  for (size_t i = 0; ! end_of_queue(&q1); i++) {
    CarveInfo **c = pointer_to_current(&q1);
    memcpy(identities[i].identity, (*c)->binuuid, sizeof(uuid_t));
    memcpy(identities[i].identity + sizeof(uuid_t), (*c)->clone_binuuid, sizeof(uuid_t));
    if ((*c)->carvehashkey[CARVE_HASH_KEY_SIZE - 1]) {
      memcpy((*sources)[*source_count].key, (*c)->carvehashkey, CARVE_HASH_KEY_SIZE);
      (*sources)[(*source_count)++].source = 0;
    }
    add_to_queue(qm, c, (*c)->qposition);
    next_element(&q1);
  }

  qsort(identities, q1_count, sizeof(*identities), compare_candidate_identity);

  rewind_queue(&q2);
  while (! end_of_queue(&q2)) {
    CarveInfo **c2 = pointer_to_current(&q2);
    CandidateIdentity identity;
    memcpy(identity.identity, (*c2)->binuuid, sizeof(uuid_t));
    memcpy(identity.identity + sizeof(uuid_t), (*c2)->clone_binuuid, sizeof(uuid_t));
    if (! bsearch(&identity, identities, q1_count, sizeof(*identities), compare_candidate_identity)) {
      if ((*c2)->carvehashkey[CARVE_HASH_KEY_SIZE - 1]) {
        memcpy((*sources)[*source_count].key, (*c2)->carvehashkey, CARVE_HASH_KEY_SIZE);
        (*sources)[(*source_count)++].source = 1;
      }
      add_to_queue(qm, c2, (*c2)->qposition);
    }
    next_element(&q2);
  }

  free(identities);
  qsort(*sources, *source_count, sizeof(**sources), compare_candidate_state_source);
  for (size_t i = 1; i < *source_count; i++) {
    CHECK_IO(compare_candidate_state_source(&(*sources)[i - 1], &(*sources)[i]) != 0,
             "duplicate candidate state identity");
  }
}


static int compare_state_records(const void *a, const void *b) {
  const StateRecord *left = a, *right = b;
  int cmp = memcmp(left->key, right->key, left->key_size);
  if (cmp) {
    return cmp;
  }
  return (left->source > right->source) - (left->source < right->source);
}


// Frame checks keep opaque, variable-sized validator values out of the merge tool.
static size_t read_state_records(const void *blob, size_t size, size_t key_size,
                                 unsigned int source, StateRecord **records) {
  *records = NULL;
  if (! size) {
    return 0;
  }
  oa_hash_disk_header header;
  CHECK_IO(size >= sizeof(header), "validator table header size");
  memcpy(&header, blob, sizeof(header));
  CHECK_IO(header.magic == OA_HASH_DISK_MAGIC && header.version == OA_HASH_DISK_VERSION
               && header.shards == OA_SHARDS && ! header.reserved && ! header.reserved2,
           "validator table header");
  size_t remaining = size - sizeof(header);
  CHECK_IO(header.total <= remaining / (sizeof(oa_hash_disk_entry) + key_size + 1)
               && header.total < SIZE_MAX / sizeof(**records), "validator table count");
  *records = calloc((size_t)header.total + 1, sizeof(**records));
  check_memory_allocation(*records, __LINE__, __FILE__, "validator records");
  const unsigned char *cursor = (const unsigned char *)blob + sizeof(header);
  for (size_t i = 0; i < header.total; i++) {
    oa_hash_disk_entry entry;
    CHECK_IO(remaining >= sizeof(entry), "validator entry header");
    memcpy(&entry, cursor, sizeof(entry));
    CHECK_IO(entry.key_size == key_size && entry.value_size > 0
                 && entry.key_size <= remaining - sizeof(entry)
                 && entry.value_size <= remaining - sizeof(entry) - entry.key_size,
             "validator entry lengths");
    size_t bytes = sizeof(entry) + key_size + (size_t)entry.value_size;
    (*records)[i] = (StateRecord){cursor + sizeof(entry), cursor, bytes, key_size, source};
    cursor += bytes;
    remaining -= bytes;
  }
  CHECK_IO(remaining == 0, "validator table trailing bytes");
  return (size_t)header.total;
}


// Candidate state follows the selected queue entry. Block state is the union,
// with the first checkpoint taking precedence for a duplicate physical block.
static void merge_state_blob(void **output, size_t *output_size,
                             const void *left, size_t left_size, const void *right, size_t right_size,
                             size_t key_size, const CandidateStateSource *sources, size_t source_count) {
  StateRecord *a = NULL, *b = NULL;
  size_t na = read_state_records(left, left_size, key_size, 0, &a);
  size_t nb = read_state_records(right, right_size, key_size, 1, &b);
  CHECK_IO(na <= SIZE_MAX - nb && na + nb < SIZE_MAX / sizeof(*a), "merged state count");
  StateRecord *records = realloc(a, (na + nb + 1) * sizeof(*a));
  check_memory_allocation(records, __LINE__, __FILE__, "merged state records");
  if (nb) {
    memcpy(records + na, b, nb * sizeof(*b));
  }
  free(b);
  qsort(records, na + nb, sizeof(*records), compare_state_records);
  CHECK_IO(left_size <= SIZE_MAX - right_size
               && left_size + right_size <= SIZE_MAX - sizeof(oa_hash_disk_header), "merged state size");
  unsigned char *data = malloc(left_size + right_size + sizeof(oa_hash_disk_header));
  check_memory_allocation(data, __LINE__, __FILE__, "merged state data");
  oa_hash_disk_header header = { .magic = OA_HASH_DISK_MAGIC,
                                 .version = OA_HASH_DISK_VERSION,
                                 .shards = OA_SHARDS };
  size_t written = sizeof(header);
  for (size_t i = 0; i < na + nb; i++) {
    StateRecord *record = &records[i];
    bool duplicate = i && memcmp(records[i - 1].key, record->key, key_size) == 0;
    CHECK_IO(! duplicate || records[i - 1].source != record->source, "duplicate validator state key");
    if (key_size == CARVE_HASH_KEY_SIZE) {
      CandidateStateSource query;
      memcpy(query.key, record->key, key_size);
      const CandidateStateSource *selected = source_count
          ? bsearch(&query, sources, source_count, sizeof(*sources), compare_candidate_state_source) : NULL;
      if (! selected || selected->source != record->source) {
        continue;
      }
    }
    else if (duplicate) {
      continue;
    }
    memcpy(data + written, record->record, record->size);
    written += record->size;
    header.total++;
  }
  memcpy(data, &header, sizeof(header));
  free(records);
  *output = data;
  *output_size = left_size || right_size ? written : 0;
}


// Size the opaque state array from its own file before reading either checkpoint.
static SpecBlob *read_checkpoint_state(ScalpelState *state, char *path) {
  uint32_t count;
  FILE *fp = fopen(path, "rb");
  CHECK_IO(fp, "checkpoint state open");
  CHECK_IO(fseek(fp, 32 + PATH_MAX + PATH_MAX + sizeof(uint32_t), SEEK_SET) == 0
               && fread(&count, sizeof(count), 1, fp) == 1, "checkpoint type count");
  fclose(fp);
  CHECK_IO(count > 0 && count < UINT32_MAX, "checkpoint type count bounds");
  SpecBlob *blobs = calloc(count, sizeof(*blobs));
  check_memory_allocation(blobs, __LINE__, __FILE__, "validator tables");
  scalpel_state_serialization(state, DESERIALIZE, path, blobs);
  return blobs;
}


static uint64_t get_numblocks_from_blockmap(const char *blockmap_path) {

  uint64_t numblocks;

  FILE *fbm = fopen(blockmap_path, "rb");
  if (! fbm) {
    perror(blockmap_path);
    exit(1);
  }

  if (fseek(fbm, 4, SEEK_SET) != 0) {
    perror("fseek");
    exit(1);
  }

  CHECK_IO(fread(&numblocks, sizeof(numblocks), 1, fbm) == 1, "numblocks from blockmap");

  fclose(fbm);
  return numblocks;
}


static bool parent_directory(const char *path, char *parent, size_t parent_size) {

  char *slash;
  size_t length;

  if (! path || ! path[0] || ! parent || parent_size == 0) {
    errno = EINVAL;
    return false;
  }

  length = strlen(path);
  while (length > 1 && path[length - 1] == '/') {
    length--;
  }
  if (length >= parent_size) {
    errno = ENAMETOOLONG;
    return false;
  }

  memcpy(parent, path, length);
  parent[length] = '\0';
  slash = strrchr(parent, '/');
  if (! slash) {
    if (parent_size < 2) {
      errno = ENAMETOOLONG;
      return false;
    }
    strcpy(parent, ".");
  }
  else if (slash == parent) {
    slash[1] = '\0';
  }
  else {
    *slash = '\0';
  }

  return true;
}


static void write_merged_checkpoint(const char *out_dir, uint64_t numblocks, unsigned char **btm, Queue *qm, uint64_t sequence_number, SpecBlob *blobs) {

  char path_out[8192];
  char temporary_path[8192];
  FILE *fqm;

  CHECK_IO(mkdir(out_dir, 0755) == 0, "merged checkpoint staging directory");

  CHECK_IO(checkpoint_slot_path(temporary_path, sizeof(temporary_path), out_dir,
                                CHECKPOINT_COMPONENT_STATE, 0, true)
               && checkpoint_slot_path(path_out, sizeof(path_out), out_dir,
                                       CHECKPOINT_COMPONENT_STATE, 0, false),
           "merged scalpel state path");
  scalpel_state_serialization(&merged_state, SERIALIZE, temporary_path, blobs);
  CHECK_IO(checkpoint_atomic_replace(temporary_path, path_out, out_dir),
           "merged scalpel state publication");

  int output_length = snprintf(path_out, sizeof(path_out), "%s/%s", out_dir,
                               BLOCKCLASSIFICATION_FILENAME);
  int temporary_length = output_length < 0 || (size_t)output_length >= sizeof(path_out)
                             ? -1
                             : snprintf(temporary_path, sizeof(temporary_path), "%s_",
                                        path_out);
  CHECK_IO(output_length >= 0 && (size_t)output_length < sizeof(path_out)
               && temporary_length >= 0
               && (size_t)temporary_length < sizeof(temporary_path),
           "merged blockclassification path");
  filemirror_serialize_blockclassification_data(
      numblocks, btm, SERIALIZE, temporary_path, &merged_state);
  CHECK_IO(checkpoint_atomic_replace(temporary_path, path_out, out_dir),
           "merged blockclassification publication");

  CHECK_IO(checkpoint_slot_path(temporary_path, sizeof(temporary_path), out_dir,
                                CHECKPOINT_COMPONENT_QUEUE, 0, true)
               && checkpoint_slot_path(path_out, sizeof(path_out), out_dir,
                                       CHECKPOINT_COMPONENT_QUEUE, 0, false),
           "merged promising queue path");
  fqm = fopen(temporary_path, "wb");
  if (! fqm) {
    perror(temporary_path);
    exit(1);
  }

  CHECK_IO(serialize_queue(qm, promising_queue_element_serialization, fqm),
           "merged promising queue serialization");
  CHECK_IO(checkpoint_durable_close(fqm), "merged promising queue close");
  CHECK_IO(checkpoint_atomic_replace(temporary_path, path_out, out_dir),
           "merged promising queue publication");

  CHECK_IO(checkpoint_write_slot_manifest(out_dir, 0, sequence_number,
                                          merged_state.sha256),
           "merged checkpoint manifest");
  CHECK_IO(checkpoint_publish_slot(out_dir, 0, sequence_number),
           "merged checkpoint marker");
}


int main(int argc, char **argv) {

  if (! isatty(1) || ! isatty(2)) {
    DISABLE_ALL_COLOR;
  }

  mergecps_logo();

  if (argc != 4) {
    usage();
  }

  CheckpointSelection checkpoint1, checkpoint2;
  if (! checkpoint_select_slot(argv[1], NULL, true, &checkpoint1, stdout)
      || ! checkpoint_select_slot(argv[2], NULL, true, &checkpoint2, stdout)) {
    fprintf(stderr, "Both inputs must contain a valid checkpoint slot. Aborting.\n");
    exit(1);
  }

  ScalpelState state1, state2;

  memset(&state1, 0, sizeof(state1));
  memset(&state2, 0, sizeof(state2));
  memset(&merged_state, 0, sizeof(merged_state));

  char path1[8192], path2[8192];

  snprintf(path1, sizeof(path1), "%s", checkpoint1.state_path);
  SpecBlob *blobs1 = read_checkpoint_state(&state1, path1);

  snprintf(path2, sizeof(path2), "%s", checkpoint2.state_path);
  SpecBlob *blobs2 = read_checkpoint_state(&state2, path2);

  if (state1.num_specs != state2.num_specs) {
    fprintf(stderr, "Checkpoints have different file types. Aborting.\n");
    exit(1);
  }

  if (state1.modico_enabled != state2.modico_enabled
      || state1.modico_num_specs != state2.modico_num_specs
      || (state1.modico_num_specs
          && memcmp(state1.modico_spec_to_class, state2.modico_spec_to_class,
                     (size_t)state1.modico_num_specs * sizeof(int)) != 0)) {
    fprintf(stderr, "Checkpoints have different MoDiCo ranking metadata. Aborting.\n");
    exit(1);
  }

  if (state1.blocksize != state2.blocksize) {
    fprintf(stderr, "Checkpoints have different blocksizes. Aborting.\n");
    exit(1);
  }

  if (memcmp(state1.sha256, state2.sha256, 32)) {
    fprintf(stderr, "Checkpoints were created by different scalpel3 executables. Aborting.\n");
    exit(1);
  }

  if (strncmp(state1.image_pathname, state2.image_pathname, PATH_MAX)) {
    fprintf(stderr, "Checkpoints are for different images (\"%s\" vs \"%s\"). Aborting.\n",
            state1.image_pathname, state2.image_pathname);
    exit(1);
  }

  if (strncmp(state1.blockmap_pathname, state2.blockmap_pathname, PATH_MAX)) {
    fprintf(stderr, "Checkpoints are for different blockmaps. Aborting.\n");
    exit(1);
  }

  merged_state = state1;
  merged_state.search_specs = calloc(merged_state.num_specs + 1, sizeof(SearchSpec));

  merge_global_counters(&state1, &state2);

  uint64_t numblocks = get_numblocks_from_blockmap(state1.blockmap_pathname);

  // blocktype is column-major (matches filemirror.c): one numblocks-byte column per file type.
  unsigned char **bt1 = calloc(state1.num_specs, sizeof(unsigned char *));
  unsigned char **bt2 = calloc(state1.num_specs, sizeof(unsigned char *));
  unsigned char **btm = calloc(state1.num_specs, sizeof(unsigned char *));

  for (uint32_t s = 0; s < state1.num_specs; s++) {
    bt1[s] = calloc(numblocks, 1);
    bt2[s] = calloc(numblocks, 1);
    btm[s] = calloc(numblocks, 1);
  }

  int path1_length = snprintf(path1, sizeof(path1), "%s/%s", argv[1],
                              BLOCKCLASSIFICATION_FILENAME);
  int path2_length = snprintf(path2, sizeof(path2), "%s/%s", argv[2],
                              BLOCKCLASSIFICATION_FILENAME);
  CHECK_IO(path1_length >= 0 && (size_t)path1_length < sizeof(path1)
               && path2_length >= 0 && (size_t)path2_length < sizeof(path2),
           "input blockclassification path");

  filemirror_serialize_blockclassification_data(
      numblocks, bt1, DESERIALIZE, path1, &state1);
  filemirror_serialize_blockclassification_data(
      numblocks, bt2, DESERIALIZE, path2, &state2);

  for (uint32_t i = 0; i < state1.num_specs; i++) {
    if (state1.search_specs[i].MASTER != state2.search_specs[i].MASTER
        || state1.search_specs[i].mastertype != state2.search_specs[i].mastertype
        || strcmp(state1.search_specs[i].FILETYPE,
                  state2.search_specs[i].FILETYPE) != 0) {
      fprintf(stderr,
              "Checkpoints have different file type mappings. Aborting.\n");
      exit(1);
    }
    if (! state1.search_specs[i].MASTER
        && state1.search_specs[i].BLOCKVALIDATIONSCOPE
               != state2.search_specs[i].BLOCKVALIDATIONSCOPE) {
      fprintf(stderr,
              "Checkpoints use different block validation dispositions for "
              "file type \"%s\". Aborting.\n",
              state1.search_specs[i].FILETYPE);
      exit(1);
    }
  }

  for (uint32_t i = 0; i < state1.num_specs; i++) {
    merge_search_spec(&merged_state.search_specs[i], &state1.search_specs[i], &state2.search_specs[i]);
  }

  merge_blocktypes(btm, bt1, bt2, numblocks, merged_state.num_specs);

  Queue qm;
  init_queue(&qm, sizeof(CarveInfo *), true, NULL, false);

  snprintf(path1, sizeof(path1), "%s", checkpoint1.queue_path);
  snprintf(path2, sizeof(path2), "%s", checkpoint2.queue_path);

  CandidateStateSource *sources = NULL;
  size_t source_count = 0;
  merge_promising_queues(&qm, path1, path2, &sources, &source_count);
  SpecBlob *merged_blobs = calloc(merged_state.num_specs, sizeof(*merged_blobs));
  check_memory_allocation(merged_blobs, __LINE__, __FILE__, "merged validator tables");
  for (uint32_t i = 0; i < merged_state.num_specs; i++) {
    merge_state_blob(&merged_blobs[i].carve_blob, &merged_blobs[i].carve_size,
                     blobs1[i].carve_blob, blobs1[i].carve_size,
                     blobs2[i].carve_blob, blobs2[i].carve_size,
                     CARVE_HASH_KEY_SIZE, sources, source_count);
    merge_state_blob(&merged_blobs[i].block_blob, &merged_blobs[i].block_size,
                     blobs1[i].block_blob, blobs1[i].block_size,
                     blobs2[i].block_blob, blobs2[i].block_size,
                     BLOCK_HASH_KEY_SIZE, NULL, 0);
  }
  free(sources);

  uint64_t sequence_number = checkpoint_get_sequence(&checkpoint1, &checkpoint2);
  char output_dir[PATH_MAX];
  size_t output_length = strlen(argv[3]);
  while (output_length > 1 && argv[3][output_length - 1] == '/') {
    output_length--;
  }
  if (output_length == 0 || output_length >= sizeof(output_dir)) {
    fprintf(stderr, "Output directory pathname is too long. Aborting.\n");
    exit(1);
  }
  memcpy(output_dir, argv[3], output_length);
  output_dir[output_length] = '\0';

  struct stat output_stat;
  if (lstat(output_dir, &output_stat) == 0 || errno != ENOENT) {
    fprintf(stderr, "Output directory %s already exists or cannot be inspected. Aborting.\n",
            output_dir);
    exit(1);
  }

  char staging_dir[PATH_MAX];
  char output_parent[PATH_MAX];
  int written = snprintf(staging_dir, sizeof(staging_dir), "%s.tmp.%ld", output_dir,
                         (long)getpid());
  if (written < 0 || (size_t)written >= sizeof(staging_dir)
      || ! parent_directory(output_dir, output_parent, sizeof(output_parent))) {
    fprintf(stderr, "Output directory pathname is too long. Aborting.\n");
    exit(1);
  }

  write_merged_checkpoint(staging_dir, numblocks, btm, &qm, sequence_number,
                          merged_blobs);
  checkpoint_test_crash_after("merge-output-ready");
  CHECK_IO(checkpoint_atomic_replace(staging_dir, output_dir, output_parent),
           "merged checkpoint directory publication");

  printf("Merge complete. Result in %s\n", output_dir);

  return 0;
}
