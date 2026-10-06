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

// FileMirror design and implementation Copyright (c) 2021-2026 by Golden G. Richard III. The
// filemirror handles most high-performance sequential and vector-based I/O as well as blockmap
// operations for scalpel3.
//

#if ! defined(FILEMIRROR_H)
#define FILEMIRROR_H

#define _USE_LARGEFILE 1
#define _USE_FILEOFFSET64 1
#define _USE_LARGEFILE64 1
#define _LARGEFILE_SOURCE 1
#define _LARGEFILE64_SOURCE 1
#define _FILE_OFFSET_BITS 64

#define FILEMIRROR_STAGING_PATTERN "*.scalpel3-part-*"

#include "prioque.h"
#include "roaring.h"            // GGRIII:  Address pre-std23 atomic vs. stdatomic incompat
#include "scalpel.h"
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/timeb.h>
#include <time.h>
#include <unistd.h>

typedef enum FilePublicationReservation {
  FILE_PUBLICATION_RESERVED = 0,
  FILE_PUBLICATION_COMMITTED = 1,
  FILE_PUBLICATION_IN_PROGRESS = 2,
  FILE_PUBLICATION_ERROR = 3,
} FilePublicationReservation;

// main filemirror type
typedef struct FileMirror FileMirror;

// main blockvector type
typedef struct BlockVector BlockVector;

// since BlockVector is an opaque type, this data structure allows exposing apparent and actual
// block numbers for a blockvector for debugging and human-in-the-loop decision-making, while hiding
// details that depend on filemirror and scalpel3 state. An instance of EssentialBlockVector can be
// allocated and initialized by calling init_essential_blockvector(). To create an initially empty
// EssentialBlockVector instance with a fixed number of blocks, init_empty_essential_blockvector()
// can be used. free_essential_blockvector() should be called to free an instance of
// EssentialBlockVector. Functions are also provided to serialize EssentialBlockVector instances.
typedef struct EssentialBlockVector {
  uint64_t numblocks;             // # of blocks in block vector
  int64_t *apparent_blocknumber;  // vector of block numbers adjusted
                                  // to ignore covered blocks
  int64_t *actual_blocknumber;    // vector of actual block numbers in
                                  // file being mirrored
} EssentialBlockVector;


// from scalpel.h
typedef enum BlockValidationDecision BlockValidationDecision;

// function prototypes for public FileMirror functions

// blockvector functions
//
// IMPORTANT: data associated with blockvectors is synchronized only by inflate_blockvector() or
// inflate_blockvector_single_block(). Changing apparent or actual block numbers does not update the
// current byte view. Call one of the inflate functions before expecting
// blockvector_get_data_pointer() to reflect block number changes. Full inflation and deflation do
// not change logical length; the single-block pair temporarily extends it for a trial block.
// A generic blockvector starts with zero logical byte extent. Its caller must
// set the intended length explicitly as slots become part of the candidate.
void init_blockvector(FileMirror *state, BlockVector **b,
                      uint64_t num_blocks, bool disable_reservations);
void init_essential_blockvector(BlockVector *b, EssentialBlockVector **e);
void init_empty_essential_blockvector(EssentialBlockVector **e, uint64_t num_blocks);
bool read_essential_blockvector(EssentialBlockVector **blockvector, FILE *fp);
bool write_essential_blockvector(EssentialBlockVector *blockvector, FILE *fp);
// A contiguous blockvector starts with the full byte extent of its slots.
void init_contiguous_blockvector(FileMirror *state, BlockVector **b,
                                 int64_t start, int64_t stop, bool disable_reservations);
// The data length is the logical byte extent represented by a blockvector. It
// is independent of whether the corresponding bytes are currently resident.
void blockvector_set_data_length(BlockVector *b, uint64_t length);
void blockvector_set_data_length_to_mapped_extent(BlockVector *b);
uint64_t blockvector_get_data_length(BlockVector *b);
uint64_t blockvector_get_non_peekahead_data_length(BlockVector *b);
uint64_t blockvector_get_num_blocks(BlockVector *b);
// Setting a negative apparent block number explicitly unmaps and invalidates
// the slot; the next inflation represents it as a zero-filled block.
void blockvector_set_apparent_blocknumber(BlockVector *b, uint64_t index, int64_t blocknumber);
int64_t blockvector_get_apparent_blocknumber(BlockVector *b, uint64_t index);
int64_t blockvector_get_actual_blocknumber(BlockVector *b, uint64_t index);
char *blockvector_get_data_pointer(BlockVector *b);
uint64_t blockvector_data_pointer_offset_to_actual_location(BlockVector *b, uint64_t offset);
void normalize_blockvector(BlockVector *b);
void free_blockvector(BlockVector **b);
void free_essential_blockvector(EssentialBlockVector **e);
void inflate_blockvector(BlockVector *b);
uint64_t inflate_blockvector_single_block(BlockVector *b, uint64_t apparentindex);
void deflate_blockvector_single_block(BlockVector *b,
                                      uint64_t apparentindex, uint64_t oldlength);
void deflate_blockvector(BlockVector *b);
void clone_blockvector(BlockVector *s, BlockVector **d, bool clone_choices);
FilePublicationReservation filemirror_reserve_output(const char *pathname,
                                                      CarveInfoFlavor flavor,
                                                      char staging_pathname[PATH_MAX]);
void write_blockvector(BlockVector *b,
                       char *pathname,
                       char *staging_pathname,
                       char *blockvector_pathname,
                       CarveInfoFlavor flavor,
                       bool update_blockmap);
void filemirror_wait_for_vector_operations(FileMirror *state);
void resize_blockvector(BlockVector *b, uint64_t num_blocks);
void display_blockvector(BlockVector *b, char *msg);
void validate_blockvector(BlockVector *b, bool truncate);
bool apparent_block_in_blockvector(BlockVector *b,
                                   int64_t apparentblocknumber);

// blockvector block choice functions
int64_t blockvector_get_choice(BlockVector *b,
                               uint64_t index,
                               int64_t apparentblocknumber,
                               int64_t count,
                               uint64_t *blocks_evaluated);
bool blockvector_choice_is_excluded(BlockVector *b,
                                    uint64_t index,
                                    int64_t apparentblocknumber);
roaring64_bitmap_t *blockvector_clone_choice_exclusions(BlockVector *b,
                                                        uint64_t index);
void blockvector_restore_choice_exclusions(
    BlockVector *b,
    uint64_t index,
    const roaring64_bitmap_t *excluded_actual_blocks);
void blockvector_add_choice(BlockVector *b,
                            uint64_t index,
                            int64_t apparentblocknumber);
void blockvector_remove_choice(BlockVector *b,
                               uint64_t index,
                               int64_t apparentblocknumber);
void blockvector_free_choices(BlockVector *b,
                              uint64_t index);
void blockvector_free_all_choices(BlockVector *b);
void seq_read_blockvector(FileMirror *state, BlockVector **b, FILE *fp);
void seq_write_blockvector(BlockVector *b, FILE *fp);

// primary filemirror functions
FileMirror *filemirror_start(char *image_pathname,
			     char *blockmap_pathname,
                             uint32_t blocksize,
                             uint64_t readahead_bytes,
                             uint32_t num_readahead_bufs,
                             uint32_t num_threads,
                             uint64_t peekahead_bytes,
                             bool restoring_from_checkpoint,
                             bool reduce_aggressive_allocation,
                             uint64_t start_block,
                             uint64_t end_block);

void filemirror_stop(FileMirror *state);
void filemirror_rewind(FileMirror *state);
BlockVector *filemirror_read(FileMirror *state);
uint64_t filemirror_ftello(FileMirror *state);
uint64_t filemirror_filesize(FileMirror *state);
bool filemirror_actual_location_covered(FileMirror *state, uint64_t location);
bool filemirror_actual_block_covered(FileMirror *state, int64_t actualblocknumber);
bool filemirror_actual_block_is_zero(FileMirror *state, int64_t actualblocknumber);
char *filemirror_actual_block_data_pointer(FileMirror *state,
                                           int64_t actualblocknumber,
                                           uint64_t *length);
int64_t filemirror_actual_block_reserved(FileMirror *state, int64_t actualblocknumber);
uint64_t filemirror_actual_block_reference_count(FileMirror *state,
                                                 int64_t actualblocknumber);
uint64_t filemirror_apparent_filesize(FileMirror *state);
uint64_t filemirror_apparent_blocks(FileMirror *state);
uint64_t filemirror_actual_location(FileMirror *state,
                                    uint64_t apparent_location);
uint64_t filemirror_apparent_location(FileMirror *state,
                                      uint64_t actual_location);
int64_t filemirror_actual_blocknumber(FileMirror *state,
                                      int64_t apparentblocknumber);
int64_t filemirror_apparent_blocknumber(FileMirror *state,
                                        int64_t actualblocknumber);
void filemirror_update_blockmap(FileMirror *state, BlockVector *b);
void filemirror_write_blockmap(FileMirror *state, char *filename);
void filemirror_publish_blockmap(FileMirror *state);
bool filemirror_write_blockmap_h(FileMirror *state, int handle);
void filemirror_swap_blockmaps(FileMirror *state);
uint32_t filemirror_load(FileMirror *state);
int64_t filemirror_get_exemplar(FileMirror *state, int64_t actualblocknumber);
BlockValidationDecision filemirror_get_blocktype(FileMirror *state,
                                                 int64_t actualblocknumber,
                                                 uint32_t filetype);
void filemirror_set_blocktype(FileMirror *state,
                              int64_t actualblocknumber,
                              uint32_t filetype,
                              BlockValidationDecision blocktype);
// records several file types' decisions for one block under a single lock acquisition and a single
// exemplar lookup, instead of one lock round-trip per (block, file type). Equivalent in effect to
// calling filemirror_set_blocktype() once per assignment. Intended for callers that grade many file
// types per block, such as MoDiCo. Same locking rationale and block_validation_complete restriction
// as filemirror_set_blocktype(). BlocktypeAssignment is defined in scalpel.h, which is where the
// complete BlockValidationDecision enum lives (it is not yet visible this early in the header chain).
struct BlocktypeAssignment;
void filemirror_set_blocktype_batch(FileMirror *state,
                                    int64_t actualblocknumber,
                                    const struct BlocktypeAssignment *assignments,
                                    uint32_t count);
bool filemirror_copy_blocktype_column(FileMirror *state,
                                      uint32_t filetype,
                                      unsigned char *column,
                                      uint64_t count);
bool filemirror_replace_blocktype_column(FileMirror *state,
                                         uint32_t filetype,
                                         const unsigned char *column,
                                         uint64_t count);
uint64_t filemirror_default_unclassified_blocktypes(
    FileMirror *state,
    const uint32_t *filetypes,
    uint32_t count,
    BlockValidationDecision default_blocktype);
void filemirror_add_blocktype_slot(FileMirror *state);
bool filemirror_serialize_blockclassification_data(FileMirror *state,
                                                   StateSerialization mode,
                                                   char *filename);
unsigned char *get_apparent_block_data(FileMirror *state, int64_t apparentblocknumber);
bool get_apparent_block_bytes(FileMirror *state, int64_t apparentblocknumber,
                              uint64_t offset, uint32_t count, unsigned char *out);

// GLOBALS

// the following timing variables are NOT checkpointed and refer to timings for the current run,
// regardless of whether scalpel3 was restarted from a checkpoint with -R
extern uint64_t seq_io_wait;              // number of nanoseconds in sequential I/O
extern atomic_ullong random_read_wait;    // number of nanoseconds in random reads
extern atomic_ullong random_write_wait;   // number of nanoseconds in random writes
extern atomic_ullong header_footer_wait;  // number of nanoseconds to find headers/footers


#endif  // FILEMIRROR_H

