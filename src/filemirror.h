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
// blockvector_get_data_pointer() to reflect block number changes.
void init_blockvector(FileMirror *state, BlockVector **b,
                      uint64_t num_blocks, bool disable_reservations);
void init_essential_blockvector(BlockVector *b, EssentialBlockVector **e);
void init_empty_essential_blockvector(EssentialBlockVector **e, uint64_t num_blocks);
bool read_essential_blockvector(EssentialBlockVector **blockvector, FILE *fp);
bool write_essential_blockvector(EssentialBlockVector *blockvector, FILE *fp);
void init_contiguous_blockvector(FileMirror *state, BlockVector **b,
                                 int64_t start, int64_t stop, bool disable_reservations);
void blockvector_set_data_length(BlockVector *b, uint64_t length);
uint64_t blockvector_get_data_length(BlockVector *b);
uint64_t blockvector_get_num_blocks(BlockVector *b);
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
void write_blockvector(BlockVector *b,
                       char *pathname,
                       char *blockvector_pathname,
                       bool update_blockmap);
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
void filemirror_add_blocktype_slot(FileMirror *state);
bool filemirror_serialize_blocktype_data(FileMirror *state, StateSerialization mode,
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

