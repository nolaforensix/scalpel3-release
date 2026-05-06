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
//------------------------------
// Additional Integration Terms
// -----------------------------
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

#include "scalpel.h"

// realloc() calls are done in this increment to reduce the total number of memory allocation
// operations
#define MALLOC_SLACK 64

// encapsulates instructions for vector write threads and tracks state of thread
typedef struct VectorWriteThreadWork {
  int id;                               // thread id
  FileMirror *state;                    // pointer to owning FileMirror state
  atomic_bool vector_thread_running;    // thread is alive?
  atomic_bool vector_thread_stop;       // if true, thread should exit
  atomic_bool vector_thread_ready;      // if true, thread is idle and waiting for work
  pthread_mutex_t work_is_available;    // mutexes and condition variables for work
  pthread_cond_t check_work_available;  // allocation
  BlockVector *b;                       // blockvector to write
  char pathname[PATH_MAX];              // pathname for blockvector data
  char blockvector_pathname[PATH_MAX];  // pathname for blockvector metadata
  bool update_blockmap;                 // update shadow blockmap using b?
} VectorWriteThreadWork;


// encapsulates instructions for vector write threads and tracks state of thread
typedef struct VectorWriteThreadWork VectorWriteThreadWork;

// internal state of file mirror
typedef struct FileMirror {
  char image_pathname[PATH_MAX];      // pathname of file being mirrored
  char blockmap_pathname[PATH_MAX];   // pathname of associated blockmap file
  FILE *imagefile;                    // file handle for file being mirrored
  int mmap_fd;                        // low-level file handle for mmap()-ing of image file
  char *mmap;                         // memory-mapped access to image file for vector reads
  uint64_t seqoffset;                 // current location for sequential readahead thread
  bool reduce_aggressive_allocation;  // if set, try to reduce memory usage
  uint64_t readahead_bytes;           // readahead thread creates blockvectors of this size +
  uint64_t peekahead_bytes;           // ...this many bytes of peek-ahead in the image file
  uint32_t num_readahead_bufs;        // readahead thread maintains this many blockvectors
  uint64_t blocksize;                 // blocksize for image file
  uint64_t filesize;                  // actual size of image file
  uint64_t apparent_filesize;         // size of image file with covered blocks removed
  uint64_t apparent_blocks;           // number of uncovered blocks
  Blockmap *blockmap;                 // in-core primary coverage blockmap
  Blockmap *shadow_blockmap;          // tracks changes to coverage blockmap before commitment
  pthread_mutex_t update_blockmap;    // semaphore that protects shadow blockmap updates
  int64_t *blockmap_mapping;          // maps apparent block numbers to actual block numbers
  int64_t *blockmap_reverse_mapping;  // maps actual block numbers to apparent block numbers
  uint32_t readahead;                 // # of bytes available past length for sequential readahead
  unsigned char **blocktype;          // for each block, allocate a single byte for *each*
                                      // file type, to store block identification info. This
                                      // structure is indexed by actual block number and an index
                                      // into scalpel_state.search_specs

  pthread_mutex_t blocktype_lock;     // semaphore that protects blocktype access

  // readadhead thread
  pthread_t read_thread;                 // thread that handles sequential readahead and
                                         // fills read queue
  atomic_bool read_thread_stop;          // alerts read thread to stop
  atomic_bool read_thread_running;       // true if read_thread is running
  pthread_mutex_t readahead_full;        // limits readahead thread's queue size
  pthread_cond_t wait_readahead_full;    // " "
  pthread_mutex_t readahead_empty;       // blocks read operations when no readahead is ready
  pthread_cond_t wait_readahead_empty;   // " "
  pthread_mutex_t sequential_read_lock;  // enforces sequential read semantics for filemirror_read()
  Queue blockvectors;                    // collection of blockvectors prepared by read_thread
  uint32_t num_threads;                  // # of threads in vector read and write pools

  // write threads
  pthread_t *vector_write_threads;                  // thread pool for blockvector writes
  VectorWriteThreadWork *vector_write_thread_work;  // work and control structures for write threads
  atomic_uint num_idle_vector_write_threads;        // # of write threads that are currently idle
  pthread_mutex_t choose_vector_write_thread;       // semaphore that protects write thread selection
  atomic_uint vector_operations_pending;            // tracks currently pending vector I/O operations
} FileMirror;

// This structure represents a vector of blocks read from the file being mirrored. For each block in
// the vector, both the actual block number and apparent block number (skipping covered blocks) are
// stored. Read operations will fill any blocks marked invalid ('valid' == false) with data from the
// file being mirrored and valid blocks will be left as-is. Write operations also operate only on
// valid blocks. Apparent block numbers are accessed by user code to identify blocks to read and
// write and actual block numbers are calculated when the blockvector is normalized.
//
// Data associated with blockvectors is synchronized only by inflate_blockvector() or
// inflate_blockvector_single_block(). Changing apparent or actual block numbers does not update
// data/seqdata. Until one of the inflate functions is called, data/seqdata may still represent the
// byte view from the previous inflation.

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

// function prototypes for private FileMirror functions
static BlockVector *sequential_read(FileMirror *state);
static void *vector_write_thread(void *arg);
static void read_vector(BlockVector *b);
static void inflate_blockvector_no_IO(BlockVector *b);
static void blockvector_reserve_blocks(BlockVector *b, uint64_t start, uint64_t stop);
static void blockvector_unreserve_blocks(BlockVector *b, uint64_t start, uint64_t stop);
static void blockvector_init_choices(BlockVector *b, uint64_t index, roaring64_bitmap_t *s);
static void blockvector_set_actual_blocknumber(BlockVector *b, uint64_t index, int64_t blocknumber);
static uint64_t blockvector_actual_block_length(BlockVector *b, uint64_t index);
static void mem_pretouch_read(void *p, size_t n);
static void mem_pretouch_write(void *p, size_t n);
static bool all_consecutive_actual_blocknumbers(BlockVector *b);


// GLOBALS

// cached page size, initialized once via pthread_once
static size_t cached_pagesize;
static pthread_once_t pagesize_once = PTHREAD_ONCE_INIT;
static void init_pagesize(void) { cached_pagesize = (size_t)sysconf(_SC_PAGESIZE); }

// profiling globals
uint64_t seq_io_wait;
atomic_ullong random_read_wait;
atomic_ullong random_write_wait;

// ******************************************************************************
// ******************************************************************************
// *                           BLOCKVECTOR FUNCTIONS                            *
// ******************************************************************************
// ******************************************************************************


// ******************************************************************************
// * BLOCKVECTOR FUNCTIONS ARE THREAD-SAFE AS LONG AS OVERLAPPING CALLS ARE NOT *
// * MADE THAT CORRESPOND TO THE SAME BLOCKVECTOR. AN INDIVIDUAL BLOCKVECTOR    *
// * SHOULD BE MANIPULATED BY A SINGLE THREAD AT A TIME.                        *
// ******************************************************************************

// set apparent length of data associated with blockvector
void blockvector_set_data_length(BlockVector *b, uint64_t length) {

  b->length = length <= b->numblocks * b->filemirror->blocksize ? length : b->numblocks * b->filemirror->blocksize;
}


// get apparent length of data associated with blockvector
uint64_t blockvector_get_data_length(BlockVector *b) {
  return b->length;
}


uint64_t blockvector_data_pointer_offset_to_actual_location(BlockVector *b, uint64_t offset) {

  uint64_t block_index = offset / b->filemirror->blocksize;
  uint64_t offset_in_block = offset % b->filemirror->blocksize;
  int64_t actual_block = b->actual_blocknumber[block_index];

  return actual_block * b->filemirror->blocksize + offset_in_block;
}


static uint64_t blockvector_actual_block_length(BlockVector *b, uint64_t index) {

  uint64_t block_start;
  uint64_t blocksize = b->filemirror->blocksize;

  if (b->actual_blocknumber[index] < 0) {
    return 0;
  }

  block_start = (uint64_t)b->actual_blocknumber[index] * blocksize;
  if (block_start >= b->filemirror->filesize) {
    return 0;
  }

  return block_start + blocksize > b->filemirror->filesize
             ? b->filemirror->filesize - block_start
             : blocksize;
}


// return number of blocks currently in blockvector
uint64_t blockvector_get_num_blocks(BlockVector *b) {
  return b->numblocks;
}


// set apparent blocknumber at specified index
void blockvector_set_apparent_blocknumber(BlockVector *b, uint64_t index, int64_t blocknumber) {

  b->apparent_blocknumber[index] = blocknumber;
}


// retrieve apparent blocknumber at specified index
int64_t blockvector_get_apparent_blocknumber(BlockVector *b, uint64_t index) {
  return b->apparent_blocknumber[index];
}


// set actual blocknumber at specified index and handle associated block reservations
static void blockvector_set_actual_blocknumber(BlockVector *b, uint64_t index, int64_t blocknumber) {

  if (b->actual_blocknumber[index] != blocknumber) {
    // remove reservation on old blocknumber
    blockvector_unreserve_blocks(b, index, index);
    b->actual_blocknumber[index] = blocknumber;
    // place reservation on new blocknumber
    blockvector_reserve_blocks(b, index, index);
  }
}


// retrieve actual blocknumber at specified index. Actual blocknumbers are only accurate after a
// blockvector is normalized.
int64_t blockvector_get_actual_blocknumber(BlockVector *b, uint64_t index) {
  return b->actual_blocknumber[index];
}


// return pointer to the current inflated byte view for a blockvector. This is primarily an accessor:
// it does not generally synchronize block number changes with byte storage. If both the mmap
// fast-path (seqdata) and the allocated buffer (data) are NULL, re-inflate the blockvector to
// populate the data. This can happen when deflate_blockvector_single_block() clears seqdata but data
// was never allocated (blocks were always read via the mmap fast path). The validated data length is
// preserved across the re-inflate.
char *blockvector_get_data_pointer(BlockVector *b) {

  if (b->seqdata) {
    return b->seqdata;
  }

  if (!b->data && b->numblocks > 0) {
    uint64_t saved_length = b->length;
    inflate_blockvector(b);
    b->length = saved_length;
    if (b->seqdata) {
      return b->seqdata;
    }
  }

  return b->data;
}


// output blockvector contents for debugging
void display_blockvector(BlockVector *b, char *msg) {

  MUTEX_ERROR_CHECK(pthread_mutex_lock(&printf_is_available), __LINE__, __FILE__);
  if (msg) {
    fprintf(stdout, "display_blockvector(): %s\n", msg);
  }

  if (b) {
    fprintf(stdout, "Contents of blockvector %p:\n", b);
    fprintf(stdout, "Capacity:     %8" PRIu64 " blocks\n", b->numblocks);
    fprintf(stdout, "Length:       %8" PRIu64 " bytes\n", b->length);
    fprintf(stdout, "Index\tValid\tActual\tApparent\n");
    for (uint64_t i = 0; i < b->numblocks; i++) {
      fprintf(stdout, "%" PRIu64 "\t%d\t%" PRId64 "\t%" PRId64 "\n", i, b->valid[i], b->actual_blocknumber[i],
              b->apparent_blocknumber[i]);
    }
  }
  else {
    fprintf(stdout, "NULL blockvector in display_blockvector().\n");
  }

  MUTEX_ERROR_CHECK(pthread_mutex_unlock(&printf_is_available), __LINE__, __FILE__);
}


// refresh actual block numbers in a blockvector 'b' based on valid apparent block numbers.
// Reservations on actual blocknumbers that change are released.
void normalize_blockvector(BlockVector *b) {

  int64_t oldactual, newactual;

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Normalizing blockvector %p.\n", b);
  }

  if (! b) {
    // fatal
    handle_error(SCALPEL_ERROR_UNINITIALIZED_BLOCKVECTOR, "normalize_blockvector()", __LINE__, __FILE__);
  }

  for (uint64_t i = 0; i < b->numblocks; i++) {
    if (b->apparent_blocknumber[i] >= 0) {
      oldactual = b->actual_blocknumber[i];
      newactual = b->filemirror->blockmap_mapping[b->apparent_blocknumber[i]];
      if (oldactual != newactual) {
        b->valid[i] = false;
        blockvector_set_actual_blocknumber(b, i, newactual);
      }
    }
    else {
      b->valid[i] = false;
    }
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Normalization of blockvector %p complete.\n", b);
  }
}


// duplicate the blockvector 's' into the blockvector 'd'. 'd' should not be a currently allocated
// blockvector, as existing contents are destroyed by this function. This function also adds one
// block reservation for each block in 's'.
void clone_blockvector(BlockVector *s, BlockVector **d, bool clone_choices) {

  uint64_t i;
  uint64_t saved_length;

  if (! s) {
    // fatal
    handle_error(SCALPEL_ERROR_UNINITIALIZED_BLOCKVECTOR, "clone_blockvector()", __LINE__, __FILE__);
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Cloning blockvector %p to %p.\n", s, *d);
  }

  saved_length = s->length;
  inflate_blockvector(s);
  s->length = saved_length;

  init_blockvector(s->filemirror, d, s->numblocks, false);

  memcpy((*d)->apparent_blocknumber, s->apparent_blocknumber, sizeof(int64_t) * s->numblocks);
  memcpy((*d)->actual_blocknumber, s->actual_blocknumber, sizeof(int64_t) * s->numblocks);

  (*d)->seqdata = s->seqdata;
  (*d)->length = s->length;

  if (! (*d)->seqdata) {
    inflate_blockvector_no_IO((*d));
    memcpy((*d)->data, s->data, s->numblocks * s->filemirror->blocksize);
  }

  // inflate_blockvector_no_IO() may clear valid[] when it allocates a fresh
  // data buffer, so restore the source validity bitmap after allocation.
  memcpy((*d)->valid, s->valid, sizeof(bool) * s->numblocks);

  // perform a deep copy of the block 'choices' for 's' if choices are active and 'clone_choices' is
  // true
  if (s->choices && clone_choices) {
    for (i = 0; i < s->numblocks; i++) {
      if (s->choices[i]) {
        blockvector_init_choices(*d, i, s->choices[i]);
      }
    }
  }

  // this is necessary because the helper function blockvector_set_actual_blocknumber() is bypassed
  // for efficiency
  if ((*d)->numblocks > 0) {
    blockvector_reserve_blocks(*d, 0, (*d)->numblocks - 1);
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Cloning of blockvector %p to %p complete.\n", s, *d);
  }
}


// initialize a blockvector 'b' that will contain at most 'num_blocks' blocks. Storage for data is
// *not* allocated by this function, but is handled separately by inflate_blockvector().
void init_blockvector(FileMirror *state, BlockVector **b, uint64_t num_blocks, bool disable_reservations) {

  (*b) = malloc(sizeof(BlockVector));
  check_memory_allocation(*b, __LINE__, __FILE__, "b");

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Initializing new blockvector %p.\n", *b);
  }

  (*b)->filemirror = state;
  (*b)->numblocks = num_blocks;
  (*b)->ignore_reservations = ! scalpel_state.reservations || disable_reservations;
  (*b)->malloc_length = num_blocks + MALLOC_SLACK;
  (*b)->actual_blocknumber = malloc(sizeof(int64_t) * (*b)->malloc_length);
  check_memory_allocation((*b)->actual_blocknumber, __LINE__, __FILE__, "b");
  (*b)->apparent_blocknumber = malloc(sizeof(int64_t) * (*b)->malloc_length);
  check_memory_allocation((*b)->apparent_blocknumber, __LINE__, __FILE__, "b");
  (*b)->valid = malloc(sizeof(bool) * (*b)->malloc_length);
  check_memory_allocation((*b)->valid, __LINE__, __FILE__, "b");

  memset_int64_t((*b)->actual_blocknumber, -1, (*b)->numblocks);
  memset_int64_t((*b)->apparent_blocknumber, -1, (*b)->numblocks);
  memset((*b)->valid, false, (*b)->numblocks);

  (*b)->length = 0;
  (*b)->data = NULL;
  (*b)->seqdata = NULL;
  (*b)->choices = NULL;

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Initialization of blockvector %p complete.\n", *b);
  }
}


// GGRIII: THESE FUNCTIONS MUST NOT BE USED EXCEPT WHEN ALL THREADS ARE IDLE:


// allocate and initialize an essential blockvector 'e' that will contain exactly b->numblocks
// blocks and copy the apparent and actual blocknumber arrays into 'e'. If *e is non-NULL, then the
// size and contents of 'e' are adjusted to match 'b'.
void init_essential_blockvector(BlockVector *b, EssentialBlockVector **e) {

  if (! *e) {
    (*e) = malloc(sizeof(EssentialBlockVector));
    memset(*e, 0, sizeof(EssentialBlockVector));
    check_memory_allocation(*e, __LINE__, __FILE__, "e");
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Initializing and loading essential blockvector %p.\n", *e);
  }

  (*e)->numblocks = b->numblocks;

  (*e)->actual_blocknumber = realloc((*e)->actual_blocknumber, sizeof(int64_t) * (*e)->numblocks);
  check_memory_allocation((*e)->actual_blocknumber, __LINE__, __FILE__, "e");
  (*e)->apparent_blocknumber = realloc((*e)->apparent_blocknumber, sizeof(int64_t) * (*e)->numblocks);
  check_memory_allocation((*e)->apparent_blocknumber, __LINE__, __FILE__, "e");

  memcpy((*e)->actual_blocknumber, b->actual_blocknumber, sizeof(int64_t) * (*e)->numblocks);
  memcpy((*e)->apparent_blocknumber, b->apparent_blocknumber, sizeof(int64_t) * (*e)->numblocks);

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Initialization and loading of essential blockvector %p complete.\n", *e);
  }
}


// allocate and initialize an essential blockvector 'e' that will contain exactly b->numblocks
// blocks and copy the apparent and actual blocknumber arrays into 'e'. If *e is non-NULL, then the
// size and contents of 'e' are adjusted to match 'b'.
void init_empty_essential_blockvector(EssentialBlockVector **e, uint64_t num_blocks) {

  if (! *e) {
    (*e) = malloc(sizeof(EssentialBlockVector));
    memset(*e, 0, sizeof(EssentialBlockVector));
    check_memory_allocation(*e, __LINE__, __FILE__, "e");
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Initializing essential blockvector %p.\n", *e);
  }

  (*e)->numblocks = num_blocks;

  (*e)->actual_blocknumber = realloc((*e)->actual_blocknumber, sizeof(int64_t) * (*e)->numblocks);
  check_memory_allocation((*e)->actual_blocknumber, __LINE__, __FILE__, "e");
  (*e)->apparent_blocknumber = realloc((*e)->apparent_blocknumber, sizeof(int64_t) * (*e)->numblocks);
  check_memory_allocation((*e)->apparent_blocknumber, __LINE__, __FILE__, "e");

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Initialization of essential blockvector %p complete.\n", *e);
  }
}


// allocate and initialize an essential blockvector by reading data from 'fp'.
bool read_essential_blockvector(EssentialBlockVector **e, FILE *fp) {

  uint64_t num_blocks;

  // num_blocks:
  if (fread(&num_blocks, sizeof(uint64_t), 1, fp) != 1) {
    perror("couldn't deserialize numblocks");
    goto err;
  }

  init_empty_essential_blockvector(e, num_blocks);

  // actual_blocknumber:
  if (fread((*e)->actual_blocknumber, (*e)->numblocks * sizeof(int64_t), 1, fp) != 1) {
    perror("couldn't deserialize actual_blockvector");
    goto err;
  }

  // apparent_blocknumber:
  if (fread((*e)->apparent_blocknumber, (*e)->numblocks * sizeof(int64_t), 1, fp) != 1) {
    perror("couldn't deserialize apparent_blockvector");
    goto err;
  }

  return true;

err:

  free_essential_blockvector(e);
  return false;
}


// write essential blockvector data to 'fp'.
bool write_essential_blockvector(EssentialBlockVector *e, FILE *fp) {
  // num_blocks:
  if (fwrite(&e->numblocks, sizeof(uint64_t), 1, fp) != 1) {
    perror("couldn't serialize numblocks");
    goto err;
  }

  // actual_blocknumber:
  if (fwrite(e->actual_blocknumber, e->numblocks * sizeof(int64_t), 1, fp) != 1) {
    perror("couldn't serialize actual_blocknumber");
    goto err;
  }

  // apparent_blocknumber:
  if (fwrite(e->apparent_blocknumber, e->numblocks * sizeof(int64_t), 1, fp) != 1) {
    perror("couldn't serialize apparent_blocknumber");
    goto err;
  }

  return true;

err:

  return false;
}


// free all resources associated with 'e'
void free_essential_blockvector(EssentialBlockVector **e) {

  free((*e)->apparent_blocknumber);
  free((*e)->actual_blocknumber);
  free(*e);
  *e = NULL;
}


// validate a blockvector by removing blocks that have become covered as a result of a blockmap
// change. The blockvector is assumed to be deflated and must have been normalized before the
// blockmap change. The blockvector is truncated before the first covered block if 'truncated' is
// true. This is the behavior expected by the default left-to-right reassembly thread
// implementation. If 'truncated' is false, then the blockvector is not truncated, but the apparent
// *and* actual blocknumbers for covered blocks are set to -1 and the block reservation is released.
// If *no* mapped blocks remain after validation is complete, the blockvector is truncated to zero
// blocks regardless of the setting of 'truncated'.
//
// The important points:
//
// o Before a blockmap change, each blockvector that is intended to survive the change must be
// normalized.
//
// o After a blockmap change, it is REQUIRED that this function be called for every active
// blockvector, to adjust apparent block numbers and handle blocks becoming covered.
//
// o This function may potentially remove ALL of the blocks in the blockvector, so calling code must
// check for this condition and potentially destroy the blockvector.
void validate_blockvector(BlockVector *b, bool truncate) {

  uint64_t new_length = 0;
  uint64_t mapped = 0;
  bool stop = false;

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Validating blockvector %p.\n", b);
  }
  if (! b) {
    // fatal
    handle_error(SCALPEL_ERROR_UNINITIALIZED_BLOCKVECTOR, "validate_blockvector()", __LINE__, __FILE__);
  }

  // find new length for blockvector if truncating and unmap all covered blocks if not truncating
  while (new_length < b->numblocks && ! stop) {
    // Skip blocks whose actual mapping is already gone. A stale negative
    // apparent block number alone is not enough to discard a restored
    // checkpoint candidate: if the actual block number is still valid, the
    // current apparent mapping must be recomputed from the live blockmap first.
    if (b->actual_blocknumber[new_length] < 0) {
      if (! truncate) {
        new_length++;
      }
      else {
        // that's it if we're truncating, since truncation occurs at the first unmapped block from
        // L-R
        stop = true;
      }
      continue;
    }

    // update apparent blocknumber
    b->apparent_blocknumber[new_length] = filemirror_apparent_blocknumber(b->filemirror, b->actual_blocknumber[new_length]);

    // is it covered now? && new_length > 1 GGRIII: new_length > 1 would not invalidated covered
    // headers)
    if (b->apparent_blocknumber[new_length] < 0) {
      // unmap the block completely
      blockvector_set_actual_blocknumber(b, new_length, -1);

      // that's it if we're truncating, since truncation occurs at the first unmapped block from L-R
      if (truncate) {
        stop = true;
        continue;
      }
    }
    else {
      mapped++;
    }

    new_length++;
  }

  // then see if truncation is necessary
  if (! mapped) {
    // there are no valid blocknumbers in this blockvector at all. Truncate it to zero blocks.
    resize_blockvector(b, 0);           // this also truncates the choice sets
    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout, "validate_blockvector() on %p: no valid blocks left, truncating to zero blocks.\n", b);
    }
  }
  else if (truncate && new_length != b->numblocks) {
    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout, "validate_blockvector() on %p: truncating from %" PRIu64 " to %" PRIu64 " blocks.\n", b, b->numblocks,
                   new_length);
    }
    resize_blockvector(b, new_length);  // this also truncates the choice sets
  }
}


// resize the storage allocated to a blockvector to correspond to new 'num_blocks' value without
// destroying existing data. The blockvector must have been previously initialized. A design goal is
// to minimize the number of calls to realloc().
void resize_blockvector(BlockVector *b, uint64_t num_blocks) {

  uint64_t i;
  bool need_realloc = false;

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Resizing blockvector %p from %" PRIu64 " to %" PRIu64 " blocks, original length = %" PRIu64 ".\n", b,
                 b->numblocks, num_blocks, b->length);
  }

  if (scalpel_state.memory_profiling) {
    memory_footprint("before BV resize");
  }

  if (num_blocks == b->numblocks) {
    goto resize_complete;
  }

  // free choices associated with block indices that are disappearing and adjust size of choices
  // array as necessary.
  if (b->choices) {
    for (i = num_blocks; i < b->numblocks; i++) {
      blockvector_free_choices(b, i);
    }
  }

  // release any block reservations associated with blocks that are disappearing
  if (b->numblocks > 0) {
    blockvector_unreserve_blocks(b, num_blocks, b->numblocks - 1);
  }

  if (num_blocks == 0) {
    // in this case, free everything
    free(b->actual_blocknumber);
    b->actual_blocknumber = NULL;
    free(b->apparent_blocknumber);
    b->apparent_blocknumber = NULL;
    free(b->valid);
    b->valid = NULL;
    free(b->data);
    b->data = NULL;
    b->seqdata = NULL;
    blockvector_free_all_choices(b);
    b->malloc_length = 0;
  }
  else {
    if (num_blocks >= b->malloc_length || num_blocks + MALLOC_SLACK < b->numblocks) {
      b->malloc_length = num_blocks + MALLOC_SLACK;
      need_realloc = true;
    }

    if (need_realloc) {
      b->actual_blocknumber = realloc(b->actual_blocknumber, sizeof(int64_t) * b->malloc_length);
      check_memory_allocation(b->actual_blocknumber, __LINE__, __FILE__, "b");

      b->apparent_blocknumber = realloc(b->apparent_blocknumber, sizeof(int64_t) * b->malloc_length);
      check_memory_allocation(b->apparent_blocknumber, __LINE__, __FILE__, "b");

      b->valid = realloc(b->valid, sizeof(bool) * b->malloc_length);
      check_memory_allocation(b->valid, __LINE__, __FILE__, "b");

      if (b->choices) {
        b->choices = (roaring64_bitmap_t **)realloc(b->choices, sizeof(roaring64_bitmap_t *) * b->malloc_length);
        check_memory_allocation(b->choices, __LINE__, __FILE__, "b->choices");
      }
    }

    // any new blocks are invalid and so are associated choices
    for (i = b->numblocks; i < num_blocks; i++) {
      b->apparent_blocknumber[i] = -1;
      b->actual_blocknumber[i] = -1;
      b->valid[i] = false;
      if (b->choices) {
        b->choices[i] = NULL;
      }
    }
  }

  b->numblocks = num_blocks;

resize_complete:

  // constrain length to length of blockvector
  if (b->length > b->numblocks * b->filemirror->blocksize) {
    b->length = b->numblocks * b->filemirror->blocksize;
  }

  if (scalpel_state.memory_profiling) {
    memory_footprint("after BV resize");
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Resizing of blockvector %p completed, num_blocks = %" PRIu64 ", length = %" PRIu64 ".\n", b, b->numblocks,
                 b->length);
  }
}


// initialize a blockvector using *apparent* positions 'start' and 'stop' in the image file. All
// block numbers are inserted and blocks are marked invalid. No I/O is performed.
void init_contiguous_blockvector(FileMirror *state, BlockVector **b, int64_t start, int64_t stop, bool disable_reservations) {

  uint64_t i;

  (*b) = malloc(sizeof(BlockVector));
  check_memory_allocation(*b, __LINE__, __FILE__, "b");

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Initializing new contiguous blockvector %p.\n", *b);
  }

  (*b)->filemirror = state;
  (*b)->numblocks = CEILDIV((stop - start + 1), state->blocksize);
  (*b)->ignore_reservations = ! scalpel_state.reservations || disable_reservations;
  (*b)->malloc_length = (*b)->numblocks + MALLOC_SLACK;
  (*b)->actual_blocknumber = malloc(sizeof(int64_t) * (*b)->malloc_length);
  check_memory_allocation((*b)->actual_blocknumber, __LINE__, __FILE__, "b");
  (*b)->apparent_blocknumber = malloc(sizeof(int64_t) * (*b)->malloc_length);
  check_memory_allocation((*b)->apparent_blocknumber, __LINE__, __FILE__, "b");
  (*b)->valid = malloc(sizeof(bool) * (*b)->malloc_length);
  check_memory_allocation((*b)->valid, __LINE__, __FILE__, "b");
  for (i = 0; i < (*b)->numblocks; i++) {
    (*b)->apparent_blocknumber[i] = (start + i * state->blocksize) / state->blocksize;
    (*b)->actual_blocknumber[i] = (*b)->filemirror->blockmap_mapping[(*b)->apparent_blocknumber[i]];
    (*b)->valid[i] = false;
  }
  if ((*b)->numblocks > 0) {
    blockvector_reserve_blocks(*b, 0, (*b)->numblocks - 1);
  }
  (*b)->length = 0;
  (*b)->data = NULL;
  (*b)->seqdata = NULL;
  (*b)->choices = NULL;

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Initialization of contiguous blockvector %p complete.\n", *b);
  }
}


// release all resources associated with BlockVector 'b'
void free_blockvector(BlockVector **b) {

  if (! *b) {
    // fatal
    handle_error(SCALPEL_ERROR_UNINITIALIZED_BLOCKVECTOR, "free_blockvector()", __LINE__, __FILE__);
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Destroying blockvector %p.\n", *b);
  }

  if ((*b)->actual_blocknumber) {
    // release any block reservations
    if ((*b)->numblocks > 0) {
      blockvector_unreserve_blocks((*b), 0, (*b)->numblocks - 1);
    }
    free((*b)->actual_blocknumber);
    (*b)->actual_blocknumber = NULL;
  }

  if ((*b)->apparent_blocknumber) {
    free((*b)->apparent_blocknumber);
    (*b)->apparent_blocknumber = NULL;
  }

  if ((*b)->valid) {
    free((*b)->valid);
    (*b)->valid = NULL;
  }

  if ((*b)->data) {
    free((*b)->data);
    (*b)->data = NULL;
  }

  if ((*b)->choices) {
    blockvector_free_all_choices(*b);
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Destruction of blockvector %p complete.\n", *b);
  }

  free(*b);
  *b = NULL;
}


// used internally to allocate memory and determine whether fast mode reads are possible. The
// blockvector should already be normalized.
static void inflate_blockvector_no_IO(BlockVector *b) {

  uint64_t i;

  if (! b) {
    // fatal
    handle_error(SCALPEL_ERROR_UNINITIALIZED_BLOCKVECTOR, "inflate_blockvector_no_IO()", __LINE__, __FILE__);
  }

  bool was_consecutive = b->seqdata != NULL;

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Allocating storage for blockvector %p with capacity %1" PRIu64 " blocks.\n", (void *)b, b->numblocks);
  }

  if (all_consecutive_actual_blocknumbers(b)) {
    // fast read and no data allocation if all actual blocknumbers are consecutive
    free(b->data);
    b->data = NULL;

    // set seqdata to allow fast reads against mmap()-ed image file
    b->seqdata = b->filemirror->mmap + b->actual_blocknumber[0] * b->filemirror->blocksize;
    b->length = b->numblocks * b->filemirror->blocksize;

    // cap length to file size
    if (b->actual_blocknumber[b->numblocks - 1] == (int64_t)b->filemirror->blockmap->numblocks - 1
        && b->filemirror->filesize % b->filemirror->blocksize) {
      b->length -= b->filemirror->blocksize - b->filemirror->filesize % b->filemirror->blocksize;
    }

    // make all blocks valid
    for (i = 0; i < b->numblocks; i++) {
      b->valid[i] = true;
    }
  }
  else {
    bool data_was_null = (b->data == NULL);

    // actual blocks are disjoint, regular reads based on memcpy() will be used, so need b->data
    b->seqdata = NULL;
    b->data = realloc(b->data, b->malloc_length * b->filemirror->blocksize);
    check_memory_allocation(b->data, __LINE__, __FILE__, "b->data");
    mem_pretouch_write(b->data, b->malloc_length * b->filemirror->blocksize);

    // Entering slow mode with a fresh buffer means existing valid[] bits
    // are no longer trustworthy for b->data contents. If they remain set,
    // read_vector() can skip refilling those slots and leave garbage bytes
    // at the front of the logical file.
    if (was_consecutive || data_was_null) {
      for (i = 0; i < b->numblocks; i++) {
        b->valid[i] = false;
      }
    }
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Storage allocation complete for blockvector %p.\n", b);
  }
}


// allocate storage for blocks for a previously initialized blockvector, if that allocation was not
// already performed. The blockvector is also normalized and vector I/O performed to populate the
// blockvector.
void inflate_blockvector(BlockVector *b) {

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Inflating blockvector %p.\n", b);
  }

  // normalize
  normalize_blockvector(b);

  // allocate memory or initiate fast mode read
  inflate_blockvector_no_IO(b);

  if (! b->seqdata) {
    // read data
    read_vector(b);
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Inflation of blockvector %p complete.\n", b);
  }
}


// Optimized read for a *single* apparent block at index 'apparentindex'.
// inflate_blockvector() *must* have been previously called for 'b' and
// all blocks except 'apparentindex' must be valid.  Safe for any index
// position (the consecutive-sequence check verifies contiguity with both
// predecessor and successor blocks).
//
// Returns the *previous* length of the blockvector.  Each call MUST be
// paired with deflate_blockvector_single_block() to restore the previous
// length; unpaired calls cause b->length to drift because this function
// increases length but does not decrease it.
//
// This function places a reservation on the actual blocknumber at index
// apparentindex.
uint64_t inflate_blockvector_single_block(BlockVector *b, uint64_t apparentindex) {

  uint64_t i;
  uint64_t start;
  uint64_t length;
  uint64_t newlength;
  uint64_t ret = b->length;
  bool was_consecutive = b->seqdata != NULL;

  blockvector_set_actual_blocknumber(b, apparentindex, b->filemirror->blockmap_mapping[b->apparent_blocknumber[apparentindex]]);

  start = b->actual_blocknumber[apparentindex] * b->filemirror->blocksize;

  // constrain to actual image file size
  if (start + b->filemirror->blocksize > b->filemirror->filesize) {
    length = b->filemirror->filesize - start;
  }
  else {
    length = b->filemirror->blocksize;
  }

  newlength = (apparentindex * b->filemirror->blocksize) + length;
  if (newlength > b->length) {
    b->length = newlength;
  }

  // Fast check: if we were already consecutive, verify the new block is
  // contiguous with BOTH its predecessor and successor.  Current usage is
  // append-at-end (successor doesn't exist), but the forward check
  // prevents silent data corruption if a middle block is ever replaced.
  // If we were not consecutive, do a full scan (which typically fails
  // fast at the first gap).
  bool consecutive;
  if (was_consecutive) {
    bool back_ok = (apparentindex == 0
        || b->actual_blocknumber[apparentindex - 1] + 1
           == b->actual_blocknumber[apparentindex]);
    bool fwd_ok = (apparentindex >= b->numblocks - 1
        || b->actual_blocknumber[apparentindex] + 1
           == b->actual_blocknumber[apparentindex + 1]);
    consecutive = back_ok && fwd_ok;
  }
  else {
    consecutive = all_consecutive_actual_blocknumbers(b);
  }

  if (consecutive) {
    if (b->data) {
      // "slow mode" to "fast mode" transition
      free(b->data);
      b->data = NULL;
    }

    // all blocks are valid
    for (i = 0; i < b->numblocks; i++) {
      b->valid[i] = true;
    }
    b->seqdata = b->filemirror->mmap + b->actual_blocknumber[0] * b->filemirror->blocksize;
  }
  else {
    bool data_was_null = (b->data == NULL);
    b->data = realloc(b->data, b->malloc_length * b->filemirror->blocksize);
    check_memory_allocation(b->data, __LINE__, __FILE__, "b->data");
    mem_pretouch_write(b->data + apparentindex * b->filemirror->blocksize, b->filemirror->blocksize);

    if (!was_consecutive && !data_was_null) {
      // We are staying in slow mode and b->data already had prefix
      // block data populated.  Just read the new block.
      b->valid[apparentindex] = true;
      memcpy(b->data + apparentindex * b->filemirror->blocksize, b->filemirror->mmap + start, length);
    }
    else {
      // Either transitioning from fast mode to slow mode, or b->data
      // was NULL (freed by deflate_blockvector_single_block after
      // seqdata was cleared).  In both cases, the buffer is freshly
      // allocated and prefix blocks are not populated.  Need to read
      // the entire blockvector.
      b->seqdata = NULL;

      for (i = 0; i < b->numblocks; i++) {
        b->valid[i] = false;
      }

      // read_vector reads all blocks (including the new one) and sets b->length to the new correct
      // total.
      read_vector(b);
    }
  }

  return ret;
}


// this function rewinds the action taken by inflate_blockvector_single_block() by marking a single
// block invalid, destroying the corresponding block numbers, and restoring the previous length. The
// block's reservation is also revoked.
void deflate_blockvector_single_block(BlockVector *b, uint64_t apparentindex, uint64_t oldlength) {
  // reverse the other changes
  b->valid[apparentindex] = false;
  blockvector_set_actual_blocknumber(b, apparentindex, -1);
  b->length = oldlength;
  // if we were in fast (seqdata) mode, the sequence is no longer fully consecutive, so clear
  // seqdata to avoid leaving a stale pointer that misrepresents the blockvector state.
  // Also free b->data so the next blockvector_get_data_pointer() call triggers a full
  // re-inflate via read_vector(), which correctly populates all valid blocks and zeroes
  // invalid ones.  Without this, b->data may contain stale prefix data from before the
  // seqdata fast path was established — prefix blocks were never copied into b->data.
  if (b->seqdata) {
    b->seqdata = NULL;
    free(b->data);
    b->data = NULL;
  }
}


// deallocate data storage for blocks for a previously initialized block vector.
void deflate_blockvector(BlockVector *b) {

  if (! b) {
    // fatal
    handle_error(SCALPEL_ERROR_UNINITIALIZED_BLOCKVECTOR, "deflate_blockvector()", __LINE__, __FILE__);
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Deflating blockvector %p.\n", b);
  }

  memset(b->valid, false, b->numblocks);

  if (b->data) {
    free(b->data);
  }

  b->data = NULL;
  b->seqdata = NULL;
  b->length = 0;

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Deflation of blockvector %p complete.\n", b);
  }
}


// add a block reservation on each *apparent* block in blockvector 'b', between indices 'start' and
// 'stop' (inclusive).
static void blockvector_reserve_blocks(BlockVector *b, uint64_t start, uint64_t stop) {

  uint64_t i;

  if (! b->ignore_reservations) {
    for (i = start; i <= stop; i++) {
      if (b->actual_blocknumber[i] >= 0) {
        reserve_block(b->filemirror->blockmap, b->actual_blocknumber[i]);

        // GGRIII: This can be uncommented for reservations testing. If the reservation system is
        // used correctly, there should never be negative reservation numbers.
        /*
        lock_fprintf(stdout,
                     "RESERVATION for %"PRId64" (now %"PRId64") in %"PRIu64" block %p blockvector.\n",
                     b->actual_blocknumber[i], b->filemirror->blockmap->reservations[b->actual_blocknumber[i]], b->numblocks, b);
         */
      }
    }
  }
}


// remove a block reservation on each *apparent* block in blockvector 'b', between indices 'start'
// and 'stop' (inclusive).
static void blockvector_unreserve_blocks(BlockVector *b, uint64_t start, uint64_t stop) {

  uint64_t i;

  if (! b->ignore_reservations) {
    for (i = start; i <= stop; i++) {
      if (b->actual_blocknumber[i] >= 0) {
        unreserve_block(b->filemirror->blockmap, b->actual_blocknumber[i]);


        // GGRIII: This can be uncommented for reservations testing. If the reservation system is
        // used correctly, there should never be negative reservation numbers.
        /*

                int64_t r;


                if ((r = atomic_load_explicit(&(b->filemirror->blockmap->reservations[b->actual_blocknumber[i]]),
                                              memory_order_acquire) < 0)) {
                  printf("*** PROBLEM *** in blockmap_unreserve_blocks()--for %p, reservation for block %"PRId64" is now
           "PRId64".\n", b, b->actual_blocknumber[i], r); crash();
                }

                if (scalpel_state.mode_verbose) {
                  lock_fprintf(stdout, "UNRESERVATION for %" PRId64 " (now %" PRId64 ")
                                       in %" PRIu64 " block %p blockvector.\n", b->actual_blocknumber[i],
                               atomic_load_explicit(&b->filemirror->blockmap->reservations[b->actual_blocknumber[i]],
                                                    memory_order_acquire), b->numblocks, b);
                }
        */
      }
    }
  }
}


// allocate storage as necessary for the choices array and for a particular block index. If
// b->choices[index] is non-NULL, this function has no impact. If s is NULL, all blocks
// for this block index are initially available (empty exclusion set). If 's' is non-NULL,
// then the exclusion set s is copied into b->choices[index]. If b->choices[index] is
// non-NULL, s must be NULL.
//
// The exclusion set for a particular block index contains *actual* block numbers that have
// been eliminated as choices. Membership in the set means excluded.
void blockvector_init_choices(BlockVector *b, uint64_t index, roaring64_bitmap_t *s) {

  if (! b->choices) {
    // first use of choices (ever or since last free)
    b->choices = (roaring64_bitmap_t **)calloc(b->malloc_length, sizeof(roaring64_bitmap_t *));
    check_memory_allocation(b->choices, __LINE__, __FILE__, "b->choices");
  }

  if (! b->choices[index]) {
    if (s) {
      // copy existing exclusion set of actual block numbers
      b->choices[index] = roaring64_bitmap_copy(s);
    }
    else {
      // create new empty exclusion set (all blocks initially available)
      b->choices[index] = roaring64_bitmap_create();
      check_memory_allocation(b->choices[index], __LINE__, __FILE__, "b->choices");
    }
  }
}


// return the next choice for a previously unselected *apparent* block number >
// 'apparentblocknumber' (or a random choice if -1 is provided for 'apparentblocknumber'), modulo #
// of apparent blocks. A block is excluded if its actual block number is present in the exclusion
// set. -1 is returned if there are no remaining choices. The blocks_evaluated parameter indicates
// how many apparent blocks were considered to arrive at a choice. If count > 0, then at most count
// blocks are considered.
int64_t blockvector_get_choice(BlockVector *b, uint64_t index, int64_t apparentblocknumber, int64_t count,
                               uint64_t *blocks_evaluated) {

  int64_t blocknumber = -1;
  int64_t i;
  uint64_t j;
  int64_t toconsider = count > 0 ? count : (int64_t)b->filemirror->apparent_blocks;
  bool in_bitmap, selectable;

  *blocks_evaluated = 0;

  if (b->filemirror->apparent_blocks == 0) {
    return -1;
  }

  if (toconsider > (int64_t)b->filemirror->apparent_blocks) {
    toconsider = (int64_t)b->filemirror->apparent_blocks;
  }

  // if 'apparentblocknumber' is negative, choose a random starting point
  if (apparentblocknumber < 0) {
    apparentblocknumber = portable_random() % b->filemirror->apparent_blocks;
  }
  else {
    apparentblocknumber = apparentblocknumber % b->filemirror->apparent_blocks;
  }


  // search for at most one cycle through all apparent blocks, possibly limited by count
  for (j = apparentblocknumber; j < apparentblocknumber + b->filemirror->apparent_blocks && --toconsider >= 0 && blocknumber < 0; j++) {
    (*blocks_evaluated)++;
    // the choices bitmap represents *actual* block numbers so that info about previously chosen
    // blocks can can persist across blockmap modifications
    i = b->filemirror->blockmap_mapping[j % b->filemirror->apparent_blocks];

    // NULL choices means no exclusions have been recorded yet for this index
    in_bitmap = (b->choices && b->choices[index]) ? roaring64_bitmap_contains(b->choices[index], i) : false;
    selectable = is_block_selectable(b->filemirror->blockmap, i);

    // shadow peeking looks at the shadow blockmap to see if the block has been covered recently--if
    // so, this block is no longer a viable candidate, since it's going to be officially covered on
    // the next blockmap swap
    if (selectable && ! scalpel_state.disable_shadow_peeking && b->filemirror->shadow_blockmap &&
	is_block_covered(b->filemirror->shadow_blockmap, i)) {
      // not a good choice
      selectable = false;
    }

    if (! in_bitmap && selectable) {
      blocknumber = j % b->filemirror->apparent_blocks;
    }
  }

  return blocknumber;
}


// add 'apparentblocknumber' to the set of choices for a block index by removing the corresponding
// actual block number from the exclusion set for the 'index'th block in the blockvector 'b'.
void blockvector_add_choice(BlockVector *b, uint64_t index, int64_t apparentblocknumber) {

  // sanity check--the specified block number must valid and not be covered in the primary blockmap!
  if (apparentblocknumber < 0 || apparentblocknumber >= (int64_t)b->filemirror->apparent_blocks ||
      b->filemirror->blockmap_mapping[apparentblocknumber] < 0 ||
      is_block_covered(b->filemirror->blockmap, b->filemirror->blockmap_mapping[apparentblocknumber])) {
    // supplied block number is invalid or covered in the primary blockmap. This is a fatal error,
    // since something has gone horribly wrong.
    lock_fprintf(stderr, "%s", RED);
    lock_fprintf(stderr, "\nBLOCK NUMBER: %" PRId64 ".\n", apparentblocknumber);
    handle_error(SCALPEL_ERROR_BAD_BLOCKMAP_BLOCK_NUMBER, "blockvector_add_choice()", __LINE__, __FILE__);
  }

  // NULL choices means no exclusions exist for this index -- block is already available, no-op
  if (b->choices && b->choices[index]) {
    roaring64_bitmap_remove_checked(b->choices[index], b->filemirror->blockmap_mapping[apparentblocknumber]);
  }
}


// remove 'apparentblocknumber' from the set of choices for a block index by adding the
// corresponding actual block number to the exclusion set.
void blockvector_remove_choice(BlockVector *b, uint64_t index, int64_t apparentblocknumber) {

  // sanity check--the specified block number must be valid and not be covered in the primary
  // blockmap!
  if (apparentblocknumber < 0 || apparentblocknumber >= (int64_t)b->filemirror->apparent_blocks ||
      b->filemirror->blockmap_mapping[apparentblocknumber] < 0 ||
      is_block_covered(b->filemirror->blockmap, b->filemirror->blockmap_mapping[apparentblocknumber])) {
    // supplied block number is invalid or covered in the primary blockmap. This is a fatal error, since
    // something has gone horribly wrong.
    lock_fprintf(stderr, "%s", RED);
    lock_fprintf(stderr, "\nBLOCK NUMBER: %" PRId64 ".\n", apparentblocknumber);
    handle_error(SCALPEL_ERROR_BAD_BLOCKMAP_BLOCK_NUMBER, "blockvector_remove_choice()", __LINE__, __FILE__);
  }

  // if choices are not initialized, then initialize first
  blockvector_init_choices(b, index, NULL);

  // add actual block number to the exclusion set
  roaring64_bitmap_add_checked(b->choices[index], b->filemirror->blockmap_mapping[apparentblocknumber]);
}


// free 'choices' resources associated with a particular block index
void blockvector_free_choices(BlockVector *b, uint64_t index) {

  if (! b->choices) {
    return;
  }

  if (b->choices[index]) {
    roaring64_bitmap_free(b->choices[index]);
  }
  b->choices[index] = NULL;
}


// free all resources associated with 'choices' for a blockvector
void blockvector_free_all_choices(BlockVector *b) {

  if (b->choices) {
    for (uint64_t i = 0; i < b->numblocks; i++) {
      blockvector_free_choices(b, i);
    }
  }
  free(b->choices);
  b->choices = NULL;
}


// determine if an apparent block number is already in a blockvector
bool apparent_block_in_blockvector(BlockVector *b, int64_t apparentblocknumber) {
  // Exact apparent-block reuse is never valid within a single candidate, even for
  // exemplar/deduplicated blocks such as all-zero regions.
  if (apparentblocknumber < 0) {
    return false;
  }

  return contains_int64_t(b->apparent_blocknumber, b->numblocks, apparentblocknumber) >= 0;
}


// write data associated with blockvector 'b'. If 'pathname' is non-NULL, blockvector data is
// written to the file 'pathname'. If 'blockvector_pathname' is non-NULL, blockvector metadata is
// written to the file 'blockvector_pathname'. If 'update_blockmap' is true, then the shadow
// blockmap is updated. This function handles assignment of blockvector write operations to vector
// write threads so writes occur asynchronously.
//
// IMPORTANT: The blockvector is assumed to be inflated and normalized.n All resources associated
// with the blockvetor are freed by by this function.
//
// DO NOT ACCESS THE BLOCKVECTOR AFTER CALLING THIS FUNCTION.
//
void write_blockvector(BlockVector *b, char *pathname, char *blockvector_pathname, bool update_blockmap) {

  int free_vector_thread = -1;
  uint32_t i;

  if (! b) {
    // fatal
    handle_error(SCALPEL_ERROR_UNINITIALIZED_BLOCKVECTOR, "write_blockvector()", __LINE__, __FILE__);
  }

  // one more vector operation pending
  atomic_fetch_add_explicit(&b->filemirror->vector_operations_pending, 1, memory_order_acq_rel);

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Initiating vector write for %p.\n", (void *)b);
    lock_fprintf(stdout, "Number of vector operations pending = %d.\n",
                 atomic_load_explicit(&b->filemirror->vector_operations_pending, memory_order_acquire));
  }

  while (free_vector_thread < 0) {
    // wait for a free thread
    while (atomic_load_explicit(&b->filemirror->num_idle_vector_write_threads, memory_order_acquire) == 0) {
      sched_yield();
    }

    // some thread became free--try to grab it
    MUTEX_ERROR_CHECK(pthread_mutex_lock(&b->filemirror->choose_vector_write_thread), __LINE__, __FILE__);
    for (i = 0; i < b->filemirror->num_threads && free_vector_thread < 0; i++) {
      if (atomic_load_explicit(&b->filemirror->vector_write_thread_work[i].vector_thread_ready, memory_order_acquire)) {
        free_vector_thread = i;
      }
    }
    if (free_vector_thread < 0) {
      // we didn't manage to grab it
      MUTEX_ERROR_CHECK(pthread_mutex_unlock(&b->filemirror->choose_vector_write_thread), __LINE__, __FILE__);
    }
  }

  // one less free thread
  atomic_fetch_sub_explicit(&b->filemirror->num_idle_vector_write_threads, 1, memory_order_acq_rel);

  // mark thread busy, assign work, and signal the thread to start working
  MUTEX_ERROR_CHECK(pthread_mutex_lock(&b->filemirror->vector_write_thread_work[free_vector_thread].work_is_available), __LINE__,
                    __FILE__);
  atomic_store_explicit(&b->filemirror->vector_write_thread_work[free_vector_thread].vector_thread_ready, false,
                        memory_order_release);

  // work
  b->filemirror->vector_write_thread_work[free_vector_thread].b = b;

  if (pathname) {
    strncpy(b->filemirror->vector_write_thread_work[free_vector_thread].pathname, pathname, PATH_MAX - 1);
    b->filemirror->vector_write_thread_work[free_vector_thread].pathname[PATH_MAX - 1] = '\0';
  }
  else {
    (b->filemirror->vector_write_thread_work[free_vector_thread].pathname)[0] = 0;
  }

  if (blockvector_pathname) {
    strncpy(b->filemirror->vector_write_thread_work[free_vector_thread].blockvector_pathname, blockvector_pathname, PATH_MAX - 1);
    b->filemirror->vector_write_thread_work[free_vector_thread].blockvector_pathname[PATH_MAX - 1] = '\0';
  }
  else {
    (b->filemirror->vector_write_thread_work[free_vector_thread].blockvector_pathname)[0] = 0;
  }

  b->filemirror->vector_write_thread_work[free_vector_thread].update_blockmap = update_blockmap;

  // signal thread to proceed
  pthread_cond_signal(&b->filemirror->vector_write_thread_work[free_vector_thread].check_work_available);
  MUTEX_ERROR_CHECK(pthread_mutex_unlock(&b->filemirror->vector_write_thread_work[free_vector_thread].work_is_available), __LINE__,
                    __FILE__);

  // let vector threads be chosen again
  MUTEX_ERROR_CHECK(pthread_mutex_unlock(&b->filemirror->choose_vector_write_thread), __LINE__, __FILE__);
}


// ******************************************************************************
// ******************************************************************************
// *                             FILEMIRROR FUNCTIONS                           *
// ******************************************************************************
// ******************************************************************************


// Configuration for write optimizations
#define WRITE_BUFFER_SIZE (4 * 1024 * 1024)  // 4MB buffer

// optimized synchronous write that works on Linux and Mac
static int write_file_optimized(const char *pathname, void *data, size_t length) {

  FILE *fp;
  int fd;
  int ret = 0;
  static __thread char *write_buffer = NULL;  // Thread-local buffer

  // Allocate thread-local buffer once
  if (! write_buffer) {
    write_buffer = aligned_alloc(4096, WRITE_BUFFER_SIZE);
    if (! write_buffer) {
      write_buffer = malloc(WRITE_BUFFER_SIZE);
    }
  }

  // Open with optimal flags for bulk writes
  int flags = O_WRONLY | O_CREAT | O_TRUNC;

#ifdef __linux__
  // Linux-specific optimizations
  flags |= O_NOATIME;  // Don't update access time
#endif

  fd = open(pathname, flags, 0644);
  if (fd < 0) {
    return -1;
  }

#ifdef __APPLE__
  // macOS optimizations
  fcntl(fd, F_NOCACHE, 1);  // Don't pollute cache with one-time writes
  fcntl(fd, F_RDAHEAD, 0);  // Disable read-ahead

  // preallocate space (reduces fragmentation)
  if (length > 0) {
    fstore_t fstore = {F_ALLOCATECONTIG, F_PEOFPOSMODE, 0, (off_t)length, 0};

    if (fcntl(fd, F_PREALLOCATE, &fstore) == -1) {
      // try non-contiguous if contiguous fails
      fstore.fst_flags = F_ALLOCATEALL;
      fcntl(fd, F_PREALLOCATE, &fstore);
    }
  }
#else
  // Linux optimizations advise kernel about our access pattern
  posix_fadvise(fd, 0, length, POSIX_FADV_DONTNEED);  // won't need this data again

  // attempt to preallocate space to reduce fragmentation
  if (length > 0) {
    posix_fallocate(fd, 0, length);
  }
#endif

  // use FILE* with large buffer for efficiency
  fp = fdopen(fd, "wb");
  if (! fp) {
    close(fd);
    return -1;
  }

  // set up large buffer for writes
  setvbuf(fp, write_buffer, _IOFBF, WRITE_BUFFER_SIZE);

  // perform write
  if (length > 0) {
    size_t written = fwrite(data, 1, length, fp);

    if (written != length) {
      ret = -1;
    }
  }

  fclose(fp);

  return ret;
}


// vector write thread provides asynchronous I/O
static void *vector_write_thread(void *arg) {

  VectorWriteThreadWork *work = (VectorWriteThreadWork *)(arg);
  BlockVector *b;
  FILE *fp;
  struct timespec start, end;

  atomic_store_explicit(&work->vector_thread_running, true, memory_order_release);

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Write thread # %1d initialized, sleeping.\n", work->id);
  }

  while (! atomic_load_explicit(&work->vector_thread_stop, memory_order_acquire)) {
    // wait for work
    MUTEX_ERROR_CHECK(pthread_mutex_lock(&work->work_is_available), __LINE__, __FILE__);
    while (atomic_load_explicit(&work->vector_thread_ready, memory_order_acquire)
           && ! atomic_load_explicit(&work->vector_thread_stop, memory_order_acquire)) {
      pthread_cond_wait(&work->check_work_available, &work->work_is_available);
    }
    MUTEX_ERROR_CHECK(pthread_mutex_unlock(&work->work_is_available), __LINE__, __FILE__);

    if (atomic_load_explicit(&work->vector_thread_stop, memory_order_acquire)) {
      break;
    }

    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout, "Write thread # %1d waking up to write %p.\n", work->id, work->b);
    }

    clock_gettime(CLOCK_MONOTONIC, &start);

    // potentially write blockvector
    if (work->blockvector_pathname[0]) {
      fp = fopen(work->blockvector_pathname, "w");
      if (fp) {
        fprintf(fp, "Capacity:     %8" PRIu64 " blocks\n", work->b->numblocks);
        fprintf(fp, "Length:       %8" PRIu64 " bytes\n", work->b->length);
        fprintf(fp, "Index\t\tActual\t\tApparent\n");
        for (uint64_t i = 0; i < work->b->numblocks; i++) {
          if (work->b->valid[i]) {
            fprintf(fp, "%8" PRId64 "\t%8" PRId64 "\t%8" PRId64 "\n", i, work->b->actual_blocknumber[i],
                    work->b->apparent_blocknumber[i]);
          }
        }
        fclose(fp);
      }
    }

    // write data for blockvector
    if (work->pathname[0]) {
      if (work->b->length == 0) {
        lock_fprintf(stderr,
                     "\nScalpel not writing zero length file \"%s\".\n"
                     "The associated validator is probably misbehaving and should be checked.\n\n",
                     work->pathname);
      }
      else {
        char *data = blockvector_get_data_pointer(work->b);

        if (work->b->seqdata) {
          // fast path: all blocks consecutive and valid via mmap.
          if (write_file_optimized(work->pathname, data, work->b->length) < 0) {
            handle_error(SCALPEL_ERROR_FILE_WRITE, work->pathname, __LINE__, __FILE__);
          }
        }
        else {
          // slow path: write coalesced runs of valid blocks, zeroes for invalid blocks.
          // Invalid blocks (valid[i] == false) may contain stale data from deflate/resize
          // cycles--write zeroes instead.
          int flags = O_WRONLY | O_CREAT | O_TRUNC;
#ifdef __linux__
          flags |= O_NOATIME;
#endif
          int fd = open(work->pathname, flags, 0644);
          if (fd < 0) {
            handle_error(SCALPEL_ERROR_FILE_WRITE, work->pathname, __LINE__, __FILE__);
          }
          else {
            FILE *fp = fdopen(fd, "wb");
            if (! fp) {
              close(fd);
              handle_error(SCALPEL_ERROR_FILE_WRITE, work->pathname, __LINE__, __FILE__);
            }
            else {
              uint64_t blocksize = work->b->filemirror->blocksize;
              uint64_t remaining = work->b->length;
              uint64_t i = 0;
              bool write_error = false;

              while (i < work->b->numblocks && remaining > 0 && ! write_error) {
                if (work->b->valid[i] && data) {
                  // coalesce consecutive valid blocks into one write
                  uint64_t run_start = i;
                  uint64_t run_bytes = 0;
                  while (i < work->b->numblocks && remaining > 0
                         && work->b->valid[i]) {
                    uint64_t chunk = (remaining < blocksize) ? remaining : blocksize;
                    run_bytes += chunk;
                    remaining -= chunk;
                    i++;
                  }
                  if (fwrite(data + run_start * blocksize, 1, run_bytes, fp) != run_bytes) {
                    write_error = true;
                  }
                }
                else {
                  // coalesce consecutive invalid blocks into one zero write
                  uint64_t zero_bytes = 0;
                  while (i < work->b->numblocks && remaining > 0
                         && ! work->b->valid[i]) {
                    uint64_t chunk = (remaining < blocksize) ? remaining : blocksize;
                    zero_bytes += chunk;
                    remaining -= chunk;
                    i++;
                  }
                  // write zeroes in blocksize-aligned chunks
                  static __thread char *zero_buf = NULL;
                  if (! zero_buf) {
                    zero_buf = calloc(1, blocksize);
                    check_memory_allocation(zero_buf, __LINE__, __FILE__, "zero_buf");
                  }
                  uint64_t zr = zero_bytes;
                  while (zr > 0 && ! write_error) {
                    uint64_t zchunk = (zr < blocksize) ? zr : blocksize;
                    if (fwrite(zero_buf, 1, zchunk, fp) != zchunk) {
                      write_error = true;
                    }
                    zr -= zchunk;
                  }
                }
              }
              fclose(fp);

              if (write_error) {
                handle_error(SCALPEL_ERROR_FILE_WRITE, work->pathname, __LINE__, __FILE__);
              }
            }
          }
        }
      }
    }

    // Update the shadow blockmap if needed
    if (work->update_blockmap) {
      filemirror_update_blockmap(work->state, work->b);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    atomic_fetch_add_explicit(&random_write_wait, (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec),
                              memory_order_acq_rel);

    // mark thread as ready again
    MUTEX_ERROR_CHECK(pthread_mutex_lock(&work->b->filemirror->choose_vector_write_thread), __LINE__, __FILE__);

    atomic_store_explicit(&work->b->filemirror->vector_write_thread_work[work->id].vector_thread_ready, true, memory_order_release);

    atomic_fetch_add_explicit(&work->b->filemirror->num_idle_vector_write_threads, 1, memory_order_acq_rel);

    atomic_fetch_sub_explicit(&work->b->filemirror->vector_operations_pending, 1, memory_order_acq_rel);

    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout, "Write thread # %1d completed work on %p, sleeping.\n", work->id, work->b);
      lock_fprintf(stdout, "Number of vector operations pending = %d.\n",
                   atomic_load_explicit(&work->b->filemirror->vector_operations_pending, memory_order_acquire));
    }

    b = work->b;

    MUTEX_ERROR_CHECK(pthread_mutex_unlock(&work->b->filemirror->choose_vector_write_thread), __LINE__, __FILE__);

    // free blockvector resources
    free_blockvector(&b);
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Write thread # %1d exiting.\n", work->id);
  }

  atomic_store_explicit(&work->vector_thread_running, false, memory_order_release);

  return NULL;
}


// this read function skips covered blocks and assembles a block vector for use by the sequential
// readahead thread.
static BlockVector *sequential_read(FileMirror *state) {

  BlockVector *b = NULL;
  uint64_t curblock;

  uint64_t readahead_blocks = CEILDIV(state->readahead_bytes + state->peekahead_bytes, state->blockmap->blocksize);
  uint64_t needed_blocks = readahead_blocks + CEILDIV(state->peekahead_bytes, state->blockmap->blocksize);
  uint64_t readahead_end_block = 0;
  uint64_t valid_blocks_read = 0;
  uint64_t block_index = 0;
  bool consecutive = true;
  uint64_t i;
  int64_t prevblock;
  uint64_t startindex;
  uint64_t start;
  uint64_t length;

  // quit immediately if end of image file was reached
  if (state->seqoffset >= state->filesize) {
    goto done;
  }

  // because readahead blockvectors have to include extra "peekahead" data, init_blockvector() is
  // bypassed and the functionality is essentially replicated here, with minor changes.

  b = malloc(sizeof(BlockVector));
  check_memory_allocation(b, __LINE__, __FILE__, "b");

  b->filemirror = state;
  b->numblocks = needed_blocks;
  b->ignore_reservations = true;
  b->malloc_length = needed_blocks;
  b->actual_blocknumber = malloc(sizeof(int64_t) * b->malloc_length);
  check_memory_allocation(b->actual_blocknumber, __LINE__, __FILE__, "b");
  b->apparent_blocknumber = malloc(sizeof(int64_t) * b->malloc_length);
  check_memory_allocation(b->apparent_blocknumber, __LINE__, __FILE__, "b");
  b->valid = malloc(sizeof(bool) * b->malloc_length);
  check_memory_allocation(b->valid, __LINE__, __FILE__, "b");

  memset_int64_t(b->actual_blocknumber, -1, b->numblocks);
  memset_int64_t(b->apparent_blocknumber, -1, b->numblocks);
  memset(b->valid, false, b->numblocks);

  b->length = 0;
  b->data = NULL;
  b->seqdata = NULL;
  b->choices = NULL;

  // find actual block # associated with current position.
  curblock = state->seqoffset / state->blocksize;

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Readahead thread using BV %p. Current actual block # is %1" PRIu64 ".\n", (void *)b, curblock);
  }

  while (needed_blocks && block_index < b->numblocks && curblock < state->blockmap->numblocks) {
    // skip consecutive covered or zero blocks in the image file starting from the current position

    if (! is_block_covered(state->blockmap, curblock) && ! is_zero_block(state->blockmap, curblock)) {
      b->actual_blocknumber[block_index] = curblock;
      b->apparent_blocknumber[block_index] = state->blockmap_reverse_mapping[curblock];
      b->valid[block_index] = true;
      block_index++;
      needed_blocks--;
      valid_blocks_read++;
      if (valid_blocks_read == readahead_blocks) {
        readahead_end_block = curblock + 1;
      }
    }
    else {
      consecutive = false;
    }

    curblock++;
  }

  // set file position for next call
  state->seqoffset = state->blockmap->blocksize * (readahead_end_block ? readahead_end_block : curblock);

  b->numblocks = block_index;

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Readahead thread: Using BV %p. Blocks to read = %1" PRIu64 ".\n", (void *)b, block_index);
  }

  if (block_index != 0) {
    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout, "Readahead thread using BV %p %sdoing fast-mode read.\n", (void *)b, consecutive ? "" : "not ");
    }

    if (consecutive) {
      // all data is contiguous, use pointer directly into mmap()-ed file data
      b->seqdata = state->mmap + b->actual_blocknumber[0] * state->blocksize;
      b->length = b->numblocks * state->blocksize;

      // constrain length to actual image file size
      if (b->actual_blocknumber[b->numblocks - 1] == (int64_t)state->blockmap->numblocks - 1
          && state->filesize % state->blocksize) {
        b->length -= state->blocksize - state->filesize % state->blocksize;
      }
    }
    else {
      // data is not contiguous, fall back to memcpy() from mmap()-ed file data
      b->data = calloc(b->malloc_length * b->filemirror->blocksize, sizeof(char));
      check_memory_allocation(b->data, __LINE__, __FILE__, "b->data");

      i = 0;
      while (i < b->numblocks) {
        startindex = i;
        start = b->actual_blocknumber[i] * b->filemirror->blocksize;

        // minimize calls to memcpy() by coalescing copies of adjacent blocks
        length = 0;
        prevblock = b->actual_blocknumber[i] - 1;
        while (i < b->numblocks && prevblock + 1 == b->actual_blocknumber[i]) {
          length += b->filemirror->blocksize;
          prevblock = b->actual_blocknumber[i];
          b->valid[i] = true;
          i++;
        }

        if (start + length > b->filemirror->filesize) {
          length = b->filemirror->filesize - start;
        }

        // warm up

#if ! defined(__APPLE__)
        posix_fadvise(b->filemirror->mmap_fd, start, length, POSIX_FADV_WILLNEED);
        madvise(b->filemirror->mmap + start, length, MADV_POPULATE_READ);
#else
        struct radvisory ra;

        ra.ra_offset = start;
        ra.ra_count = length;
        fcntl(b->filemirror->mmap_fd, F_RDADVISE, &ra);
#endif

        mem_pretouch_read(b->filemirror->mmap + start, length);

        memcpy(b->data + startindex * b->filemirror->blocksize, b->filemirror->mmap + start, length);
        b->length += length;
      }

      // constrain length to actual image file size
      if (b->actual_blocknumber[b->numblocks - 1] == (int64_t)state->blockmap->numblocks - 1
          && state->filesize % state->blocksize) {
        b->length -= state->blocksize - state->filesize % state->blocksize;
      }
    }
  }

done:

  if (b && block_index == 0) {
    free_blockvector(&b);
  }

  if (scalpel_state.mode_verbose) {
    if (b) {
      lock_fprintf(stdout, "Readahead thread read complete, bytes/blocks in %p = %" PRIu64 "/%" PRIu64 ".\n", b, b->length,
                   b->numblocks);
    }
    else {
      lock_fprintf(stdout, "Readahead thread read complete, end of file, no more data.\n");
    }
  }

  return b;
}


// this thread maintains a queue filled with blockvectors, to support asynchronous readahead. The
// thread exits when it hits end of file on the read thread filehandle or is ordered to stop. It can
// be restarted with filemirror_rewind() as needed. The thread synchronization model is based on a
// single readahead thread.
static void *read_thread(void *arg) {

  FileMirror *state = (FileMirror *)(arg);
  bool eof;
  BlockVector *b;

  state->read_thread_running = true;

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Sequential readahead thread starting.\n");
  }

  eof = false;
  while (! atomic_load_explicit(&state->read_thread_stop, memory_order_acquire) && ! eof) {
    if (scalpel_state.mode_verbose && nolock_queue_length(&state->blockvectors) >= state->num_readahead_bufs) {
      lock_fprintf(stdout, "Sequential readahead thread queue full, sleeping.\n");
    }

    // wait for space in the readahead queue, if needed
    MUTEX_ERROR_CHECK(pthread_mutex_lock(&state->readahead_full), __LINE__, __FILE__);
    while (nolock_queue_length(&state->blockvectors) >= state->num_readahead_bufs
           && ! atomic_load_explicit(&state->read_thread_stop, memory_order_acquire)) {
      pthread_cond_wait(&state->wait_readahead_full, &state->readahead_full);
    }
    MUTEX_ERROR_CHECK(pthread_mutex_unlock(&state->readahead_full), __LINE__, __FILE__);

    if (atomic_load_explicit(&state->read_thread_stop, memory_order_acquire)) {
      // thread was ordered to exit
      break;
    }

    // read another sequence of blocks into the mirror
    b = sequential_read(state);

    if (b) {
      if (scalpel_state.mode_verbose) {
        lock_fprintf(stdout, "Sequential readahead thread adding %p with length %" PRIu64 " to readahead queue.\n", b, b->length);
      }

      add_to_queue(&state->blockvectors, &b, 0);
    }
    else {
      eof = true;
    }

    // signal that a read attempt was made
    MUTEX_ERROR_CHECK(pthread_mutex_lock(&state->readahead_empty), __LINE__, __FILE__);
    pthread_cond_broadcast(&state->wait_readahead_empty);
    MUTEX_ERROR_CHECK(pthread_mutex_unlock(&state->readahead_empty), __LINE__, __FILE__);
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Sequential readahead thread exiting.\n");
  }

  // all done
  MUTEX_ERROR_CHECK(pthread_mutex_lock(&state->readahead_empty), __LINE__, __FILE__);
  state->read_thread_running = false;
  pthread_cond_broadcast(&state->wait_readahead_empty);
  MUTEX_ERROR_CHECK(pthread_mutex_unlock(&state->readahead_empty), __LINE__, __FILE__);

  return NULL;
}


// returns the actual size of the file being mirrored
//
// THIS FUNCTION IS THREAD-SAFE.
uint64_t filemirror_filesize(FileMirror *state) {

  if (state) {
    return state->filesize;
  }
  else {
    return 0;
  }
}


// returns the apparent size of the file being mirrored--this is actual size - the contribution of
// covered blocks
//
// THIS FUNCTION IS THREAD-SAFE.
uint64_t filemirror_apparent_filesize(FileMirror *state) {

  if (state) {
    return state->apparent_filesize;
  }
  else {
    return 0;
  }
}


// returns the number of apparent blocks in the file being mirrored--this is actual number of bocks
// - the contribution of covered blocks
//
// THIS FUNCTION IS THREAD-SAFE.
uint64_t filemirror_apparent_blocks(FileMirror *state) {

  if (state) {
    return state->apparent_blocks;
  }
  else {
    return 0;
  }
}


// returns the actual file location corresponding to 'apparent_location'. 'apparent_location' does
// not include the contribution of covered blocks, but the actual location does.
//
// THIS FUNCTION IS THREAD-SAFE.
uint64_t filemirror_actual_location(FileMirror *state, uint64_t apparent_location) {

  uint64_t actual = apparent_location + state->blocksize *
					(state->blockmap_mapping[apparent_location / state->blocksize] - apparent_location / state->blocksize);

  if (actual > state->filesize) {
    lock_fprintf(stderr, "%s", RED);
    lock_fprintf(stderr, "\nLOCATION:: %" PRIu64 ".\n", apparent_location);
    handle_error(SCALPEL_ERROR_BAD_BLOCKMAP_BLOCK_NUMBER, "filemirror_actual_location()", __LINE__, __FILE__);
  }

  return actual;
}


// returns the apparent file location corresponding to 'actual_location'. 'actual_location' includes
// the contribution of covered blocks, but the apparent location does not.
//
// THIS FUNCTION IS THREAD-SAFE.
uint64_t filemirror_apparent_location(FileMirror *state, uint64_t actual_location) {

  uint64_t apparent = actual_location
                      - state->blocksize
                            * (actual_location / state->blocksize
                               - state->blockmap_reverse_mapping[actual_location / state->blocksize]);

  return apparent;
}


// returns the actual blocknumber corresponding to 'apparentblocknumber'.
//
// THIS FUNCTION IS THREAD-SAFE.
int64_t filemirror_actual_blocknumber(FileMirror *state, int64_t apparentblocknumber) {

  if (apparentblocknumber < 0 || apparentblocknumber >= (int64_t)state->apparent_blocks) {
    lock_fprintf(stderr, "%s", RED);
    lock_fprintf(stderr, "\nBLOCKNUMBER: %" PRId64 ".\n", apparentblocknumber);
    handle_error(SCALPEL_ERROR_BAD_BLOCKMAP_BLOCK_NUMBER, "filemirror_actual_blocknumber()", __LINE__, __FILE__);
  }

  return state->blockmap_mapping[apparentblocknumber];
}


// returns the apparent blocknumber corresponding to 'actualblocknumber' or -1 if the block is
// covered.
//
// THIS FUNCTION IS THREAD-SAFE.
int64_t filemirror_apparent_blocknumber(FileMirror *state, int64_t actualblocknumber) {

  return state->blockmap_reverse_mapping[actualblocknumber];
}


// initialize and start the file mirror. This function is also responsible for opening the image
// file and handling initialization of the coverage blockmap. 'readahead_bytes' tunes the size of
// the blockvector returned by filemirror_read(). At most 'num_readahead_bufs' buffers of this size
// will be maintained at once until the file being mirrored is exhausted. Readahead blockvectors
// will include at least 'peekahead' bytes of data unless an EOF condition occurs. 'num_threads'
// controls the size of the thread pools for asynchronous vector write operations. All errors are
// fatal--the function will generate appropriate error messages and exit if errors are encountered.
//
// THIS FUNCTION IS NOT THREAD-SAFE.
FileMirror *filemirror_start(char *image_pathname, char *blockmap_pathname, uint32_t blocksize, uint64_t readahead_bytes,
                             uint32_t num_readahead_bufs, uint32_t num_threads, uint64_t peekahead_bytes,
                             bool restoring_from_checkpoint, bool reduce_aggressive_allocation, uint64_t start_block,
                             uint64_t end_block) {

  uint64_t i, j, deduped, zero;
  int64_t apparent_blocknum;      // used to initialize blockmap mapping vectors
  uint64_t num_covered;           // used to initialize blockmap mapping vectors
  FILE *blockmapfile;             // file handle used to read blockmap
  pthread_mutexattr_t mutextype;  // used to set types of all mutexes
  char fn[PATH_MAX];

  lock_fprintf(stdout, "File mirror initialization starting.\n");

  // set default mutex type
  if (pthread_mutexattr_init(&mutextype) != 0) {
    handle_error(SCALPEL_ERROR_MUTEX_FAILURE, "filemirror_start()", __LINE__, __FILE__);
  }

  if (pthread_mutexattr_settype(&mutextype, PTHREAD_MUTEX_TYPE) != 0) {
    handle_error(SCALPEL_ERROR_MUTEX_FAILURE, "filemirror_start()", __LINE__, __FILE__);
  }

  FileMirror *state = malloc(sizeof(FileMirror));
  check_memory_allocation(state, __LINE__, __FILE__, "state");

  state->reduce_aggressive_allocation = reduce_aggressive_allocation;

  state->blocksize = blocksize;
  state->readahead_bytes = readahead_bytes;
  state->num_readahead_bufs = num_readahead_bufs;
  strcpy(state->image_pathname, image_pathname);
  strcpy(state->blockmap_pathname, blockmap_pathname);
  state->num_threads = num_threads;
  state->peekahead_bytes = peekahead_bytes;

  state->imagefile = fopen(state->image_pathname, "rb");
  state->seqoffset = 0;
  state->mmap_fd = open(state->image_pathname, O_RDONLY);

  if (! state->imagefile || state->mmap_fd < 0) {
    if (state->imagefile) { fclose(state->imagefile); }
    if (state->mmap_fd >= 0) { close(state->mmap_fd); }
    // fatal
    handle_error(SCALPEL_ERROR_FILE_OPEN, image_pathname, __LINE__, __FILE__);
    return NULL;
  }

  // get sizes for image file
  fseek(state->imagefile, 0, SEEK_END);        // discover actual size
  state->filesize = ftello(state->imagefile);  // actual size of image file
  state->apparent_filesize = state->filesize;  // apparent size starts out as full size

  // set up memory-mapped access to image file for vector reads
  state->mmap = mmap(0, state->filesize, PROT_READ, MAP_PRIVATE, state->mmap_fd, 0);

#ifdef __APPLE__
  int ra = 1;

  (void)fcntl(state->mmap_fd, F_RDAHEAD, &ra);
#endif

  if (state->mmap == MAP_FAILED) {
    perror("");
    fclose(state->imagefile);
    close(state->mmap_fd);
    // fatal
    handle_error(SCALPEL_ERROR_MMAP_FAILURE, NULL, __LINE__, __FILE__);
  }

  lock_fprintf(stdout, "Setting up in-core blockmap.\n");

  // see if blockmap exists--a blockmap is required to continue
  blockmapfile = fopen(state->blockmap_pathname, "rb");

  if (! blockmapfile) {
    munmap(state->mmap, state->filesize);
    fclose(state->imagefile);
    close(state->mmap_fd);
    // fatal
    handle_error(SCALPEL_ERROR_NO_BLOCKMAP, NULL, __LINE__, __FILE__);
  }

  if (! read_blockmap(&state->blockmap, blockmapfile, true)) {
    // fatal
    handle_error(SCALPEL_ERROR_BLOCKMAP_FORMAT, NULL, __LINE__, __FILE__);
  }

  fclose(blockmapfile);

  if (state->blockmap->blocksize != state->blocksize) {
    // fatal
    handle_error(SCALPEL_ERROR_BLOCKSIZE, NULL, __LINE__, __FILE__);
  }

  if (state->blockmap->numblocks != CEILDIV(state->filesize, state->blocksize)) {
    // fatal
    handle_error(SCALPEL_ERROR_IMAGE_BLOCKFILESIZE, NULL, __LINE__, __FILE__);
  }

  if (start_block == UINT64_MAX) {
    // this indicates the start block wasn't overridden--just use the one in the blockmap
    start_block = state->blockmap->start_block;
  }

  if (end_block == UINT64_MAX) {
    // this indicates the end block wasn't overridden--just use the one in the blockmap
    end_block = state->blockmap->end_block;
  }

  if (start_block > CEILDIV(state->filesize, state->blocksize) || (end_block > CEILDIV(state->filesize, state->blocksize))) {
    // fatal
    handle_error(SCALPEL_ERROR_BAD_START_END_BLOCKS, NULL, __LINE__, __FILE__);
  }

  lock_fprintf(stdout, "Active carve window: %" PRIu64 " - %" PRIu64 ".\n", start_block, end_block);

  // different active window in image file requires recomputation of dedup info and implicit block
  // coverage
  if (start_block != state->blockmap->start_block || end_block != state->blockmap->end_block) {
    set_blockmap_window(state->blockmap, start_block, end_block);
    lock_fprintf(stdout, "Adjusting blockmap to match current carve window.\n");

    dedup_blockmap(state->blockmap, state->imagefile, &deduped, &zero, true);
  }
  else {
    lock_fprintf(stdout, "Current carve window matches blockmap, no action is necessary.\n");
  }

  fseek(state->imagefile, 0, SEEK_SET);  // rewind image file

  state->blockmap_mapping = (int64_t *)malloc((state->blockmap->numblocks) * sizeof(int64_t));
  check_memory_allocation(state->blockmap_mapping, __LINE__, __FILE__, "state->blockmap_mapping");

  state->blockmap_reverse_mapping = (int64_t *)malloc((state->blockmap->numblocks) * sizeof(int64_t));
  check_memory_allocation(state->blockmap_reverse_mapping, __LINE__, __FILE__, "state->blockmap_reverse_mapping");

  lock_fprintf(stdout, "Setup of in-core blockmap complete.\n");

  // initialize semaphore that protects shadow blockmap updates
  if (pthread_mutex_init(&state->update_blockmap, &mutextype)) {
    // fatal
    handle_error(SCALPEL_ERROR_MUTEX_FAILURE, "filemirror_start()", __LINE__, __FILE__);
  }

  // IMPORTANT: memory allocation for the the shadow blockmap is done on a lazy basis to reduce
  // memory pressure. That's performed only when filemirror_update_blockmap() is called for the
  // first time. For now, the shadow is just NULL.
  state->shadow_blockmap = NULL;

  // initialize the blockmap_mapping and blockmap_reverse_mapping vectors, which allow fast
  // conversion between apparent and actual block numbers
  num_covered = 0;
  for (i = 0; i < state->blockmap->numblocks; i++) {
    state->blockmap_mapping[i] = -1;
    if (! is_block_covered(state->blockmap, i)) {
      state->blockmap_reverse_mapping[i] = i - num_covered;
    }
    else {
      state->blockmap_reverse_mapping[i] = -1;
      num_covered++;
    }
  }

  apparent_blocknum = 0;
  for (i = 0; i < state->blockmap->numblocks; i++) {
    if (apparent_blocknum == state->blockmap_reverse_mapping[i]) {
      state->blockmap_mapping[apparent_blocknum] = i;
      apparent_blocknum++;
    }
  }

  if (num_covered) {
    // now reduce apparent file size of the file being mirrored by # of blocks that are covered in
    // the coverage blockmap.
    if (state->filesize % state->blocksize != 0) {
      state->apparent_filesize -= state->blocksize * (num_covered - 1);
      state->apparent_filesize -= state->filesize % state->blocksize;
    }
    else {
      state->apparent_filesize -= state->blocksize * num_covered;
    }
  }

  state->apparent_blocks = CEILDIV(state->apparent_filesize, state->blocksize);

  // allocate blocktype structure
  state->blocktype = (unsigned char **)malloc(state->blockmap->numblocks * sizeof(unsigned char *));
  check_memory_allocation(state->blocktype, __LINE__, __FILE__, "state->blocktype");
  for (i = 0; i < state->blockmap->numblocks; i++) {
    state->blocktype[i] = (unsigned char *)malloc(scalpel_state.num_specs * sizeof(unsigned char));
    check_memory_allocation(state->blocktype, __LINE__, __FILE__, "state->blocktype");
    for (j = 0; j < scalpel_state.num_specs; j++) {
      state->blocktype[i][j] = BLOCK_CONFIDENCE_INVALID;
    }
  }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
  // if restoring from checkpoint, read blocktype data
  if (restoring_from_checkpoint) {
    snprintf(fn, PATH_MAX, "%s/blocktypes.chk", scalpel_state.base_output_directory);
    if (! filemirror_serialize_blocktype_data(state, DESERIALIZE, fn)) {
      // fatal
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
  }
#pragma GCC diagnostic pop

  // initialize semaphore that protects shadow blockmap updates
  if (pthread_mutex_init(&state->blocktype_lock, &mutextype)) {
    // fatal
    handle_error(SCALPEL_ERROR_MUTEX_FAILURE, "filemirror_start()", __LINE__, __FILE__);
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Filemirror: actual image file size = %" PRIu64 ", apparent = %" PRIu64 ".\n", state->filesize,
                 state->apparent_filesize);
    lock_fprintf(stdout, "Creating readahead thread in file mirror.\n");
  }

  // initialize performance stats
  seq_io_wait = 0;
  atomic_init(&random_read_wait, 0);
  atomic_init(&random_write_wait, 0);

  // initialize queue of blockvectors used by readahead thread
  init_queue(&state->blockvectors, sizeof(BlockVector *), true, 0, true);

  // initilize semaphores and condition variables used to handle readahead
  if (pthread_mutex_init(&state->readahead_full, &mutextype)) {
    // fatal
    handle_error(SCALPEL_ERROR_MUTEX_FAILURE, "filemirror_start()", __LINE__, __FILE__);
  }
  if (pthread_cond_init(&state->wait_readahead_full, NULL)) {
    // fatal
    handle_error(SCALPEL_ERROR_MUTEX_FAILURE, "filemirror_start()", __LINE__, __FILE__);
  }
  if (pthread_mutex_init(&state->readahead_empty, &mutextype)) {
    // fatal
    handle_error(SCALPEL_ERROR_MUTEX_FAILURE, "filemirror_start()", __LINE__, __FILE__);
  }
  if (pthread_cond_init(&state->wait_readahead_empty, NULL)) {
    // fatal
    handle_error(SCALPEL_ERROR_MUTEX_FAILURE, "filemirror_start()", __LINE__, __FILE__);
  }
  if (pthread_mutex_init(&state->sequential_read_lock, &mutextype)) {
    // fatal
    handle_error(SCALPEL_ERROR_MUTEX_FAILURE, "filemirror_start()", __LINE__, __FILE__);
  }

  atomic_init(&state->read_thread_stop, false);
  atomic_init(&state->read_thread_running, false);

  // start readahead thread
  if (pthread_create(&state->read_thread, NULL, read_thread, (void *)state) != 0) {
    // fatal
    handle_error(SCALPEL_ERROR_PTHREAD_FAILURE, "filemirror_start()", __LINE__, __FILE__);
  }

  if (pthread_mutex_init(&state->choose_vector_write_thread, &mutextype)) {
    // fatal
    handle_error(SCALPEL_ERROR_MUTEX_FAILURE, "filemirror_start()", __LINE__, __FILE__);
  }

  // track # of pending vector operations to prevent early shutdown
  atomic_init(&state->vector_operations_pending, 0);

  // create write threads and associated work structures
  atomic_init(&state->num_idle_vector_write_threads, 0);

  state->vector_write_threads = malloc(sizeof(pthread_t) * state->num_threads);
  check_memory_allocation(state->vector_write_threads, __LINE__, __FILE__, "state->vector_write_threads");
  state->vector_write_thread_work = malloc(sizeof(VectorWriteThreadWork) * state->num_threads);
  check_memory_allocation(state->vector_write_thread_work, __LINE__, __FILE__, "state->vector_write_thread_work");
  for (i = 0; i < state->num_threads; i++) {
    state->vector_write_thread_work[i].id = i;
    state->vector_write_thread_work[i].state = state;
    atomic_init(&state->vector_write_thread_work[i].vector_thread_running, false);
    atomic_init(&state->vector_write_thread_work[i].vector_thread_stop, false);
    atomic_init(&state->vector_write_thread_work[i].vector_thread_ready, true);
    state->vector_write_thread_work[i].b = NULL;

    if (pthread_mutex_init(&state->vector_write_thread_work[i].work_is_available, &mutextype)) {
      // fatal
      handle_error(SCALPEL_ERROR_MUTEX_FAILURE, "filemirror_start()", __LINE__, __FILE__);
    }
    if (pthread_cond_init(&state->vector_write_thread_work[i].check_work_available, NULL)) {
      // fatal
      handle_error(SCALPEL_ERROR_MUTEX_FAILURE, "filemirror_start()", __LINE__, __FILE__);
    }

    // start thread
    if (pthread_create(&state->vector_write_threads[i], NULL, vector_write_thread, (void *)(&state->vector_write_thread_work[i]))
        != 0) {
      // fatal
      handle_error(SCALPEL_ERROR_PTHREAD_FAILURE, "filemirror_start()", __LINE__, __FILE__);
    }
  }

  atomic_store_explicit(&state->num_idle_vector_write_threads, num_threads, memory_order_release);

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "File mirror initialization complete.\n");
  }

  return state;
}


// stop all threads, free memory, and close all associated files. New filemirror operations must not
// be initiated while this function is in progress.
//
// THIS FUNCTION IS NOT THREAD-SAFE. CALLING CODE *MUST* ENFORCE MUTUAL EXCLUSION.
void filemirror_stop(FileMirror *state) {

  BlockVector *b;
  uint32_t i;
  uint32_t pending;
  char fn[PATH_MAX];
  char newfn[PATH_MAX];

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Stopping file mirror.\n");
  }

  if (scalpel_state.mode_verbose && (pending = atomic_load_explicit(&state->vector_operations_pending, memory_order_acquire))) {
    lock_fprintf(stdout, "filemirror_stop(): waiting for %1d vector operations to complete...\n", pending);
  }

  while ((pending = atomic_load_explicit(&state->vector_operations_pending, memory_order_acquire)))
    ;

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "filemirror_stop(): all pending vector operations have completed.\n");
  }

  // empty readahead queue
  while (! empty_queue(&state->blockvectors)) {
    remove_from_front(&state->blockvectors, &b);
    free_blockvector(&b);
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Stopping readahead thread.\n");
  }

  // signal readahead thread to die
  MUTEX_ERROR_CHECK(pthread_mutex_lock(&state->readahead_full), __LINE__, __FILE__);
  atomic_store_explicit(&state->read_thread_stop, true, memory_order_release);
  pthread_cond_signal(&state->wait_readahead_full);
  MUTEX_ERROR_CHECK(pthread_mutex_unlock(&state->readahead_full), __LINE__, __FILE__);

  // wait for readahead thread to exit
  pthread_join(state->read_thread, NULL);

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Readahead thread stopped.\n");
  }

  // wait to destroy queue after readahead thread stops, because it accesses this queue
  destroy_queue(&state->blockvectors);

  // destroy write threads
  for (i = 0; i < state->num_threads; i++) {
    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout, "Stopping vector write thread # %d...\n", i);
    }
    atomic_store_explicit(&state->vector_write_thread_work[i].vector_thread_stop, true, memory_order_release);
    MUTEX_ERROR_CHECK(pthread_mutex_lock(&state->vector_write_thread_work[i].work_is_available), __LINE__, __FILE__);
    pthread_cond_signal(&state->vector_write_thread_work[i].check_work_available);
    MUTEX_ERROR_CHECK(pthread_mutex_unlock(&state->vector_write_thread_work[i].work_is_available), __LINE__, __FILE__);
    pthread_join(state->vector_write_threads[i], NULL);
    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout, "Vector write thread # %d stopped.\n", i);
    }
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "All vector write threads stopped.\n");
  }

  free(state->vector_write_threads);
  state->vector_write_threads = NULL;
  free(state->vector_write_thread_work);
  state->vector_write_thread_work = NULL;

  // close image file
  fclose(state->imagefile);

  // close memory mapping of image file
  munmap(state->mmap, state->filesize);
  close(state->mmap_fd);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"

  // write the most up-to-date blockmap
  snprintf(fn, PATH_MAX, "%s_", state->blockmap_pathname);

  if (state->shadow_blockmap) {
    if (! clone_blockmap(state->shadow_blockmap, &state->blockmap)) {
      handle_error(SCALPEL_ERROR_BLOCKMAP_FORMAT, "clone_blockmap() for blockmap swap", __LINE__, __FILE__);
    }
    free_blockmap(&state->shadow_blockmap);
  }

  filemirror_write_blockmap(state, fn);

  // write blocktype data
  snprintf(fn, PATH_MAX, "%s/blocktypes.chk_", scalpel_state.base_output_directory);
  if (! filemirror_serialize_blocktype_data(state, SERIALIZE, fn)) {
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  // finalize filenames for blockmap and blocktypes
  snprintf(fn, PATH_MAX, "%s_", state->blockmap_pathname);
  unlink(state->blockmap_pathname);
  rename(fn, state->blockmap_pathname);

  snprintf(fn, PATH_MAX, "%s/blocktypes.chk_", scalpel_state.base_output_directory);
  snprintf(newfn, PATH_MAX, "%s/blocktypes.chk", scalpel_state.base_output_directory);
  unlink(newfn);
  rename(fn, newfn);

#pragma GCC diagnostic pop

  // free memory associated with mirror
  for (i = 0; i < state->blockmap->numblocks; i++) {
    free(state->blocktype[i]);
  }

  free(state->blocktype);
  state->blocktype = NULL;
  free_blockmap(&state->blockmap);
  free(state->blockmap_mapping);
  state->blockmap_mapping = NULL;
  free(state->blockmap_reverse_mapping);
  state->blockmap_reverse_mapping = NULL;
  free(state);
  state = NULL;

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "File mirror stopped.\n");
  }
}


// stop the readahead thread, flush all buffers, rewind to the beginning of the file being mirrored,
// and restart readahead
//
// THIS FUNCTION IS NOT THREAD-SAFE. CALLING CODE *MUST* ENFORCE MUTUAL EXCLUSION.
void filemirror_rewind(FileMirror *state) {

  BlockVector *b;
  uint32_t pending;

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Rewinding file mirror.\n");
  }

  if (scalpel_state.mode_verbose) {
    if ((pending = atomic_load_explicit(&state->vector_operations_pending, memory_order_acquire))) {
      lock_fprintf(stdout, "Rewind:  waiting for %1d vector operations to complete...\n", pending);
    }
  }

  while ((pending = atomic_load_explicit(&state->vector_operations_pending, memory_order_acquire)))
    ;

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Rewind: all pending vector operations have completed.\n");
  }

  // empty readahead queue
  while (! empty_queue(&state->blockvectors)) {
    remove_from_front(&state->blockvectors, &b);

    free_blockvector(&b);
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Stopping readahead thread.\n");
  }

  // signal readahead thread to die
  MUTEX_ERROR_CHECK(pthread_mutex_lock(&state->readahead_full), __LINE__, __FILE__);
  atomic_store_explicit(&state->read_thread_stop, true, memory_order_release);
  pthread_cond_signal(&state->wait_readahead_full);
  MUTEX_ERROR_CHECK(pthread_mutex_unlock(&state->readahead_full), __LINE__, __FILE__);

  // wait for read thread to exit
  pthread_join(state->read_thread, NULL);

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Readahead thread stopped.\n");
  }

  // reset file positions
  fseek(state->imagefile, 0, SEEK_SET);
  state->seqoffset = 0;

  // restart readahead thread
  atomic_store_explicit(&state->read_thread_stop, false, memory_order_release);
  atomic_store_explicit(&state->read_thread_running, false, memory_order_release);
  if (pthread_create(&state->read_thread, NULL, read_thread, (void *)state) != 0) {
    // fatal
    handle_error(SCALPEL_ERROR_PTHREAD_FAILURE, "filemirror_start()", __LINE__, __FILE__);
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Readahead thread restarted.\n");
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "File mirror rewind complete.\n");
  }
}


// this read function fills any blocks with valid == false and a valid actual blocknumber (actual
// blocknumber >= 0) in 'b' with valid data. The blockvector b is assumed to be initialized and
// normalized.
//
// THIS FUNCTION IS THREAD-SAFE AS LONG AS OVERLAPPING CALLS ARE NOT MADE THAT CORRESPOND TO THE
// SAME BLOCKVECTOR.
static void read_vector(BlockVector *b) {

  uint64_t i;
  int64_t prevblock;
  uint64_t startindex;
  uint64_t start;
  uint64_t length;
  struct timespec begintime, endtime;

  if (! b) {
    // fatal
    handle_error(SCALPEL_ERROR_UNINITIALIZED_BLOCKVECTOR, "read_vector()", __LINE__, __FILE__);
  }

  // one more vector operation pending
  atomic_fetch_add_explicit(&b->filemirror->vector_operations_pending, 1, memory_order_acq_rel);

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Initiating vector read for %p.\n", b);
    lock_fprintf(stdout, "Number of vector operations pending = %d.\n",
                 atomic_load_explicit(&b->filemirror->vector_operations_pending, memory_order_acquire));
  }

  // time vector read operations
  clock_gettime(CLOCK_MONOTONIC, &begintime);

  i = 0;
  b->length = 0;

  while (i < b->numblocks) {
    // skip blocks marked valid
    while (i < b->numblocks && b->valid[i]) {
      b->length += blockvector_actual_block_length(b, i);
      i++;
    }

    // zero and skip blocks with invalid actual block numbers
    while (i < b->numblocks && b->actual_blocknumber[i] < 0) {
      uint64_t zlen = b->filemirror->blocksize;
      // Cap to file boundary, same as valid blocks below.
      if (b->length + zlen > b->filemirror->filesize) {
        zlen = (b->length < b->filemirror->filesize)
            ? b->filemirror->filesize - b->length : 0;
      }
      memset(b->data + i * b->filemirror->blocksize, 0, b->filemirror->blocksize);
      b->length += zlen;
      i++;
    }

    // any blocks left?
    if (i == b->numblocks || b->actual_blocknumber[i] < 0) {
      i = b->numblocks;
      // nothing left to do
      continue;
    }

    startindex = i;
    start = b->actual_blocknumber[i] * b->filemirror->blocksize;

    if (start >= b->filemirror->filesize) {
      // fatal--bad block number
      display_blockvector(b, NULL);
      lock_fprintf(stderr, "%s", RED);
      lock_fprintf(stderr, "\nBLOCK NUMBER: %" PRId64 ".\n", start);
      handle_error(SCALPEL_ERROR_BAD_BLOCKMAP_BLOCK_NUMBER, "read_vector()", __LINE__, __FILE__);
    }

    // minimize calls to memcpy() by coalescing copies of adjacent blocks
    length = 0;
    prevblock = b->actual_blocknumber[i] - 1;
    while (i < b->numblocks && prevblock + 1 == b->actual_blocknumber[i]) {
      length += b->filemirror->blocksize;
      prevblock = b->actual_blocknumber[i];
      b->valid[i] = true;
      i++;
    }

    // constrain to actual image file size
    if (start + length > b->filemirror->filesize) {
      length = b->filemirror->filesize - start;
    }

    // warm up

#if ! defined(__APPLE__)
    madvise(b->filemirror->mmap + start, length, MADV_POPULATE_READ);
#else
    struct radvisory ra;

    ra.ra_offset = start;
    ra.ra_count = length;
    fcntl(b->filemirror->mmap_fd, F_RDADVISE, &ra);
    mem_pretouch_read(b->filemirror->mmap + start, length);
#endif

    memcpy(b->data + startindex * b->filemirror->blocksize, b->filemirror->mmap + start, length);
    b->length += length;
  }

  clock_gettime(CLOCK_MONOTONIC, &endtime);
  atomic_fetch_add_explicit(&random_read_wait, (endtime.tv_sec - begintime.tv_sec) * 1e9 + (endtime.tv_nsec - begintime.tv_nsec),
                            memory_order_acq_rel);

  // one less vector operation pending
  atomic_fetch_sub_explicit(&b->filemirror->vector_operations_pending, 1, memory_order_acq_rel);

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Vector read complete for %p.\n", b);
    lock_fprintf(stdout, "Number of vector operations pending = %d.\n",
                 atomic_load_explicit(&b->filemirror->vector_operations_pending, memory_order_acquire));
  }
}


// this function returns a pointer to a BlockVector from the queue maintained by the sequential read
// thread or NULL if end of file has been reached.
//
BlockVector *filemirror_read(FileMirror *state) {

  BlockVector *b = NULL;
  BlockVector *bv = NULL;
  bool quit = false;
  struct timespec start, end;

  clock_gettime(CLOCK_MONOTONIC, &start);

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "filemirror_read() starting.\n");
  }

  // this entire function is a critical section, because otherwise semantics become really
  // complex--the idea is to enforce sequential read semantics over the entire image file, with
  // aggressive readahead. Random-access reads are handled through vector I/O operations by other
  // functions in filemirror.c.

  // sequentialize access to readahead buffers
  MUTEX_ERROR_CHECK(pthread_mutex_lock(&state->sequential_read_lock), __LINE__, __FILE__);

  while (! bv && ! quit) {
    MUTEX_ERROR_CHECK(pthread_mutex_lock(&state->readahead_empty), __LINE__, __FILE__);

    bv = remove_from_front(&state->blockvectors, &b);

    if (bv) {
      // update current position for image file that is accessible via filemirror_ftello()
      fseek(state->imagefile, b->actual_blocknumber[0] * state->blocksize + b->length, SEEK_SET);

      // blockvectors with consecutive blocks that are using ->seqdata must be warmed right before
      // use

      if (b->seqdata) {
        // warm up

#if ! defined(__APPLE__)
        posix_fadvise(b->filemirror->mmap_fd, b->actual_blocknumber[0] * state->blocksize, b->length, POSIX_FADV_WILLNEED);
        madvise(b->filemirror->mmap + b->actual_blocknumber[0] * state->blocksize, b->length, MADV_POPULATE_READ);
#else
        struct radvisory ra;

        ra.ra_offset = b->actual_blocknumber[0] * state->blocksize, ra.ra_count = b->length;
        fcntl(b->filemirror->mmap_fd, F_RDADVISE, &ra);
#endif
        mem_pretouch_read(b->filemirror->mmap + b->actual_blocknumber[0] * state->blocksize, b->length);
      }
    }

    if (bv
        || (! atomic_load_explicit(&state->read_thread_running, memory_order_acquire)
            && nolock_queue_length(&state->blockvectors) == 0)) {
      quit = true;
    }
    else {
      pthread_cond_wait(&state->wait_readahead_empty, &state->readahead_empty);
    }

    MUTEX_ERROR_CHECK(pthread_mutex_unlock(&state->readahead_empty), __LINE__, __FILE__);
  }

  // signal that space is available
  MUTEX_ERROR_CHECK(pthread_mutex_lock(&state->readahead_full), __LINE__, __FILE__);
  pthread_cond_signal(&state->wait_readahead_full);
  MUTEX_ERROR_CHECK(pthread_mutex_unlock(&state->readahead_full), __LINE__, __FILE__);

  // next reader ok
  MUTEX_ERROR_CHECK(pthread_mutex_unlock(&state->sequential_read_lock), __LINE__, __FILE__);

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "filemirror_read() complete, return value is %p.\n", b);
  }

  clock_gettime(CLOCK_MONOTONIC, &end);
  seq_io_wait += (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec + 1);

  return b;
}


// update the *shadow* blockmap. Any blocks marked valid in the block vector 'b' are marked covered
// in the shadow blockmap. The shadow blockmap is allocated on a lazy basis in this function to
// reduce memory pressure.
//
// THIS FUNCTION IS THREAD-SAFE.
void filemirror_update_blockmap(FileMirror *state, BlockVector *b) {

  uint64_t i;

  MUTEX_ERROR_CHECK(pthread_mutex_lock(&state->update_blockmap), __LINE__, __FILE__);

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "filemirror_update_blockmap() starting for %p.\n", b);
  }

  if (! state->shadow_blockmap) {
    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout, "filemirror_update_blockmap() allocating shadow blockmap of len %" PRIu64 ".\n",
                   state->blockmap->numblocks);
    }

    // allocate shadow blockmap and copy from current blockmap
    if (! clone_blockmap(state->blockmap, &state->shadow_blockmap)) {
      handle_error(SCALPEL_ERROR_BLOCKMAP_FORMAT, "clone_blockmap() for shadow blockmap", __LINE__, __FILE__);
    }
  }

  // perform updates
  for (i = 0; i < b->numblocks; i++) {
    if (b->valid[i]) {
      cover_block(state->shadow_blockmap, b->actual_blocknumber[i]);
    }
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "filemirror_update_blockmap() complete for %p.\n", b);
  }

  MUTEX_ERROR_CHECK(pthread_mutex_unlock(&state->update_blockmap), __LINE__, __FILE__);
}


// determines if an actual location in the image file is covered by a validated file. true is
// returned if the location is covered, otherwise false is returned.
//
// THIS FUNCTION IS THREAD-SAFE.
bool filemirror_actual_location_covered(FileMirror *state, uint64_t location) {

  return state->blockmap_reverse_mapping[location / state->blocksize] < 0;
}


// determines if an actual block in the image file is covered by a validated file. true is returned
// if the block is covered, otherwise false is returned.
//
// THIS FUNCTION IS THREAD-SAFE.
bool filemirror_actual_block_covered(FileMirror *state, int64_t actualblocknumber) {

  return state->blockmap_reverse_mapping[actualblocknumber] < 0;
}


// determines if an actual block in the image file is known to be an all-zero block.
//
// THIS FUNCTION IS THREAD-SAFE.
bool filemirror_actual_block_is_zero(FileMirror *state, int64_t actualblocknumber) {

  return is_zero_block(state->blockmap, actualblocknumber);
}


char *filemirror_actual_block_data_pointer(FileMirror *state,
                                           int64_t actualblocknumber,
                                           uint64_t *length) {
  uint64_t start;
  uint64_t n;

  if (length) {
    *length = 0;
  }

  if (! state || actualblocknumber < 0) {
    return NULL;
  }

  start = (uint64_t)actualblocknumber * state->blocksize;
  if (start >= state->filesize) {
    return NULL;
  }

  n = state->blocksize;
  if (start + n > state->filesize) {
    n = state->filesize - start;
  }

  if (length) {
    *length = n;
  }

  return state->mmap + start;
}


// determines if an actual block in the image file has at reservations. 0 is returned if there are
// no reservations, otherwise the number of active reservations is returned.
//
// THIS FUNCTION IS THREAD-SAFE.
int64_t filemirror_actual_block_reserved(FileMirror *state, int64_t actualblocknumber) {

  return is_block_reserved(state->blockmap, actualblocknumber);
}


// write the primary blockmap back to disk. This is done by writing the new blockmap to a temporary
// file and then renaming that file, to minimize the possibility of corrupting the blockmap.
//
// THIS FUNCTION IS NOT THREAD-SAFE. CALLING CODE *MUST* ENFORCE MUTUAL EXCLUSION.
void filemirror_write_blockmap(FileMirror *state, char *filename) {

  FILE *blockmapfile;

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Writing blockmap.\n");
  }

  blockmapfile = fopen(filename, "wb");
  if (! blockmapfile) {
    // fatal
    handle_error(SCALPEL_ERROR_FILE_WRITE, filename, __LINE__, __FILE__);
  }

  if (! write_blockmap(state->blockmap, blockmapfile)) {
    // fatal
    handle_error(SCALPEL_ERROR_FILE_WRITE, filename, __LINE__, __FILE__);
  }

  fclose(blockmapfile);

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Blockmap write complete.\n");
  }
}


// write the primary blockmap back to an open low-level handle. Returns true on success, false on
// failure. THIS FUNCTION IS NOT THREAD-SAFE. CALLING CODE *MUST* ENFORCE MUTUAL EXCLUSION.
bool filemirror_write_blockmap_h(FileMirror *state, int handle) {

  bool ret;

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Writing blockmap to handle.\n");
  }

  ret = write_blockmap_h(state->blockmap, handle);

  if (scalpel_state.mode_verbose) {
    if (ret) {
      lock_fprintf(stdout, "Blockmap write to handle complete.\n");
    }
    else {
      lock_fprintf(stdout, "Blockmap write to handle failed.\n");
    }
  }

  return ret;
}


// make the shadow blockmap the primary blockmap, recompute mappings, and deallocate the shadow
// blockmap. Block state associated with covered blocks is also freed by this function.  Additional
// I/O calls should not be made while this function is in progress and NO sequential I/O operations
// must be in progress. After a blockmap swap, blockvectors *must* be validated via
// validate_blockvector(), as choices and block mappings are impacted.
//
// THIS FUNCTION IS NOT THREAD-SAFE. CALLING CODE *MUST* ENFORCE MUTUAL EXCLUSION.
void filemirror_swap_blockmaps(FileMirror *state) {

  uint32_t n;
  uint64_t i;
  int64_t apparent_blocknum;  // used to initialize blockmap mapping vectors
  uint64_t num_covered;       // used to initialize blockmap mapping vectors
  uint32_t pending;
  char blockhashkey[BLOCK_HASH_KEY_SIZE];


  // if the shadow blockmap wasn't allocated, it means there were no changes since the filemirror
  // was started--in this case, do nothing
  if (! state->shadow_blockmap) {
    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout, "No blockmap swap is necessary.\n");
    }
  }
  else {
    // otherwise, swap the blockmaps and deallocate the shadow
    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout, "Swapping shadow and primary blockmaps.\n");
    }

    if (scalpel_state.mode_verbose && (pending = atomic_load_explicit(&state->vector_operations_pending, memory_order_acquire))) {
      lock_fprintf(stdout, "Blockmap swap: waiting for %1d vector operations to complete...\n", pending);
    }

    // vector operations have to complete before the blockmaps can be swapped
    while ((pending = atomic_load_explicit(&state->vector_operations_pending, memory_order_acquire)))
      ;

    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout, "Blockmap swap: all pending vector operations have completed.\n");
    }

    if (! clone_blockmap(state->shadow_blockmap, &state->blockmap)) {
      handle_error(SCALPEL_ERROR_BLOCKMAP_FORMAT, "clone_blockmap() for blockmap swap", __LINE__, __FILE__);
    }
    free_blockmap(&state->shadow_blockmap);

    // recalculate apparent image file size and recompute mappings based on new blockmap
    state->apparent_filesize = state->filesize;  // apparent size starts out as full size

    // initialize the blockmap_mapping and blockmap_reverse_mapping vectors, which allow fast
    // conversion between apparent and actual block numbers
    num_covered = 0;
    for (i = 0; i < state->blockmap->numblocks; i++) {
      state->blockmap_mapping[i] = -1;
      if (! is_block_covered(state->blockmap, i)) {
        state->blockmap_reverse_mapping[i] = i - num_covered;
      }
      else {
        state->blockmap_reverse_mapping[i] = -1;
        num_covered++;
      }
    }

    apparent_blocknum = 0;
    for (i = 0; i < state->blockmap->numblocks; i++) {
      if (apparent_blocknum == state->blockmap_reverse_mapping[i]) {
        state->blockmap_mapping[apparent_blocknum] = i;
        apparent_blocknum++;
      }

      // free block state for any block whose reference count is zero (this means that all copies of
      // the block are now covered)

      if (get_reference_count(state->blockmap, i) < 1) {
        for (n = 0; n < scalpel_state.num_specs; n++) {
          if (scalpel_state.search_specs[n].FREEBLOCKSTATEFUNC && gen_block_hash_key(blockhashkey, n, i)) {
            oa_hash_delete(scalpel_state.search_specs[n].block_state, blockhashkey);
          }
        }
      }
    }

    if (num_covered) {
      // now reduce apparent file size of the file being mirrored by # of blocks that are covered in
      // the coverage blockmap.
      if (state->filesize % state->blocksize != 0) {
        state->apparent_filesize -= state->blocksize * (num_covered - 1);
        state->apparent_filesize -= state->filesize % state->blocksize;
      }
      else {
        state->apparent_filesize -= state->blocksize * num_covered;
      }
    }

    state->apparent_blocks = CEILDIV(state->apparent_filesize, state->blocksize);

    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout, "Swap of shadow and primary blockmaps complete.\n");
    }
  }
}


// simple wrapper for ftello() that uses the coverage bitmap to report the actual current image file
// position *minus* the contribution of marked blocks.
//
uint64_t filemirror_ftello(FileMirror *state) { return ftello(state->imagefile); }

// exposes the number of pending vector I/O operations as a sign of current file mirror load
uint32_t filemirror_load(FileMirror *state) {

  return atomic_load_explicit(&state->vector_operations_pending, memory_order_acquire);
}


// retrieves a confidence level measuring the likelihood that 'actualblocknumber' could be a
// component of a file of type 'filetype'. For non-exemplar blocks, the value associated with the
// block's exemplar is returned.
BlockValidationDecision filemirror_get_blocktype(FileMirror *state, int64_t actualblocknumber, uint32_t filetype) {
  // need a lock to touch state->blocktype unless block validation is complete, because of the
  // realloc() call in filemirror_add_blocktype_slot().
  bool locked = false;

  // need lock?
  if (! scalpel_state.block_validation_complete) {
    MUTEX_ERROR_CHECK(pthread_mutex_lock(&state->blocktype_lock), __LINE__, __FILE__);
    locked = true;
  }

  BlockValidationDecision ret = state->blocktype[filemirror_get_exemplar(state, actualblocknumber)][filetype];

  // need unlock?
  if (locked) {
    MUTEX_ERROR_CHECK(pthread_mutex_unlock(&state->blocktype_lock), __LINE__, __FILE__);
  }

  return ret;
}


// sets confidence level indicating the likelihood that 'actualblocknumber' could be a component of
// a file of type 'filetype'. For non-exemplar blocks, the value associated with the block's
// exemplar is set.
//
// THIS FUNCTION MUST NOT BE CALLED AFTER scalpel_state->block_validation_complete BECOMES true!
// This is an optimization to allow access to block types without holding a lock in
// filemirror_get_blocktype().
void filemirror_set_blocktype(FileMirror *state, int64_t actualblocknumber, uint32_t filetype, BlockValidationDecision blocktype) {
  // need a lock to touch state->blocktype because of the realloc in filemirror_add_blocktype_slot()
  MUTEX_ERROR_CHECK(pthread_mutex_lock(&state->blocktype_lock), __LINE__, __FILE__);

  state->blocktype[filemirror_get_exemplar(state, actualblocknumber)][filetype] = blocktype;

  MUTEX_ERROR_CHECK(pthread_mutex_unlock(&state->blocktype_lock), __LINE__, __FILE__);
}


// add an additional file type slot for each block, reflected in an increase of
// scalpel_state.num_specs by exactly one since the last call to this function. The additional slot
// is associated with a new file subtype.
//
// THIS FUNCTION MUST NOT BE CALLED AFTER scalpel_state->block_validation_complete BECOMES true!
// This is an optimization to allow access to block types without holding a lock in
// filemirror_get_blocktype().
void filemirror_add_blocktype_slot(FileMirror *state) {

  uint64_t i;

  // need a lock to touch state->blocktype because of the realloc in this function
  MUTEX_ERROR_CHECK(pthread_mutex_lock(&state->blocktype_lock), __LINE__, __FILE__);

  for (i = 0; i < state->blockmap->numblocks; i++) {
    state->blocktype[i] = (unsigned char *)realloc(state->blocktype[i], scalpel_state.num_specs * sizeof(unsigned char));
    check_memory_allocation(state->blocktype[i], __LINE__, __FILE__, "state->blocktype");

    state->blocktype[i][scalpel_state.num_specs - 1] = BLOCK_CONFIDENCE_INVALID;
  }

  // release lock
  MUTEX_ERROR_CHECK(pthread_mutex_unlock(&state->blocktype_lock), __LINE__, __FILE__);
}


// wrapper for get_exemplar() which supplies an appropriate blockmap
int64_t filemirror_get_exemplar(FileMirror *state, int64_t actualblocknumber) {

  return get_exemplar(state->blockmap, actualblocknumber);
}


// read/write blocktypes data as part of checkpoint creation or restore. Returns true if the
// blocktype data is processed successfully or false on failure. Only blocktype data for exemplar
// blocks is stored.
//
// THIS FUNCTION IS NOT THREAD-SAFE. CALLING CODE *MUST* ENFORCE MUTUAL EXCLUSION.
bool filemirror_serialize_blocktype_data(FileMirror *state, StateSerialization mode, char *filename) {

  FILE *fp;
  uint64_t i;
  uint32_t j;

  size_t (*fb)(void *ptr, size_t size, size_t nitems,
               FILE *stream) = mode == SERIALIZE ? (size_t (*)(void *ptr, size_t size, size_t nitems, FILE *stream))fwrite
                                                 : (size_t (*)(void *ptr, size_t size, size_t nitems, FILE *stream))fread;

  if (mode == SERIALIZE) {
    unlink(filename);
  }

  fp = fopen(filename, mode == SERIALIZE ? "wb" : "rb");
  if (! fp) {
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  for (i = 0; i < state->blockmap->numblocks; i++) {
    for (j = 0; j < scalpel_state.num_specs; j++) {
      if (fb(&state->blocktype[i][j], sizeof(unsigned char), 1, fp) != 1) {
        // something went wrong
        return false;
      }
    }
  }

  fclose(fp);

  return true;
}


// convenience function to initialize a blockvector and then deserialize the ** non-data ** portions
// of the blockvector 'b' from a file 'fp'. All blocks are marked invalid, since data is not saved
// by seq_write_blockvector(). This function fails with a fatal error if the blockvector can't be
// successfully read. This function does not use the threading facilities in the filemirror.
//
// THIS FUNCTION IS NOT THREAD-SAFE.
void seq_read_blockvector(FileMirror *state, BlockVector **b, FILE *fp) {

  uint64_t i;
  int64_t index = 0;
  uint64_t num_blocks = 0;
  char *serialized_bitmap;
  size_t serialized_length;

  if (fread(&num_blocks, sizeof(num_blocks), 1, fp) != 1) {
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  init_blockvector(state, b, num_blocks, false);

  for (i = 0; i < num_blocks; i++) {
    if (fread(&((*b)->apparent_blocknumber[i]), sizeof((*b)->apparent_blocknumber[i]), 1, fp) != 1) {
      // fatal
      perror("apparent blocknumber");
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    if (fread(&((*b)->actual_blocknumber[i]), sizeof((*b)->actual_blocknumber[i]), 1, fp) != 1) {
      // fatal
      perror("actual blocknumber");
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    // must issue a reservation manually, since blockvector_set_actual_blocknumber() was bypassed
    blockvector_reserve_blocks(*b, i, i);
  }

  if (fread(&((*b)->length), sizeof((*b)->length), 1, fp) != 1) {
    // fatal
    perror("length");
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  // read choices data

  // get initial index
  if (fread(&index, sizeof(index), 1, fp) != 1) {
    // fatal
    perror("index");
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  // choices was in use if initial index >= 0
  if (index >= 0) {
    // allocate b->choices array
    (*b)->choices = (roaring64_bitmap_t **)calloc((*b)->malloc_length, sizeof(roaring64_bitmap_t *));
    check_memory_allocation((*b)->choices, __LINE__, __FILE__, "b->choices");
    memset_uint64_t((uint64_t *)(*b)->choices, 0, (*b)->numblocks);
  }

  while (index >= 0) {
    if ((uint64_t)index >= (*b)->numblocks) {
      handle_error(SCALPEL_ERROR_CHECKPOINT, "invalid choices index", __LINE__, __FILE__);
    }

    // read size of serialized bitmap
    if (fread(&serialized_length, sizeof(serialized_length), 1, fp) != 1) {
      // fatal
      perror("length");
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    // now read serialized bitmap
    serialized_bitmap = malloc(serialized_length);
    check_memory_allocation(serialized_bitmap, __LINE__, __FILE__, "b->choices");
    if (fread(serialized_bitmap, serialized_length, 1, fp) != 1) {
      // fatal
      perror("bitmap");
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    // ...and deserialize bitmap
    (*b)->choices[index] = roaring64_bitmap_portable_deserialize_safe(serialized_bitmap, serialized_length);
    free(serialized_bitmap);

    if (! roaring64_bitmap_internal_validate((*b)->choices[index], NULL)) {
      // fatal
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    // get next index (-1 terminates)
    if (fread(&index, sizeof(index), 1, fp) != 1) {
      perror("index");
      // fatal
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
  }

  // read ignore_reservations flag
  if (fread(&(*b)->ignore_reservations, sizeof((*b)->ignore_reservations), 1, fp) != 1) {
    perror("ignore_reservations");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }
}


// convenience function to serialize the ** non-data ** portions of a blockvector 'b' to a file
// 'fp'. The 'valid' array is not written, since 'data' is not written. seq_read_blockvector() will
// set all blocks to be invalid so on inflation, the entire blockvector data will be read again.
// This function fails with a fatal error if the blockvector metadata can't be successfully written.
// This function intentionally ** does not ** use the threading facilities in the filemirror.
//
// THIS FUNCTION IS NOT THREAD-SAFE.
void seq_write_blockvector(BlockVector *b, FILE *fp) {

  int64_t i;
  char *serialized_bitmap;
  size_t serialized_length;

  if (fwrite(&b->numblocks, sizeof(b->numblocks), 1, fp) != 1) {
    // fatal
    perror("num_blocks");
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  for (i = 0; i < (int64_t)b->numblocks; i++) {
    if (fwrite(&b->apparent_blocknumber[i], sizeof(b->apparent_blocknumber[i]), 1, fp) != 1) {
      // fatal
      perror("apparent_blocknumber");
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    if (fwrite(&b->actual_blocknumber[i], sizeof(b->actual_blocknumber[i]), 1, fp) != 1) {
      // fatal
      perror("actual_blocknumber");
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
  }

  if (fwrite(&b->length, sizeof(b->length), 1, fp) != 1) {
    // fatal
    perror("length");
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  // write choices data

  if (b->choices) {
    // write b->choices only when it's in use
    for (i = 0; i < (int64_t)b->numblocks; i++) {
      if (b->choices[i]) {
        // write index first
        if (fwrite(&i, sizeof(i), 1, fp) != 1) {
          // fatal
          perror("index");
          handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
        }

        // then write size of serialized bitmap
        serialized_length = roaring64_bitmap_portable_size_in_bytes(b->choices[i]);
        if (fwrite(&serialized_length, sizeof(serialized_length), 1, fp) != 1) {
          // fatal
          perror("length");
          handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
        }

        // ...and finally, write serialized bitmap
        serialized_bitmap = malloc(serialized_length);
        check_memory_allocation(serialized_bitmap, __LINE__, __FILE__, "b->choices");
        memset(serialized_bitmap, 0, serialized_length);
        roaring64_bitmap_portable_serialize(b->choices[i], serialized_bitmap);

        if (fwrite(serialized_bitmap, serialized_length, 1, fp) != 1) {
          // fatal
          perror("bitmap");
          handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
        }
        free(serialized_bitmap);
      }
    }
  }

  // end of choices data marked with a final -1
  i = -1;
  if (fwrite(&i, sizeof(i), 1, fp) != 1) {
    // fatal
    perror("index");
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  // write ignore_reservations flag
  if (fwrite(&b->ignore_reservations, sizeof(b->ignore_reservations), 1, fp) != 1) {
    // fatal
    perror("ignore_reservations");
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }
}


// determine if all actual blocknumbers in 'b' are consecutive
static bool all_consecutive_actual_blocknumbers(BlockVector *b) {

  if (b->numblocks == 0 || b->actual_blocknumber[0] < 0) {
    return false;
  }

  for (uint64_t i = 1; i < b->numblocks; i++) {
    if (b->actual_blocknumber[i] < 0 || b->actual_blocknumber[i - 1] + 1 != b->actual_blocknumber[i]) {
      return false;
    }
  }

  return true;
}


// touch every page in an allocation to warm it up
static void mem_pretouch_read(void *p, size_t n) {

  pthread_once(&pagesize_once, init_pagesize);
  const size_t ps = cached_pagesize;
  volatile unsigned char *c = (volatile unsigned char *)p;

  for (size_t off = 0; off < n; off += ps) {
    (void)c[off];
  }
  if (n) {
    (void)c[n - 1];
  }
}


// touch every page in an allocation to warm it up
static void mem_pretouch_write(void *p, size_t n) {

  pthread_once(&pagesize_once, init_pagesize);
  const size_t ps = cached_pagesize;
  volatile unsigned char *c = (volatile unsigned char *)p;
  for (size_t off = 0; off < n; off += ps) {
    c[off] = c[off];
  }
  if (n) {
    c[n - 1] = c[n - 1];
  }
}


// returns a heap-allocated copy of the data in a specified *apparent* block that is zero-padded to
// blocksize. The returned buffer must be freed by the caller.
// Read 'count' bytes at 'offset' within apparent block into 'out'.
// No allocation. Returns false if block or offset is out of range.
bool get_apparent_block_bytes(FileMirror *state, int64_t apparentblocknumber,
                              uint64_t offset, uint32_t count, unsigned char *out) {

  if (apparentblocknumber < 0
      || (uint64_t)apparentblocknumber >= state->apparent_blocks) {
    return false;
  }
  int64_t actual = state->blockmap_mapping[apparentblocknumber];
  if (actual < 0) {
    return false;
  }
  uint64_t byte_start = (uint64_t)actual * state->blockmap->blocksize + offset;
  if (byte_start + count > state->filesize) {
    return false;
  }
  memcpy(out, state->mmap + byte_start, count);
  return true;
}


unsigned char *get_apparent_block_data(FileMirror *state, int64_t apparentblocknumber) {

  unsigned char *block_copy = calloc(state->blockmap->blocksize, 1);
  int64_t actualblocknumber = state->blockmap_mapping[apparentblocknumber];
  uint64_t length = ((uint64_t)actualblocknumber + 1) * state->blockmap->blocksize > state->filesize ?
		   state->filesize % state->blockmap->blocksize : state->blockmap->blocksize;

  check_memory_allocation(block_copy, __LINE__, __FILE__, "block_copy");
  memcpy(block_copy,
	 state->mmap + state->blockmap_mapping[apparentblocknumber] * state->blockmap->blocksize,
	 length);
  return block_copy;
}
