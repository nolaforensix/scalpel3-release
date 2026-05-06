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

#include "scalpel.h"

// track header/footer patterns that require thread-based searching
typedef struct ThreadSearchPattern {
  uint32_t spec_idx;
  bool is_header;  // true = header, false = footer
} ThreadSearchPattern;

// header/footer callback context
typedef struct PatternSearchContext {
  PatternList *pl;
  BlockVector *b;
} PatternSearchContext;

// this structure bundles parameters to string search threads
typedef struct SearchThreadWork {
  int id;
  bool is_header;                     // true if header, otherwise footer
  atomic_bool thread_running;         // thread is alive?
  atomic_bool thread_stop;            // if true, should exit
  atomic_bool thread_ready;           // if true, waiting for work
  pthread_mutex_t work_is_available;  // sync for work allocation
  pthread_cond_t check_work_available;

  uint32_t needleidx;                 // index into scalpel_state.search_specs
  char *needle;                       // string to search for
  size_t needlelength;                // length of search string
  char *filetype;                     // file type associated with search
  char *(*needlefunc)(char *data,     // search function
                      uint64_t offset, uint64_t length, char **matchpos, uint32_t *matchlen, uint32_t blocksize);

  BlockVector *b;                     // blockvector to search
  bool str_is_RE;                     // regular expression search string?

  union {                             // internal RE stuff
    size_t *table;
    pcre2_code *regex;
  };

  bool case_sensitive;                // is search case-sensitive?
  bool block_aligned_only;            // block-aligned matches only?
} SearchThreadWork;


// types that support checkpoint integrity checks
typedef struct {
    uint64_t sequence_number;
    time_t timestamp;
    unsigned char scalpel_sha256[32];
    struct {
      char filename[PATH_MAX];
      unsigned char sha256[32];
    } files[16];
    int num_files;
    unsigned char hmac[32];
} CheckpointManifest;


///////////////////////////////////// GLOBALS //////////////////////////////////////////////
// These are deliberately left out of the global scalpel state because they don't need to be
// checkpointed--they will be recreated every time scalpel3 starts
////////////////////////////////////////////////////////////////////////////////////////////

// main scalpel state variable
ScalpelState scalpel_state;

// list of patterns requiring thread-based search
ThreadSearchPattern *thread_search_patterns = NULL;
uint32_t num_thread_search_patterns = 0;

// tracks last checkpoint and start time for current run
struct timespec last_checkpoint;
struct timespec starttime;

// command line overrides for threadpool sizes and number of CPU cores
uint32_t max_filemirror_threads_override = 0;
uint32_t max_reassembly_threads_override = 0;
uint32_t max_search_threads_override = 0;
uint32_t max_validation_threads_override = 0;
int NC = -1;

// IPC config
int ipcsocket;  // scalpel3 IPC socket
bool no_IPC;    // IPC is disabled if no_IPC is true

// flag that induces reassembly threads to flush work and go back into idle state during a periodic
// or user-initiated checkpoint
atomic_bool REASS_RETURN_TO_IDLE;

// controls checkpoint and exit events
atomic_bool TAKE_CHECKPOINT_AND_EXIT;

// controls recovery checkpoints, which write checkpoint data
atomic_bool TAKE_RECOVERY_CHECKPOINT;

// controls periodic checkpoints, which swap blockmaps
atomic_bool TAKE_PERIODIC_CHECKPOINT;

// controls progress checkpoints, which update INPROGRESS
atomic_bool TAKE_PROGRESS_CHECKPOINT;

// contains blocks or carving candidates for validation threads
static Queue carvelist;
atomic_bool carvelist_initialized;

// contains promising carving candidates that were partially validated by validation threads and
// processsed by reassembly threads
Queue promising_queue;
atomic_bool promising_initialized;

// mirrors candidates currently being processed by reassembly threads
Queue reassembly_queue;

// contains UUIDs of candidates that should be abandoned
Queue kill_queue;
atomic_bool kill_queue_initialized;

// contains UUIDs whose stale PROMISING/INPROGRESS output should be removed
static Queue partial_cleanup_queue;
static pthread_t partial_cleanupthread;
static pthread_mutex_t partial_cleanup_work_is_available;
static pthread_cond_t partial_cleanup_check_work_available;
static atomic_bool partial_cleanup_queue_initialized;
static atomic_bool partial_cleanup_thread_stop;

// performance stats
atomic_ullong header_footer_wait;

//////// OPTIMIZED PATTERN SEARCH //////////
// Pattern lists for SIMD-accelerated search
static PatternList *header_pattern_list = NULL;
static PatternList *footer_pattern_list = NULL;

////////////// SEARCH THREADS //////////////
// thread pool for header/footer searches
static pthread_t *searchthreads;

// # of currently idle search threads
static atomic_uint num_idle_search_threads;

// structures that define work for carving threads
static SearchThreadWork *searchthreadargs;

//////// VALIDATION THREADS //////////
// thread pool for block/file validation
static pthread_t *validationthreads;

// state for validation threads
static ThreadWork *validationthreadargs;

// global, shared work available synchronization for validation threads
static pthread_mutex_t validation_work_is_available;
static pthread_cond_t validation_check_work_available;
static atomic_uint num_idle_validation_threads;

//////// REASSEMBLY THREADS //////////
// thread pool for file reassembly
static pthread_t *reassemblythreads;

// state for reassembly threads
static ThreadWork *reassemblythreadargs;

// global, shared work available synchronization for reassembly threads
pthread_mutex_t reassembly_work_is_available;    // sync for for work allocation
pthread_cond_t reassembly_check_work_available;  // among all threads
atomic_uint num_idle_reassembly_threads;

//////// IPC THREAD //////////
static pthread_t ipc;

// prototypes for private carve.c functions
static void start_threads(void);
static void stop_threads(void);
static int int_compare(const void *a, const void *b);
static void search_for_headers_footers(void);
static void search_for_headers_footers_buffer(BlockVector *b);
static void prune_header_footer_database(void);
static void validate_block(BlockInfo *blockinfo);
static void validate_file(CarveInfo *candidate, unsigned int id);
static void validate_blocks(void);
static void add_file_validation_work(CarveInfo *candidate, int64_t priority);
static bool block_validation_memdiag_enabled(void);
static void block_validation_memdiag_report(const char *stage,
                                            uint64_t num_blocks,
                                            uint64_t queued_total,
                                            uint64_t skipped_non_exemplar,
                                            uint64_t default_valid,
                                            const uint64_t *queued_by_type,
                                            uint32_t num_non_subtypes);
static void *search_thread(void *args);
static void *validation_thread(void *args);
static void *partial_cleanup_thread(void *args);
static void sync_and_validate_queues(void);
static uint64_t carve_logically_contiguous_single_pass(FILE_DEFRAG_PRIORITY priority);
static void carve_logically_contiguous_files(FILE_DEFRAG_PRIORITY priority);
static void carve_fragmented_files(FILE_DEFRAG_PRIORITY priority);
static void scalpel_state_serialization(StateSerialization mode, char *filename);
static void insert_F2_reassembly_candidates(FILE_DEFRAG_PRIORITY priority);
static void *ipc_thread(void *arg);
static void *reassembly_thread(void *args);
static bool get_reassembly_candidate(ThreadWork *work, CarveInfo **candidate);
static void carve_free_state(void *carvehashkey);
static void prune_uuid_from_promising_queue(uuid_t uuid);
static void sync_promising_and_kill_queues(void);
static bool primary_uuid_is_killed(uuid_t uuid);
static void queue_partial_cleanup(uuid_t uuid);
static void cleanup_partial_artifacts(uuid_t uuid);
static void reconcile_partial_artifacts_on_restore(void);
static bool best_choices_element_serialization(void **element, int64_t *priority, FILE *fp, StateSerialization mode);
static bool promising_queue_element_serialization(void **element, int64_t *priority, FILE *fp, StateSerialization mode);
static bool write_essential_carveinfo_element(EssentialCarveInfo *e, FILE *fp);
static bool write_essential_carveinfo_queue_from_carveinfo_queue(Queue *q, FILE *fp);
static bool write_essential_carveinfo_queue_from_carveinfo_queue_h(Queue *q, int handle);
static bool write_essential_carveinfo_queue(Queue *q, FILE *fp);
static bool write_essential_carveinfo_queue_h(Queue *q, int handle);
static void add_to_reassembly_queue(CarveInfo *c);
static void init_optimized_pattern_search(void);
static void free_pattern_list(PatternList *pl);
static PatternList *build_pattern_list(SearchSpec *specs, uint32_t num_specs, bool headers);
static void optimized_pattern_search(PatternList *pl, const unsigned char *buf, size_t len, BlockVector *b,
                                     void (*callback)(uint32_t, uint64_t, size_t, bool));
static void record_pattern_match(uint32_t needleidx, uint64_t position, size_t match_len, bool is_header);
static bool has_wildcard(const char *pattern, size_t len);
static bool pattern_in_simd_list(PatternList *pl, uint32_t spec_idx, bool is_header);
static uint64_t read_u64_unaligned(const void *ptr);
static uint32_t read_u32_unaligned(const void *ptr);
static uint16_t read_u16_unaligned(const void *ptr);
static void update_inprogress_directories(void);
static bool checkpoint_verify_manifest(void);
static bool checkpoint_save_manifest(void);
static bool checkpoint_hash_file(const char *filepath, unsigned char hash[32]);
static uint64_t checkpoint_get_sequence(void);
static void serialize_essential_offsets(char *filename);
// these are used in various compile-time branches
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
static size_t lower_bound_u64(const uint64_t *a, uint64_t n, uint64_t key);
static size_t upper_bound_u64(const uint64_t *a, uint64_t n, uint64_t key);
#pragma GCC diagnostic pop


static int64_t scalpel_debug_start_block_target(void) {
  static bool initialized = false;
  static int64_t target = -1;

  if (!initialized) {
    const char *env = getenv("SCALPEL_DEBUG_STARTBLOCK");
    initialized = true;
    if (env && *env) {
      char *endptr = NULL;
      long long value = strtoll(env, &endptr, 10);
      if (endptr != env && !*endptr && value >= 0) {
        target = (int64_t)value;
      }
    }
  }

  return target;
}

static inline bool scalpel_debug_trace_candidate(CarveInfo *candidate) {
  uint64_t start_block;
  int64_t target = scalpel_debug_start_block_target();

  if (!candidate || scalpel_state.blocksize == 0 || target < 0) {
    return false;
  }

  start_block = candidate->start / scalpel_state.blocksize;
  return start_block == (uint64_t)target;
}

static void scalpel_debug_trace(const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
}


static void add_file_validation_work(CarveInfo *candidate, int64_t priority) {
  ValidationInfo work;

  memset(&work, 0, sizeof(work));
  work.workload = VALIDATE_FILE;
  work.candidate = candidate;
  add_to_queue_priority_relaxed(&carvelist, &work, priority);
}


static bool block_validation_memdiag_enabled(void) {
  static int enabled = -1;

  if (enabled < 0) {
    const char *env = getenv("SCALPEL_BLOCK_VALIDATION_MEMDIAG");
    enabled = scalpel_state.memory_profiling
              || (env && *env && strcmp(env, "0") != 0);
  }

  return enabled != 0;
}

static void block_validation_memdiag_report(const char *stage,
                                            uint64_t num_blocks,
                                            uint64_t queued_total,
                                            uint64_t skipped_non_exemplar,
                                            uint64_t default_valid,
                                            const uint64_t *queued_by_type,
                                            uint32_t num_non_subtypes) {
  if (! block_validation_memdiag_enabled()) {
    return;
  }

  lock_fprintf(stdout,
               "\nBLOCK VALIDATION MEMDIAG [%s]\n"
               "  apparent_blocks=%" PRIu64
               ", queued_candidates=%" PRIu64
               ", skipped_non_exemplar_blocks=%" PRIu64
               ", default_valid_marks=%" PRIu64
               ", live_queue=%" PRIu64 "\n"
               "  sizeof(CarveInfo)=%zu, sizeof(queue_node)=%zu, "
               "queue_payload_size=%u\n",
               stage, num_blocks, queued_total, skipped_non_exemplar,
               default_valid, nolock_queue_length(&carvelist),
               sizeof(CarveInfo), sizeof(struct _Queue_element),
               carvelist.elementsize);

  for (uint32_t i = 0; i < num_non_subtypes; i++) {
    SearchSpec *spec = &scalpel_state.search_specs[i];
    uint64_t queued = queued_by_type ? queued_by_type[i] : 0;
    size_t block_state_entries = spec->block_state
                                 ? oa_hash_size(spec->block_state) : 0;
    size_t block_state_capacity = spec->block_state
                                  ? oa_hash_capacity(spec->block_state) : 0;
    size_t block_state_size = spec->SIZEOFBLOCKSTATEFUNC
                              ? spec->SIZEOFBLOCKSTATEFUNC(NULL) : 0;

    if (!spec->BLOCKVALIDATOR && queued == 0 && block_state_entries == 0) {
      continue;
    }

    lock_fprintf(stdout,
                 "  type=%s, needle=%u, has_block_validator=%d, queued=%" PRIu64
                 ", block_state_entries=%zu, block_state_capacity=%zu, "
                 "block_state_size=%zu, approx_state_payload=%zu\n",
                 spec->FILETYPE[0] ? spec->FILETYPE : "(empty)", i,
                 spec->BLOCKVALIDATOR ? 1 : 0, queued, block_state_entries,
                 block_state_capacity, block_state_size,
                 block_state_entries * block_state_size);
  }

  memory_footprint(stage);
}


// serialize essential components of the header/footer database
static void serialize_essential_offsets(char *filename) {

  FILE *fp = fopen(filename, "wb");

  if (!fp) {
    handle_error(SCALPEL_ERROR_FILE_WRITE, filename, __LINE__, __FILE__);
    return;
  }

  // write # of file types
  if (fwrite(&scalpel_state.num_specs, sizeof(uint32_t), 1, fp) != 1) {
    handle_error(SCALPEL_ERROR_FILE_WRITE, filename, __LINE__, __FILE__);
    fclose(fp);
    return;
  }

  // write data for each filet type
  for (uint32_t i = 0; i < scalpel_state.num_specs; i++) {

    SearchSpec *spec = &scalpel_state.search_specs[i];
    SearchSpecOffsets *src = &spec->offsets;

    // file type (suffix). Calculate length including null terminator.
    uint32_t suffix_len = (spec->FILETYPE[0] == 0) ? 0 : (uint32_t)strlen(spec->FILETYPE) + 1;

    if (fwrite(&suffix_len, sizeof(uint32_t), 1, fp) != 1) {
      handle_error(SCALPEL_ERROR_FILE_WRITE, filename, __LINE__, __FILE__);
      break;
    }

    if (suffix_len > 0) {
      if (fwrite(spec->FILETYPE, sizeof(char), suffix_len, fp) != suffix_len) {
        handle_error(SCALPEL_ERROR_FILE_WRITE, filename, __LINE__, __FILE__);
        break;
      }
    }

    // --- headers ---
    if (fwrite(&src->numheaders, sizeof(uint64_t), 1, fp) != 1) {
      handle_error(SCALPEL_ERROR_FILE_WRITE, filename, __LINE__, __FILE__);
      break;
    }

    if (src->numheaders > 0) {
      if (fwrite(src->headers, sizeof(uint64_t), src->numheaders, fp) != src->numheaders) {
        handle_error(SCALPEL_ERROR_FILE_WRITE, filename, __LINE__, __FILE__);
        break;
      }
      if (fwrite(src->headerlens, sizeof(size_t), src->numheaders, fp) != src->numheaders) {
        handle_error(SCALPEL_ERROR_FILE_WRITE, filename, __LINE__, __FILE__);
        break;
      }
    }

    // --- footers ---
    if (fwrite(&src->numfooters, sizeof(uint64_t), 1, fp) != 1) {
      handle_error(SCALPEL_ERROR_FILE_WRITE, filename, __LINE__, __FILE__);
      break;
    }

    if (src->numfooters > 0) {
      if (fwrite(src->footers, sizeof(uint64_t), src->numfooters, fp) != src->numfooters) {
        handle_error(SCALPEL_ERROR_FILE_WRITE, filename, __LINE__, __FILE__);
        break;
      }
      if (fwrite(src->footerlens, sizeof(size_t), src->numfooters, fp) != src->numfooters) {
        handle_error(SCALPEL_ERROR_FILE_WRITE, filename, __LINE__, __FILE__);
        break;
      }
    }
  }

  fclose(fp);
}


// this function wipes all files from the INPROGRESS directory, leaving directory structure intact,
// then writes each file in the promising_queue to INPROGRESS.
static void update_inprogress_directories(void) {

  char purge_pathname[PATH_MAX];
  CarveInfo **c;

  frame_message("WIPING INPROGRESS DIRECTORIES");
  // first wipe all files in the INPROGRESS directory
  snprintf(purge_pathname, PATH_MAX, "*INPROGRESS/*/*");
  delete_files_recursive(scalpel_state.base_output_directory, purge_pathname);

  frame_message("WRITING TO INPROGRESS DIRECTORIES");
  // now walk the promising queue and write each file to INPROGRESS
  rewind_queue(&promising_queue);
  while (! end_of_queue(&promising_queue)) {
    c = nolock_pointer_to_current(&promising_queue);
    (*c)->flavor = INPROGRESS;
    // preserve is on, so the candidate isn't destroyed
    write_candidate(c, true);
    next_element(&promising_queue);
  }
}


// this function serializes a single EssentialCarveInfo element received via 'fp'.
static bool write_essential_carveinfo_element(EssentialCarveInfo *e, FILE *fp) {

  // filetype:
  if (fwrite(e->filetype, sizeof(e->filetype), 1, fp) != 1) {
    perror("couldn't serialize filetype");
    return false;
  }

  // num_blocks:
  if (fwrite(&(e->numblocks), sizeof(e->numblocks), 1, fp) != 1) {
    perror("couldn't serialize numblocks");
    return false;
  }

  // qposition:
  if (fwrite(&(e->qposition), sizeof(e->qposition), 1, fp) != 1) {
    perror("couldn't serialize qposition");
    return false;
  }

  // primary UUID:
  if (fwrite(e->binuuid, sizeof(e->binuuid), 1, fp) != 1) {
    perror("couldn't serialize binuuid");
    return false;
  }

  // clone UUID:
  if (fwrite(e->clone_binuuid, sizeof(e->clone_binuuid), 1, fp) != 1) {
    perror("couldn't serialize clone_binuuid");
    return false;
  }

  // active:
  if (fwrite(&(e->active), sizeof(e->active), 1, fp) != 1) {
    perror("couldn't serialize active");
    return false;
  }

  return true;
}


// reads the contents of a queue containing CarveInfo structures and serializes the elements as
// EssentialCarveInfo elements to 'fp'.
static bool write_essential_carveinfo_queue_from_carveinfo_queue(Queue *q, FILE *fp) {

  uint64_t num_elements;
  CarveInfo *c;
  EssentialCarveInfo e;
  bool ret = true;

  // get a consistent view across promising queue and reassembly queue
  MUTEX_ERROR_CHECK(pthread_mutex_lock(&reassembly_work_is_available), __LINE__, __FILE__);

  lock_queue(q);

  num_elements = nolock_queue_length(q);
  // write number of elements
  if (fwrite(&num_elements, sizeof(num_elements), 1, fp) != 1) {
    perror("couldn't serialize number of elements");
    ret = false;
    goto done;
  }

  nolock_rewind_queue(q);

  // walk promising queue and write important elements
  while (nolock_peek_at_current(q, &c, NULL)) {
    strcpy(e.filetype, scalpel_state.search_specs[c->needleidx].FILETYPE);
    e.numblocks = blockvector_get_num_blocks(c->b);
    e.qposition = c->qposition;
    memcpy(e.binuuid, c->binuuid, sizeof(c->binuuid));
    memcpy(e.clone_binuuid, c->clone_binuuid, sizeof(c->clone_binuuid));
    e.active = false;

    if (! write_essential_carveinfo_element(&e, fp)) {
      ret = false;
      goto done;
    }
    nolock_next_element(q);
  }
  fflush(fp);

done:

  // unlock queue
  unlock_queue(q);

  // release mutex
  MUTEX_ERROR_CHECK(pthread_mutex_unlock(&reassembly_work_is_available), __LINE__, __FILE__);

  return ret;
}


// reads the contents of a queue containing CarveInfo structures and serializes the elements as
// EssentialCarveInfo elements to 'handle'
static bool write_essential_carveinfo_queue_from_carveinfo_queue_h(Queue *q, int handle) {

  FILE *fp;
  bool ret;
  int h;

  h = dup(handle);
  if (h < 0) {
    return false;
  }
  fp = fdopen(h, "wb");
  if (! fp) {
    close(h);
    return false;
  }

  ret = write_essential_carveinfo_queue_from_carveinfo_queue(q, fp);
  fclose(fp);
  return ret;
}


// serializes a queue containing EssentialCarveInfo structures to 'fp'.
static bool write_essential_carveinfo_queue(Queue *q, FILE *fp) {

  uint64_t num_elements;
  EssentialCarveInfo e;
  bool ret = true;

  // get a consistent view across promising queue and reassembly queue
  MUTEX_ERROR_CHECK(pthread_mutex_lock(&reassembly_work_is_available), __LINE__, __FILE__);

  // lock q
  lock_queue(q);

  num_elements = nolock_queue_length(q);
  // write number of elements
  if (fwrite(&num_elements, sizeof(num_elements), 1, fp) != 1) {
    perror("couldn't serialize number of elements");
    ret = false;
    goto done;
  }

  nolock_rewind_queue(q);

  // walk reassembly queue and write elements
  while (nolock_peek_at_current(q, &e, NULL)) {
    if (! write_essential_carveinfo_element(&e, fp)) {
      ret = false;
      goto done;
    }
    nolock_next_element(q);
  }
  fflush(fp);

done:

  // unlock queue
  unlock_queue(q);

  // release mutex
  MUTEX_ERROR_CHECK(pthread_mutex_unlock(&reassembly_work_is_available), __LINE__, __FILE__);
  return ret;
}


// serializes a queue containing EssentialCarveInfo structures to 'handle'.
static bool write_essential_carveinfo_queue_h(Queue *q, int handle) {

  FILE *fp;
  bool ret;
  int h;

  h = dup(handle);
  if (h < 0) {
    return false;
  }
  fp = fdopen(h, "wb");
  if (! fp) {
    close(h);
    return false;
  }

  ret = write_essential_carveinfo_queue(q, fp);
  fclose(fp);
  return ret;
}


// destroy a carving candidate and release all resources
void destroy_candidate(CarveInfo **candidate) {

  if (*candidate) {
    // if it's a file carving candidate, remove candidate from reassembly queue, which mirrors work
    // being done by reassembly threads
    if ((*candidate)->workload == VALIDATE_FILE) {
      delete_from_reassembly_queue(*candidate);
    }

    if ((*candidate)->best_choices) {
      destroy_queue((*candidate)->best_choices);
      free((*candidate)->best_choices);
      (*candidate)->best_choices = NULL;
    }

    if ((*candidate)->b) {
      free_blockvector(&((*candidate)->b));
    }

    // free any carve state associated with this candidate, if the candidate is associated with a
    // file carving operation. Note that block state CANNOT be freed unless the blocks are
    // associated with a validated file AND a blockmap update is performed, so that isn't done here.
    if ((*candidate)->workload == VALIDATE_FILE && scalpel_state.search_specs[(*candidate)->needleidx].carve_state) {
      carve_free_state((*candidate)->carvehashkey);
    }

    free(*candidate);
    *candidate = NULL;
  }
}


// hash one file in checkpoint set
static bool checkpoint_hash_file(const char *filepath, unsigned char hash[32]) {

  FILE *fp = fopen(filepath, "rb");
  if (! fp) {
    return false;
  }

  fseek(fp, 0, SEEK_END);
  long size = ftell(fp);
  fseek(fp, 0, SEEK_SET);
  if (size <= 0) { fclose(fp); return false; }
  unsigned char *data = malloc(size);
  if (!data || fread(data, 1, size, fp) != (size_t)size) {
        free(data); fclose(fp); return false;
  }

  fclose(fp);
  SHA256(data, size, hash);
  free(data);
  return true;
}


// save checkpoint manifest to support checkpoint integrity checks
static bool checkpoint_save_manifest(void) {

  CheckpointManifest m = {0};
  char path[PATH_MAX];
  FILE *fp;
  unsigned char key[32];
  int idx = 0;

  m.sequence_number = checkpoint_get_sequence();
  m.timestamp = time(NULL);
  memcpy(m.scalpel_sha256, scalpel_state.sha256, 32);

  // hash all checkpoint files
#define ADD_FILE(name) \
        snprintf(path, sizeof(path), "%s/%s", scalpel_state.base_output_directory, name); \
        if (checkpoint_hash_file(path, m.files[idx].sha256)) { \
          strncpy(m.files[idx].filename, name, PATH_MAX - 1);\
          idx++; \
        }

  // these live in the scalpel-output directory
  ADD_FILE("scalpel_state.chk");
  ADD_FILE("promising_queue.chk");
  ADD_FILE("blocktypes.chk");

  m.num_files = idx;
  if (idx == 0) {
    return false;
  }

  // sign with HMAC
  memcpy(key, scalpel_state.sha256, 32);
  HMAC(EVP_sha256(), key, 32, (unsigned char*)&m,
       offsetof(CheckpointManifest, hmac), m.hmac, NULL);

  // save
  snprintf(path, sizeof(path), "%s/checkpoint_manifest.chk", scalpel_state.base_output_directory);
  fp = fopen(path, "wb");
  if (! fp || fwrite(&m, sizeof(m), 1, fp) != 1) {
    if (fp) {
      fclose(fp);
    }
    return false;
  }

  fclose(fp);
  return true;
}


// verify checkpoint integrity
static bool checkpoint_verify_manifest(void) {

  CheckpointManifest m;
  char path[PATH_MAX];
  FILE *fp;
  unsigned char key[32], hmac[32], hash[32];

  snprintf(path, sizeof(path), "%s/checkpoint_manifest.chk", scalpel_state.base_output_directory);
  fp = fopen(path, "rb");
  if (! fp || fread(&m, sizeof(m), 1, fp) != 1) {
    if (fp) {
      fclose(fp);
    }
    lock_fprintf(stderr,"Couldn't read checkpoint manifest.\n");
    return false;
  }

  fclose(fp);

  lock_fprintf(stdout, "Verifying checkpoint...\n");

  // verify HMAC
  memcpy(key, scalpel_state.sha256, 32);
  HMAC(EVP_sha256(), key, 32, (unsigned char*)&m,
       offsetof(CheckpointManifest, hmac), hmac, NULL);
  if (memcmp(hmac, m.hmac, 32) != 0) {
    lock_fprintf(stderr, "Manifest HMAC verification failed.\n");
    return false;
  }

  // verify all checkpoint files
  for (int i = 0; i < m.num_files; i++) {
    snprintf(path, sizeof(path), "%s/%s", scalpel_state.base_output_directory, m.files[i].filename);
    lock_fprintf(stdout, "  %s... ", m.files[i].filename);
    fflush(stdout);
    if (! checkpoint_hash_file(path, hash) || memcmp(hash, m.files[i].sha256, 32) != 0) {
      lock_fprintf(stdout, "FAILED.\n");
      return false;
    }
    lock_fprintf(stdout, "OK.\n");
  }

  fprintf(stdout, "Done.\n");
  return true;
}


// get sequence number for checkpoint
static uint64_t checkpoint_get_sequence(void) {

  struct timespec ts;
  if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
    return 0;
  }

  return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}


// serialize one element of the promising queue. CarveInfo field last_start is not serialized, since
// it tracks reassembly time devoted to the candidate during most recent assignment to a thread.
static bool promising_queue_element_serialization(void **element, int64_t *priority, FILE *fp, StateSerialization mode) {

  size_t (*fb)(void *ptr, size_t size, size_t nitems,
               FILE *stream) = mode == SERIALIZE ? (size_t (*)(void *ptr, size_t size, size_t nitems, FILE *stream))fwrite
                                                 : (size_t (*)(void *ptr, size_t size, size_t nitems, FILE *stream))fread;

  void *slot = *element;
  CarveInfo *c;
  CarveInfo **tmp = (CarveInfo **)slot;

  if (mode == SERIALIZE) {
    c = *tmp;
  }
  else {
    c = calloc(1, sizeof(*c));
    check_memory_allocation(c, __LINE__, __FILE__, "c");
    *tmp = c;
  }

  // priority field for queue element
  if (fb(priority, sizeof(*priority), 1, fp) != 1) {
    perror("priority");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  // workload:
  if (fb(&(c->workload), sizeof(c->workload), 1, fp) != 1) {
    perror("workload");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  // needleidx:
  if (fb(&(c->needleidx), sizeof(c->needleidx), 1, fp) != 1) {
    perror("needleidx");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  // b (blockvector):
  if (mode == SERIALIZE) {
    // write important fields for the blockvector c->b. The data isn't written, as the blockvector
    // can be reinflated using image data on demand. This function will not return if there's an
    // error.
    seq_write_blockvector(c->b, fp);
  }
  else {
    // initialize and read important fields for the blockvector c->b. This function will not return
    // if there's an error.
    seq_read_blockvector(scalpel_state.filemirror, &(c->b), fp);
  }

  // chopped:
  if (fb(&(c->chopped), sizeof(c->chopped), 1, fp) != 1) {
    perror("chopped");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  // cloned:
  if (fb(&(c->cloned), sizeof(c->cloned), 1, fp) != 1) {
    perror("cloned");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  // clone:
  if (fb(&(c->clone), sizeof(c->clone), 1, fp) != 1) {
    perror("clone");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  // deposited:
  if (fb(&(c->deposited), sizeof(c->deposited), 1, fp) != 1) {
    perror("deposited");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  // partial_artifact_written:
  if (fb(&(c->partial_artifact_written), sizeof(c->partial_artifact_written), 1, fp) != 1) {
    perror("partial_artifact_written");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  // qposition:
  if (fb(&(c->qposition), sizeof(c->qposition), 1, fp) != 1) {
    perror("qposition");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  // flavor:
  if (fb(&(c->flavor), sizeof(c->flavor), 1, fp) != 1) {
    perror("flavor");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  // best_validates_to:
  if (fb(&(c->best_validates_to), sizeof(c->best_validates_to), 1, fp) != 1) {
    perror("best_validates_to");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  // newblock:
  if (fb(&(c->newblock), sizeof(c->newblock), 1, fp) != 1) {
    perror("newblock");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  // block_choice_start:
  if (fb(&(c->block_choice_start), sizeof(c->block_choice_start), 1, fp) != 1) {
    perror("block_choice_start");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  // no_initial_block_extension
  if (fb(&(c->no_initial_block_extension), sizeof(c->no_initial_block_extension), 1, fp) != 1) {
    perror("no_initial_block_extension");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  // fastpath
  if (fb(&(c->fastpath), sizeof(c->fastpath), 1, fp) != 1) {
    perror("fastpath");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  static const uint64_t PQ_BEST_MAGIC = 0xB35DB3357A17CAFEULL;

  // debug sentinel: prove alignment right before best_choices
  if (mode == SERIALIZE) {
    if (fwrite(&PQ_BEST_MAGIC, sizeof(PQ_BEST_MAGIC), 1, fp) != 1) {
      perror("pq_best_magic(write)");
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
  }
  else {
    uint64_t chk = 0;

    if (fread(&chk, sizeof(chk), 1, fp) != 1) {
      perror("pq_best_magic(read)");
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
    if (chk != PQ_BEST_MAGIC) {
      long pos = ftell(fp);

      fprintf(stderr,
              "[ckpt dbg] BEST_MAGIC mismatch before best_choices: "
              "got=0x%016llx pos=%ld (misalignment happens earlier)\n",
              (unsigned long long)chk, pos);
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
  }

  // best_choices:
  if (mode == SERIALIZE) {
    if (! serialize_queue(c->best_choices, best_choices_element_serialization, fp)) {
      // fatal
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
  }
  else {
    c->best_choices = malloc(sizeof(Queue));
    check_memory_allocation(c->best_choices, __LINE__, __FILE__, "c->best_choices");
    init_queue(c->best_choices, sizeof(int64_t), true, NULL, true);
    if (! deserialize_queue(c->best_choices, best_choices_element_serialization, false, fp)) {
      // fatal
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
  }

  // binuuid
  if (fb(c->binuuid, sizeof(c->binuuid), 1, fp) != 1) {
    perror("binuuid");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  // clone_binuuid
  if (fb(c->clone_binuuid, sizeof(c->clone_binuuid), 1, fp) != 1) {
    perror("clone_binuuid");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  // block validation candidates are never checkpointed, because block validation completes before
  // scalpel3 becomes responsive to checkpointing, so only carvehashkey is written here

  // hash key
  if (fb(c->carvehashkey, sizeof(c->carvehashkey), 1, fp) != 1) {
    perror("carvehashkey");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (mode == DESERIALIZE) {
    c->filetype = scalpel_state.search_specs[c->needleidx].FILETYPE;
    c->searchtype = scalpel_state.search_specs[c->needleidx].SEARCHTYPE;
  }

  return true;
}


// serialize one element of a best_choices queue
static bool best_choices_element_serialization(void **element, int64_t *priority, FILE *fp, StateSerialization mode) {

  size_t (*fb)(void *, size_t, size_t, FILE *) = mode == SERIALIZE ? (size_t (*)(void *, size_t, size_t, FILE *))fwrite
                                                                   : (size_t (*)(void *, size_t, size_t, FILE *))fread;

  void *slot = *element;

  // priority
  if (fb(priority, sizeof(*priority), 1, fp) != 1) {
    perror("priority");
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (mode == SERIALIZE) {
    int64_t *block = (int64_t *)slot;
    if (fb(block, sizeof(*block), 1, fp) != 1) {
      perror("block");
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
  }
  else {             // DESERIALIZE
    int64_t *buf = (int64_t *)calloc(1, sizeof(int64_t));
    check_memory_allocation(buf, __LINE__, __FILE__, "best_choices buf");
    if (fb(buf, sizeof(*buf), 1, fp) != 1) {
      perror("block");
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
    *element = buf;  // give bytes back to prioque
  }

  return true;
}


// prune any elements matching a specified UUID from the promising queue
static void prune_uuid_from_promising_queue(uuid_t uuid) {

  static CarveInfo *c = NULL;
  CarveInfo **candidate = NULL;

  lock_queue(&promising_queue);

  // this is thread-safe because of the queue lock
  if (! c) {
    c = calloc(1, sizeof(CarveInfo));
    check_memory_allocation(c, __LINE__, __FILE__, "c");
  }

  // the promising queue's comparison function matches either UUID in the candidate, so just set
  // both
  memcpy(c->binuuid, uuid, sizeof(uuid_t));
  memcpy(c->clone_binuuid, uuid, sizeof(uuid_t));

  while (nolock_element_in_queue(&promising_queue, &c)) {
    candidate = nolock_pointer_to_current(&promising_queue);
    destroy_candidate(candidate);
    nolock_delete_current(&promising_queue);
  }

  unlock_queue(&promising_queue);
}


// sync the promising and kill queues by ensuring that the promising queue is purged of any UUIDs
// present in the kill queue. Kill orders are retained so active writers can suppress stale
// PROMISING/INPROGRESS output until the normal kill queue pruning interval expires.
static void sync_promising_and_kill_queues(void) {

  lock_queue(&kill_queue);
  nolock_rewind_queue(&kill_queue);
  while (! nolock_end_of_queue(&kill_queue)) {
    prune_uuid_from_promising_queue(nolock_pointer_to_current(&kill_queue));
    nolock_next_element(&kill_queue);
  }
  unlock_queue(&kill_queue);
}


static bool primary_uuid_is_killed(uuid_t uuid) {

  return atomic_load_explicit(&kill_queue_initialized, memory_order_acquire)
         && element_in_queue(&kill_queue, uuid);
}


static void queue_partial_cleanup(uuid_t uuid) {

  if (! atomic_load_explicit(&partial_cleanup_queue_initialized, memory_order_acquire)) {
    return;
  }

  add_to_queue(&partial_cleanup_queue, uuid, INT_MAX - time(NULL));

  MUTEX_ERROR_CHECK(pthread_mutex_lock(&partial_cleanup_work_is_available), __LINE__, __FILE__);
  pthread_cond_signal(&partial_cleanup_check_work_available);
  MUTEX_ERROR_CHECK(pthread_mutex_unlock(&partial_cleanup_work_is_available), __LINE__, __FILE__);
}


static void cleanup_partial_artifacts(uuid_t uuid) {

  char purge_pathname[PATH_MAX];
  uuid_string_t uuidp;

  uuid_unparse_lower(uuid, uuidp);

  snprintf(purge_pathname, PATH_MAX, "*PROMISING/*/UUIDS-$$%s$$*", uuidp);
  delete_files_recursive(scalpel_state.base_output_directory, purge_pathname);
  snprintf(purge_pathname, PATH_MAX, "*INPROGRESS/*/UUIDS-$$%s$$*", uuidp);
  delete_files_recursive(scalpel_state.base_output_directory, purge_pathname);
}


typedef struct RestoreUUIDSet {
  uuid_t *uuids;
  uint64_t count;
  uint64_t capacity;
} RestoreUUIDSet;


static int restore_uuid_compare(const void *a, const void *b) {

  return uuid_compare((const unsigned char *)a, (const unsigned char *)b);
}


static bool restore_parse_primary_uuid(const char *name, uuid_t uuid) {

  char textuuid[37];
  const char *uuid_start = strstr(name, "UUIDS-$$");

  if (! uuid_start) {
    return false;
  }

  uuid_start += strlen("UUIDS-$$");
  if (strlen(uuid_start) < 38 || uuid_start[36] != '$' || uuid_start[37] != '$') {
    return false;
  }

  memcpy(textuuid, uuid_start, 36);
  textuuid[36] = 0;

  return uuid_parse(textuuid, uuid) == 0;
}


static void restore_uuid_set_add(RestoreUUIDSet *set, uuid_t uuid) {

  if (set->count == set->capacity) {
    uint64_t new_capacity = set->capacity ? set->capacity * 2 : 1024;

    set->uuids = realloc(set->uuids, new_capacity * sizeof(uuid_t));
    check_memory_allocation(set->uuids, __LINE__, __FILE__, "restore uuid set");
    set->capacity = new_capacity;
  }

  uuid_copy(set->uuids[set->count++], uuid);
}


static void restore_uuid_set_sort_unique(RestoreUUIDSet *set) {

  uint64_t i;
  uint64_t out = 0;

  if (set->count == 0) {
    return;
  }

  qsort(set->uuids, set->count, sizeof(uuid_t), restore_uuid_compare);

  for (i = 0; i < set->count; i++) {
    if (out == 0 || uuid_compare(set->uuids[out - 1], set->uuids[i])) {
      if (out != i) {
        uuid_copy(set->uuids[out], set->uuids[i]);
      }
      out++;
    }
  }

  set->count = out;
}


static bool restore_uuid_set_contains(RestoreUUIDSet *set, uuid_t uuid) {

  return set->count > 0
         && bsearch(uuid, set->uuids, set->count, sizeof(uuid_t),
                    restore_uuid_compare) != NULL;
}


static void restore_collect_validated_uuids(const char *current_path,
                                            RestoreUUIDSet *set) {

  DIR *dir;
  struct dirent *entry;
  char path[PATH_MAX];
  struct stat statbuf;
  uuid_t uuid;

  if (! (dir = opendir(current_path))) {
    return;
  }

  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
      continue;
    }

    if (snprintf(path, sizeof(path), "%s/%s", current_path, entry->d_name) >= PATH_MAX) {
      continue;
    }

    if (lstat(path, &statbuf) == -1) {
      continue;
    }

    if (S_ISDIR(statbuf.st_mode)) {
      restore_collect_validated_uuids(path, set);
    }
    else if (S_ISREG(statbuf.st_mode)
             && strstr(path, "/VALIDATED/")
             && restore_parse_primary_uuid(entry->d_name, uuid)) {
      restore_uuid_set_add(set, uuid);
    }
  }

  closedir(dir);
}


static void restore_delete_validated_promising(const char *current_path,
                                               RestoreUUIDSet *set,
                                               uint64_t *deleted) {

  DIR *dir;
  struct dirent *entry;
  char path[PATH_MAX];
  struct stat statbuf;
  uuid_t uuid;

  if (! (dir = opendir(current_path))) {
    return;
  }

  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
      continue;
    }

    if (snprintf(path, sizeof(path), "%s/%s", current_path, entry->d_name) >= PATH_MAX) {
      continue;
    }

    if (lstat(path, &statbuf) == -1) {
      continue;
    }

    if (S_ISDIR(statbuf.st_mode)) {
      restore_delete_validated_promising(path, set, deleted);
    }
    else if (S_ISREG(statbuf.st_mode)
             && strstr(path, "/PROMISING/")
             && restore_parse_primary_uuid(entry->d_name, uuid)
             && restore_uuid_set_contains(set, uuid)) {
      if (unlink(path) == 0) {
        (*deleted)++;
      }
    }
  }

  closedir(dir);
}


static void reconcile_partial_artifacts_on_restore(void) {

  RestoreUUIDSet set = {0};
  uint64_t deleted = 0;
  char buf[MAX_STRING_LENGTH];

  restore_collect_validated_uuids(scalpel_state.base_output_directory, &set);
  restore_uuid_set_sort_unique(&set);

  if (set.count > 0) {
    restore_delete_validated_promising(scalpel_state.base_output_directory,
                                       &set, &deleted);
  }

  snprintf(buf, sizeof(buf),
           "RESTORE RECONCILIATION: %" PRIu64
           " validated UUIDs, %" PRIu64 " stale PROMISING files removed",
           set.count, deleted);
  frame_message(buf);

  free(set.uuids);
}


// read/write scalpel state from/to file 'filename'.
static void scalpel_state_serialization(StateSerialization mode, char *filename) {

  FILE *fp;
  uint32_t i, j;
  uint64_t validated_files, files_written, backtracked;
  int err;                         // tracks regex compilation success
  PCRE2_SIZE erroffset;            // offset of error in regular expression compilation
  char errmsg[MAX_STRING_LENGTH];  // scratch for err msg generation
  char imgpath[PATH_MAX];          // sanity check for image file name
  unsigned char sha256[32];        // used to detect version mismatch for scalpel executable
  size_t (*fb)(void *ptr, size_t size, size_t nitems,
               FILE *stream) = mode == SERIALIZE ? (size_t (*)(void *ptr, size_t size, size_t nitems, FILE *stream))fwrite
                                                 : (size_t (*)(void *ptr, size_t size, size_t nitems, FILE *stream))fread;

  // stash current scalpel3 SHA256
  memcpy(sha256, scalpel_state.sha256, 32);

  if (mode == SERIALIZE) {
    unlink(filename);
  }

  fp = fopen(filename, mode == SERIALIZE ? "wb" : "rb");
  if (! fp) {
    // fatal
    perror("No checkpoint file found, fopen() returned");
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  fseek(fp, 0, SEEK_SET);

  if (fb(scalpel_state.sha256, sizeof(scalpel_state.sha256), 1, fp) != 1) {
    // fatal
    perror("scalpel_state sha256");
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (! scalpel_state.no_cp_validation && mode == DESERIALIZE && memcmp(scalpel_state.sha256, sha256, 32)) {
    handle_error(SCALPEL_ERROR_CHECKPOINT_MISMATCH, NULL, __LINE__, __FILE__);
  }

  if ((err = fb(mode == SERIALIZE ? scalpel_state.image_pathname : imgpath, 1, PATH_MAX, fp)) != PATH_MAX) {
    // fatal
    perror("scalpel_state imagefile_pathname");
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"

  if (mode == DESERIALIZE && strncmp(imgpath, scalpel_state.image_pathname, PATH_MAX)) {
    // fatal
    char errmsg[MAX_STRING_LENGTH];

    snprintf(errmsg, MAX_STRING_LENGTH,
             "Specified image filename \"%s\" doesn't match "
             "checkpointed\nfilename \"%s\"",
             scalpel_state.image_pathname, imgpath);
    handle_error(SCALPEL_ERROR_CHECKPOINT_IMAGE, errmsg, __LINE__, __FILE__);
  }

  if (fb(scalpel_state.blockmap_pathname, 1, PATH_MAX, fp) != PATH_MAX) {
    // fatal
    perror("scalpel_state blockmapfile_ pathname");
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

#pragma GCC diagnostic pop

  if (fb(&(scalpel_state.blocksize), sizeof(scalpel_state.blocksize), 1, fp) != 1) {
    // fatal
    perror("scalpel state blocksize");
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (fb(&(scalpel_state.num_specs), sizeof(scalpel_state.num_specs), 1, fp) != 1) {
    // fatal
    perror("scalpel_state num_specs");
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  // correct allocation to deal with subtypes that will be read from checkpoint
  if (mode == DESERIALIZE) {
    scalpel_state.search_specs = realloc(scalpel_state.search_specs, sizeof(SearchSpec) * (scalpel_state.num_specs + 1));
    check_memory_allocation(scalpel_state.search_specs, __LINE__, __FILE__, "scalpel_state.search_specs");
    scalpel_state.search_specs[scalpel_state.num_specs].FILETYPE[0] = 0;
  }

  if (fb(&(scalpel_state.longest_footer), sizeof(scalpel_state.longest_footer), 1, fp) != 1) {
    // fatal
    perror("scalpel_state longest_footer");
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (fb(&(scalpel_state.largest_maxfilesize), sizeof(scalpel_state.largest_maxfilesize), 1, fp) != 1) {
    // fatal
    perror("scalpel_state largest_maxfilesize");
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  // validated_files and files_written are atomic--can't R/W directly

  if (mode == SERIALIZE) {
    validated_files = atomic_load_explicit(&(scalpel_state.validated_files), memory_order_acquire);
    files_written = atomic_load_explicit(&(scalpel_state.files_written), memory_order_acquire);
  }

  if (fb(&(files_written), sizeof(files_written), 1, fp) != 1) {
    perror("scalpel_state files_written");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (fb(&(validated_files), sizeof(validated_files), 1, fp) != 1) {
    perror("scalpel state validated_files");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (mode == DESERIALIZE) {
    atomic_init(&(scalpel_state.validated_files), validated_files);
    atomic_init(&(scalpel_state.files_written), files_written);
  }

  if (fb(&(scalpel_state.candidates), sizeof(scalpel_state.candidates), 1, fp) != 1) {
    perror("scalpel_state candidates");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (fb(&(scalpel_state.chopped), sizeof(scalpel_state.chopped), 1, fp) != 1) {
    perror("scalpel_state chopped");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (fb(&(scalpel_state.reduce_aggressive_allocation), sizeof(scalpel_state.reduce_aggressive_allocation), 1, fp) != 1) {
    perror("scalpel_state reduce_aggressive_allocation");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (fb(&(scalpel_state.write_blockvectors), sizeof(scalpel_state.write_blockvectors), 1, fp) != 1) {
    perror("scalpel_state write_blockvectors");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (fb(&(scalpel_state.write_promising), sizeof(scalpel_state.write_promising), 1, fp) != 1) {
    perror("scalpel_state write_promising");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (fb(&(scalpel_state.organize_subdirectories), sizeof(scalpel_state.organize_subdirectories), 1, fp) != 1) {
    perror("scalpel_state organize_subdirectories");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (fb(&(scalpel_state.max_search_threads), sizeof(scalpel_state.max_search_threads), 1, fp) != 1) {
    perror("scalpel_state max_search_threads");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (fb(&(scalpel_state.max_validation_threads), sizeof(scalpel_state.max_validation_threads), 1, fp) != 1) {
    perror("scalpel_state max_validation_threads");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (fb(&(scalpel_state.max_reassembly_threads), sizeof(scalpel_state.max_reassembly_threads), 1, fp) != 1) {
    perror("scalpel_state max_reassembly_threads");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (fb(&(scalpel_state.max_filemirror_threads), sizeof(scalpel_state.max_filemirror_threads), 1, fp) != 1) {
    perror("scalpel_state max_filemirror_threads");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (fb(&(scalpel_state.share_reassembly), sizeof(scalpel_state.share_reassembly), 1, fp) != 1) {
    perror("scalpel_state share_reassembly");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (fb(&(scalpel_state.contig_header_reuse), sizeof(scalpel_state.contig_header_reuse), 1, fp) != 1) {
    perror("scalpel_state contig_header_reuse");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (fb(&(scalpel_state.no_defrag), sizeof(scalpel_state.no_defrag), 1, fp) != 1) {
    perror("scalpel_state no_defrag");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (fb(&(scalpel_state.backtrack), sizeof(scalpel_state.backtrack), 1, fp) != 1) {
    perror("scalpel_state backtrack");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (fb(&(scalpel_state.start_block), sizeof(scalpel_state.start_block), 1, fp) != 1) {
    perror("scalpel_state start_block");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (fb(&(scalpel_state.end_block), sizeof(scalpel_state.end_block), 1, fp) != 1) {
    perror("scalpel_state end_block");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (fb(&(scalpel_state.reservations), sizeof(scalpel_state.reservations), 1, fp) != 1) {
    perror("scalpel_state reservations");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (fb(&(scalpel_state.memory_profiling), sizeof(scalpel_state.memory_profiling), 1, fp) != 1) {
    perror("scalpel_state memory_profiling");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (fb(&(scalpel_state.disable_shadow_peeking), sizeof(scalpel_state.disable_shadow_peeking), 1, fp) != 1) {
    perror("scalpel_state disable_shadow_peeking");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (fb(&(scalpel_state.disable_backtrace), sizeof(scalpel_state.disable_backtrace), 1, fp) != 1) {
    perror("scalpel_state disable_backtrace");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (fb(&(scalpel_state.prioritize_types), sizeof(scalpel_state.prioritize_types), 1, fp) != 1) {
    perror("scalpel_state prioritize_types");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (fb(&(scalpel_state.write_inprogress), sizeof(scalpel_state.write_inprogress), 1, fp) != 1) {
    perror("scalpel_state write_inprogress");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (fb(&(scalpel_state.gallop_factor), sizeof(scalpel_state.gallop_factor), 1, fp) != 1) {
    perror("scalpel_state gallop_factor");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (fb(&(scalpel_state.gallop_limit), sizeof(scalpel_state.gallop_limit), 1, fp) != 1) {
    perror("scalpel_state gallop_limit");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (fb(&(scalpel_state.current_priority), sizeof(scalpel_state.current_priority), 1, fp) != 1) {
    perror("scalpel_state current_priority");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (fb(&(scalpel_state.block_validation_complete), sizeof(scalpel_state.block_validation_complete), 1, fp) != 1) {
    perror("scalpel_state block_validation_complete");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (fb(&(scalpel_state.F1_initiated), sizeof(scalpel_state.F1_initiated), 1, fp) != 1) {
    perror("scalpel_state F1_initiated");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (fb(&(scalpel_state.F2_initiated), sizeof(scalpel_state.F2_initiated), 1, fp) != 1) {
    perror("scalpel_state F2_initiated");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  // now serialize the scalpel_state.search_specs array, omitting MASTER file types from
  // serialization / deserialization, since MASTER file types will not be used to create new file
  // subtypes after the block validation phase

  for (i = 0; i < scalpel_state.num_specs; i++) {
    if (fb(&(scalpel_state.search_specs[i].MASTER), sizeof(scalpel_state.search_specs[i].MASTER), 1, fp) != 1) {
      perror("scalpel_state MASTER");
      // fatal
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    if (scalpel_state.search_specs[i].MASTER) {
      continue;
    }

    if (fb(scalpel_state.search_specs[i].FILETYPE, MAX_STRING_LENGTH, 1, fp) != 1) {
      perror("scalpel_state FILETYPE");
      // fatal
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    if (fb(&(scalpel_state.search_specs[i].CASESENSITIVE), sizeof(scalpel_state.search_specs[i].CASESENSITIVE), 1, fp) != 1) {
      perror("scalpel_state CASESENSITIVE");
      // fatal
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    if (fb(&(scalpel_state.search_specs[i].MAXIMUMSIZE), sizeof(scalpel_state.search_specs[i].MAXIMUMSIZE), 1, fp) != 1) {
      perror("scalpel_state MAXIMUMSIZE");
      // fatal
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    if (fb(&(scalpel_state.search_specs[i].MINIMUMSIZE), sizeof(scalpel_state.search_specs[i].MINIMUMSIZE), 1, fp) != 1) {
      perror("scalpel_state MINIMUMSIZE");
      // fatal
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    if (fb(scalpel_state.search_specs[i].HEADER, MAX_STRING_LENGTH, 1, fp) != 1) {
      perror("scalpel_state HEADER");
      // fatal
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    if (fb(scalpel_state.search_specs[i].begin, MAX_STRING_LENGTH, 1, fp) != 1) {
      perror("scalpel_state begin");
      // fatal
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    if (fb(&(scalpel_state.search_specs[i].beginlength), sizeof(scalpel_state.search_specs[i].beginlength), 1, fp) != 1) {
      perror("scalpel_state beginlength");
      // fatal
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    if (fb(&(scalpel_state.search_specs[i].begin_is_RE), sizeof(scalpel_state.search_specs[i].begin_is_RE), 1, fp) != 1) {
      perror("scalpel_state begin_is_RE");
      // fatal
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    if (fb(scalpel_state.search_specs[i].FOOTER, MAX_STRING_LENGTH, 1, fp) != 1) {
      perror("scalpel_state FOOTER");
      // fatal
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    if (fb(scalpel_state.search_specs[i].end, MAX_STRING_LENGTH, 1, fp) != 1) {
      perror("scalpel_state end");
      // fatal
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    if (fb(&(scalpel_state.search_specs[i].endlength), sizeof(scalpel_state.search_specs[i].endlength), 1, fp) != 1) {
      perror("scalpel_state endlength");
      // fatal
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    if (fb(&(scalpel_state.search_specs[i].end_is_RE), sizeof(scalpel_state.search_specs[i].end_is_RE), 1, fp) != 1) {
      perror("scalpel_state end_is_RE");
      // fatal
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    if (fb(&(scalpel_state.search_specs[i].mastertype), sizeof(scalpel_state.search_specs[i].mastertype), 1, fp) != 1) {
      perror("scalpel_state mastertype");
      // fatal
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    if (fb(&(scalpel_state.search_specs[i].SEARCHTYPE), sizeof(scalpel_state.search_specs[i].SEARCHTYPE), 1, fp) != 1) {
      perror("scalpel_state SEARCHTYPE");
      // fatal
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    if (fb(&(scalpel_state.search_specs[i].PRIORITY), sizeof(scalpel_state.search_specs[i].PRIORITY), 1, fp) != 1) {
      perror("scalpel_state PRIORITY");
      // fatal
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    if (fb(&(scalpel_state.search_specs[i].NO_DEFRAG), sizeof(scalpel_state.search_specs[i].NO_DEFRAG), 1, fp) != 1) {
      perror("scalpel_state NO_DEFRAG");
      // fatal
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    // function pointers cannot be serialized--they are just copied from INITIAL_SEARCH_SPECS on
    // checkpoint restore

    if (mode == DESERIALIZE) {
      scalpel_state.search_specs[i].HEADERFUNC = INITIAL_SEARCH_SPECS[scalpel_state.search_specs[i].mastertype].HEADERFUNC;
      scalpel_state.search_specs[i].FOOTERFUNC = INITIAL_SEARCH_SPECS[scalpel_state.search_specs[i].mastertype].FOOTERFUNC;
      scalpel_state.search_specs[i].BLOCKVALIDATOR = INITIAL_SEARCH_SPECS[scalpel_state.search_specs[i].mastertype].BLOCKVALIDATOR;
      scalpel_state.search_specs[i].FILEVALIDATOR = INITIAL_SEARCH_SPECS[scalpel_state.search_specs[i].mastertype].FILEVALIDATOR;
      scalpel_state.search_specs[i].DONTCARVE = INITIAL_SEARCH_SPECS[scalpel_state.search_specs[i].mastertype].DONTCARVE;
      scalpel_state.search_specs[i].REASSEMBLYFUNC = INITIAL_SEARCH_SPECS[scalpel_state.search_specs[i].mastertype].REASSEMBLYFUNC;
      scalpel_state.search_specs[i].SERIALIZECARVESTATEFUNC = INITIAL_SEARCH_SPECS[scalpel_state.search_specs[i].mastertype]
                                                                  .SERIALIZECARVESTATEFUNC;
      scalpel_state.search_specs[i].CLONECARVESTATEFUNC = INITIAL_SEARCH_SPECS[scalpel_state.search_specs[i].mastertype]
                                                              .CLONECARVESTATEFUNC;
      scalpel_state.search_specs[i].FREECARVESTATEFUNC = INITIAL_SEARCH_SPECS[scalpel_state.search_specs[i].mastertype]
                                                             .FREECARVESTATEFUNC;
      scalpel_state.search_specs[i].SIZEOFCARVESTATEFUNC = INITIAL_SEARCH_SPECS[scalpel_state.search_specs[i].mastertype]
                                                               .SIZEOFCARVESTATEFUNC;
      scalpel_state.search_specs[i].PRINTCARVESTATEFUNC = INITIAL_SEARCH_SPECS[scalpel_state.search_specs[i].mastertype]
                                                              .PRINTCARVESTATEFUNC;
      scalpel_state.search_specs[i].SERIALIZEBLOCKSTATEFUNC = INITIAL_SEARCH_SPECS[scalpel_state.search_specs[i].mastertype]
                                                                  .SERIALIZEBLOCKSTATEFUNC;
      scalpel_state.search_specs[i].CLONEBLOCKSTATEFUNC = INITIAL_SEARCH_SPECS[scalpel_state.search_specs[i].mastertype]
                                                              .CLONEBLOCKSTATEFUNC;
      scalpel_state.search_specs[i].FREEBLOCKSTATEFUNC = INITIAL_SEARCH_SPECS[scalpel_state.search_specs[i].mastertype]
                                                             .FREEBLOCKSTATEFUNC;
      scalpel_state.search_specs[i].SIZEOFBLOCKSTATEFUNC = INITIAL_SEARCH_SPECS[scalpel_state.search_specs[i].mastertype]
                                                               .SIZEOFBLOCKSTATEFUNC;
      scalpel_state.search_specs[i].PRINTBLOCKSTATEFUNC = INITIAL_SEARCH_SPECS[scalpel_state.search_specs[i].mastertype]
                                                              .PRINTBLOCKSTATEFUNC;
    }

    // save or create and recover state hashtables for block and carving operations global state

    // carve_state: size-prefixed so mergecps can skip/copy without needing type-specific callbacks
    if (mode == SERIALIZE) {
      long size_pos = ftell(fp);
      uint64_t placeholder = 0;
      if (fwrite(&placeholder, sizeof(placeholder), 1, fp) != 1) {
        perror("scalpel_state carve_state size");
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
      }
      if (scalpel_state.search_specs[i].SERIALIZECARVESTATEFUNC) {
        if (! oa_hash_serialize(scalpel_state.search_specs[i].carve_state, fp)) {
          perror("scalpel_state carve_state");
          handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
        }
        long end_pos = ftell(fp);
        uint64_t blob_size = (uint64_t)(end_pos - size_pos) - sizeof(uint64_t);
        if (fseek(fp, size_pos, SEEK_SET) != 0 ||
            fwrite(&blob_size, sizeof(blob_size), 1, fp) != 1 ||
            fseek(fp, end_pos, SEEK_SET) != 0) {
          perror("scalpel_state carve_state backpatch");
          handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
        }
      }
    }
    else {
      uint64_t blob_size;
      if (fread(&blob_size, sizeof(blob_size), 1, fp) != 1) {
        perror("scalpel_state carve_state blob_size");
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
      }
      long blob_start = ftell(fp);
      if (scalpel_state.search_specs[i].SERIALIZECARVESTATEFUNC && blob_size > 0) {
        oa_key_ops *key_ops = malloc(sizeof(oa_key_ops));
        check_memory_allocation(key_ops, __LINE__, __FILE__, "key_ops");

        oa_val_ops *val_ops = malloc(sizeof(oa_val_ops));
        check_memory_allocation(val_ops, __LINE__, __FILE__, "val_ops");

        *key_ops = (oa_key_ops){.hash = oa_carve_key_hash,
                                .cp = oa_carve_key_cp,
                                .free = oa_binary_key_free,
                                .eq = oa_carve_key_eq,
                                .serialize = oa_carve_key_ser,
                                .size_of = oa_carve_key_sizeof};

        *val_ops = (oa_val_ops){.cp = scalpel_state.search_specs[i].CLONECARVESTATEFUNC,
                                .free = scalpel_state.search_specs[i].FREECARVESTATEFUNC,
                                .serialize = scalpel_state.search_specs[i].SERIALIZECARVESTATEFUNC,
                                .size_of = scalpel_state.search_specs[i].SIZEOFCARVESTATEFUNC};

        scalpel_state.search_specs[i].carve_state = oa_hash_new(*key_ops, *val_ops);

        if (! oa_hash_deserialize(scalpel_state.search_specs[i].carve_state, fp)) {
          perror("scalpel_state carve_state");
          handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
        }
      }
      else {
        scalpel_state.search_specs[i].carve_state = NULL;
      }
      // alignment guard: advance to end of blob regardless of what deserialize consumed
      fseek(fp, blob_start + (long)blob_size, SEEK_SET);
    }

    // block_state: size-prefixed so mergecps can skip/copy without needing type-specific callbacks
    if (mode == SERIALIZE) {
      long size_pos = ftell(fp);
      uint64_t placeholder = 0;
      if (fwrite(&placeholder, sizeof(placeholder), 1, fp) != 1) {
        perror("scalpel_state block_state size");
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
      }
      if (scalpel_state.search_specs[i].SERIALIZEBLOCKSTATEFUNC) {
        if (! oa_hash_serialize(scalpel_state.search_specs[i].block_state, fp)) {
          perror("scalpel_state block_state");
          handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
        }
        long end_pos = ftell(fp);
        uint64_t blob_size = (uint64_t)(end_pos - size_pos) - sizeof(uint64_t);
        if (fseek(fp, size_pos, SEEK_SET) != 0 ||
            fwrite(&blob_size, sizeof(blob_size), 1, fp) != 1 ||
            fseek(fp, end_pos, SEEK_SET) != 0) {
          perror("scalpel_state block_state backpatch");
          handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
        }
      }
    }
    else {
      uint64_t blob_size;
      if (fread(&blob_size, sizeof(blob_size), 1, fp) != 1) {
        perror("scalpel_state block_state blob_size");
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
      }
      long blob_start = ftell(fp);
      if (scalpel_state.search_specs[i].SERIALIZEBLOCKSTATEFUNC && blob_size > 0) {
        oa_key_ops *key_ops = malloc(sizeof(oa_key_ops));
        check_memory_allocation(key_ops, __LINE__, __FILE__, "key_ops");

        oa_val_ops *val_ops = malloc(sizeof(oa_val_ops));
        check_memory_allocation(val_ops, __LINE__, __FILE__, "val_ops");

        *key_ops = (oa_key_ops){.hash = oa_block_key_hash,
                                .cp = oa_block_key_cp,
                                .free = oa_binary_key_free,
                                .eq = oa_block_key_eq,
                                .serialize = oa_block_key_ser,
                                .size_of = oa_block_key_sizeof};

        *val_ops = (oa_val_ops){.cp = scalpel_state.search_specs[i].CLONEBLOCKSTATEFUNC,
                                .free = scalpel_state.search_specs[i].FREEBLOCKSTATEFUNC,
                                .serialize = scalpel_state.search_specs[i].SERIALIZEBLOCKSTATEFUNC,
                                .size_of = scalpel_state.search_specs[i].SIZEOFBLOCKSTATEFUNC};

        scalpel_state.search_specs[i].block_state = oa_hash_new(*key_ops, *val_ops);

        if (! oa_hash_deserialize(scalpel_state.search_specs[i].block_state, fp)) {
          perror("scalpel_state block_state");
          handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
        }
      }
      else {
        scalpel_state.search_specs[i].block_state = NULL;
      }
      // alignment guard: advance to end of blob regardless of what deserialize consumed
      fseek(fp, blob_start + (long)blob_size, SEEK_SET);
    }

    if (fb(&(scalpel_state.search_specs[i].per_pass_candidates), sizeof(scalpel_state.search_specs[i].per_pass_candidates), 1, fp)
        != 1) {
      perror("scalpel_state per_pass_candidates");
      // fatal
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    if (fb(&(scalpel_state.search_specs[i].candidates), sizeof(scalpel_state.search_specs[i].candidates), 1, fp) != 1) {
      perror("scalpel_state candidates");
      // fatal
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    if (fb(&(scalpel_state.search_specs[i].chopped), sizeof(scalpel_state.search_specs[i].chopped), 1, fp) != 1) {
      perror("scalpel_state chopped");
      // fatal
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    // .validated_files is atomic--can't R/W directly

    if (mode == SERIALIZE) {
      validated_files = atomic_load_explicit(&(scalpel_state.search_specs[i].validated_files), memory_order_acquire);
    }

    if (fb(&(validated_files), sizeof(validated_files), 1, fp) != 1) {
      perror("scalpel_state validated_files");
      // fatal
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    if (mode == DESERIALIZE) {
      atomic_init(&(scalpel_state.search_specs[i].validated_files), validated_files);
    }

    // .backtracked is atomic--can't R/W directly

    if (mode == SERIALIZE) {
      backtracked = atomic_load_explicit(&(scalpel_state.search_specs[i].backtracked), memory_order_acquire);
    }

    if (fb(&(backtracked), sizeof(backtracked), 1, fp) != 1) {
      perror("scalpel_state backtracked");
      // fatal
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    if (mode == DESERIALIZE) {
      atomic_init(&(scalpel_state.search_specs[i].backtracked), backtracked);
    }

    if (mode == DESERIALIZE) {
      scalpel_state.search_specs[i].validated_in_subdir = 0;
      scalpel_state.search_specs[i].promising_in_subdir = 0;
      scalpel_state.search_specs[i].inprogress_in_subdir = 0;
      scalpel_state.search_specs[i].v_organize_dir_num = 0;
      scalpel_state.search_specs[i].p_organize_dir_num = 0;
      scalpel_state.search_specs[i].i_organize_dir_num = 0;
      scalpel_state.search_specs[i].v_current_subdir[0] = 0;
      scalpel_state.search_specs[i].p_current_subdir[0] = 0;
      scalpel_state.search_specs[i].i_current_subdir[0] = 0;
    }

    // a checkpoint restore could either resume using the timestamped subdir that was in use when
    // the checkpoint was taken or just start with a new one. The current implementation is to use a
    // new one, which seems to make more sense. Because of this decision, the # of files written so
    // far in each subdir, etc. are not serialized, but instead just reset to 0 on checkpoint
    // restore. This is why the following lines are commented out and the fields just initialized to
    // zero (above) instead.

    // .offsets area of scalpel_state.search_specs[i].  These comprise the scalpel3 header/footer
    // database.

    if (fb(&(scalpel_state.search_specs[i].offsets.numheaders), sizeof(scalpel_state.search_specs[i].offsets.numheaders), 1, fp)
        != 1) {
      perror("scalpel_state numheaders");
      // fatal
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    if (fb(&(scalpel_state.search_specs[i].offsets.numfooters), sizeof(scalpel_state.search_specs[i].offsets.numfooters), 1, fp)
        != 1) {
      perror("scalpel_state numfooters");
      // fatal
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    // on restore, set headerstorage and footerstorage to actual number of headers and footers,
    // since this is unlikely to change--checkpointing is always completed after a header/footer
    // search

    if (mode == DESERIALIZE) {
      scalpel_state.search_specs[i].offsets.headerstorage = scalpel_state.search_specs[i].offsets.numheaders;
      scalpel_state.search_specs[i].offsets.footerstorage = scalpel_state.search_specs[i].offsets.numfooters;
    }

    // on restore, allocate storage for headers and footers before reading

    if (mode == DESERIALIZE) {
      if (scalpel_state.search_specs[i].offsets.numheaders > 0) {
        scalpel_state.search_specs[i].offsets.headers = (uint64_t *)malloc(sizeof(uint64_t)
                                                                           * scalpel_state.search_specs[i].offsets.numheaders);
        check_memory_allocation(scalpel_state.search_specs[i].offsets.headers, __LINE__, __FILE__, "headers array");

        scalpel_state.search_specs[i].offsets.headerlens = (size_t *)malloc(sizeof(size_t)
                                                                            * scalpel_state.search_specs[i].offsets.numheaders);
        check_memory_allocation(scalpel_state.search_specs[i].offsets.headerlens, __LINE__, __FILE__, "headerlens array");

        scalpel_state.search_specs[i].offsets.deposited = (bool *)malloc(sizeof(bool)
                                                                         * scalpel_state.search_specs[i].offsets.numheaders);
        check_memory_allocation(scalpel_state.search_specs[i].offsets.deposited, __LINE__, __FILE__, "deposited");
      }
      else {
        scalpel_state.search_specs[i].offsets.headers = NULL;
        scalpel_state.search_specs[i].offsets.headerlens = NULL;
        scalpel_state.search_specs[i].offsets.deposited = NULL;
      }

      if (scalpel_state.search_specs[i].offsets.numfooters > 0) {
        scalpel_state.search_specs[i].offsets.footers = (uint64_t *)malloc(sizeof(uint64_t)
                                                                           * scalpel_state.search_specs[i].offsets.numfooters);
        check_memory_allocation(scalpel_state.search_specs[i].offsets.footers, __LINE__, __FILE__, "footers array");

        scalpel_state.search_specs[i].offsets.footerlens = (size_t *)malloc(sizeof(size_t)
                                                                            * scalpel_state.search_specs[i].offsets.numfooters);
        check_memory_allocation(scalpel_state.search_specs[i].offsets.footerlens, __LINE__, __FILE__, "footerlens array");
      }
      else {
        scalpel_state.search_specs[i].offsets.footers = NULL;
        scalpel_state.search_specs[i].offsets.footerlens = NULL;
      }
    }

    // read/write arrays of headers, headerlens, footers, footerlens
    for (j = 0; j < scalpel_state.search_specs[i].offsets.numheaders; j++) {
      if (fb(&(scalpel_state.search_specs[i].offsets.headers[j]), sizeof(scalpel_state.search_specs[i].offsets.headers[j]), 1, fp)
          != 1) {
        perror("headers");
        // fatal
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
      }

      if (fb(&(scalpel_state.search_specs[i].offsets.headerlens[j]), sizeof(scalpel_state.search_specs[i].offsets.headerlens[j]), 1,
             fp)
          != 1) {
        perror("headerlens");
        // fatal
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
      }

      if (fb(&(scalpel_state.search_specs[i].offsets.deposited[j]), sizeof(scalpel_state.search_specs[i].offsets.deposited[j]), 1,
             fp)
          != 1) {
        perror("deposited");
        // fatal
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
      }
    }

    for (j = 0; j < scalpel_state.search_specs[i].offsets.numfooters; j++) {
      if (fb(&(scalpel_state.search_specs[i].offsets.footers[j]), sizeof(scalpel_state.search_specs[i].offsets.footers[j]), 1, fp)
          != 1) {
        perror("footers");
        // fatal
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
      }

      if (fb(&(scalpel_state.search_specs[i].offsets.footerlens[j]), sizeof(scalpel_state.search_specs[i].offsets.footerlens[j]), 1,
             fp)
          != 1) {
        perror("footerlens");
        // fatal
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
      }
    }

    if (mode == DESERIALIZE) {
      // initialize some other fields for this file type that aren't stored in the checkpoint

      if (pthread_mutex_init(&(scalpel_state.search_specs[i].filewritelock), NULL)) {
        // fatal
        handle_error(SCALPEL_ERROR_MUTEX_FAILURE, "scalpel_state_serialization()", __LINE__, __FILE__);
      }

      if (pthread_mutex_init(&(scalpel_state.search_specs[i].offsets.headerlock), NULL)) {
        // fatal
        handle_error(SCALPEL_ERROR_MUTEX_FAILURE, "scalpel_state_serialization()", __LINE__, __FILE__);
      }

      if (pthread_mutex_init(&(scalpel_state.search_specs[i].offsets.footerlock), NULL)) {
        // fatal
        handle_error(SCALPEL_ERROR_MUTEX_FAILURE, "scalpel_state_serialization()", __LINE__, __FILE__);
      }

      // header-related init
      if (scalpel_state.search_specs[i].HEADER[0]) {
        if (scalpel_state.search_specs[i].begin_is_RE) {
          if (scalpel_state.mode_verbose) {
            lock_fprintf(stdout, "Compiling regular expression for header of type \"%s\".\n",
                         scalpel_state.search_specs[i].FILETYPE);
          }
          // compile regular expression
          scalpel_state.search_specs[i].beginstate.re = pcre2_compile((PCRE2_SPTR8)scalpel_state.search_specs[i].begin,
                                                                      scalpel_state.search_specs[i].beginlength,
                                                                      PCRE2_CASELESS
                                                                          * (! scalpel_state.search_specs[i].CASESENSITIVE),
                                                                      &err, &erroffset, NULL);

          if (! scalpel_state.search_specs[i].beginstate.re) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
            snprintf(errmsg, MAX_STRING_LENGTH, "Header of file type \"%s\" in \"scalpelconf.c\".\n",
                     scalpel_state.search_specs[i].FILETYPE);
#pragma GCC diagnostic pop
            // fatal
            handle_error(SCALPEL_ERROR_BAD_REGEX, errmsg, __LINE__, __FILE__);
          }
        }
        else {
          // non-regular expression header
          init_bm_table(scalpel_state.search_specs[i].begin, scalpel_state.search_specs[i].beginstate.bm_table,
                        scalpel_state.search_specs[i].beginlength, scalpel_state.search_specs[i].CASESENSITIVE);
        }
      }

      // footer-related init
      if (scalpel_state.search_specs[i].FOOTER[0]) {
        if (scalpel_state.search_specs[i].end_is_RE) {
          if (scalpel_state.mode_verbose) {
            lock_fprintf(stdout, "Compiling regular expression for footer of type \"%s\".\n",
                         scalpel_state.search_specs[i].FILETYPE);
          }

          // compile regular expression
          scalpel_state.search_specs[i].endstate.re = pcre2_compile((PCRE2_SPTR8)scalpel_state.search_specs[i].end,
                                                                    scalpel_state.search_specs[i].endlength,
                                                                    PCRE2_CASELESS
                                                                        * (! scalpel_state.search_specs[i].CASESENSITIVE),
                                                                    &err, &erroffset, NULL);

          if (! scalpel_state.search_specs[i].endstate.re) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
            snprintf(errmsg, MAX_STRING_LENGTH, "Footer of file type \"%s\" in \"scalpelconf.c\".\n",
                     scalpel_state.search_specs[i].FILETYPE);
#pragma GCC diagnostic pop
            // fatal
            handle_error(SCALPEL_ERROR_BAD_REGEX, errmsg, __LINE__, __FILE__);
          }
        }
        else {
          init_bm_table(scalpel_state.search_specs[i].end, scalpel_state.search_specs[i].endstate.bm_table,
                        scalpel_state.search_specs[i].endlength, scalpel_state.search_specs[i].CASESENSITIVE);
        }
      }
    }
  }
  fclose(fp);
}


// write scalpel state so that scalpel3 can be resumed from the saved state upon a checkpoint
// restore.
//
// Checkpoint state consists of:
//
// o serialized version of scalpel_state (including the search_specs array)
//
// o serialized version of promising_queue, with all UUIDs in kill queue pruned
//
// o filemirror state, including blockmap and blocktype data, which is saved automatically when the
// filemirror shuts down or here, if a periodic checkpoint is being taken
//
// o a manifest file that is used to verify checkpoint integrity
//
// IMPORTANT: queue serialization functions depend on the filemirror for I/O, so it must *not* be
// shut down before save_checkpoint() is complete.
//
void save_checkpoint(void) {

  char fn[PATH_MAX];
  char newfn[PATH_MAX];
  FILE *fp;

  // save current scalpel state
  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Serializing main scalpel state.\n");
  }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"

  snprintf(fn, PATH_MAX, "%s/scalpel_state.chk_", scalpel_state.base_output_directory);
  scalpel_state_serialization(SERIALIZE, fn);  // will not return on error
  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Serialization of main scalpel state is complete.\n");
  }

  // serialize promising queue
  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Serializing promising queue (%" PRIu64 " elements).\n", nolock_queue_length(&promising_queue));
  }

  snprintf(fn, PATH_MAX, "%s/promising_queue.chk_", scalpel_state.base_output_directory);
  if (! (fp = fopen(fn, "wb"))) {
    perror("opening promising_queue.chk_");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  if (! serialize_queue(&promising_queue, promising_queue_element_serialization, fp)) {
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }
  fclose(fp);
  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Serialization of promising queue is complete.\n");
  }

  // checkpoint and exit events will result in filemirror_stop() being called, which writes the
  // blockmap and blocktype data, so write that data here only if scalpel won't exit after this
  // checkpoint
  if (! atomic_load_explicit(&TAKE_CHECKPOINT_AND_EXIT, memory_order_acquire)) {
    // periodic checkpoint

    // save blockmap and block types in file mirror
    snprintf(fn, PATH_MAX, "%s_", scalpel_state.blockmap_pathname);
    filemirror_write_blockmap(scalpel_state.filemirror, fn);

    snprintf(fn, PATH_MAX, "%s/blocktypes.chk_", scalpel_state.base_output_directory);
    if (! filemirror_serialize_blocktype_data(scalpel_state.filemirror, SERIALIZE, fn)) {
      // fatal
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    // now overwrite old checkpoint data with new data, to minimize failure window
    snprintf(fn, PATH_MAX, "%s_", scalpel_state.blockmap_pathname);
    unlink(scalpel_state.blockmap_pathname);
    rename(fn, scalpel_state.blockmap_pathname);

    snprintf(fn, PATH_MAX, "%s/blocktypes.chk_", scalpel_state.base_output_directory);
    snprintf(newfn, PATH_MAX, "%s/blocktypes.chk", scalpel_state.base_output_directory);
    unlink(newfn);
    rename(fn, newfn);
  }

  snprintf(fn, PATH_MAX, "%s/promising_queue.chk_", scalpel_state.base_output_directory);
  snprintf(newfn, PATH_MAX, "%s/promising_queue.chk", scalpel_state.base_output_directory);
  unlink(newfn);
  rename(fn, newfn);

  snprintf(fn, PATH_MAX, "%s/scalpel_state.chk_", scalpel_state.base_output_directory);
  snprintf(newfn, PATH_MAX, "%s/scalpel_state.chk", scalpel_state.base_output_directory);
  unlink(newfn);
  rename(fn, newfn);

  if (! checkpoint_save_manifest()) {
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

#pragma GCC diagnostic pop
}


// restore scalpel state from checkpoint data. filemirror initialization takes care of setting up
// the blockmaps and initializing and reading the blocktype data structure when the filemirror is
// started in "resume" mode. A separate function restore_checkpointed_promising_queue() handles
// restoration of carving candidates into the promising queue, as the file mirror must be up first.
void restore_checkpointed_scalpel_state(void) {

  char fn[PATH_MAX];

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"


  if (! scalpel_state.no_cp_validation && ! checkpoint_verify_manifest()) {
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  // read checkpointed scalpel state
  snprintf(fn, PATH_MAX, "%s/scalpel_state.chk", scalpel_state.base_output_directory);
  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Deserializing scalpel state from \"%s\".\n", fn);
  }
  scalpel_state_serialization(DESERIALIZE, fn);  // will not return on error

#pragma GCC diagnostic pop
}


// restore promising queue from checkpoint and set global flag that indicates the queue is
// initialized.
void restore_checkpointed_promising_queue(void) {

  char fn[PATH_MAX];
  FILE *fp;

  // restore promising queue from checkpoint
  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Deserializing promising queue.\n");
  }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"

  snprintf(fn, PATH_MAX, "%s/promising_queue.chk", scalpel_state.base_output_directory);

#pragma GCC diagnostic pop

  if (! (fp = fopen(fn, "rb"))) {
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  init_queue(&promising_queue, sizeof(CarveInfo *), true, carveinfo_match_either_uuid, false);

  if (! deserialize_queue(&promising_queue, promising_queue_element_serialization, true, fp)) {
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  fclose(fp);

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Deserialized %" PRIu64 " elements into promising queue.\n", nolock_queue_length(&promising_queue));
  }

  /*
    // uncoment to scrutinize queue restoration
       CarveInfo *c;
       rewind_queue(&promising_queue);
       while (peek_at_current(&promising_queue, &c)) {
       lock_fprintf(stdout, "c:         %p\n",   c);
       lock_fprintf(stdout, "needleidx: %"PRIu32"\n",   c->needleidx);
       lock_fprintf(stdout, "b:         %p\n",   c->b);
       lock_fprintf(stdout, "best:      %"PRIu64"\n",  c->best_validates_to);
       lock_fprintf(stdout, "clone:      %d\n",  c->clone);
       lock_fprintf(stdout, "cloned:     %d\n",  c->cloned);
       lock_fprintf(stdout, "deposited:  %d\n",  c->deposited);
       next_element(&promising_queue);
       }
   */
}


// delete checkpoint data
void remove_checkpoint(void) {

  // wipe all checkpoint files
  delete_files_recursive(scalpel_state.base_output_directory, "*.chk*");
}


// add a file subtype based on a master file type. Duplicates are silently ignored. Returns the
// index of the subtype in scalpel_state.search_specs[] or masteridx if no subtype was added.
uint32_t add_file_subtype(uint32_t masteridx, char *filetype) {

  bool found = false;
  uint32_t idx = masteridx;
  uint32_t i;

  if (! filetype || ! filetype[0] || filetype[0] == '-') {
    char errmsg[MAX_STRING_LENGTH];

    snprintf(errmsg, sizeof(errmsg),
             "Invalid file subtype \"%s\". File types must not be empty or begin with '-'.",
             filetype ? filetype : "(null)");
    handle_error(SCALPEL_GENERAL_ABORT, errmsg, __LINE__, __FILE__);
  }

  // subtypes can only be added during block validation
  if (scalpel_state.block_validation_complete) {
    handle_error(SCALPEL_ERROR_SUBTYPE_ERROR, NULL, __LINE__, __FILE__);
  }

  // need a lock to access scalpel_state.search_specs array before block validation is complete,
  // because the array may be reallocated
  MUTEX_ERROR_CHECK(pthread_mutex_lock(&scalpel_state.search_specs_lock), __LINE__, __FILE__);

  for (i = 0; i < scalpel_state.num_specs && ! found; i++) {
    if (! strcmp(scalpel_state.search_specs[i].FILETYPE, filetype)) {
      found = true;
      idx = i;
    }
  }

  if (! found) {
    // subtype is unique--add it (realloc() must also accomodate the "null" file type that
    // terminates search_specs, thus the +1)
    idx = scalpel_state.num_specs;
    scalpel_state.num_specs++;
    scalpel_state.search_specs = realloc(scalpel_state.search_specs, sizeof(SearchSpec) * (scalpel_state.num_specs + 1));
    check_memory_allocation(scalpel_state.search_specs, __LINE__, __FILE__, "scalpel_state.search_specs");

    // use the master as a template to create a new file type
    copy_search_spec(&scalpel_state.search_specs[scalpel_state.num_specs - 1], &scalpel_state.search_specs[masteridx]);

    // file subtypes aren't a master type and inherent function pointers of master type
    scalpel_state.search_specs[scalpel_state.num_specs - 1].MASTER = false;
    scalpel_state.search_specs[scalpel_state.num_specs - 1].mastertype = masteridx;

    // update the type
    strcpy(scalpel_state.search_specs[scalpel_state.num_specs - 1].FILETYPE, filetype);

    // inform filemirror that another file type is present

    filemirror_add_blocktype_slot(scalpel_state.filemirror);
  }

  // release the lock
  MUTEX_ERROR_CHECK(pthread_mutex_unlock(&scalpel_state.search_specs_lock), __LINE__, __FILE__);

  return idx;
}


// sync the promising and kill queues to remove any killed candidates from the promising queue. Then
// walk the promising queue and validate each element. This ensures that all reassembly data for an
// element in the queue corresponds to uncovered blocks. Any carving candidates that are truncated
// to zero blocks are removed from the queue and destroyed.
//
// THIS FUNCTION IS NOT THREAD-SAFE.
static void sync_and_validate_queues(void) {

  CarveInfo *c;
  uuid_string_t uuidp;
  uuid_string_t uuidc;
  uint64_t numblocks;
  int64_t block;

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Syncing kill and promising queues and validating all elements\n"
                         "in promising queue.\n");
  }

  // remove any elements from the promising queue that match an element in the kill queue
  sync_promising_and_kill_queues();

  // now validate all remaining promising queue elements
  rewind_queue(&promising_queue);
  while (peek_at_current(&promising_queue, &c, NULL)) {
    // get human readable UUIDs for reporting
    uuid_unparse_lower(c->binuuid, uuidp);
    uuid_unparse_lower(c->clone_binuuid, uuidc);

    // remember number of blocks before validation
    numblocks = blockvector_get_num_blocks(c->b);
    // validate_blockvector() will ensure reservations are removed from any blocks that are
    // eliminated
    validate_blockvector(c->b, scalpel_state.search_specs[c->needleidx].REASSEMBLYFUNC == LR_reassembly
                                   || ! scalpel_state.search_specs[c->needleidx].REASSEMBLYFUNC);

    // if the candidate's blockvector shrunk to zero blocks, destroy the candidate, announce the
    // destruction, and move to next candidate in queue
    //
    if (blockvector_get_num_blocks(c->b) == 0) {
      lock_fprintf(stdout,
                   "sync_and_validate_queues() deleting candidate with "
                   "blockvector %p and UUIDs\n%s / %s.\n",
                   c->b, uuidp, uuidc);
      destroy_candidate(&c);

      // next candidate by deleting current element in promising queue
      delete_current(&promising_queue);

      continue;
    }

    // there's a nasty edge case here: regardless of whether the blockvector has shrunk so far, when
    // a checkpoint occurs, c->newblock may be tracking the best *actual* block so far for extending
    // the candidate. This block may now be covered. If it is, it can no longer be used. Since this
    // throws off determination of the best block for extending the candidate, if the blockvector
    // hasn't already shrunk, it needs to be trimmed by one block to reset evaluation of the best
    // block for extending the candidate.
    //
    if (c->newblock >= 0 && filemirror_actual_block_covered(scalpel_state.filemirror, c->newblock)
        && numblocks == blockvector_get_num_blocks(c->b)) {
      // validation hasn't yet reduced the length of the blockvector, so trim by one block
      resize_blockvector(c->b, blockvector_get_num_blocks(c->b) - 1);
    }

    // need to check once again to see if the candidate has been truncated to zero blocks. If so,
    // destroy the candidate, announce the destruction, and move to next candidate in queue.
    //
    if (blockvector_get_num_blocks(c->b) == 0) {
      lock_fprintf(stdout,
                   "validate_promising_queue() deleting candidate with "
                   "blockvector %p and UUIDs\n%s / %s.\n",
                   c->b, uuidp, uuidc);
      destroy_candidate(&c);

      // next candidate by deleting current element in promising queue
      delete_current(&promising_queue);

      continue;
    }

    // if the blockvector has shrunk for any reason during validation, then work on the terminal
    // block that was underway when a checkpoint occurred has to be abandoned, since some of the
    // interior blocks are now covered. Make corrections to candidate and then move to next
    // candidate in queue.
    //
    if (numblocks != blockvector_get_num_blocks(c->b)) {
      c->no_initial_block_extension = false;
      c->fastpath = false;

      // best choices only apply to the current last block, so those have to go as well
      if (c->best_choices) {
        destroy_queue(c->best_choices);
      }

      // next candidate by advancing to next element in promising queue
      next_element(&promising_queue);

      continue;
    }

    // at this point, the entire blockvector in the candidate has survived the blockmap swap, but
    // it's still necessary to make sure that all elements in the best_choices queue remain
    // uncovered. Entries in the best_choices queue are *actual* blocknumbers.
    //
    if (c->best_choices) {
      rewind_queue(c->best_choices);
      while (peek_at_current(c->best_choices, &block, NULL)) {
        if (filemirror_actual_block_covered(scalpel_state.filemirror, block)) {
          // block is covered, has to go
          delete_current(c->best_choices);
        }
        else {
          next_element(c->best_choices);
        }
      }
    }

    // next candidate by advancing to next element in promising queue
    next_element(&promising_queue);
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Sync and validation of queues is complete.\n");
  }
}


// threads to support multithreaded header/footer searches. Search threads are NOT responsive to
// pending checkpoint operations.
static void *search_thread(void *args) {

  SearchThreadWork *work = (SearchThreadWork *)args;
  pcre2_match_data *match_data;
  uint32_t matchlen;
  unsigned int id = work->id;
  char *startpos;
  char *matchpos;
  char *bdata;
  size_t buflen;
  size_t blen;
  uint64_t start_location = 0;
  char temp[MAX_STRING_LENGTH];

  atomic_store_explicit(&work->thread_running, true, memory_order_release);

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Search thread # %1d initialized, work = %p, sleeping.\n", id, work);
  }

  // ready for work
  atomic_store_explicit(&work->thread_ready, true, memory_order_release);

  while (! atomic_load_explicit(&work->thread_stop, memory_order_acquire)) {
    // wait for work to do
    MUTEX_ERROR_CHECK(pthread_mutex_lock(&work->work_is_available), __LINE__, __FILE__);
    while (! work->b && ! atomic_load_explicit(&work->thread_stop, memory_order_acquire)) {
      pthread_cond_wait(&work->check_work_available, &work->work_is_available);
    }
    MUTEX_ERROR_CHECK(pthread_mutex_unlock(&work->work_is_available), __LINE__, __FILE__);

    if (atomic_load_explicit(&work->thread_stop, memory_order_acquire)) {
      // thread was ordered to exit
      break;
    }

    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout, "Search thread # %d waking up to find \"%s\".\n", id,
                   sprinthex(temp, work->needle, work->needlelength, true));
    }

    blen = blockvector_get_data_length(work->b);
    bdata = blockvector_get_data_pointer(work->b);
    matchlen = 0;
    matchpos = (char *)1;
    startpos = blockvector_get_data_pointer(work->b);
    buflen = blockvector_get_data_length(work->b);
    while (matchpos && startpos < bdata + blen - 1) {
      matchpos = NULL;

      // prefer validation function over binary string comparison
      if (work->needlefunc) {
        char *filetype = work->needlefunc(bdata, (uint64_t)startpos - (uint64_t)bdata, buflen, &matchpos, &matchlen,
                                          scalpel_state.blocksize);

        if (filetype && strcmp(filetype, work->filetype)) {
          // incorrect file type
          matchpos = NULL;
        }
        free(filetype);
        filetype = NULL;
      }
      else if (! work->str_is_RE) {
        matchpos = find_binary_string(work->needle, work->needlelength, startpos, buflen, work->table, work->case_sensitive);
        matchlen = work->needlelength;
      }
      else {
        match_data = find_regular_expression(work->regex, startpos, buflen);
        if (match_data) {
          PCRE2_SIZE *ovector;
          ovector = pcre2_get_ovector_pointer(match_data);
          matchpos = startpos + ovector[0];
          matchlen = ovector[1] - ovector[0];
          pcre2_match_data_free(match_data);
        }
      }

      if (matchpos >= startpos) {  // only record a valid position
        // header/footer locations are *absolute* offsets in the image file, so they can be used
        // regardless of which blockmap is in use
        start_location = blockvector_data_pointer_offset_to_actual_location(work->b, matchpos - bdata);
        record_pattern_match(work->needleidx, start_location, matchlen, work->is_header);
      }

      if (matchpos < startpos) {  // header/footer functions is broken, avoid hang
        matchpos = NULL;
      }
      else {
        startpos = matchpos + 1;  // this is slower, but accommodates detection
                                  // of overlapping strings
      }

      buflen = blen - ((size_t)startpos - (size_t)bdata);
    }

    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout, "Search thread # %1d completed work, sleeping.\n", id);
    }

    work->b = NULL;

    // signal completion of work
    atomic_store_explicit(&work->thread_ready, true, memory_order_release);

    // one more free thread
    atomic_fetch_add_explicit(&num_idle_search_threads, 1, memory_order_acq_rel);
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Search thread # %1d exiting.\n", id);
  }

  atomic_store_explicit(&work->thread_running, false, memory_order_release);

  return 0;
}


// validate a single file candidate during contiguous file carving
static void validate_file(CarveInfo *candidate, unsigned int id) {

  bool promising = false;     // is the candidate promising enough for reassembly?
  bool validates = false;     // did the candidate completely validate?
  uint64_t validates_to = 0;  // candidate validates to this index
  uuid_string_t uuidp;        // primary and clone UUIDs for candidate
  uuid_string_t uuidc;

  // get textual UUIDs for status reports. The textual versions are maintained only when a candidate
  // is actively being improved to save space.
  uuid_unparse_lower(candidate->binuuid, uuidp);
  uuid_unparse_lower(candidate->clone_binuuid, uuidc);

  // most of the work is handled by the file validation function for this file type

#if PRINT_CARVE_STATE > 0

  char output[CARVE_HASH_KEY_PRINTABLE_SIZE];

  if ((scalpel_state.mode_verbose || PRINT_CARVE_STATE > 0)
      && scalpel_state.search_specs[candidate->needleidx].SERIALIZECARVESTATEFUNC
      && scalpel_state.search_specs[candidate->needleidx].PRINTCARVESTATEFUNC) {
    // locking is used to generate coherent output when multiple threads are active--this reduces
    // performance, but PRINT_CARVE_STATE should only be used for debugging.
    MUTEX_ERROR_CHECK(pthread_mutex_lock(&printf_is_available), __LINE__, __FILE__);

    fprintf(stdout,
            "\nStored state for contiguous candidate with UUIDs\n"
            "%s and %s and\n"
            "hash key %s\n"
            "BEFORE file validation:\n",
            uuidp, uuidc, displayable_carve_hash_key(candidate->carvehashkey, output));
    void *_pcs = carve_get_state(candidate->carvehashkey);
    scalpel_state.search_specs[candidate->needleidx].PRINTCARVESTATEFUNC(_pcs);
    scalpel_state.search_specs[candidate->needleidx].FREECARVESTATEFUNC(&_pcs);
    fprintf(stdout, "\n");

    MUTEX_ERROR_CHECK(pthread_mutex_unlock(&printf_is_available), __LINE__, __FILE__);
  }
#endif


  // inflate blockvector for candidate so the file validation function can see associated data
  inflate_blockvector(candidate->b);

  scalpel_state.search_specs[candidate->needleidx].FILEVALIDATOR(blockvector_get_data_pointer(candidate->b),
                                                                 blockvector_get_data_length(candidate->b), &validates,
                                                                 &validates_to, &promising, candidate->needleidx,
                                                                 scalpel_state.blocksize, candidate->carvehashkey);

  if (scalpel_debug_trace_candidate(candidate)) {
    scalpel_debug_trace("[candbg] validate start=%" PRIu64
                        " len=%" PRIu64 " validates=%d"
                        " validates_to=%" PRIu64 " promising=%d"
                        " deposited=%d chopped=%d type=%s",
                        candidate->start / scalpel_state.blocksize,
                        blockvector_get_data_length(candidate->b),
                        validates, validates_to, promising,
                        candidate->deposited, candidate->chopped,
                        candidate->filetype);
  }

#if PRINT_CARVE_STATE > 0
  if (scalpel_state.search_specs[candidate->needleidx].SERIALIZECARVESTATEFUNC
      && scalpel_state.search_specs[candidate->needleidx].PRINTCARVESTATEFUNC) {
    // locking is used to generate coherent output when multiple threads are active--this reduces
    // performance, but PRINT_CARVE_STATE should only be used for debugging.
    MUTEX_ERROR_CHECK(pthread_mutex_lock(&printf_is_available), __LINE__, __FILE__);

    fprintf(stdout,
            "\nStored state for contiguous candidate with UUIDs\n"
            "%s and %s and\n"
            "hash key %s\n"
            "AFTER file validation:\n",
            uuidp, uuidc, displayable_carve_hash_key(candidate->carvehashkey, output));
    void *_pcs = carve_get_state(candidate->carvehashkey);
    scalpel_state.search_specs[candidate->needleidx].PRINTCARVESTATEFUNC(_pcs);
    scalpel_state.search_specs[candidate->needleidx].FREECARVESTATEFUNC(&_pcs);
    fprintf(stdout, "\n");

    MUTEX_ERROR_CHECK(pthread_mutex_unlock(&printf_is_available), __LINE__, __FILE__);
  }
#endif

  if (! validates
      && (scalpel_state.search_specs[candidate->needleidx].NO_DEFRAG || scalpel_state.no_defrag || candidate->deposited)) {
    // NO_DEFRAG is set or a candidate with this header has already been deposited for fragmented
    // reassembly, so that's it
    promising = false;
  }

  if (promising && blockvector_get_data_length(candidate->b) > validates_to) {
    // the validator found a better limit on size of valid data for promising fragment

    // GGRIII:

    // validates_to is where validation began to fail in the candidate--if that wasn't on a block
    // boundary, it's better to let fragmented reassembly determine the best block for the current
    // tail as long as a full block would remain, because building on a block that didn't complete
    // validate will very likely result in backtracking and additional work.

    if (validates_to + 1 < scalpel_state.blocksize) {
      blockvector_set_data_length(candidate->b, validates_to + 1);
      resize_blockvector(candidate->b, 1);
    }
    else {
      blockvector_set_data_length(candidate->b, (validates_to + 1) / scalpel_state.blocksize * scalpel_state.blocksize);
      resize_blockvector(candidate->b, blockvector_get_data_length(candidate->b) / scalpel_state.blocksize);
    }

    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout, "Validation thread # %1d: %p shrinking promising candidate to %" PRIu64 " bytes.\n", id, candidate->b,
                   blockvector_get_data_length(candidate->b));
    }
  }
  else if (validates && blockvector_get_data_length(candidate->b) > validates_to) {
    // the validator found a better limit on size of valid data for validated file.

    blockvector_set_data_length(candidate->b, validates_to + 1);
    resize_blockvector(candidate->b, CEILDIV(blockvector_get_data_length(candidate->b), scalpel_state.blocksize));

    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout, "Validation thread # %1d: %p shrinking promising candidate to %" PRIu64 " bytes.\n", id, candidate->b,
                   blockvector_get_data_length(candidate->b));
    }
  }

  if (promising) {
    if (scalpel_debug_trace_candidate(candidate)) {
      scalpel_debug_trace("[candbg] enqueue-promising start=%" PRIu64
                          " new_len=%" PRIu64
                          " best_validates_to=%" PRIu64,
                          candidate->start / scalpel_state.blocksize,
                          blockvector_get_data_length(candidate->b),
                          validates_to);
    }
    if (! scalpel_state.write_promising) {
      if (scalpel_state.mode_verbose) {
        lock_fprintf(stdout,
                     "Validation thread # %1d: %p didn't validate and "
                     "write_promising is false.\n",
                     id, candidate->b);
      }
    }
    else {
      if (scalpel_state.mode_verbose) {
        lock_fprintf(stdout, "Validation thread # %1d: %p promising, writing.\n", id, candidate->b);
      }

      candidate->flavor = PROMISING;
      write_candidate(&candidate, true);
    }

    // if aggressive mem allocation is off, deflate candidate's blockvector to save resources until
    // data is actually needed later
    if (scalpel_state.reduce_aggressive_allocation) {
      deflate_blockvector(candidate->b);
    }

    // save candidate for processing during fragmented reassembly
    candidate->best_choices = malloc(sizeof(Queue));
    check_memory_allocation(candidate->best_choices, __LINE__, __FILE__, "candidate->best_choices");
    init_queue(candidate->best_choices, sizeof(int64_t), true, NULL, true);
    add_to_queue_priority_relaxed(&promising_queue, &candidate, candidate->qposition);
  }
  else if (validates) {
    if (scalpel_debug_trace_candidate(candidate)) {
      scalpel_debug_trace("[candbg] write-validated start=%" PRIu64
                          " final_len=%" PRIu64
                          " validates_to=%" PRIu64,
                          candidate->start / scalpel_state.blocksize,
                          blockvector_get_data_length(candidate->b),
                          validates_to);
    }
    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout, "Validation thread # %1d: file %p validated, writing.\n", id, candidate->b);
    }

    // write file and possibly blockvector and then free blockvector--blockvector will be freed as
    // appropriate, so we're off the hook
    candidate->flavor = VALIDATED;
    write_candidate(&candidate, false);
  }

  if (! promising && ! validates) {
    if (scalpel_debug_trace_candidate(candidate)) {
      scalpel_debug_trace("[candbg] drop start=%" PRIu64
                          " len=%" PRIu64
                          " validates_to=%" PRIu64
                          " deposited=%d type=%s",
                          candidate->start / scalpel_state.blocksize,
                          blockvector_get_data_length(candidate->b),
                          validates_to, candidate->deposited,
                          candidate->filetype);
    }
    // destroy candidate
    destroy_candidate(&candidate);
  }
}


// validate a single block candidate
static void validate_block(BlockInfo *blockinfo) {

  BlockValidationDecision decision;
  int32_t nidx;           // index into scalpel_state.search_specs
                          // returned by block validator; used to detect subtypes
  uint64_t validates_to;  // block candidate validates to this index
  uint64_t length;
  char *data;

#if PRINT_BLOCK_STATE > 0
  char output[BLOCK_HASH_KEY_PRINTABLE_SIZE];

  if (blockinfo->printblockstatefunc) {
    // locking is used to generate coherent output when multiple threads are active--this reduces
    // performance, but PRINT_BLOCK_STATE should only be used for debugging.
    MUTEX_ERROR_CHECK(pthread_mutex_lock(&printf_is_available), __LINE__, __FILE__);

    fprintf(stdout,
            "\nStored state for block %" PRId64 " and file type \"%s\" with hash key\n"
            "%s BEFORE block validation"
            " (should be NULL!):\n",
            blockinfo->actual_block, blockinfo->filetype,
            displayable_block_hash_key(blockinfo->blockhashkey, output));
    void *_pbs = block_get_state(blockinfo->blockhashkey);
    blockinfo->printblockstatefunc(_pbs);
    if (_pbs) {
      scalpel_state.search_specs[blockinfo->needleidx].FREEBLOCKSTATEFUNC(&_pbs);
    }
    fprintf(stdout, "\n");

    MUTEX_ERROR_CHECK(pthread_mutex_unlock(&printf_is_available), __LINE__, __FILE__);
  }
#endif

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "About to validate block %" PRId64 " for file type %s...\n",
                 blockinfo->actual_block, blockinfo->filetype);
  }

  data = filemirror_actual_block_data_pointer(scalpel_state.filemirror,
                                              blockinfo->actual_block,
                                              &length);
  decision = BLOCK_CONFIDENCE_INVALID;
  validates_to = 0;
  nidx = blockinfo->needleidx;

  if (data) {
    nidx = blockinfo->blockvalidator(data, length, &decision, &validates_to,
                                     blockinfo->needleidx,
                                     scalpel_state.blocksize,
                                     blockinfo->blockhashkey);
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Completed validation for block %" PRId64 " for file type %s.\n",
                 blockinfo->actual_block, blockinfo->filetype);
  }

#if PRINT_BLOCK_STATE > 0
  if (blockinfo->printblockstatefunc) {
    // locking is used to generate coherent output when multiple threads are active--this reduces
    // performance, but PRINT_BLOCK_STATE should only be used for debugging.
    MUTEX_ERROR_CHECK(pthread_mutex_lock(&printf_is_available), __LINE__, __FILE__);

    fprintf(stdout,
            "\nStored state for block %" PRId64 " and file type \"%s\" with hash key\n"
            "%s AFTER block validation:\n",
            blockinfo->actual_block, blockinfo->filetype,
            displayable_block_hash_key(blockinfo->blockhashkey, output));
    void *_pbs = block_get_state(blockinfo->blockhashkey);
    blockinfo->printblockstatefunc(_pbs);
    if (_pbs) {
      scalpel_state.search_specs[blockinfo->needleidx].FREEBLOCKSTATEFUNC(&_pbs);
    }
    fprintf(stdout, "\n");

    MUTEX_ERROR_CHECK(pthread_mutex_unlock(&printf_is_available), __LINE__, __FILE__);
  }
#endif

  // update block type
  if (filemirror_get_blocktype(scalpel_state.filemirror,
                               blockinfo->actual_block, nidx)
      == BLOCK_CONFIDENCE_INVALID) {
    filemirror_set_blocktype(scalpel_state.filemirror,
                             blockinfo->actual_block, nidx, decision);
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout,
                 "validate_block: decision for filetype %s on block %" PRId64
                 " was %d.\n",
                 blockinfo->filetype, blockinfo->actual_block, decision);
  }

  // check special case for files for which only validated single blocks are carved. For blocks
  // associated with a master file type, modify the needleidx in the candidate so the block gets
  // more tightly categorized.

  if (decision != BLOCK_CONFIDENCE_INVALID
      && blockinfo->searchtype == SEARCHTYPE_BLOCK_ONLY) {
    CarveInfo *candidate = (CarveInfo *)calloc(1, sizeof(CarveInfo));
    check_memory_allocation(candidate, __LINE__, __FILE__, "candidate");

    candidate->workload = VALIDATE_FILE;
    candidate->filetype = scalpel_state.search_specs[nidx].FILETYPE;
    candidate->searchtype = scalpel_state.search_specs[nidx].SEARCHTYPE;
    candidate->needleidx = nidx;
    candidate->flavor = VALIDATED;
    init_blockvector(scalpel_state.filemirror, &candidate->b, 1, true);
    blockvector_set_apparent_blocknumber(candidate->b, 0,
                                         blockinfo->apparent_block);
    normalize_blockvector(candidate->b);
    inflate_blockvector(candidate->b);
    if (validates_to + 1 < blockvector_get_data_length(candidate->b)) {
      blockvector_set_data_length(candidate->b, validates_to + 1);
    }

    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout,
                   "validate_block: writing special case single block for %p "
                   "with actual length %" PRIu64 ".\n",
                   candidate->b, blockvector_get_data_length(candidate->b));
    }

    write_candidate(&candidate, false);
  }
}


static void *partial_cleanup_thread(void *args) {

  uuid_t uuid;

  (void)args;

  while (1) {
    MUTEX_ERROR_CHECK(pthread_mutex_lock(&partial_cleanup_work_is_available), __LINE__, __FILE__);
    while (! atomic_load_explicit(&partial_cleanup_thread_stop, memory_order_acquire)
           && empty_queue(&partial_cleanup_queue)) {
      pthread_cond_wait(&partial_cleanup_check_work_available, &partial_cleanup_work_is_available);
    }
    MUTEX_ERROR_CHECK(pthread_mutex_unlock(&partial_cleanup_work_is_available), __LINE__, __FILE__);

    while (remove_from_front(&partial_cleanup_queue, uuid)) {
      cleanup_partial_artifacts(uuid);
    }

    if (atomic_load_explicit(&partial_cleanup_thread_stop, memory_order_acquire)
        && empty_queue(&partial_cleanup_queue)) {
      break;
    }
  }

  return NULL;
}


// threads that support asynchronous block and contiguous file validation. Block validation includes
// discovery of new file subtypes based on master file types.
//
// Validation threads are NOT responsive to pending checkpoint operations.
static void *validation_thread(void *args) {

  ThreadWork *work = (ThreadWork *)args;
  unsigned int id = work->id;
  ValidationInfo validation_info;
  ValidationInfo *work_item;
  CarveInfo *candidate;

  atomic_store_explicit(&work->thread_running, true, memory_order_release);

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Validation thread # %1d initialized.\n", work->id);
  }

  while (! atomic_load_explicit(&work->thread_stop, memory_order_acquire)) {
    // wait for work to do
    work_item = NULL;
    while (! work_item && ! atomic_load_explicit(&work->thread_stop, memory_order_acquire)) {
      work_item = NULL;
      MUTEX_ERROR_CHECK(pthread_mutex_lock(&validation_work_is_available), __LINE__, __FILE__);
      if (atomic_load_explicit(&carvelist_initialized, memory_order_acquire)
          && atomic_load_explicit(&promising_initialized, memory_order_acquire)) {
        work_item = remove_from_front_sync(&carvelist, &validation_info,
                                           &num_idle_validation_threads, -1);
      }

      if (! work_item && ! atomic_load_explicit(&work->thread_stop, memory_order_acquire)) {
        if (scalpel_state.mode_verbose) {
          lock_fprintf(stdout, "Validation thread # %1d waiting for work, sleeping.\n", work->id);
        }

        pthread_cond_wait(&validation_check_work_available, &validation_work_is_available);
      }

      MUTEX_ERROR_CHECK(pthread_mutex_unlock(&validation_work_is_available), __LINE__, __FILE__);
    }

    if (atomic_load_explicit(&work->thread_stop, memory_order_acquire)) {
      // thread should exit
      goto done;
    }

    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout, "Validation thread # %1d waking up to process %s.\n",
                   id, validation_info.workload == VALIDATE_FILE ? "file" : "block");
    }

    if (validation_info.workload == VALIDATE_FILE) {
      candidate = validation_info.candidate;
      if (! candidate->b) {
        init_contiguous_blockvector(scalpel_state.filemirror, &candidate->b,
                                    candidate->start, candidate->stop, false);
      }

      if (scalpel_state.mode_verbose) {
        lock_fprintf(stdout, "Validation thread # %1d attempting to validate file %p.\n",
                     id, candidate->b);
      }

      validate_file(candidate, id);
    }
    else {
      if (scalpel_state.mode_verbose) {
        lock_fprintf(stdout,
                     "Validation thread # %1d attempting to validate block %" PRId64 ".\n",
                     id, validation_info.block.actual_block);
      }

      validate_block(&validation_info.block);
    }

    // work is complete
    atomic_fetch_add_explicit(&num_idle_validation_threads, 1, memory_order_acq_rel);

    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout, "Validation thread # %1d completed work.\n", id);
    }
  }

done:

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Validation thread # %1d exiting.\n", work->id);
  }

  atomic_store_explicit(&work->thread_running, false, memory_order_release);

  return 0;
}


// determine type of each uncovered block. New file subtypes based on master file types are also
// discovered in this function. For duplicate blocks, validation is performed only for the exemplar
// to increase performance.
//
// This function is NOT responsive to pending checkpoint operations.
static void validate_blocks(void) {

  int64_t block;
  int64_t actual_block;
  uint32_t needlenum;
  ValidationInfo validation_info;
  uint64_t num_blocks;
  uint64_t q_length;
  uint64_t f_load;
  uint64_t pending_verifications;
  uint64_t load;
  long then = time(NULL);
  long now = time(NULL);
  struct timespec endtime;
  uint64_t total_wait;
  uint32_t num_non_subtypes;
  uint64_t queued_total = 0;
  uint64_t skipped_non_exemplar = 0;
  uint64_t default_valid = 0;
  uint64_t *queued_by_type = NULL;
  bool memdiag;

  if (scalpel_state.memory_profiling) {
    memory_footprint("block validation start");
  }

  frame_message("BLOCK VALIDATION PHASE STARTING");
  frame_message("CREATING QUEUE OF BLOCKS TO VALIDATE");

  num_blocks = filemirror_apparent_blocks(scalpel_state.filemirror);

  // scalpel_state.num_specs may increase during block validation because of new file subtypes being
  // created, but we don't want to iterate over subtypes here anyway
  num_non_subtypes = scalpel_state.num_specs;
  memdiag = block_validation_memdiag_enabled();
  if (memdiag) {
    queued_by_type = (uint64_t *)calloc(num_non_subtypes, sizeof(*queued_by_type));
    check_memory_allocation(queued_by_type, __LINE__, __FILE__, "queued_by_type");
    block_validation_memdiag_report("block validation queue build start",
                                    num_blocks, queued_total,
                                    skipped_non_exemplar, default_valid,
                                    queued_by_type, num_non_subtypes);
  }

  for (block = num_blocks - 1; block >= 0; block--) {
    // progress display
    if (block % 100000 == 0) {
      clock_gettime(CLOCK_MONOTONIC, &endtime);
      total_wait = (endtime.tv_sec - starttime.tv_sec) * 1e9 + (endtime.tv_nsec - starttime.tv_nsec);

      lock_fprintf(stdout,
                   "Queueing blocks for validation (%3.1lf%%), total elapsed "
                   "time = %.2lf secs.\n",
                   100.0 - (double)block / (double)num_blocks * 100.0, (double)total_wait / 1e9);
    }

    actual_block = filemirror_actual_blocknumber(scalpel_state.filemirror,
                                                 block);

    // validate block only for exemplars
    if (filemirror_get_exemplar(scalpel_state.filemirror, actual_block)
        != actual_block) {
      // not an exemplar--skip
      skipped_non_exemplar++;
      continue;
    }

    for (needlenum = 0; needlenum < num_non_subtypes; needlenum++) {
      // validate block only if there's a block validation function for this file type--otherwise,
      // mark the block as valid
      if (! scalpel_state.search_specs[needlenum].BLOCKVALIDATOR) {
        filemirror_set_blocktype(scalpel_state.filemirror, actual_block,
                                 needlenum, BLOCK_CONFIDENCE_VALID);
        default_valid++;
        continue;
      }

      memset(&validation_info, 0, sizeof(validation_info));
      validation_info.workload = VALIDATE_BLOCK;
      validation_info.block.apparent_block = block;
      validation_info.block.actual_block = actual_block;
      validation_info.block.filetype = scalpel_state.search_specs[needlenum].FILETYPE;
      validation_info.block.searchtype = scalpel_state.search_specs[needlenum].SEARCHTYPE;
      validation_info.block.needleidx = needlenum;
      gen_block_hash_key(validation_info.block.blockhashkey,
                         validation_info.block.needleidx, actual_block);
      validation_info.block.blockvalidator =
          scalpel_state.search_specs[needlenum].BLOCKVALIDATOR;

      if (scalpel_state.search_specs[needlenum].PRINTBLOCKSTATEFUNC
          && scalpel_state.search_specs[needlenum].SERIALIZEBLOCKSTATEFUNC) {
        validation_info.block.printblockstatefunc =
            scalpel_state.search_specs[needlenum].PRINTBLOCKSTATEFUNC;
      }

      add_to_queue_priority_relaxed(&carvelist, &validation_info, 0);
      queued_total++;
      if (queued_by_type) {
        queued_by_type[needlenum]++;
      }

      if (memdiag && (queued_total % 500000 == 0)) {
        block_validation_memdiag_report("block validation queue build progress",
                                        num_blocks, queued_total,
                                        skipped_non_exemplar, default_valid,
                                        queued_by_type, num_non_subtypes);
      }

      if (scalpel_state.mode_verbose) {
        lock_fprintf(stdout, "Adding block %" PRId64 " to queue.\n",
                     actual_block);
      }
    }
  }

  // broadcast to let validation threads know that work has been inserted into the queue. pthreads
  // requires that an associated lock be held to avoid lost signals. Threads are not activated until
  // after the queue is populated, because access to scalpel_state.search_specs requires a lock
  // during block validation!
  MUTEX_ERROR_CHECK(pthread_mutex_lock(&validation_work_is_available), __LINE__, __FILE__);
  pthread_cond_broadcast(&validation_check_work_available);
  MUTEX_ERROR_CHECK(pthread_mutex_unlock(&validation_work_is_available), __LINE__, __FILE__);

  clock_gettime(CLOCK_MONOTONIC, &endtime);
  total_wait = (endtime.tv_sec - starttime.tv_sec) * 1e9 + (endtime.tv_nsec - starttime.tv_nsec);

  lock_fprintf(stdout,
               "Queueing blocks for validation (%3.1lf%%), total elapsed time "
               "= %.2lf secs.\n",
               100.0, (double)total_wait / 1e9);

  frame_message("QUEUE OF BLOCKS TO VALIDATE CREATED");
  if (memdiag) {
    block_validation_memdiag_report("block validation queue build complete",
                                    num_blocks, queued_total,
                                    skipped_non_exemplar, default_valid,
                                    queued_by_type, num_non_subtypes);
  }

  // ---------- thread group synchronization point ----------- //
  // ---------- thread group synchronization point ----------- //

  // synchronization here is complicated. Validation threads might be active, there could still be
  // elements in the candidates queue, or pending vector I/O operations in the file mirror. All of
  // these things must be resolved before continuing, since the blockmap is going to be modified
  // when this function exits and that shouldn't happen if pending operations depend on the current
  // blockmap.
  q_length = nolock_queue_length(&carvelist);
  f_load = filemirror_load(scalpel_state.filemirror);
  pending_verifications = scalpel_state.max_validation_threads
                          - atomic_load_explicit(&num_idle_validation_threads, memory_order_acquire);
  load = q_length + f_load + pending_verifications;

  while (load > 0) {
    q_length = nolock_queue_length(&carvelist);
    f_load = filemirror_load(scalpel_state.filemirror);
    pending_verifications = scalpel_state.max_validation_threads
                            - atomic_load_explicit(&num_idle_validation_threads, memory_order_acquire);
    load = q_length + f_load + pending_verifications;

    // chill on the progress display
    now = time(NULL);
    if (now - then >= 2) {
      then = now;
      clock_gettime(CLOCK_MONOTONIC, &endtime);
      total_wait = (endtime.tv_sec - starttime.tv_sec) * 1e9 + (endtime.tv_nsec - starttime.tv_nsec);

      lock_fprintf(stdout,
                   "\nStatus: Blocks queued for validation: %" PRIu64
                   ", %d idle block validation threads of %d, NOT CHECKPOINTING,\n"
                   "total elapsed time: %.2lf secs.\n",
                   q_length, (int)atomic_load_explicit(&num_idle_validation_threads, memory_order_acquire),
                   (int)scalpel_state.max_validation_threads, (double)total_wait / 1e9);
    }
  }

  // block global state is now locked and no more subtypes will be created
  scalpel_state.block_validation_complete = true;

  frame_message("BLOCK VALIDATION PHASE COMPLETE");
  if (memdiag) {
    block_validation_memdiag_report("block validation complete",
                                    num_blocks, queued_total,
                                    skipped_non_exemplar, default_valid,
                                    queued_by_type, num_non_subtypes);
  }

  if (scalpel_state.memory_profiling) {
    memory_footprint("block validation done");
  }

  free(queued_by_type);
}


// remove headers and footers that are in covered blocks or in blocks of the incorrect type
//
// This function is NOT responsive to pending checkpoint operations.
static void prune_header_footer_database(void) {

  uint64_t i, k;
  uint32_t needlenum;           // index of current file type
  SearchSpec *currentfilespec;  // current file type being processed

  for (needlenum = 0; needlenum < scalpel_state.num_specs; needlenum++) {
    currentfilespec = &scalpel_state.search_specs[needlenum];

    // skip MASTER file types
    if (currentfilespec->MASTER) {
      continue;
    }

    // any headers that are covered or in a block of the incorrect type are pruned
    k = 0;
    for (i = 0; i < currentfilespec->offsets.numheaders; i++) {
      if (filemirror_actual_location_covered(scalpel_state.filemirror, currentfilespec->offsets.headers[i])
          || ! filemirror_get_blocktype(scalpel_state.filemirror, currentfilespec->offsets.headers[i] / scalpel_state.blocksize,
                                        needlenum)) {
        continue;
      }

      if (k != i) {
        currentfilespec->offsets.headers[k] = currentfilespec->offsets.headers[i];
        currentfilespec->offsets.headerlens[k] = currentfilespec->offsets.headerlens[i];
        currentfilespec->offsets.deposited[k] = currentfilespec->offsets.deposited[i];
      }
      k++;
    }

    // resize
    currentfilespec->offsets.numheaders = k;
    currentfilespec->offsets.headerstorage = k;


    if (currentfilespec->offsets.numheaders == 0) {
      if (currentfilespec->offsets.headers) {
        free(currentfilespec->offsets.headers);
        free(currentfilespec->offsets.headerlens);
        free(currentfilespec->offsets.deposited);
        currentfilespec->offsets.headers = NULL;
        currentfilespec->offsets.headerlens = NULL;
        currentfilespec->offsets.deposited = NULL;
      }
    }
    else {
      currentfilespec->offsets.headers = (uint64_t *)realloc(currentfilespec->offsets.headers,
                                                             sizeof(uint64_t) * currentfilespec->offsets.headerstorage);
      check_memory_allocation(currentfilespec->offsets.headers, __LINE__, __FILE__, "headers array");

      currentfilespec->offsets.headerlens = (size_t *)realloc(currentfilespec->offsets.headerlens,
                                                              sizeof(size_t) * currentfilespec->offsets.headerstorage);
      check_memory_allocation(currentfilespec->offsets.headerlens, __LINE__, __FILE__, "headerlens array");

      currentfilespec->offsets.deposited = (bool *)realloc(currentfilespec->offsets.deposited,
                                                           sizeof(bool) * currentfilespec->offsets.headerstorage);
      check_memory_allocation(currentfilespec->offsets.deposited, __LINE__, __FILE__, "deposited");
    }

    // any footers that are covered or in a block of the incorrect type are pruned
    k = 0;
    for (i = 0; i < currentfilespec->offsets.numfooters; i++) {
      if (filemirror_actual_location_covered(scalpel_state.filemirror, currentfilespec->offsets.footers[i])
          || ! filemirror_get_blocktype(scalpel_state.filemirror, currentfilespec->offsets.footers[i] / scalpel_state.blocksize,
                                        needlenum)) {
        continue;
      }

      if (k != i) {
        currentfilespec->offsets.footers[k] = currentfilespec->offsets.footers[i];
        currentfilespec->offsets.footerlens[k] = currentfilespec->offsets.footerlens[i];
      }
      k++;
    }

    // resize
    currentfilespec->offsets.numfooters = k;
    currentfilespec->offsets.footerstorage = k;

    if (currentfilespec->offsets.numfooters == 0) {
      if (currentfilespec->offsets.footers) {
        free(currentfilespec->offsets.footers);
        free(currentfilespec->offsets.footerlens);
        currentfilespec->offsets.footers = NULL;
        currentfilespec->offsets.footerlens = NULL;
      }
    }
    else {
      currentfilespec->offsets.footers = (uint64_t *)realloc(currentfilespec->offsets.footers,
                                                             sizeof(uint64_t) * currentfilespec->offsets.footerstorage);
      check_memory_allocation(currentfilespec->offsets.footers, __LINE__, __FILE__, "footers array");

      currentfilespec->offsets.footerlens = (size_t *)realloc(currentfilespec->offsets.footerlens,
                                                              sizeof(size_t) * currentfilespec->offsets.footerstorage);
      check_memory_allocation(currentfilespec->offsets.footerlens, __LINE__, __FILE__, "footerlens array");
    }
  }
}


// write file and possibly blockvector, subject to configuration options. A file type's (optional)
// NOCARVE function can override the carving operation to avoid writing files that are, e.g., known
// to be uninteresting.
//
// NOTE: The same candidate may be encountered more than once due to work sharing. An fopen("wx")
// check on the UUID-based filename prevents the same candidate from being written twice. For
// suppressed duplicates, the shadow blockmap is still updated so covered blocks are not reused.
// This can result in blockmap updates that do not correspond to carved files.
//
// IMPORTANT: THIS FUNCTION DESTROYS THE 'candidate' unless preserve == true.
void write_candidate(CarveInfo **candidatep, bool preserve) {

  CarveInfo *candidate = *candidatep;
  char file_pathname[PATH_MAX];
  char blockvector_pathname[PATH_MAX];
  unsigned char sha256[32];
  BlockVector *cloneb;

  char sha256hex[32 * 2 + sizeof("-CHOPPED")];

  FILE *check;
  bool dont_carve = false;
  bool too_small = false;
  uuid_string_t uuidp;
  uuid_string_t uuidc;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"

  // generate base pathname from sha256 only when required (VALIDATED/PROMISING).
  // INPROGRESS filenames are UUID-based and don't use hashes.
  sha256hex[0] = 0;
  if (candidate->flavor == VALIDATED || candidate->flavor == PROMISING) {
    SHA256((unsigned char *)blockvector_get_data_pointer(candidate->b),
           blockvector_get_data_length(candidate->b), sha256);
    sprinthex(sha256hex, (char *)sha256, 32, false);
  }

  // get human-readable UUIDs
  uuid_unparse_lower(candidate->binuuid, uuidp);
  uuid_unparse_lower(candidate->clone_binuuid, uuidc);

  if ((candidate->flavor == PROMISING || candidate->flavor == INPROGRESS)
      && primary_uuid_is_killed(candidate->binuuid)) {
    dont_carve = true;
    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout,
                   "write_candidate() suppressing stale %s candidate with "
                   "primary UUID %s.\n",
                   candidate->flavor == PROMISING ? "PROMISING" : "INPROGRESS",
                   uuidp);
    }
  }

  if (candidate->flavor == VALIDATED
      && (candidate->partial_artifact_written || candidate->clone || candidate->cloned)
      && atomic_load_explicit(&kill_queue_initialized, memory_order_acquire)) {
    add_to_queue(&kill_queue, candidate->binuuid, INT_MAX - time(NULL));
    queue_partial_cleanup(candidate->binuuid);
  }

  // if there's a NOCARVE function and the file is fully validated, see if the carve should proceed
  if (! dont_carve && candidate->flavor == VALIDATED && scalpel_state.search_specs[candidate->needleidx].DONTCARVE) {

    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout, "Calling don't carve function on %p.\n", candidate);
    }

    if (scalpel_state.search_specs[candidate->needleidx].DONTCARVE(blockvector_get_data_pointer(candidate->b),
                                                                   blockvector_get_data_length(candidate->b), sha256hex)) {
      if (scalpel_state.mode_verbose) {
        lock_fprintf(stdout, "Don't carve confirmed for %p, will not write file.\n", candidate);
      }
      dont_carve = true;
    }
  }
  else if (! dont_carve
           && candidate->flavor != INPROGRESS
           && blockvector_get_data_length(candidate->b) < scalpel_state.search_specs[candidate->needleidx].MINIMUMSIZE
           && scalpel_state.search_specs[candidate->needleidx].SEARCHTYPE != SEARCHTYPE_BLOCK_ONLY) {
    // too short and not special block-only case, so don't write
    dont_carve = true;
    too_small = true;
    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout,
                   "Candidate with UUIDS \n%s and %s\n"
                   "does not meet min size requirements for file type, not writing.\n",
                   uuidp, uuidc);
    }
  }

  if (! dont_carve) {

    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout,
                   "write_candidate() processing candidate with UUIDs\n"
                   "%s and %s (%s),\ngenerating unique filename.\n",
                   uuidp, uuidc,
                   candidate->flavor == PROMISING ? "PROMISING" : (candidate->flavor == VALIDATED ? "VALIDATED" : "INPROGRESS"));
    }

    // lock needle for filename creation
    MUTEX_ERROR_CHECK(pthread_mutex_lock(&scalpel_state.search_specs[candidate->needleidx].filewritelock), __LINE__, __FILE__);

    // one more file to write
    file_pathname[0] = 0;
    blockvector_pathname[0] = 0;

    // get pathname for carved file and associated blockvector

    // flavor and subdir first
    if (scalpel_state.organize_subdirectories) {
      if (candidate->flavor == VALIDATED && scalpel_state.search_specs[candidate->needleidx].validated_in_subdir == 0) {
        // first file in new subdir, so update subdir name and call mkdir()
        snprintf(scalpel_state.search_specs[candidate->needleidx].v_current_subdir, PATH_MAX, "%s/%s/%s-%1" PRIu64 "",
                 scalpel_state.output_directory, "VALIDATED", scalpel_state.search_specs[candidate->needleidx].FILETYPE,
                 scalpel_state.search_specs[candidate->needleidx].v_organize_dir_num);
        mkdir(scalpel_state.search_specs[candidate->needleidx].v_current_subdir, 0777);
      }
      else if (candidate->flavor == PROMISING && scalpel_state.search_specs[candidate->needleidx].promising_in_subdir == 0) {
        // first file in new subdir, so update subdir name and call mkdir()
        snprintf(scalpel_state.search_specs[candidate->needleidx].p_current_subdir, PATH_MAX, "%s/%s/%s-%1" PRIu64 "",
                 scalpel_state.output_directory, "PROMISING", scalpel_state.search_specs[candidate->needleidx].FILETYPE,
                 scalpel_state.search_specs[candidate->needleidx].p_organize_dir_num);
        mkdir(scalpel_state.search_specs[candidate->needleidx].p_current_subdir, 0777);
      }
      else if (candidate->flavor == INPROGRESS && scalpel_state.search_specs[candidate->needleidx].inprogress_in_subdir == 0
               && ! candidate->inprogress_pathname[0]) {
        // no fixed inprogress_pathname yet and first file in new subdir, so update subdir name and
        // call mkdir()
        snprintf(scalpel_state.search_specs[candidate->needleidx].i_current_subdir, PATH_MAX, "%s/%s/%s-%1" PRIu64 "",
                 scalpel_state.output_directory, "INPROGRESS", scalpel_state.search_specs[candidate->needleidx].FILETYPE,
                 scalpel_state.search_specs[candidate->needleidx].i_organize_dir_num);
        mkdir(scalpel_state.search_specs[candidate->needleidx].i_current_subdir, 0777);
      }
    }
    else {
      // no organization into subdirs
      snprintf(scalpel_state.search_specs[candidate->needleidx].v_current_subdir, PATH_MAX, "%s/%s", scalpel_state.output_directory,
               "VALIDATED");
      snprintf(scalpel_state.search_specs[candidate->needleidx].p_current_subdir, PATH_MAX, "%s/%s", scalpel_state.output_directory,
               "PROMISING");
      snprintf(scalpel_state.search_specs[candidate->needleidx].i_current_subdir, PATH_MAX, "%s/%s", scalpel_state.output_directory,
               "INPROGRESS");
    }

    switch (candidate->flavor) {
    case VALIDATED:
      // put UUIDS in filenames for job tracking
      snprintf(file_pathname, PATH_MAX, "%s/UUIDS-$$%s$$%s$$-%s.%s",
               scalpel_state.search_specs[candidate->needleidx].v_current_subdir, uuidp, uuidc, sha256hex,
               scalpel_state.search_specs[candidate->needleidx].FILETYPE);

      // UNIQUENESS CHECK (needed because work sharing can cause the same candidate to validate
      // more than once)
      if ((check = fopen(file_pathname, "wx"))) {
        // file didn't exist, now it does
        fclose(check);
        // one more validated file
        scalpel_state.search_specs[candidate->needleidx].validated_in_subdir++;
        atomic_fetch_add_explicit(&scalpel_state.validated_files, 1, memory_order_acq_rel);
        atomic_fetch_add_explicit(&scalpel_state.search_specs[candidate->needleidx].validated_files, 1, memory_order_acq_rel);

        // only a reasonable number of files in each subdir
        if (scalpel_state.search_specs[candidate->needleidx].validated_in_subdir == MAX_FILES_PER_SUBDIRECTORY
            && scalpel_state.organize_subdirectories) {
          // reached max # of files per subdir; next write will be in a new subdir
          scalpel_state.search_specs[candidate->needleidx].v_organize_dir_num++;
          scalpel_state.search_specs[candidate->needleidx].v_current_subdir[0] = 0;
          scalpel_state.search_specs[candidate->needleidx].validated_in_subdir = 0;
        }
      }
      else {
        dont_carve = true;
      }
      break;

    case PROMISING:
      // mark CHOPPED files
      if (candidate->chopped) {
        strcat(sha256hex, "-CHOPPED");
      }

      // put UUIDS in filenames for job tracking
      snprintf(file_pathname, PATH_MAX, "%s/UUIDS-$$%s$$%s$$-%s.%s",
               scalpel_state.search_specs[candidate->needleidx].p_current_subdir, uuidp, uuidc, sha256hex,
               scalpel_state.search_specs[candidate->needleidx].FILETYPE);

      // UNIQUENESS CHECK (needed because of reassembly thread work sharing)
      if ((check = fopen(file_pathname, "wx"))) {
        // file didn't exist, now it does
        fclose(check);
        scalpel_state.search_specs[candidate->needleidx].promising_in_subdir++;

        // only a reasonable number of files in each subdir
        if (scalpel_state.search_specs[candidate->needleidx].promising_in_subdir == MAX_FILES_PER_SUBDIRECTORY
            && scalpel_state.organize_subdirectories) {
          // reached max # of files per subdir; next write will be in a new subdir
          scalpel_state.search_specs[candidate->needleidx].p_organize_dir_num++;
          scalpel_state.search_specs[candidate->needleidx].p_current_subdir[0] = 0;
          scalpel_state.search_specs[candidate->needleidx].promising_in_subdir = 0;
        }
      }
      else {
        dont_carve = true;
      }
      break;

    case INPROGRESS:
      // INPROGRESS files have a fixed pathname to make monitoring easier. The filename consists
      // solely of the UUIDs for the candidate to make the name unique.

      if (! candidate->inprogress_pathname[0]) {
        // no fixed name yet, so generate one
        snprintf(file_pathname, PATH_MAX, "%s/UUIDS-$$%s$$%s$$.%s",
                 scalpel_state.search_specs[candidate->needleidx].i_current_subdir, uuidp, uuidc,
                 scalpel_state.search_specs[candidate->needleidx].FILETYPE);
        strcpy(candidate->inprogress_pathname, file_pathname);

        scalpel_state.search_specs[candidate->needleidx].inprogress_in_subdir++;

        // only a reasonable number of files in each subdir
        if (scalpel_state.search_specs[candidate->needleidx].inprogress_in_subdir == MAX_FILES_PER_SUBDIRECTORY
            && scalpel_state.organize_subdirectories) {
          // reached max # of files per subdir; next unique inprogress will be in a new subdir
          scalpel_state.search_specs[candidate->needleidx].i_organize_dir_num++;
          scalpel_state.search_specs[candidate->needleidx].i_current_subdir[0] = 0;
          scalpel_state.search_specs[candidate->needleidx].inprogress_in_subdir = 0;
        }
      }
      else {
        strcpy(file_pathname, candidate->inprogress_pathname);
      }
      break;

    default:
      handle_error(SCALPEL_GENERAL_ABORT,
                   "** BAD STATE IN write_candidate() **,\nPLEASE REPORT THIS "
                   "ERROR, ABORTING.\n",
                   __LINE__, __FILE__);
    }

    if (scalpel_state.write_blockvectors) {
      // generate pathname for blockvector
      snprintf(blockvector_pathname, PATH_MAX, "%s.BLOCKVECTOR.txt", file_pathname);
    }

    // unlock needle for filename creation. The lock is only needed for filename generation--I/O can
    // happen without the lock, to increase performance.
    MUTEX_ERROR_CHECK(pthread_mutex_unlock(&scalpel_state.search_specs[candidate->needleidx].filewritelock), __LINE__, __FILE__);

    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout,
                   "write_candidate() using pathname\n\"%s\"\n for "
                   "candidate with blockvector %p and UUIDs\n%s / %s%s",
                   file_pathname, candidate->b, uuidp, uuidc, dont_carve ? "\nbut the file will not be written.\n" : ".\n");
    }
  }

  // free global carve state associated with this candidate only for destructive
  // writes. Preserved writes (e.g. INPROGRESS / backtracking snapshots) must
  // retain state so recovery can resume from the same frontier.
  if (!preserve
      && candidate->workload == VALIDATE_FILE
      && scalpel_state.search_specs[candidate->needleidx].carve_state) {
    carve_free_state(candidate->carvehashkey);
  }

  // write only if the file is unique and the DONTCARVE function is allowing the file to be written.
  // For VALIDATED files, always update the blockmap, since there could be duplicate files. Passing
  // NULL for both filenames causes write_blockvector() to update the shadow blockmap but not write
  // any data to disk. The blockvector is freed by write_blockvector().

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "\n%s %s candidate with UUIDs\n%s / %s.\n.", dont_carve ? "Not writing" : "Writing",
                 candidate->flavor == PROMISING   ? "PROMISING"
                 : candidate->flavor == VALIDATED ? "VALIDATED"
                                                  : "INPROGRESS",
                 uuidp, uuidc);
  }

  if (! dont_carve) {
    // if preserve is set, this is a non-destructive write, so a clone of the blockvector must be
    // used, as write_blockvector always frees the blockvector

    if (preserve) {
      // clone blockvector *without* copying the choice info
      clone_blockvector(candidate->b, &cloneb, false);
      // For INPROGRESS candidates: trim the clone to best_validates_to + 1
      // so only validated data is written. This prevents transient exploration
      // state (unvalidated blocks being tested) from appearing in checkpoints.
      if (candidate->flavor == INPROGRESS && candidate->best_validates_to > 0
          && candidate->best_validates_to + 1 < blockvector_get_data_length(cloneb)
          && scalpel_state.blocksize > 0) {
        blockvector_set_data_length(cloneb, candidate->best_validates_to + 1);
        resize_blockvector(cloneb, CEILDIV(candidate->best_validates_to + 1, scalpel_state.blocksize));
      }
    }
    else {
      cloneb = NULL;
    }

    write_blockvector(cloneb ? cloneb : candidate->b, dont_carve ? NULL : file_pathname,
                      (dont_carve || ! scalpel_state.write_blockvectors) ? NULL : blockvector_pathname,
                      candidate->flavor == VALIDATED);  // blockmap updates only for validated files

    if (candidate->flavor == PROMISING || candidate->flavor == INPROGRESS) {
      candidate->partial_artifact_written = true;
      if (primary_uuid_is_killed(candidate->binuuid)) {
        queue_partial_cleanup(candidate->binuuid);
      }
    }

    // only update the files written counter if something is actually written one more file written
    atomic_fetch_add_explicit(&scalpel_state.files_written, 1, memory_order_acq_rel);
  }
  else if (candidate->flavor == VALIDATED && ! too_small) {
    // suppressed validated candidate (duplicate or DONTCARVE)--still cover the blocks
    filemirror_update_blockmap(scalpel_state.filemirror, candidate->b);
  }

  // remove fully validated candidates from reassembly queue, which mirrors carving operations being
  // performed by threads
  if (candidate->flavor == VALIDATED) {
    delete_from_reassembly_queue(candidate);
  }

  if (! preserve) {
    if (! dont_carve) {
      // IMPORTANT: destroy_candidate() is NOT called here because write_blockvector will free
      // candidate->b. Other resources associated with candidate are manually freed instead.

      if (candidate->best_choices) {
        destroy_queue(candidate->best_choices);
        free(candidate->best_choices);
        candidate->best_choices = NULL;
      }

      free(candidate);
    }
    else {
      // didn't call write_blockvector(), so need full destroy
      destroy_candidate(&candidate);
    }
    *candidatep = NULL;
  }

#pragma GCC diagnostic pop
}


// initialize thread-related data structures and create threads
static void start_threads(void) {

  int32_t i;
  pthread_mutexattr_t mutextype;  // used to set types of all mutexes

  // set default mutex type
  if (pthread_mutexattr_init(&mutextype) != 0) {
    handle_error(SCALPEL_ERROR_MUTEX_FAILURE, "start_threads()", __LINE__, __FILE__);
  }

  if (pthread_mutexattr_settype(&mutextype, PTHREAD_MUTEX_TYPE) != 0) {
    handle_error(SCALPEL_ERROR_MUTEX_FAILURE, "start_threads", __LINE__, __FILE__);
  }

  // initialize global data structures for threads

  atomic_init(&partial_cleanup_thread_stop, false);

  if (pthread_mutex_init(&partial_cleanup_work_is_available, &mutextype)) {
    // fatal
    handle_error(SCALPEL_ERROR_MUTEX_FAILURE, "init_threads()", __LINE__, __FILE__);
  }

  if (pthread_cond_init(&partial_cleanup_check_work_available, NULL)) {
    // fatal
    handle_error(SCALPEL_ERROR_MUTEX_FAILURE, "init_threads()", __LINE__, __FILE__);
  }

  if (pthread_create(&partial_cleanupthread, NULL, partial_cleanup_thread, NULL)) {
    // fatal
    handle_error(SCALPEL_ERROR_PTHREAD_FAILURE, "init_threads()", __LINE__, __FILE__);
  }

  // search threads
  searchthreads = (pthread_t *)malloc(scalpel_state.max_search_threads * sizeof(pthread_t));
  check_memory_allocation(searchthreads, __LINE__, __FILE__, "searchthreads");
  searchthreadargs = (SearchThreadWork *)malloc(scalpel_state.max_search_threads * sizeof(SearchThreadWork));
  check_memory_allocation(searchthreadargs, __LINE__, __FILE__, "searchthreadargs");

  // validation threads
  validationthreads = (pthread_t *)malloc(scalpel_state.max_validation_threads * sizeof(pthread_t));
  check_memory_allocation(validationthreads, __LINE__, __FILE__, "validationthreads");
  validationthreadargs = (ThreadWork *)malloc(scalpel_state.max_validation_threads * sizeof(ThreadWork));
  check_memory_allocation(validationthreadargs, __LINE__, __FILE__, "validationthreadargs");

  // reassembly threads
  reassemblythreads = (pthread_t *)malloc(scalpel_state.max_reassembly_threads * sizeof(pthread_t));
  check_memory_allocation(reassemblythreads, __LINE__, __FILE__, "reassemblythreads");
  reassemblythreadargs = (ThreadWork *)malloc(scalpel_state.max_reassembly_threads * sizeof(ThreadWork));
  check_memory_allocation(reassemblythreadargs, __LINE__, __FILE__, "reassemblythreadargs");

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Creating search threads.\n");
  }

  // initialize related mutexes and condition variables then create and start search threads
  atomic_init(&num_idle_search_threads, scalpel_state.max_search_threads);

  for (i = 0; i < scalpel_state.max_search_threads; i++) {
    searchthreadargs[i].id = i;
    searchthreadargs[i].b = NULL;
    atomic_init(&searchthreadargs[i].thread_running, false);
    atomic_init(&searchthreadargs[i].thread_stop, false);
    atomic_init(&searchthreadargs[i].thread_ready, false);

    if (pthread_mutex_init(&searchthreadargs[i].work_is_available, &mutextype)) {
      // fatal
      handle_error(SCALPEL_ERROR_MUTEX_FAILURE, "init_threads()", __LINE__, __FILE__);
    }

    if (pthread_cond_init(&searchthreadargs[i].check_work_available, NULL)) {
      // fatal
      handle_error(SCALPEL_ERROR_MUTEX_FAILURE, "init_threads()", __LINE__, __FILE__);
    }

    if (pthread_create(&searchthreads[i], NULL, search_thread, &searchthreadargs[i])) {
      // fatal
      handle_error(SCALPEL_ERROR_PTHREAD_FAILURE, "init_threads()", __LINE__, __FILE__);
    }
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Creating reassembly threads.\n");
  }

  // initialize related mutexes and condition variables then create and start reassembly threads
  atomic_init(&num_idle_reassembly_threads, scalpel_state.max_reassembly_threads);

  if (pthread_mutex_init(&reassembly_work_is_available, &mutextype)) {
    // fatal
    handle_error(SCALPEL_ERROR_MUTEX_FAILURE, "init_threads()", __LINE__, __FILE__);
  }

  if (pthread_cond_init(&reassembly_check_work_available, NULL)) {
    // fatal
    handle_error(SCALPEL_ERROR_MUTEX_FAILURE, "init_threads()", __LINE__, __FILE__);
  }

  for (i = 0; i < scalpel_state.max_reassembly_threads; i++) {
    reassemblythreadargs[i].id = i;
    atomic_init(&reassemblythreadargs[i].thread_running, false);
    atomic_init(&reassemblythreadargs[i].thread_stop, false);

    if (pthread_create(&reassemblythreads[i], NULL, reassembly_thread, &reassemblythreadargs[i])) {
      // fatal
      handle_error(SCALPEL_ERROR_PTHREAD_FAILURE, "init_threads()", __LINE__, __FILE__);
    }
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Creating validation threads.\n");
  }

  // initialize related mutexes and condition variables then create and start validation threads
  atomic_init(&num_idle_validation_threads, scalpel_state.max_validation_threads);

  if (pthread_mutex_init(&validation_work_is_available, &mutextype)) {
    // fatal
    handle_error(SCALPEL_ERROR_MUTEX_FAILURE, "init_threads()", __LINE__, __FILE__);
  }

  if (pthread_cond_init(&validation_check_work_available, NULL)) {
    // fatal
    handle_error(SCALPEL_ERROR_MUTEX_FAILURE, "init_threads()", __LINE__, __FILE__);
  }

  for (i = 0; i < scalpel_state.max_validation_threads; i++) {
    validationthreadargs[i].id = i;
    atomic_init(&validationthreadargs[i].thread_running, false);
    atomic_init(&validationthreadargs[i].thread_stop, false);

    if (pthread_create(&validationthreads[i], NULL, validation_thread, &validationthreadargs[i])) {
      // fatal
      handle_error(SCALPEL_ERROR_PTHREAD_FAILURE, "init_threads()", __LINE__, __FILE__);
    }
  }

  // create IPC thread that supports status reports, checkpoint initiation, etc. unless IPC is off

  if (! no_IPC) {
    // start IPC thread
    if (pthread_create(&ipc, NULL, ipc_thread, NULL) != 0) {
      // fatal
      handle_error(SCALPEL_ERROR_PTHREAD_FAILURE, "create_ipc_thread()", __LINE__, __FILE__);
    }
  }
  else {
    frame_message("IPC IS OFF BECAUSE OF COMMAND LINE OPTION");
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Thread creation completed.\n");
  }
}


// thread that supports "human in the loop" IPC with scalpel3-ctl through a Unix domain socket.
static void *ipc_thread(void *arg) {

  int clientsock;
  int len;
  struct sockaddr_un server;
  char sockname[PATH_MAX];
  static char buf[SOCKBUFSIZE + 1];
  static char buf2[SOCKBUFSIZE + 2];
  uuid_t killuuid;
  uuid_string_t textuuid;
  struct timeval tv;
  static struct timespec brief_wait = {.tv_sec = 0, .tv_nsec = 100 * 1000};

  (void)arg;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"

  // establish IPC endpoint in base output directory for this scalpel3 instance
  snprintf(sockname, PATH_MAX, "%s/.scalpel3IPC", scalpel_state.base_output_directory);

#pragma GCC diagnostic pop

  // kill IPC endpoint file if it exists
  unlink(sockname);

  // establish endpoint
  ipcsocket = socket(AF_UNIX, SOCK_STREAM, 0);
  if (ipcsocket < 0) {
    handle_error(SCALPEL_ERROR_IPC, "ipc_thread()", __LINE__, __FILE__);
  }

  // Unix domain sockets are used for endpoint
  server.sun_family = AF_UNIX;
  if (strlen(sockname) >= sizeof(server.sun_path)) {
    fprintf(stderr, "Error: Socket path too long (max %zu bytes): %s\n", sizeof(server.sun_path) - 1, sockname);
    handle_error(SCALPEL_ERROR_IPC, "ipc_thread()", __LINE__, __FILE__);
  }

  strcpy(server.sun_path, sockname);
  if (bind(ipcsocket, (struct sockaddr *)&server, sizeof(struct sockaddr_un))) {
    handle_error(SCALPEL_ERROR_IPC, "ipc_thread()", __LINE__, __FILE__);
  }

  listen(ipcsocket, 15);

  lock_fprintf(stdout, "\nIPC thread is awake and listening on Unix domain socket \"%s\".\n", sockname);

  // repeatedly accept one request from an IPC client, process, close connection
  while (1) {
    clientsock = accept(ipcsocket, 0, 0);
    if (clientsock < 0) {
      handle_error(SCALPEL_ERROR_IPC, "ipc_thread()", __LINE__, __FILE__);
    }

    // timeouts on read and write prevent the IPC thread from hanging because of a misbehaving
    // client, without the need for multithreading (since all scalpel3 IPC interactions are brief).
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(clientsock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt(clientsock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));

    lock_fprintf(stdout, "\nIPC connection accepted.\n");

    while (1) {
      memset(buf, 0, sizeof(buf));
      if ((len = read(clientsock, buf, SOCKBUFSIZE)) <= 0) {
        goto endclient;
      }

      if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = 0;
      }

      if (! strcmp(buf, KILL_CMD)) {
        if (! atomic_load_explicit(&kill_queue_initialized, memory_order_acquire)) {
          snprintf(buf, SOCKBUFSIZE, "IPC KILL COMMAND BEFORE QUEUE INITIALIZATION, REJECTING");
          frame_message(buf);
          if (write(clientsock, NOT_READY_KILL_RESPONSE, NOT_READY_KILL_RESPONSE_LEN) != NOT_READY_KILL_RESPONSE_LEN) {
            lock_fprintf(stderr, "\nNon-fatal error: couldn't send response to IPC instance.\n");
            goto endclient;
          }
        }
        else {
          // if the UUID wasn't coalesced into the first read, do a second read
          if (len <= (int)KILL_CMD_LEN) {
            int ulen = read(clientsock, buf + len, SOCKBUFSIZE - len);
            if (ulen <= 0) {
              goto endclient;
            }
            len += ulen;
          }
          buf[KILL_CMD_LEN + 37] = 0;
          memcpy(textuuid, buf + KILL_CMD_LEN, 37);
          if (uuid_parse(textuuid, killuuid) < 0) {
            snprintf(buf, SOCKBUFSIZE, "IPC KILL COMMAND HAD INVALID UUID \"%s\", REJECTING", textuuid);
            frame_message(buf);
            if (write(clientsock, BAD_KILL_RESPONSE, BAD_KILL_RESPONSE_LEN) != BAD_KILL_RESPONSE_LEN) {
              lock_fprintf(stderr, "\nNon-fatal error: couldn't send response "
                                   "to IPC instance.\n");
              goto endclient;
            }
          }
          else {
            snprintf(buf, SOCKBUFSIZE, "QUEUEING IPC KILL COMMAND FOR UUID \"%s\"", textuuid);
            frame_message(buf);

            // add kill command to kill queue so active threads will destroy associated carving
            // candidate(s)
            add_to_queue(&kill_queue, killuuid, INT_MAX - time(NULL));

            // ...and also immediately remove any matching candidates from the promising queue
            prune_uuid_from_promising_queue(killuuid);

            if (write(clientsock, KILL_RESPONSE, KILL_RESPONSE_LEN) != KILL_RESPONSE_LEN) {
              lock_fprintf(stderr, "\nNon-fatal error: couldn't send response "
                                   "to IPC instance.\n");
              goto endclient;
            }
          }
        }
      }
      else if (! strcmp(buf, STATUS_CMD)) {
        frame_message("PROCESSING IPC STATUS COMMAND");
        // status response isn't fixed, so there's no associated definition in scalpel.h
        uint64_t total_wait;
        struct timespec endtime;

        clock_gettime(CLOCK_MONOTONIC, &endtime);
        total_wait = (endtime.tv_sec - starttime.tv_sec) * 1e9 + (endtime.tv_nsec - starttime.tv_nsec);

        buf2[0] = 0;

#if VALIDATOR_PERFORMANCE_STATS > 0
        if (! scalpel_state.no_defrag) {
          strncpy(buf2, "\nFragmented reassembly backtracking report:\n", SOCKBUFSIZE);
          for (uint64_t i = 0; i < scalpel_state.num_specs; i++) {
            if (! scalpel_state.search_specs[i].MASTER && ! scalpel_state.search_specs[i].NO_DEFRAG
                && (scalpel_state.search_specs[i].FILEVALIDATOR || scalpel_state.search_specs[i].REASSEMBLYFUNC)) {
              snprintf(buf, SOCKBUFSIZE, "  %-10s\t%9" PRIu64 " backtracking operations\n", scalpel_state.search_specs[i].FILETYPE,
                       (uint64_t)atomic_load_explicit(&scalpel_state.search_specs[i].backtracked, memory_order_acquire));
              strncat(buf2, buf, SOCKBUFSIZE + 1 - strlen(buf2));
            }
          }

          strncat(buf2, "\nFragmented reassembly file validator performance:\n", SOCKBUFSIZE + 1 - strlen(buf2));
          for (uint64_t i = 0; i < scalpel_state.num_specs; i++) {
            if (! scalpel_state.search_specs[i].MASTER && ! scalpel_state.search_specs[i].NO_DEFRAG
                && (scalpel_state.search_specs[i].FILEVALIDATOR || scalpel_state.search_specs[i].REASSEMBLYFUNC)) {
              snprintf(buf, SOCKBUFSIZE,
                       "  %-10s\t%9" PRIu64 " calls, \t%8.4lf secs total time, "
                       "\t%5.4lf secs longest time\n",
                       scalpel_state.search_specs[i].FILETYPE,
                       (uint64_t)atomic_load_explicit(&scalpel_state.search_specs[i].FV_calls, memory_order_acquire),
                       (double)atomic_load_explicit(&scalpel_state.search_specs[i].FV_total, memory_order_acquire) / 1e9,
                       (double)atomic_load_explicit(&scalpel_state.search_specs[i].FV_longest, memory_order_acquire) / 1e9);
              strncat(buf2, buf, SOCKBUFSIZE + 1 - strlen(buf2));
            }
          }
        }
        else {
          snprintf(buf2, SOCKBUFSIZE, "Contiguous-only carving via -f, omitting reassembly reports.\n");
        }
#endif

#if BLOCK_SELECTION_PERFORMANCE_STATS > 0
        if (! scalpel_state.no_defrag) {
          strncat(buf2, "\nFragmented reassembly block selection performance:\n", SOCKBUFSIZE + 1 - strlen(buf2));
          for (uint64_t i = 0; i < scalpel_state.num_specs; i++) {
            if (! scalpel_state.search_specs[i].MASTER && ! scalpel_state.search_specs[i].NO_DEFRAG
                && (scalpel_state.search_specs[i].FILEVALIDATOR || scalpel_state.search_specs[i].REASSEMBLYFUNC)) {
              snprintf(buf, SOCKBUFSIZE,
                       "  %-10s\t%9" PRIu64 " calls, \t%8.4lf secs total time, \t%5.4lf secs "
                       "longest time,\tmost considered: %9" PRIu64 "\n",
                       scalpel_state.search_specs[i].FILETYPE,
                       (uint64_t)atomic_load_explicit(&scalpel_state.search_specs[i].BLK_calls, memory_order_acquire),
                       (double)atomic_load_explicit(&scalpel_state.search_specs[i].BLK_total, memory_order_acquire) / 1e9,
                       (double)atomic_load_explicit(&scalpel_state.search_specs[i].BLK_longest, memory_order_acquire) / 1e9,
                       (uint64_t)atomic_load_explicit(&scalpel_state.search_specs[i].BLK_most_blocks, memory_order_acquire));
              strncat(buf2, buf, SOCKBUFSIZE + 1 - strlen(buf2));
            }
          }
        }
        else {
          snprintf(buf2, SOCKBUFSIZE,
                   "Contiguous-only carving via -f, omitting block selection "
                   "reports.\n");
        }
#endif

        snprintf(buf, SOCKBUFSIZE,
                 "\nCarving stats:\n"
                 "Header/footer discovery [real time]   = %.4lf secs.\n"
                 "Sequential I/O wait     [real time]   = %.4lf secs.\n"
                 "Random read wait        [overlapping] = %.4lf secs.\n"
                 "Random write wait       [overlapping] = %.4lf secs.\n"
                 "Total elapsed time                    = %.4lf secs.\n"
                 "Validated files                       = %" PRIu64 ".\n"
                 "Total unique files carved             = %" PRIu64 ".\n"
                 "File mirror load                      = %" PRIu32 ".\n"
                 "Carvelist queue length                = %" PRIu64 ".\n"
                 "Promising queue length                = %" PRIu64 ".\n"
                 "Search threads     (idle / max)       = %" PRIu32 " / %" PRIu32 ".\n"
                 "Validation threads (idle / total)     = %" PRIu32 " / %" PRIu32 ".\n"
                 "Reassembly threads (idle / total)     = %" PRIu32 " / %" PRIu32 ".\n",
                 (double)atomic_load_explicit(&header_footer_wait, memory_order_acquire) / 1e9, (double)seq_io_wait / 1e9,
                 (double)atomic_load_explicit(&random_read_wait, memory_order_acquire) / 1e9,
                 (double)atomic_load_explicit(&random_write_wait, memory_order_acquire) / 1e9, (double)total_wait / 1e9,
                 (uint64_t)atomic_load_explicit(&scalpel_state.validated_files, memory_order_acquire),
                 (uint64_t)atomic_load_explicit(&scalpel_state.files_written, memory_order_acquire),
                 filemirror_load(scalpel_state.filemirror), nolock_queue_length(&carvelist), nolock_queue_length(&promising_queue),
                 atomic_load_explicit(&num_idle_search_threads, memory_order_acquire), scalpel_state.max_search_threads,
                 atomic_load_explicit(&num_idle_validation_threads, memory_order_acquire), scalpel_state.max_validation_threads,
                 atomic_load_explicit(&num_idle_reassembly_threads, memory_order_acquire), scalpel_state.max_reassembly_threads);
        strncat(buf2, buf, SOCKBUFSIZE + 1 - strlen(buf2));

        if (write(clientsock, buf2, strlen(buf2) + 1) != (ssize_t)(strlen(buf2) + 1)) {
          lock_fprintf(stderr, "Non-fatal error: couldn't send response to IPC instance.\n");
          goto endclient;
        }
      }
      else if (! strcmp(buf, CHECKPOINTEXIT_CMD)) {
        frame_message("IPC CHECKPOINT AND EXIT COMMAND QUEUED. SHUTTING DOWN SOON");
        atomic_store_explicit(&TAKE_CHECKPOINT_AND_EXIT, true, memory_order_release);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"

        // immediately inhibit additional IPC operations
        snprintf(sockname, PATH_MAX, "%s/.scalpel3IPC", scalpel_state.base_output_directory);
        unlink(sockname);

#pragma GCC diagnostic pop

        if (write(clientsock, CHECKPOINTEXIT_RESPONSE, CHECKPOINTEXIT_RESPONSE_LEN) != CHECKPOINTEXIT_RESPONSE_LEN) {
          lock_fprintf(stderr, "Non-fatal error: couldn't send response to IPC instance.\n");
          goto endclient;
        }
      }
      else if (! strcmp(buf, PROGRESSCHECKPOINT_CMD)) {
        if (atomic_load_explicit(&TAKE_CHECKPOINT_AND_EXIT, memory_order_acquire)
            || atomic_load_explicit(&TAKE_RECOVERY_CHECKPOINT, memory_order_acquire)
            || atomic_load_explicit(&TAKE_PERIODIC_CHECKPOINT, memory_order_acquire)
            || atomic_load_explicit(&TAKE_PROGRESS_CHECKPOINT, memory_order_acquire)
            || atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
          frame_message("IPC PROGRESS CHECKPOINT NOT INITIATED AS A CHECKPOINT IS UNDERWAY");
          if (write(clientsock, PROGRESSCHECKPOINT_RESPONSE_NACK, PROGRESSCHECKPOINT_RESPONSE_NACK_LEN)
              != PROGRESSCHECKPOINT_RESPONSE_NACK_LEN) {
            lock_fprintf(stderr, "\nNon-fatal error: couldn't send response to IPC instance.\n");
            goto endclient;
          }
        }
        else {
          frame_message("INITIATING NEW IPC PROGRESS CHECKPOINT OPERATION");
          atomic_store_explicit(&TAKE_PROGRESS_CHECKPOINT, true, memory_order_release);

          // wait for progress checkpoint to complete before sending response, so client knows when update
          // is complete
          while (atomic_load_explicit(&TAKE_PROGRESS_CHECKPOINT, memory_order_acquire)) {
            nanosleep(&brief_wait, NULL);
          }

          if (write(clientsock, PROGRESSCHECKPOINT_RESPONSE_ACK, PROGRESSCHECKPOINT_RESPONSE_ACK_LEN)
              != PROGRESSCHECKPOINT_RESPONSE_ACK_LEN) {
            lock_fprintf(stderr, "\nNon-fatal error: couldn't send response to IPC instance.\n");
            goto endclient;
          }
        }
      }
      else if (! strcmp(buf, KILLQUEUE_CMD)) {
        if (! atomic_load_explicit(&kill_queue_initialized, memory_order_acquire)) {
          snprintf(buf, SOCKBUFSIZE, "IPC KILLQUEUE COMMAND BEFORE QUEUE INITIALIZATION, REJECTING");
          frame_message(buf);
          if (write(clientsock, NOT_READY_KILLQUEUE_RESPONSE, NOT_READY_KILLQUEUE_RESPONSE_LEN)
              != NOT_READY_KILLQUEUE_RESPONSE_LEN) {
            lock_fprintf(stderr, "\nNon-fatal error: couldn't send response to IPC instance.\n");
            goto endclient;
          }
        }
        else {
          frame_message("INITIATING NEW IPC KILL QUEUE REPORT");

          if (! serialize_queue_h(&kill_queue, kill_queue_element_serialization, clientsock)) {
            lock_fprintf(stderr, "\nNon-fatal error: couldn't send response to IPC instance.\n");
            goto endclient;
          }
        }
      }
      else if (! strcmp(buf, PROMISINGQUEUE_CMD)) {
        if (! atomic_load_explicit(&promising_initialized, memory_order_acquire)) {
          snprintf(buf, SOCKBUFSIZE,
                   "IPC PROMISINGQUEUE COMMAND RECEIVED BEFORE QUEUE "
                   "INITIALIZATION, REJECTING");
          frame_message(buf);
          if (write(clientsock, NOT_READY_PROMISINGQUEUE_RESPONSE, NOT_READY_PROMISINGQUEUE_RESPONSE_LEN)
              != NOT_READY_PROMISINGQUEUE_RESPONSE_LEN) {
            lock_fprintf(stderr, "\nNon-fatal error: couldn't send response to IPC instance.\n");
            goto endclient;
          }
        }
        else {
          frame_message("INITIATING NEW IPC PROMISING QUEUE REPORT");
          if (! write_essential_carveinfo_queue_from_carveinfo_queue_h(&promising_queue, clientsock)) {
            lock_fprintf(stderr, "\nNon-fatal error: couldn't send response to IPC instance.\n");
            goto endclient;
          }
        }
      }
      else if (! strcmp(buf, REASSEMBLYQUEUE_CMD)) {
        if (! atomic_load_explicit(&promising_initialized, memory_order_acquire)) {
          snprintf(buf, SOCKBUFSIZE,
                   "IPC REASSEMBLYQUEUE COMMAND RECEIVED BEFORE QUEUE "
                   "INITIALIZATION, REJECTING");
          frame_message(buf);
          if (write(clientsock, NOT_READY_REASSEMBLYQUEUE_RESPONSE, NOT_READY_REASSEMBLYQUEUE_RESPONSE_LEN)
              != NOT_READY_REASSEMBLYQUEUE_RESPONSE_LEN) {
            lock_fprintf(stderr, "\nNon-fatal error: couldn't send response to IPC instance.\n");
            goto endclient;
          }
        }
        else {
          frame_message("INITIATING NEW IPC REASSEMBLY QUEUE REPORT");
          if (! write_essential_carveinfo_queue_h(&reassembly_queue, clientsock)) {
            lock_fprintf(stderr, "\nNon-fatal error: couldn't send response to IPC instance.\n");
            goto endclient;
          }
        }
      }
      else if (! strcmp(buf, HELLO_CMD)) {
        frame_message("PROCESSING IPC HELLO COMMAND");
        if (write(clientsock, HELLO_RESPONSE, HELLO_RESPONSE_LEN) != HELLO_RESPONSE_LEN) {
          lock_fprintf(stderr, "\nNon-fatal error: couldn't send response to IPC instance.\n");
        }
      }
      else if (! strcmp(buf, BLOCKMAP_CMD)) {
        frame_message("PROCESSING IPC BLOCKMAP COMMAND");
        if (! filemirror_write_blockmap_h(scalpel_state.filemirror, clientsock)) {
          lock_fprintf(stderr, "\nNon-fatal error: couldn't send response to IPC instance.\n");
        }
      }
      else {
        lock_fprintf(stderr, "Unrecognized IPC command \"%s\", ignoring.\n", buf);
      }
    }

  endclient:
    lock_fprintf(stdout, "\nClosing IPC connection.\n");
    close(clientsock);
  }

  close(ipcsocket);
  unlink(sockname);
  return 0;
}


// prepare to shutdown, release memory, cleanup threads. IMPORTANT: This thread simply asks threads
// to stop. There should be no pending work for the threads remaining when stop_threads() is called.
void stop_threads(void) {

  int32_t i;

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Signaling all threads to stop.\n");
  }

  // kill reassembly threads
  for (i = 0; i < scalpel_state.max_reassembly_threads; i++) {
    atomic_store_explicit(&reassemblythreadargs[i].thread_stop, true, memory_order_release);
  }

  MUTEX_ERROR_CHECK(pthread_mutex_lock(&reassembly_work_is_available), __LINE__, __FILE__);
  pthread_cond_broadcast(&reassembly_check_work_available);
  MUTEX_ERROR_CHECK(pthread_mutex_unlock(&reassembly_work_is_available), __LINE__, __FILE__);

  // kill validation threads
  for (i = 0; i < scalpel_state.max_validation_threads; i++) {
    atomic_store_explicit(&validationthreadargs[i].thread_stop, true, memory_order_release);
  }

  MUTEX_ERROR_CHECK(pthread_mutex_lock(&validation_work_is_available), __LINE__, __FILE__);
  pthread_cond_broadcast(&validation_check_work_available);
  MUTEX_ERROR_CHECK(pthread_mutex_unlock(&validation_work_is_available), __LINE__, __FILE__);

  // allow stale artifact cleanup to drain before shutdown completes
  atomic_store_explicit(&partial_cleanup_thread_stop, true, memory_order_release);
  MUTEX_ERROR_CHECK(pthread_mutex_lock(&partial_cleanup_work_is_available), __LINE__, __FILE__);
  pthread_cond_signal(&partial_cleanup_check_work_available);
  MUTEX_ERROR_CHECK(pthread_mutex_unlock(&partial_cleanup_work_is_available), __LINE__, __FILE__);
  pthread_join(partial_cleanupthread, NULL);

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "STOP broadcast to all threads completed.\n");
  }

  lock_fprintf(stdout, "All threads stopped.\n");
}


// check for wildcards in pattern
static bool has_wildcard(const char *pattern, size_t len) {
  return memchr(pattern, SCALPEL_WILDCARD_CHAR, len) != NULL;
}


// simple escape parser - converts \x{HH} and \xHH to actual bytes
static size_t parse_simple_escapes(const char *input, size_t input_len, char *output, size_t max_output) {

  size_t out_pos = 0;
  size_t i = 0;

  while (i < input_len && out_pos < max_output) {
    if (input[i] == '\\' && i + 1 < input_len) {
      if (input[i + 1] == 'x') {
        // \x{HH} or \xHH
        if (i + 2 < input_len && input[i + 2] == '{') {
          // \x{HH}
          unsigned int val = 0;
          size_t j = i + 3;

          while (j < input_len && input[j] != '}') {
            int digit;

            if (input[j] >= '0' && input[j] <= '9') {
              digit = input[j] - '0';
            }
            else if (input[j] >= 'a' && input[j] <= 'f') {
              digit = input[j] - 'a' + 10;
            }
            else if (input[j] >= 'A' && input[j] <= 'F') {
              digit = input[j] - 'A' + 10;
            }
            else {
              return 0;  // invalid
            }
            val = (val << 4) | digit;
            j++;
          }
          if (j >= input_len || val > 255) {
            return 0;
          }
          output[out_pos++] = (char)val;
          i = j + 1;
        }
        else if (i + 3 < input_len) {
          // \xHH
          char hex[3] = {input[i + 2], input[i + 3], 0};
          unsigned int val;

          if (sscanf(hex, "%2x", &val) != 1) {
            return 0;
          }
          output[out_pos++] = (char)val;
          i += 4;
        }
        else {
          return 0;  // incomplete
        }
      }
      else {
        return 0;    // other escape
      }
    }
    else {
      output[out_pos++] = input[i];
      i++;
    }
  }
  return out_pos;
}


// look for simple alternatives in regex's
static bool is_simple_alternative(const char *alt, size_t alt_len) {

  char parsed[256];
  size_t parsed_len = parse_simple_escapes(alt, alt_len, parsed, sizeof(parsed));

  if (parsed_len == 0) {
    // parse failed, fall back to original check
    for (size_t i = 0; i < alt_len; i++) {
      char c = alt[i];

      if (c == '.') {
        continue;
      }
      if (c >= 'A' && c <= 'Z') {
        continue;
      }
      if (c >= 'a' && c <= 'z') {
        continue;
      }
      if (c >= '0' && c <= '9') {
        continue;
      }
      if ((unsigned char)c >= 0x80) {
        continue;
      }

      if (c == '[' || c == ']' || c == '(' || c == ')' || c == '*' || c == '+' || c == '?' || c == '{' || c == '}' || c == '^'
          || c == '$' || c == '\\') {
        return false;
      }
    }
    return true;
  }

  // successfully parsed - check if result is simple
  for (size_t i = 0; i < parsed_len; i++) {
    char c = parsed[i];

    if (c == '.') {
      continue;
    }
    if (c >= 'A' && c <= 'Z') {
      continue;
    }
    if (c >= 'a' && c <= 'z') {
      continue;
    }
    if (c >= '0' && c <= '9') {
      continue;
    }
    if ((unsigned char)c >= 0x80) {
      continue;
    }

    if (c == '[' || c == ']' || c == '(' || c == ')' || c == '*' || c == '+' || c == '?' || c == '{' || c == '}' || c == '^'
        || c == '$') {
      return false;
    }
  }
  return true;
}


// count alternatives in regex
static int count_or_alternatives(const char *pattern, size_t pattern_len) {

  int count = 1;
  for (size_t i = 0; i < pattern_len; i++) {
    if (pattern[i] == '|') {
      count++;
    }
  }
  return count;
}


// populates a single pattern entry, handling first8/first4/wildcards logic
static void populate_pattern_entry(PatternList *pl, uint32_t idx, const char *final_pattern, size_t len, bool has_wildcards,
                                   bool *mask, uint32_t spec_idx, bool is_header) {

  pl->patterns[idx].pattern = final_pattern;
  pl->patterns[idx].length = len;
  pl->patterns[idx].spec_idx = spec_idx;
  pl->patterns[idx].is_header = is_header;
  pl->patterns[idx].has_wildcards = has_wildcards;
  pl->patterns[idx].wildcard_mask = mask;

  fbs_add(&pl->first_bytes, (unsigned char)final_pattern[0]);

  if (len > 1) {
    if (has_wildcards && final_pattern[1] == SCALPEL_WILDCARD_CHAR) {
      for (int k = 0; k < 256; k++) {
        fbs_add(&pl->valid_second_bytes[(unsigned char)final_pattern[0]], (unsigned char)k);
      }
    }
    else {
      fbs_add(&pl->valid_second_bytes[(unsigned char)final_pattern[0]], (unsigned char)final_pattern[1]);
    }
  }

  if (len >= 8 && ! has_wildcards) {
    memcpy(&pl->patterns[idx].first8, final_pattern, 8);
    pl->patterns[idx].has_first8 = true;
  }
  else {
    pl->patterns[idx].has_first8 = false;
    if (len >= 4) {
      memcpy(&pl->patterns[idx].first4, final_pattern, 4);
      if (len == 6) {
        memcpy(&pl->patterns[idx].next2, final_pattern + 4, 2);
      }
    }
  }
}


// add alternatives using new populate_pattern_entry
static int add_or_alternatives(PatternList *pl, uint32_t *idx, const char *pattern, size_t pattern_len, uint32_t spec_idx,
                               bool is_header) {
  int num_added = 0;
  size_t alt_start = 0;

  // Pre-scan: verify ALL alternatives are simple before populating any.
  // This must match the all-or-nothing counting logic in build_pattern_list().
  alt_start = 0;
  for (size_t i = 0; i <= pattern_len; i++) {
    if (i == pattern_len || pattern[i] == '|') {
      size_t alt_len = i - alt_start;
      if (alt_len > 0 && ! is_simple_alternative(pattern + alt_start, alt_len)) {
        return -1;
      }
      alt_start = i + 1;
    }
  }

  alt_start = 0;
  for (size_t i = 0; i <= pattern_len; i++) {
    if (i == pattern_len || pattern[i] == '|') {
      size_t alt_len = i - alt_start;

      if (alt_len == 0) {
        alt_start = i + 1;
        continue;
      }

      const char *alt = pattern + alt_start;

      // parse escapes
      char *parsed = malloc(256);
      size_t parsed_len = parse_simple_escapes(alt, alt_len, parsed, 256);

      if (parsed_len == 0) {
        // no escapes, use original
        free(parsed);
        parsed = malloc(alt_len);
        memcpy(parsed, alt, alt_len);
        parsed_len = alt_len;
      }

      // check for wildcards in parsed version
      bool has_wildcards = false;
      for (size_t j = 0; j < parsed_len; j++) {
        if (parsed[j] == '.') {
          parsed[j] = SCALPEL_WILDCARD_CHAR;
          has_wildcards = true;
        }
      }

      bool *mask = NULL;
      if (has_wildcards) {
        mask = calloc(parsed_len, sizeof(bool));
        for (size_t j = 0; j < parsed_len; j++) {
          mask[j] = (parsed[j] == SCALPEL_WILDCARD_CHAR);
        }
      }

      populate_pattern_entry(pl, *idx, parsed, parsed_len, has_wildcards, mask, spec_idx, is_header);

      lock_fprintf(stdout, "  -> Added OR alternative idx=%u for spec=%u (len=%zu, first_byte=0x%02x)\n", *idx, spec_idx,
                   parsed_len, (unsigned char)parsed[0]);

      (*idx)++;
      num_added++;
      alt_start = i + 1;
    }
  }

  return num_added;
}


// build a pattern list for a header or footer
static PatternList *build_pattern_list(SearchSpec *specs, uint32_t num_specs, bool headers) {

  uint32_t pattern_count = 0;

  lock_fprintf(stdout, "\nBuilding %s pattern list...\n", headers ? "HEADER" : "FOOTER");

  for (uint32_t i = 0; i < num_specs; i++) {
    if (specs[i].MASTER) {
      continue;
    }

    const char *pattern = headers ? specs[i].begin : specs[i].end;
    size_t pattern_len = headers ? specs[i].beginlength : specs[i].endlength;
    bool has_func = headers ? (specs[i].HEADERFUNC != NULL) : (specs[i].FOOTERFUNC != NULL);
    bool is_regex = headers ? specs[i].begin_is_RE : specs[i].end_is_RE;

    lock_fprintf(stdout, "  %s: len=%zu regex=%d func=%d\n", specs[i].FILETYPE, pattern_len, is_regex, has_func);

    if (pattern_len > 0 && pattern_len < 20) {
      for (size_t j = 0; j < pattern_len; j++) {
        if (pattern[j] >= 32 && pattern[j] <= 126) {
          lock_fprintf(stdout, "'%c' ", pattern[j]);
        }
        else {
          lock_fprintf(stdout, "0x%02x ", (unsigned char)pattern[j]);
        }
      }
      lock_fprintf(stdout, "\n");
    }

    if (! pattern_len || has_func) {
      continue;
    }

    if (is_regex) {
      bool has_or = false;
      for (size_t j = 0; j < pattern_len; j++) {
        if (pattern[j] == '|') {
          has_or = true;
          break;
        }
      }

      if (has_or) {
        int num_alts = count_or_alternatives(pattern, pattern_len);

        // check if all alternatives are simple
        bool all_simple = true;
        size_t alt_start = 0;
        for (size_t j = 0; j <= pattern_len; j++) {
          if (j == pattern_len || pattern[j] == '|') {
            size_t alt_len = j - alt_start;

            if (alt_len > 0) {
              if (! is_simple_alternative(pattern + alt_start, alt_len)) {
                all_simple = false;
                break;
              }
            }
            alt_start = j + 1;
          }
        }
        if (all_simple) {
          pattern_count += num_alts;
          lock_fprintf(stdout, "    -> OR pattern: %d alternatives (simple)\n", num_alts);
        }
        else {
          lock_fprintf(stdout, "    -> OR pattern: complex, using PCRE2\n");
        }
      }
      else {
        if (is_simple_alternative(pattern, pattern_len)) {
          pattern_count++;
        }
      }
    }
    else {
      pattern_count++;
    }
  }

  if (pattern_count == 0) {
    return NULL;
  }

  PatternList *pl = calloc(1, sizeof(PatternList));
  check_memory_allocation(pl, __LINE__, __FILE__, "pattern list");

  pl->patterns = calloc(pattern_count, sizeof(PatternEntry));
  check_memory_allocation(pl->patterns, __LINE__, __FILE__, "patterns");

  pl->num_patterns = pattern_count;
  fbs_clear(&pl->first_bytes);

  for (int i = 0; i < 256; i++) {
    fbs_clear(&pl->valid_second_bytes[i]);
  }

  memset(pl->pattern_counts, 0, sizeof(pl->pattern_counts));
  memset(pl->pattern_index, 0, sizeof(pl->pattern_index));

  uint32_t idx = 0;

  for (uint32_t i = 0; i < num_specs; i++) {
    if (specs[i].MASTER) {
      continue;
    }

    const char *pattern = headers ? specs[i].begin : specs[i].end;
    size_t pattern_len = headers ? specs[i].beginlength : specs[i].endlength;
    bool has_func = headers ? (specs[i].HEADERFUNC != NULL) : (specs[i].FOOTERFUNC != NULL);
    bool is_regex = headers ? specs[i].begin_is_RE : specs[i].end_is_RE;

    if (! pattern_len || has_func) {
      continue;
    }

    if (is_regex) {
      bool has_or = false;
      for (size_t j = 0; j < pattern_len; j++) {
        if (pattern[j] == '|') {
          has_or = true;
          break;
        }
      }

      if (has_or) {
        int num_added = add_or_alternatives(pl, &idx, pattern, pattern_len, i, headers);

        if (num_added < 0) {
          lock_fprintf(stdout, "  -> OR pattern too complex, skipping\n");
        }
      }
      else {
        if (is_simple_alternative(pattern, pattern_len)) {
          char *parsed = malloc(256);
          size_t parsed_len = parse_simple_escapes(pattern, pattern_len, parsed, 256);

          if (parsed_len == 0) {
            free(parsed);
            parsed = malloc(pattern_len);
            memcpy(parsed, pattern, pattern_len);
            parsed_len = pattern_len;
          }

          bool has_wildcards = false;
          for (size_t j = 0; j < parsed_len; j++) {
            if (parsed[j] == '.') {
              parsed[j] = SCALPEL_WILDCARD_CHAR;
              has_wildcards = true;
            }
          }

          bool *mask = NULL;
          if (has_wildcards) {
            mask = calloc(parsed_len, sizeof(bool));
            for (size_t j = 0; j < parsed_len; j++) {
              mask[j] = (parsed[j] == SCALPEL_WILDCARD_CHAR);
            }
          }

          populate_pattern_entry(pl, idx, parsed, parsed_len, has_wildcards, mask, i, headers);

          if (scalpel_state.mode_verbose) {
            lock_fprintf(stdout, "  -> Added regex pattern idx=%u for %s (first_byte=0x%02x)\n", idx, specs[i].FILETYPE,
                         (unsigned char)parsed[0]);
          }
          idx++;
        }
      }
    }
    else {
      bool has_wc = has_wildcard(pattern, pattern_len);
      bool *mask = NULL;

      if (has_wc) {
        mask = calloc(pattern_len, sizeof(bool));
        for (size_t j = 0; j < pattern_len; j++) {
          mask[j] = (pattern[j] == SCALPEL_WILDCARD_CHAR);
        }
      }

      populate_pattern_entry(pl, idx, pattern, pattern_len, has_wc, mask, i, headers);

      if (scalpel_state.mode_verbose) {
        lock_fprintf(stdout,
                     "  -> Added string pattern idx=%u for %s "
                     "(first_byte=0x%02x, has_wc=%d)\n",
                     idx, specs[i].FILETYPE, (unsigned char)pattern[0], has_wc);
      }
      idx++;
    }
  }

  for (uint32_t i = 0; i < pl->num_patterns; i++) {
    unsigned char first_byte = (unsigned char)pl->patterns[i].pattern[0];

    pl->pattern_counts[first_byte]++;
  }

  for (int i = 0; i < 256; i++) {
    if (pl->pattern_counts[i] > 0) {
      pl->pattern_index[i] = malloc(pl->pattern_counts[i] * sizeof(PatternEntry *));
      check_memory_allocation(pl->pattern_index[i], __LINE__, __FILE__, "pattern index");
    }
  }

  uint16_t current_counts[256] = {0};
  for (uint32_t i = 0; i < pl->num_patterns; i++) {
    unsigned char first_byte = (unsigned char)pl->patterns[i].pattern[0];
    uint16_t idx_val = current_counts[first_byte]++;

    pl->pattern_index[first_byte][idx_val] = &pl->patterns[i];
  }

  pl->num_targets = 0;
  for (int i = 0; i < 256; i++) {
    if (fbs_contains(&pl->first_bytes, (unsigned char)i)) {
      pl->target_array[pl->num_targets++] = (unsigned char)i;
    }
  }

  simd_build_target_vectors(pl);
  return pl;
}


// free pattern list
static void free_pattern_list(PatternList *pl) {

  if (pl) {
    for (int i = 0; i < 256; i++) {
      if (pl->pattern_index[i]) {
        free(pl->pattern_index[i]);
      }
    }
    if (pl->patterns) {
      free(pl->patterns);
    }
    if (pl->simd_target_vectors) {
      simd_free_target_vectors(pl->simd_target_vectors);
    }
    free(pl);
  }
}


// encapsulates specific byte matching logic used in SIMD and scalar loops
static inline bool verify_pattern_match(const unsigned char *match_ptr, const PatternEntry *p) {
  // Check for wildcards FIRST.
  if (p->has_wildcards && p->wildcard_mask) {
    for (size_t j = 0; j < p->length; j++) {
      if (! p->wildcard_mask[j]) {
        if (match_ptr[j] != (unsigned char)p->pattern[j]) {
          return false;
        }
      }
    }
    return true;
  }
  // only do fast-path integer checks if there are NO wildcards
  else if (p->has_first8) {
    uint64_t buf_first8 = read_u64_unaligned(match_ptr);

    if (buf_first8 == p->first8) {
      if (p->length == 8 || memcmp(match_ptr + 8, p->pattern + 8, p->length - 8) == 0) {
        return true;
      }
    }
  }
  else if (p->length == 4) {
    uint32_t buf_val = read_u32_unaligned(match_ptr);

    if (buf_val == p->first4) {
      return true;
    }
  }
  else if (p->length == 6) {
    uint32_t buf_val1 = read_u32_unaligned(match_ptr);

    if (buf_val1 == p->first4) {
      uint16_t buf_val2 = read_u16_unaligned(match_ptr + 4);

      if (buf_val2 == p->next2) {
        return true;
      }
    }
  }
  else {
    if (memcmp(match_ptr, p->pattern, p->length) == 0) {
      return true;
    }
  }
  return false;
}


// SIMD-accelerated pattern search
static void optimized_pattern_search(PatternList *pl, const unsigned char *buf, size_t len, BlockVector *b,
                                     void (*callback)(uint32_t, uint64_t, size_t, bool)) {

  uint64_t match_pos = 0;

  if (! pl || pl->num_patterns == 0) {
    return;
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Starting optimized search: %u patterns, scanning %zu bytes\n", pl->num_patterns, len);
  }

  size_t pos = 0;
  const size_t CHUNK_SIZE = 64;

  // 1. SIMD-accelerated 64-byte chunk loop
  while (pos + CHUNK_SIZE <= len) {
    uint64_t mask = 0;

    simd_get_match_mask_64(buf + pos, pl, &mask);

    while (mask) {
      int bit = __builtin_ctzll(mask);
      match_pos = pos + bit;
      const unsigned char *match_ptr = buf + match_pos;

      if (match_pos + 1 < len) {
        unsigned char first_byte_val = *match_ptr;
        unsigned char second_byte_val = *(match_ptr + 1);

        if (! fbs_contains(&pl->valid_second_bytes[first_byte_val], second_byte_val)) {
          mask &= (mask - 1);  // not a valid 2-byte prefix, skip
          continue;
        }
      }

      unsigned char first_byte = *match_ptr;
      uint16_t num_candidates = pl->pattern_counts[first_byte];
      PatternEntry **candidates = pl->pattern_index[first_byte];

      for (uint16_t i = 0; i < num_candidates; i++) {
        PatternEntry *p = candidates[i];
        if (match_pos + p->length > len) {
          continue;
        }

        if (verify_pattern_match(match_ptr, p)) {
          callback(p->spec_idx, blockvector_data_pointer_offset_to_actual_location(b, match_pos), p->length, p->is_header);
        }
      }
      mask &= (mask - 1);      // clear the bit we just processed
    }
    pos += CHUNK_SIZE;         // advance by one full chunk
  }

  // 2. Scalar tail loop (for the remaining < 64 bytes)
  for (; pos < len; pos++) {
    if (fbs_contains(&pl->first_bytes, buf[pos])) {
      const unsigned char *match_ptr = buf + pos;

      if (pos + 1 < len) {
        unsigned char first_byte_val = *match_ptr;
        unsigned char second_byte_val = *(match_ptr + 1);

        if (! fbs_contains(&pl->valid_second_bytes[first_byte_val], second_byte_val)) {
          continue;  // not a valid 2-byte prefix, skip
        }
      }

      unsigned char first_byte = *match_ptr;
      uint16_t num_candidates = pl->pattern_counts[first_byte];
      PatternEntry **candidates = pl->pattern_index[first_byte];

      for (uint16_t i = 0; i < num_candidates; i++) {
        PatternEntry *p = candidates[i];
        if (pos + p->length > len) {
          continue;
        }

        if (verify_pattern_match(match_ptr, p)) {
          callback(p->spec_idx, blockvector_data_pointer_offset_to_actual_location(b, pos), p->length, p->is_header);
        }
      }
    }
  }
}


// record header/footer matches
static void record_pattern_match(uint32_t needleidx, uint64_t position, size_t match_len, bool is_header) {

  SearchSpec *spec = &scalpel_state.search_specs[needleidx];

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "MATCH FOUND: %s %s at offset %" PRIu64 " (len=%zu)\n", spec->FILETYPE, is_header ? "header" : "footer",
                 position, match_len);
  }

  // apply block-aligned filter for headers
  if (is_header && (position % scalpel_state.blocksize != 0)) {
    return;
  }

  // point to the specific arrays and counters we need to manipulate
  pthread_mutex_t *lock = is_header ? &spec->offsets.headerlock : &spec->offsets.footerlock;
  uint64_t *storage_count = is_header ? &spec->offsets.headerstorage : &spec->offsets.footerstorage;
  uint64_t *actual_count = is_header ? &spec->offsets.numheaders : &spec->offsets.numfooters;
  uint64_t **offset_array = is_header ? &spec->offsets.headers : &spec->offsets.footers;
  size_t **len_array = is_header ? &spec->offsets.headerlens : &spec->offsets.footerlens;

  // grab lock and resize db
  MUTEX_ERROR_CHECK(pthread_mutex_lock(lock), __LINE__, __FILE__);

  if (*storage_count <= *actual_count) {
    size_t new_storage = *storage_count * 2;

    if (new_storage < 1000) {
      new_storage = 1000;
    }

    *offset_array = realloc(*offset_array, new_storage * sizeof(uint64_t));
    check_memory_allocation(*offset_array, __LINE__, __FILE__, "offset storage");

    *len_array = realloc(*len_array, new_storage * sizeof(size_t));
    check_memory_allocation(*len_array, __LINE__, __FILE__, "len storage");

    if (is_header) {
      spec->offsets.deposited = realloc(spec->offsets.deposited, new_storage * sizeof(bool));
      check_memory_allocation(spec->offsets.deposited, __LINE__, __FILE__, "deposited storage");
    }
    *storage_count = new_storage;
  }

  (*offset_array)[*actual_count] = position;
  (*len_array)[*actual_count] = match_len;

  if (is_header) {
    spec->offsets.deposited[*actual_count] = false;
  }
  (*actual_count)++;

  MUTEX_ERROR_CHECK(pthread_mutex_unlock(lock), __LINE__, __FILE__);
}


static void init_optimized_pattern_search(void) {

  // build SIMD pattern lists
  header_pattern_list = build_pattern_list(scalpel_state.search_specs, scalpel_state.num_specs, true);
  footer_pattern_list = build_pattern_list(scalpel_state.search_specs, scalpel_state.num_specs, false);

  if (header_pattern_list) {
    lock_fprintf(stdout,
                 "Built optimized search for %u simple header patterns "
                 "(SIMD-accelerated)\n",
                 header_pattern_list->num_patterns);
  }
  if (footer_pattern_list) {
    lock_fprintf(stdout,
                 "Built optimized search for %u simple footer patterns "
                 "(SIMD-accelerated)\n",
                 footer_pattern_list->num_patterns);
  }

  // build list of patterns that need thread-based searching
  uint32_t thread_count = 0;

  for (uint32_t i = 0; i < scalpel_state.num_specs; i++) {
    SearchSpec *spec = &scalpel_state.search_specs[i];
    if (spec->MASTER) {
      continue;
    }

    if (spec->HEADERFUNC || (spec->HEADER[0] && ! pattern_in_simd_list(header_pattern_list, i, true))) {
      thread_count++;
    }
    if (spec->FOOTERFUNC || (spec->FOOTER[0] && ! pattern_in_simd_list(footer_pattern_list, i, false))) {
      thread_count++;
    }
  }

  if (thread_count > 0) {
    thread_search_patterns = calloc(thread_count, sizeof(ThreadSearchPattern));
    check_memory_allocation(thread_search_patterns, __LINE__, __FILE__, "thread patterns");

    uint32_t idx = 0;
    for (uint32_t i = 0; i < scalpel_state.num_specs; i++) {
      SearchSpec *spec = &scalpel_state.search_specs[i];
      if (spec->MASTER) {
        continue;
      }

      if (spec->HEADERFUNC || (spec->HEADER[0] && ! pattern_in_simd_list(header_pattern_list, i, true))) {
        thread_search_patterns[idx].spec_idx = i;
        thread_search_patterns[idx].is_header = true;
        lock_fprintf(stdout, "  %s header: thread-based search\n", spec->FILETYPE);
        idx++;
      }

      if (spec->FOOTERFUNC || (spec->FOOTER[0] && ! pattern_in_simd_list(footer_pattern_list, i, false))) {
        thread_search_patterns[idx].spec_idx = i;
        thread_search_patterns[idx].is_header = false;
        lock_fprintf(stdout, "  %s footer: thread-based search\n", spec->FILETYPE);
        idx++;
      }
    }
    num_thread_search_patterns = thread_count;
  }

  lock_fprintf(stdout, "Pattern categorization: %u SIMD, %u thread-based\n",
               (header_pattern_list ? header_pattern_list->num_patterns : 0)
                   + (footer_pattern_list ? footer_pattern_list->num_patterns : 0),
               num_thread_search_patterns);
}


static bool pattern_in_simd_list(PatternList *pl, uint32_t spec_idx, bool is_header) {

  if (! pl) {
    return false;
  }
  for (uint32_t i = 0; i < pl->num_patterns; i++) {
    if (pl->patterns[i].spec_idx == spec_idx && pl->patterns[i].is_header == is_header) {
      return true;
    }
  }
  return false;
}


// find both headers and footers contained in the blockvector 'b'. MASTER file types are skipped.
static void search_for_headers_footers_buffer(BlockVector *b) {

  int freethread;
  char *data = blockvector_get_data_pointer(b);
  size_t len = blockvector_get_data_length(b);

  // dispatch thread-based patterns
  for (uint32_t i = 0; i < num_thread_search_patterns; i++) {
    uint32_t spec_idx = thread_search_patterns[i].spec_idx;
    bool is_header = thread_search_patterns[i].is_header;
    SearchSpec *spec = &scalpel_state.search_specs[spec_idx];

    // wait for free thread
    freethread = -1;
    while (freethread < 0) {
      while (atomic_load_explicit(&num_idle_search_threads, memory_order_acquire) == 0) {
	sched_yield();
      }
      for (int j = 0; j < scalpel_state.max_search_threads && freethread < 0; j++) {
        if (atomic_load_explicit(&searchthreadargs[j].thread_ready, memory_order_acquire)) {
          freethread = j;
        }
      }
    }

    // assign work to free thread
    MUTEX_ERROR_CHECK(pthread_mutex_lock(&searchthreadargs[freethread].work_is_available), __LINE__, __FILE__);
    atomic_store_explicit(&searchthreadargs[freethread].thread_ready, false, memory_order_release);
    atomic_fetch_sub_explicit(&num_idle_search_threads, 1, memory_order_acq_rel);

    searchthreadargs[freethread].is_header = is_header;
    searchthreadargs[freethread].b = b;
    searchthreadargs[freethread].needleidx = spec_idx;
    searchthreadargs[freethread].filetype = spec->FILETYPE;
    searchthreadargs[freethread].case_sensitive = spec->CASESENSITIVE;
    searchthreadargs[freethread].needle = is_header ? spec->begin : spec->end;
    searchthreadargs[freethread].needlelength = is_header ? spec->beginlength : spec->endlength;
    searchthreadargs[freethread].needlefunc = is_header ? spec->HEADERFUNC : spec->FOOTERFUNC;
    searchthreadargs[freethread].str_is_RE = is_header ? spec->begin_is_RE : spec->end_is_RE;

    if (searchthreadargs[freethread].str_is_RE) {
      searchthreadargs[freethread].regex = is_header ? spec->beginstate.re : spec->endstate.re;
    }
    else {
      searchthreadargs[freethread].table = is_header ? spec->beginstate.bm_table : spec->endstate.bm_table;
    }

    pthread_cond_signal(&searchthreadargs[freethread].check_work_available);
    MUTEX_ERROR_CHECK(pthread_mutex_unlock(&searchthreadargs[freethread].work_is_available), __LINE__, __FILE__);
  }

  // run SIMD patterns while threads work
  if (header_pattern_list || footer_pattern_list) {
    struct timespec search_start, search_end;

    clock_gettime(CLOCK_MONOTONIC, &search_start);

    if (header_pattern_list) {
      optimized_pattern_search(header_pattern_list, (const unsigned char *)data, len, b, record_pattern_match);
    }
    if (footer_pattern_list) {
      optimized_pattern_search(footer_pattern_list, (const unsigned char *)data, len, b, record_pattern_match);
    }

    clock_gettime(CLOCK_MONOTONIC, &search_end);
    double search_time = (search_end.tv_sec - search_start.tv_sec) + (search_end.tv_nsec - search_start.tv_nsec) / 1e9;

    lock_fprintf(stdout, "Optimized SIMD pattern search completed in %.3f seconds (%.1f MB/s)\n", search_time,
                 (len / 1024.0 / 1024.0) / search_time);
  }

  // wait for threads
  int32_t t;

  do {
    t = atomic_load_explicit(&num_idle_search_threads, memory_order_acquire);
    sched_yield();
  } while (t < scalpel_state.max_search_threads);
}


// find all headers and footers
static void search_for_headers_footers(void) {

  BlockVector *b;
  struct timespec start, end, endtime;
  long rightnow = time(NULL);
  uint64_t total_wait;
  uint32_t i;

  frame_message("HEADER/FOOTER DETECTION PHASE STARTING");

  // build SIMD lists and thread pattern list
  init_optimized_pattern_search();

  // process entire image file
  while ((b = filemirror_read(scalpel_state.filemirror))) {
    clock_gettime(CLOCK_MONOTONIC, &start);

    search_for_headers_footers_buffer(b);

    clock_gettime(CLOCK_MONOTONIC, &end);
    atomic_fetch_add_explicit(&header_footer_wait, (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec),
                              memory_order_acq_rel);

    if (time(NULL) - rightnow > 2) {
      rightnow = time(NULL);
      clock_gettime(CLOCK_MONOTONIC, &endtime);
      total_wait = (endtime.tv_sec - starttime.tv_sec) * 1e9 + (endtime.tv_nsec - starttime.tv_nsec);
      lock_fprintf(stdout,
                   "\nStatus: Header/footer search position %" PRIu64 " / %" PRIu64 " bytes (%3.1lf%%), NOT CHECKPOINTING,\n"
                   "total elapsed time: %.2lf secs.\n",
                   filemirror_ftello(scalpel_state.filemirror), filemirror_apparent_filesize(scalpel_state.filemirror),
                   (double)filemirror_ftello(scalpel_state.filemirror)
                       / (double)filemirror_apparent_filesize(scalpel_state.filemirror) * 100.0,
                   (double)total_wait / 1e9);
    }
    free_blockvector(&b);
  }

  clock_gettime(CLOCK_MONOTONIC, &endtime);
  total_wait = (endtime.tv_sec - starttime.tv_sec) * 1e9 + (endtime.tv_nsec - starttime.tv_nsec);

  lock_fprintf(stdout,
               "\nStatus: Header/footer search position %" PRIu64 " / %" PRIu64 " bytes (%3.1lf%%), NOT CHECKPOINTING,\n"
               "total elapsed time: %.2lf secs.\n",
               filemirror_apparent_filesize(scalpel_state.filemirror), filemirror_apparent_filesize(scalpel_state.filemirror),
               100.0, (double)total_wait / 1e9);

  prune_header_footer_database();

  // cleanup threads
  for (i = 0; i < (uint32_t)scalpel_state.max_search_threads; i++) {
    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout, "Stopping search thread # %1d...\n", i);
    }
    MUTEX_ERROR_CHECK(pthread_mutex_lock(&searchthreadargs[i].work_is_available), __LINE__, __FILE__);
    atomic_store_explicit(&searchthreadargs[i].thread_stop, true, memory_order_release);
    pthread_cond_signal(&searchthreadargs[i].check_work_available);
    MUTEX_ERROR_CHECK(pthread_mutex_unlock(&searchthreadargs[i].work_is_available), __LINE__, __FILE__);
    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout, "Search thread # %1d stopped.\n", i);
    }
  }

  // cleanup pattern lists
  if (header_pattern_list) {
    free_pattern_list(header_pattern_list);
    header_pattern_list = NULL;
  }
  if (footer_pattern_list) {
    free_pattern_list(footer_pattern_list);
    footer_pattern_list = NULL;
  }
  if (thread_search_patterns) {
    free(thread_search_patterns);
    thread_search_patterns = NULL;
    num_thread_search_patterns = 0;
  }

  frame_message("HEADER/FOOTER DETECTION PHASE COMPLETE");
}


// top level file carving function, which supports prioritization and handles both fragmented and
// unfragmented file recovery. Only the fragmented recovery phase (which is by far the most resource
// intensive) is responsive to checkpointing operations.
//
// Basic idea for file recovery for each priority class:
//
// There are three recovery phases: C (contiguous), F1 (fragmented, level 1), and F2 (fragmented,
// level 2).
//
// Phase C identifies complete files or file fragments whose blocks are logically contiguous (that
// is, their apparent block numbers are consecutive). Promising fragments in phase C that don't
// validate completely are inserted into the promising queue and reassembly is attempted in Phase
// F1.

// Phase F1 involves trying to improve the candidates in the queue promising_queue using a
// reassembly function.
//
// A more expensive phase, F2, is initiated when there are no more promising candidates to process.
// F2 takes each remaining unprocessed header (or footer, for SEARCHTYPE_BACKWARD file types) and
// creates a single block candidate for each. These are added to the promising queue, and then the
// F1 strategy continues..
//
// More detail on Scalpel's current defragmentation strategy for F1:
//
//      The default left to right (LR) reassembly strategy requires a file validation function can
//      push validates_to farther with only a single additional block. If a left to right strategy
//      won't work, then a custom reassembly thread can be implemented via the REASSEMBLYFUNC field
//      in scalpelconf.c.  For file types where no defragmention strategy has been worked out,
//      NO_DEFRAG should be set.  In this case, no fragmented reassembly is attempted for the file
//      type.
//
//      Each reassembly thread repeatedly removes a candidate from the promising queue and tries to
//      improve the candidate by introducing additional blocks. Backtracking is used to compare
//      different "block paths" to attempt to arrive at the best block ordering for the candidate.
//
//      A thread stops work on a particular fragment when there is a correct validation, when there
//      are no more blocks to try to potentially extend the fragment, or because of a checkpoint
//      event.  When the thread stops work because it's hit a dead end on one recovery path, it
//      conditionally writes its best version of the carve candidate so far to the PROMISING
//      directory (didn't fully validate, but no more blocks to check on this path).  During
//      checkpointing events, the thread returns the candidate it was working on to the promising
//      queue.
//
//      Reassembly threads are responsive to checkpointing events for several reasons.  These events
//      are used to take periodic snapshots of the carver state, so that scalpel3 can be restarted
//      in the event of a power failure, etc.  Checkpoints during forced termination of scalpel3 are
//      also supported, to support restarts later.  Beyond maintaining backup of the scalpel3 state,
//      however, periodic checkpoints also support blockmap updates.  While threads are idle during a
//      checkpoint event, another attempt to recover unfragmented files is made (phase C), since
//      recently validated files may have removed blocks that previously separated disparate
//      fragments of other files.  This involves putting an updated blockmap into service,
//      re-running Phase C, and repeating this process until no new files are validated.  Then F1 is
//      restarted.
//
//      As noted above, custom reassembly thread implementations are supported through the
//      REASSEMBLYFUNC field in scalpelconf.c.  This allows reassembly of file types that don't
//      match the default LR strategy.  Custom reassembly functions are quite complex and should be
//      used only when LR reassembly is either impossible or inefficient.
//
//      Reassembly is complete when all of the reassembly threads are idle because there are no
//      remaining elements in the promising queue to work on.
void carve_files(void) {

  Queue priorities;
  SearchSpec *currentfilespec = 0;
  uint64_t i;
  int32_t priority;
  bool first = true;  // helps sync F1/F2 phases when restoring from checkpoint
  static char buf[MAX_STRING_LENGTH * 2];
  char purge_pathname[PATH_MAX];
  char hf_pathname[PATH_MAX];

  frame_message("CLEANING INPROGRESS DIRECTORIES");
  // wipe all files in the INPROGRESS directory for a fresh start
  snprintf(purge_pathname, PATH_MAX, "*INPROGRESS/*/*");
  delete_files_recursive(scalpel_state.base_output_directory, purge_pathname);
  frame_message("CLEANUP OF INPROGRESS DIRECTORIES COMPLETE");

  sprintf(buf, "carve_files(): RESTORING FROM CHECKPOINT: %s", scalpel_state.restore_from_checkpoint ? "true" : "false");
  frame_message(buf);

  // initialize queue that contains candidates for non-fragmented recovery efforts
  init_queue(&carvelist, sizeof(ValidationInfo), true, NULL, false);
  atomic_store_explicit(&carvelist_initialized, true, memory_order_release);

  // initialize kill queue, which allows termination of fragmented recovery jobs by UUID
  init_queue(&kill_queue, sizeof(uuid_t), false, compare_uuids, false);
  atomic_store_explicit(&kill_queue_initialized, true, memory_order_release);

  // initialize cleanup queue for stale PROMISING/INPROGRESS artifacts
  init_queue(&partial_cleanup_queue, sizeof(uuid_t), false, compare_uuids, false);
  atomic_store_explicit(&partial_cleanup_queue_initialized, true, memory_order_release);

  // initialize reassembly queue, which mirrors candidates being processed by reassembly threads
  init_queue(&reassembly_queue, sizeof(EssentialCarveInfo), false, essentialcarveinfo_match_both_uuids, false);

  if (scalpel_state.restore_from_checkpoint) {
    reconcile_partial_artifacts_on_restore();
  }

  // create thread pools
  lock_fprintf(stdout, "Starting threads.\n");
  start_threads();

  // some initialization is handled separately by checkpoint restoration and should only be done on
  // a fresh run
  if (! scalpel_state.restore_from_checkpoint) {
    // initialize queue that contains promising partially validated candidates identified by
    // validation threads. This queue persists beyond termination of this function and is processed
    // in a separate phase. Checkpoint restoration initializes this queue, so it's only initialized
    // when a checkpoint restore isn't in progress.
    init_queue(&promising_queue, sizeof(CarveInfo *), true, carveinfo_match_either_uuid, false);
    atomic_store_explicit(&promising_initialized, true, memory_order_release);

    //
    // Phase 1 is executed only once and not repeated under checkpoint restoration:
    //
    // o validate all blocks, which all creates new file subtypes based on master file types
    //
    // o discover the locations of headers and footers
    //

    // determine block types
    validate_blocks();

    /////////////////////////////////////////////////////////////////////////////////////////////////
    // ** IMPORTANT **: since no file subtypes are added after validate_blocks is complete, there //
    // is no need to hold the scalpel_state.search_specs_lock mutex to access //
    // scalpel_state.search_specs *after* validate_blocks() and any associated threads associated //
    // with block validation are complete! //
    /////////////////////////////////////////////////////////////////////////////////////////////////

    // build header/footer database...
    search_for_headers_footers();

    // ... and serialize to scalpel output directory
    snprintf(hf_pathname, PATH_MAX, "%s/headersfooters.dat", scalpel_state.base_output_directory);
    serialize_essential_offsets(hf_pathname);

    // if ONLY generating and writing header/footer database, we're done
    if (scalpel_state.hf_only) {
      frame_message("EXITING AFTER HEADER/FOOTER DB CREATION BECAUSE OF -H FLAG");
      goto done;
    }
  }
  else {  // restoring from checkpoint
    // validate all fragments in the promising queue
    sync_and_validate_queues();
    atomic_store_explicit(&promising_initialized, true, memory_order_release);
  }

  ///////////////////////////////////////////////////////////////////
  // ** both checkpoint and non-checkpoint starts coalesce here ** //
  ///////////////////////////////////////////////////////////////////

  if (! scalpel_state.prioritize_types) {
    // all file types treated equally

    // first try phase C, which attempts to recover files whose apparent blocks are logically
    // contiguous
    if (! first || ! scalpel_state.restore_from_checkpoint) {
      carve_logically_contiguous_files(PRIORITY_FLOOR);
    }

    first = false;

    if (! scalpel_state.no_defrag) {
      // ...then try to recover fragmented files
      frame_message("ATTEMPTING RECOVERY OF FRAGMENTED FILES. THIS PHASE MAY NOT COMPLETE");
      carve_fragmented_files(PRIORITY_FLOOR);
      if (! atomic_load_explicit(&TAKE_CHECKPOINT_AND_EXIT, memory_order_acquire)) {
        frame_message("RECOVERY OF FRAGMENTED FILES COMPLETE");
      }
    }
  }
  else {
    // do recovery in multiple phases, to prioritize file types

    // prioritization is handled here because the code above is not executed on checkpoint restore
    // and we do need priorities during a run that uses a checkpoint. This is inexpensive to
    // compute, so it's not saved in the checkpoint state.

    init_queue(&priorities, sizeof(int), false, int_compare, false);

    for (i = 0; i < scalpel_state.num_specs; i++) {
      currentfilespec = &scalpel_state.search_specs[i];

      // skip MASTER file types
      if (currentfilespec->MASTER) {
        continue;
      }
      // don't re-process file priorities on a checkpoint restore if they have already been handled
      if (currentfilespec->PRIORITY >= scalpel_state.current_priority) {
        add_to_queue(&priorities, &currentfilespec->PRIORITY, currentfilespec->PRIORITY);
      }
    }

    // walk the queue of priorities and recover files for each priority class separately
    rewind_queue(&priorities);
    while (! empty_queue(&priorities) && ! atomic_load_explicit(&TAKE_CHECKPOINT_AND_EXIT, memory_order_acquire)) {
      remove_from_front(&priorities, &priority);

      // these are restored from the checkpoint, but the value only corresponds to the current
      // priority.
      if (! scalpel_state.restore_from_checkpoint || ! first) {
        scalpel_state.F1_initiated = false;
        scalpel_state.F2_initiated = false;

        // first try phase C, which attempts to recover files whose apparent blocks are logically
        // contiguous
        carve_logically_contiguous_files(PRIORITY_FLOOR);
      }

      first = false;

      if (! scalpel_state.no_defrag) {
        // ...then try to recover fragmented files for current priority
        sprintf(buf,
                "ATTEMPTING RECOVERY OF FRAGMENTED FILES WITH PRIORITY %d. "
                "THIS PHASE MAY"
                " NOT COMPLETE",
                priority);
        frame_message(buf);
        carve_fragmented_files(priority);

        // it's possible that a checkpoint was requested but all the work in this priority was
        // completed anyway--handle this edge condition by also checking promising_queue to see if
        // it emptied out
        if (! atomic_load_explicit(&TAKE_CHECKPOINT_AND_EXIT, memory_order_acquire) || empty_queue(&promising_queue)) {
          sprintf(buf, "RECOVERY OF FRAGMENTED FILES FOR PRIORITY %d COMPLETE", priority);
          scalpel_state.current_priority = priority;
        }
      }
    }
  }

 done:

  // kill threads and clean up
  lock_fprintf(stdout, "Beginning shutdown.\n");

  stop_threads();
}


// carve_logically_contiguous_single_pass() uses the header/footer offsets database created by
// search_for_headers_footers() to build a list of candidate files to carve and dispatches
// validation threads to evaluate the candidates. These will be files whose blocks are logically
// contiguous when covered blocks are omitted. Files that remain fragmented even when covered blocks
// are not considered are dealt with in a separate carving phase. Returns the number of validated
// files that were carved. This function implements phase C ("logically contiguous") file recovery.
//
// This function is NOT responsive to a pending checkpoint operation.
uint64_t carve_logically_contiguous_single_pass(FILE_DEFRAG_PRIORITY priority) {

  SearchSpec *currentfilespec;  // current file type being processed
  CarveInfo *candidate;         // carving candidate
  uint64_t headerindex;         // index of header for candidate
  uint64_t start, stop;         // temp begin/end bytes for file to carve
  uint64_t prevstopindex;       // tracks index of next 'reasonable'
  // footer
  uint64_t firstcandidatefooter;  // tracks index of first 'reasonable'
  // footer for a specific header
  uint32_t needlenum;       // index of current file type
  uint64_t candidates = 0;  // # of candidates for this pass only
  uint64_t filesize = filemirror_apparent_filesize(scalpel_state.filemirror);
  static int32_t subpass = 1;
  bool chopped;             // file chopped because it exceeds max
  // carve size for type?

  uint64_t validated_files = atomic_load_explicit(&scalpel_state.validated_files, memory_order_acquire);
  uint64_t begin_q_length = nolock_queue_length(&promising_queue);
  uint64_t ret;
  uint64_t q_length;
  uint64_t f_load;
  uint64_t pending_verifications;
  uint64_t load;
  uuid_string_t uuidp;
  uuid_string_t uuidc;
  static char buf[MAX_STRING_LENGTH * 2];
  long then = time(NULL);
  long now = time(NULL);
  struct timespec endtime;
  uint64_t total_wait;

  (void)firstcandidatefooter;
  (void)prevstopindex;

  sprintf(buf, "BEGINNING CARVE OF LOGICALLY CONTIGUOUS FILES ON %" PRIu64 " BLOCKS, PASS = %1d",
          filemirror_apparent_blocks(scalpel_state.filemirror), subpass);
  frame_message(buf);

  // find carve candidates to verify
  for (needlenum = 0; needlenum < scalpel_state.num_specs; needlenum++) {
    currentfilespec = &scalpel_state.search_specs[needlenum];

    // skip MASTER file types and search types other than SEARCHTYPE_FORWARD
    if (currentfilespec->MASTER || currentfilespec->SEARCHTYPE != SEARCHTYPE_FORWARD) {
      continue;
    }

    // if file type prioritization is on, don't process file types that don't have the appropriate
    // priority.  PRIORITY_FLOOR is used as a sentinel to process ALL file types regardless.
    if (scalpel_state.prioritize_types && priority != PRIORITY_FLOOR
        && priority != currentfilespec->PRIORITY) {
      continue;
    }

    // if no headers have been identified, skip this file type
    if (currentfilespec->offsets.numheaders == 0) {
      continue;
    }

    currentfilespec->per_pass_candidates = 0;
    prevstopindex = 0;

    sprintf(buf, "carve_image_file(): PROCESSING %" PRIu64 " HEADERS / %" PRIu64 " FOOTERS FOR FILE TYPE \"%s\"",
            currentfilespec->offsets.numheaders, currentfilespec->offsets.numfooters, currentfilespec->FILETYPE);
    frame_message(buf);

    //
    // IMPORTANT: even headers that are marked deposited are re-evaluated here (unless overriden by
    // command line option -d), because file validation may have caused a header and a distant
    // footer to slide together:
    //
    // [header] [.........many interleaved blocks, including correct blocks in
    // order........][footer]
    //
    // ...may become:
    //
    // [header][correct blocks][footer]
    //
    // Even if the header is involved in a current reassembly effort, it's better to try contiguous
    // recovery again here. If an associated file is recovered, the associated reassembly job will
    // be destroyed anyway.
    //

    for (headerindex = 0; headerindex < currentfilespec->offsets.numheaders; headerindex++) {
      // progress display
      if (headerindex % 1000 == 0 && ! scalpel_state.mode_verbose) {
        lock_fprintf(stdout, "%s+%s", GREEN, BLACK);
        fflush(stdout);
      }

      // evaluate header and footer positions using apparent image file positions
      start = filemirror_apparent_location(scalpel_state.filemirror, currentfilespec->offsets.headers[headerindex]);

      // The scalpel3 architecture currently supports *only* block-aligned headers.
      //
      // IMPORTANT: Use of non-block-aligned headers as the beginning of a file to carve cannot
      // simply be turned back on without potentially breaking other code. This deprecated check is
      // left in place as a reminder even though header searches now only discover block-aligned
      // headers.

      if (start % scalpel_state.blocksize != 0 ||  // ONLY BLOCK ALIGNED HEADERS ARE CONSIDERED
          (currentfilespec->offsets.deposited[headerindex] && ! scalpel_state.contig_header_reuse)) {
        continue;
      }

      stop = 0;
      chopped = false;

      if (! currentfilespec->endlength && ! currentfilespec->FOOTERFUNC) {
        // no footer defined for this file type, so establish an initial carving candidate based on
        // the data between the header position and the maximum carve size. File validation will
        // trim this as necessary later.
        stop = start + currentfilespec->MAXIMUMSIZE - 1;
        // file types with no footer are always considered chopped, because at this stage the file
        // size is unknown
        chopped = true;
      }
      else {
        stop = start;

        if (prevstopindex > (size_t)currentfilespec->offsets.numfooters) {
          prevstopindex = (size_t)currentfilespec->offsets.numfooters;
        }

#if USE_MOST_DISTANT_FOOTER > 0
        // create a carving candidate that spans the data between the header and the most distant
        // footer location. If no footer is found in front of the header, then the maximum carve
        // size for this file type will be used. The length will be adjusted later during file
        // validation.

        prevstopindex += upper_bound_u64(currentfilespec->offsets.footers + prevstopindex,
                                         (size_t)currentfilespec->offsets.numfooters - prevstopindex,
                                         start + currentfilespec->MAXIMUMSIZE - 1);

        if (prevstopindex > 0 && currentfilespec->offsets.footers[prevstopindex - 1] > start) {
          stop = filemirror_apparent_location(scalpel_state.filemirror, currentfilespec->offsets.footers[prevstopindex - 1])
                 + currentfilespec->offsets.footerlens[prevstopindex - 1] - 1;

          prevstopindex -= 1;  // keep floor at the chosen footer
        }
#else
        // create a carving candidate that spans the data between the header and next footer
        // location. If no footer is found in front of the header, then the maximum carve size for
        // this file type will be used. The length will be adjusted later during file validation.

        prevstopindex += lower_bound_u64(currentfilespec->offsets.footers + prevstopindex,
                                         (size_t)currentfilespec->offsets.numfooters - prevstopindex, start + 1);

        if (prevstopindex < (size_t)currentfilespec->offsets.numfooters
            && currentfilespec->offsets.footers[prevstopindex] <= start + currentfilespec->MAXIMUMSIZE - 1) {
          stop = filemirror_apparent_location(scalpel_state.filemirror, currentfilespec->offsets.footers[prevstopindex])
                 + currentfilespec->offsets.footerlens[prevstopindex] - 1;
        }
#endif

        if (stop <= start || stop - start + 1 > currentfilespec->MAXIMUMSIZE) {
          // no footer found within appropriate distance, so use max carve size for this file type
          // as stop
          stop = start + currentfilespec->MAXIMUMSIZE - 1;
          chopped = true;
        }
      }

      // update chopped stats to indicate that maximum file sizes might need to be increased
      scalpel_state.chopped += chopped;
      currentfilespec->chopped += chopped;

      if (stop) {
        // we have enough information to set up a file carving candidate

        // since MAXIMUMFILESIZE may have been used to establish stop, need to sanity check against
        // the apparent size of the image file
        stop = stop > filesize - 1 ? filesize - 1 : stop;

        // create structure for carving candidate
        candidate = (CarveInfo *)calloc(1, sizeof(CarveInfo));
        check_memory_allocation(candidate, __LINE__, __FILE__, "candidate");

        candidate->workload = VALIDATE_FILE;
        candidate->b = NULL;
        candidate->start = start;
        candidate->stop = stop;
        candidate->filetype = scalpel_state.search_specs[needlenum].FILETYPE;
        candidate->searchtype = scalpel_state.search_specs[needlenum].SEARCHTYPE;
        candidate->needleidx = needlenum;
        candidate->chopped = chopped;
        candidate->cloned = false;
        candidate->clone = false;
        candidate->deposited = currentfilespec->offsets.deposited[headerindex];
        candidate->qposition = INT64_MAX;
        candidate->best_validates_to = 0;
        candidate->newblock = -1;
        candidate->block_choice_start = -2;
        candidate->no_initial_block_extension = false;
        candidate->fastpath = false;
        uuid_generate_random(candidate->binuuid);
        uuid_clear(candidate->clone_binuuid);
        uuid_unparse_lower(candidate->binuuid, uuidp);
        uuid_unparse_lower(candidate->clone_binuuid, uuidc);
        gen_carve_hash_key(candidate->carvehashkey, candidate);
        candidate->best_choices = NULL;

        if (scalpel_debug_trace_candidate(candidate)) {
          scalpel_debug_trace("[candbg] phase-c-deposit start=%" PRIu64
                              " stop=%" PRIu64 " len=%" PRIu64
                              " chopped=%d deposited=%d type=%s",
                              candidate->start / scalpel_state.blocksize,
                              candidate->stop / scalpel_state.blocksize,
                              candidate->stop - candidate->start + 1,
                              candidate->chopped, candidate->deposited,
                              candidate->filetype);
        }

        // mark this header as used
        currentfilespec->offsets.deposited[headerindex] = true;

        // update stats

        // for this needle
        currentfilespec->candidates++;

        // all time
        scalpel_state.candidates++;

        // only this pass
        candidates++;
        currentfilespec->per_pass_candidates++;

        // drop the candidate into the queue
        if (scalpel_state.mode_verbose) {
          lock_fprintf(stdout,
                       "Depositing candidate with UUIDS \n%s and %s\nand "
                       "blockvector %p into carve list.\n",
                       uuidp, uuidc, candidate->b);
          lock_fprintf(stdout, "Availability broadcast for candidate to validation threads.\n");
        }

        // broadcast to let validation threads know that work has been inserted into the queue.
        // pthreads requires that an associated lock be held to avoid lost signals.
        MUTEX_ERROR_CHECK(pthread_mutex_lock(&validation_work_is_available), __LINE__, __FILE__);

        add_file_validation_work(candidate,
                                 UINT64_MAX
                                     - (filemirror_actual_location(scalpel_state.filemirror, start)
                                        / scalpel_state.blocksize));

        pthread_cond_broadcast(&validation_check_work_available);
        MUTEX_ERROR_CHECK(pthread_mutex_unlock(&validation_work_is_available), __LINE__, __FILE__);
      }
    }
  }

  if (candidates == 0) {
    // this pass resulted in nothing new
    goto done;
  }

  // ---------- thread group synchronization point ----------- //
  // ---------- thread group synchronization point ----------- //

  // synchronization here is complicated. Validation threads might be active, there could still be
  // elements in the candidates queue, or pending vector I/O operations in the file mirror. All of
  // these things must be resolved before continuing, since the blockmap is going to be modified
  // when this function exits and that shouldn't happen if pending operations depend on the current
  // blockmap.
  q_length = nolock_queue_length(&carvelist);
  f_load = filemirror_load(scalpel_state.filemirror);
  pending_verifications = scalpel_state.max_validation_threads
                          - atomic_load_explicit(&num_idle_validation_threads, memory_order_acquire);
  load = q_length + f_load + pending_verifications;

  then = time(NULL);
  while (load > 0) {
    q_length = nolock_queue_length(&carvelist);
    f_load = filemirror_load(scalpel_state.filemirror);
    pending_verifications = scalpel_state.max_validation_threads
                            - atomic_load_explicit(&num_idle_validation_threads, memory_order_acquire);
    load = q_length + f_load + pending_verifications;

    // chill on the progress display
    now = time(NULL);
    if (now - then >= 2) {
      then = now;
      clock_gettime(CLOCK_MONOTONIC, &endtime);
      total_wait = (endtime.tv_sec - starttime.tv_sec) * 1e9 + (endtime.tv_nsec - starttime.tv_nsec);

      lock_fprintf(stdout,
                   "\nStatus: Files queued for validation: %" PRIu64 ", %d idle file validation threads of %d, NOT CHECKPOINTING,\n"
                   "validated files: %lu, total elapsed time: %.2lf secs.\n",
                   q_length, (int)atomic_load_explicit(&num_idle_validation_threads, memory_order_acquire),
                   (int)scalpel_state.max_validation_threads,
                   atomic_load_explicit(&scalpel_state.validated_files, memory_order_acquire), (double)total_wait / 1e9);
    }
    sched_yield();
  }

  if (candidates && ! scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "\n");
  }

done:

  sprintf(buf, "LOGICALLY CONTIGUOUS CARVING INSERTED %" PRIu64 " NEW CANDIDATES, PASS = %1d",
          nolock_queue_length(&promising_queue) - begin_q_length, subpass);
  frame_message(buf);

  ret = atomic_load_explicit(&scalpel_state.validated_files, memory_order_acquire) - validated_files;
  sprintf(buf, "LOGICALLY CONTIGUOUS CARVING VALIDATED %" PRIu64 " NEW FILES, PASS = %1d", ret, subpass++);
  frame_message(buf);

  // return the number of newly validated files
  return ret;
}


// repeatedly performs carving of logically contiguous files until a carving phase results in no
// additional verified files.
//
// This function is NOT responsive to pending checkpoint events.
static void carve_logically_contiguous_files(FILE_DEFRAG_PRIORITY priority) {

  uint64_t verified_files;

  // Strategy:
  //
  // o using the header/footer database, identify, assemble, validate, and potentially write
  // candidate files
  //
  // o each file that validates results in blocks that comprise this file being covered in the
  // blockmap
  //
  // o if least one file validates, repeat using updated blockmap

  do {
    verified_files = carve_logically_contiguous_single_pass(priority);
    if (! verified_files) {
      // no need to continue
      break;
    }

    // the next phase uses the updated blockmap, with blocks associated with verified blocks covered
    frame_message("UPDATING BLOCKMAP");
    filemirror_swap_blockmaps(scalpel_state.filemirror);

    // prune header/footer database of headers and footers in covered blocks
    frame_message("PRUNING HEADER/FOOTER DATABASE");
    prune_header_footer_database();

    // validate all fragments in the promising queue
    frame_message("VALIDATING QUEUED PROMISING CANDIDATES");
    sync_and_validate_queues();

  } while (verified_files);
}


// perform F1/F2 phase for file recovery for a specific priority level.
static void carve_fragmented_files(FILE_DEFRAG_PRIORITY priority) {

  uint64_t validated;
  uint64_t last_seen_validated;
  uint64_t q_length;
  uint64_t f_load;
  uint64_t pending_reassemblies;
  uint64_t load;
  bool stop = false;
  bool done;
  long checkpoint_timer = time(NULL);
  long recovery_checkpoint_timer = time(NULL);
  long prune_timer = time(NULL);
  long then = time(NULL);
  long now = time(NULL);
  int64_t prio;
  uuid_string_t uuidk;
  uuid_t binuuidk;
  static char buf[MAX_STRING_LENGTH];
  struct timespec endtime;
  struct timespec last_validation;
  double last_validation_gap;
  uint64_t total_wait;
  bool reassembly_complete = false;
  bool write_checkpoint_data;
  bool write_inprogress;
  bool swap_blockmaps;
  uint64_t num_initial_checkpoints;

  if (scalpel_state.memory_profiling) {
    memory_footprint("start frag reassembly");
  }

  if (scalpel_state.restore_from_checkpoint) {
    if (scalpel_state.F2_initiated) {
      sprintf(buf, "F2 WAS ALREADY INITIATED BEFORE CHECKPOINT RESTORE");
      frame_message(buf);
    }
    else {
      sprintf(buf, "FRAGMENTED RECOVERY IS RESUMING AFTER CHECKPOINT RESTORE, NO F2 YET");
      frame_message(buf);
    }
  }

  // initially, a sweep over all candidates is performed by doing a wave of periodic checkpoints
  num_initial_checkpoints = queue_length(&promising_queue) / scalpel_state.max_reassembly_threads + 1;

  // at this point, normal operation is resumed if a checkpoint was being restored.
  scalpel_state.restore_from_checkpoint = false;

  // F1 reassembly has started for this priority class
  scalpel_state.F1_initiated = true;

  // not taking a periodic checkpoint
  atomic_store_explicit(&REASS_RETURN_TO_IDLE, false, memory_order_release);

  // broadcast to let reassembly threads know that work is available. pthreads requires that an
  // associated lock be held to avoid lost signals.
  MUTEX_ERROR_CHECK(pthread_mutex_lock(&reassembly_work_is_available), __LINE__, __FILE__);
  pthread_cond_broadcast(&reassembly_check_work_available);
  MUTEX_ERROR_CHECK(pthread_mutex_unlock(&reassembly_work_is_available), __LINE__, __FILE__);

  // reassembly threads are now active

  while (! reassembly_complete && ! atomic_load_explicit(&TAKE_CHECKPOINT_AND_EXIT, memory_order_acquire)) {
    validated = atomic_load_explicit(&scalpel_state.validated_files, memory_order_acquire);
    last_seen_validated = validated;
    clock_gettime(CLOCK_MONOTONIC, &last_validation);

    sprintf(buf, "REASSEMBLY PHASE FOR %" PRIu64 " PROMISING CANDIDATES BEGINNING", nolock_queue_length(&promising_queue));
    frame_message(buf);

    // synchronization here is complicated. Reassembly threads might be active, there could still be
    // elements in the promising_queue queue, or pending vector I/O operations in the file mirror.
    // All of these things must be resolved before continuing.

    q_length = nolock_queue_length(&promising_queue);
    f_load = filemirror_load(scalpel_state.filemirror);
    pending_reassemblies = scalpel_state.max_reassembly_threads
                           - atomic_load_explicit(&num_idle_reassembly_threads, memory_order_acquire);
    load = q_length + f_load + pending_reassemblies;

    // initial status report
    now = time(NULL);
    clock_gettime(CLOCK_MONOTONIC, &endtime);
    total_wait = (endtime.tv_sec - starttime.tv_sec) * 1e9 + (endtime.tv_nsec - starttime.tv_nsec);
    last_validation_gap = (endtime.tv_sec - last_validation.tv_sec) + (endtime.tv_nsec - last_validation.tv_nsec) / 1000000000.0;
    lock_fprintf(stdout,
                 "\nStatus: promising queue: %" PRIu64 " elements, %d idle reassembly threads of %d, "
                 "periodic CP countdown: %ld secs%s,\n"
                 "last file validation: %.2lf secs, recovery CP countdown: %ld secs, "
                 "validated files: %lu, "
                 "total elapsed time: %.2lf secs.\n",
                 q_length, atomic_load_explicit(&num_idle_reassembly_threads, memory_order_acquire),
                 scalpel_state.max_reassembly_threads,
                 checkpoint_timer + (num_initial_checkpoints > 0 ? INITIAL_PERIODIC_CHECKPOINTING_INTERVAL : scalpel_state.checkpointing_interval) - now >= 0
                 ? checkpoint_timer + (num_initial_checkpoints > 0 ? INITIAL_PERIODIC_CHECKPOINTING_INTERVAL : scalpel_state.checkpointing_interval) - now
                     : 0,
                 now - checkpoint_timer > scalpel_state.checkpointing_interval + 5 ? " [pending a validated file]" : "",
                 last_validation_gap,
                 recovery_checkpoint_timer + RECOVERY_CHECKPOINTING_INTERVAL - now >= 0
                     ? recovery_checkpoint_timer + RECOVERY_CHECKPOINTING_INTERVAL - now
                     : 0,
                 atomic_load_explicit(&scalpel_state.validated_files, memory_order_acquire), (double)total_wait / 1e9);

    // load checking loop
    while ((load > 0 || ! scalpel_state.F2_initiated) && ! stop) {

      // is it time for F2 yet? If there's no work left in the promising queue and if uncovered
      // headers haven't yet been used to repopulate the promising queue, do so. This constitutes
      // the single initiation of F2, as there's only one set of headers that don't initially make
      // it into the promising queue.
      if (q_length == 0 && ! scalpel_state.F2_initiated) {
        // F2 population happens only once per priority level
        scalpel_state.F2_initiated = true;
        sprintf(buf, "F2 INITIATED: ALL HEADERS AND FOOTERS ARE NOW BEING CONSIDERED");
        frame_message(buf);

        insert_F2_reassembly_candidates(priority);

        // signal that more work is available
        MUTEX_ERROR_CHECK(pthread_mutex_lock(&reassembly_work_is_available), __LINE__, __FILE__);
        pthread_cond_broadcast(&reassembly_check_work_available);
        MUTEX_ERROR_CHECK(pthread_mutex_unlock(&reassembly_work_is_available), __LINE__, __FILE__);
      }

      // time to prune kill queue? If so, remove elements at head of queue that have aged out
      if (time(NULL) - prune_timer > KILL_QUEUE_PRUNE_TIME && nolock_queue_length(&kill_queue)) {
        prune_timer = time(NULL);
        done = false;
        lock_queue(&kill_queue);
        while (! done && nolock_queue_length(&kill_queue)) {
          done = true;
          nolock_rewind_queue(&kill_queue);
          if (nolock_peek_at_current(&kill_queue, binuuidk, &prio)) {
            if (prio - (INT_MAX - prune_timer) > KILL_QUEUE_PRUNE_TIME) {
              done = false;
              uuid_unparse_lower(binuuidk, uuidk);
              nolock_delete_current(&kill_queue);
              snprintf(buf, MAX_STRING_LENGTH, "PRUNING UUID \"%s\" FROM KILL QUEUE", uuidk);
              frame_message(buf);
            }
          }
        }
        unlock_queue(&kill_queue);
      }

      // do not advance periodic checkpoint timer if there's a checkpoint of any kind that's
      // pending. The timer is reset here to prevent that.
      if (atomic_load_explicit(&TAKE_RECOVERY_CHECKPOINT, memory_order_acquire)
          || atomic_load_explicit(&TAKE_PERIODIC_CHECKPOINT, memory_order_acquire)
          || atomic_load_explicit(&TAKE_PROGRESS_CHECKPOINT, memory_order_acquire)
          || atomic_load_explicit(&TAKE_CHECKPOINT_AND_EXIT, memory_order_acquire)
          || atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
        checkpoint_timer = time(NULL);
      }

      now = time(NULL);

      // any recently validated files?
      if (atomic_load_explicit(&scalpel_state.validated_files, memory_order_acquire) > last_seen_validated) {
	last_seen_validated = atomic_load_explicit(&scalpel_state.validated_files, memory_order_acquire);
	clock_gettime(CLOCK_MONOTONIC, &last_validation);
      }

      // print a periodic status message, otherwise it's awfully quiet and user anxiety spikes
      if (now - then > 1) {
        then = now;
        clock_gettime(CLOCK_MONOTONIC, &endtime);
        total_wait = (endtime.tv_sec - starttime.tv_sec) * 1e9 + (endtime.tv_nsec - starttime.tv_nsec);
        last_validation_gap = (endtime.tv_sec - last_validation.tv_sec)
                              + (endtime.tv_nsec - last_validation.tv_nsec) / 1000000000.0;
        lock_fprintf(stdout,
                     "\nStatus: promising queue: %" PRIu64 " elements, %d idle reassembly threads of %d, "
                     "periodic CP countdown: %ld secs%s,\n"
                     "last file validation: %.2lf secs, recovery CP countdown: %ld secs, "
                     "validated files: %lu, "
                     "total elapsed time: %.2lf secs.\n",
                     q_length, atomic_load_explicit(&num_idle_reassembly_threads, memory_order_acquire),
                     scalpel_state.max_reassembly_threads,
                     checkpoint_timer + (num_initial_checkpoints > 0 ? INITIAL_PERIODIC_CHECKPOINTING_INTERVAL : scalpel_state.checkpointing_interval) - now >= 0
                         ? checkpoint_timer + (num_initial_checkpoints > 0 ? INITIAL_PERIODIC_CHECKPOINTING_INTERVAL : scalpel_state.checkpointing_interval) - now
                         : 0,
                     now - checkpoint_timer > scalpel_state.checkpointing_interval + 5 ? " [pending a validated file]" : "",
                     last_validation_gap,
                     recovery_checkpoint_timer + RECOVERY_CHECKPOINTING_INTERVAL - now >= 0
                         ? recovery_checkpoint_timer + RECOVERY_CHECKPOINTING_INTERVAL - now
                         : 0,
                     atomic_load_explicit(&scalpel_state.validated_files, memory_order_acquire), (double)total_wait / 1e9);
      }

      // time for any kind of checkpoint? If so, reassembly threads will be forced into an idle
      // state before the checkpoint is taken

      if (q_length == 0) {
	num_initial_checkpoints = 0;
      }

      if ((num_initial_checkpoints > 0 && now - checkpoint_timer > INITIAL_PERIODIC_CHECKPOINTING_INTERVAL) ||
	  (now - checkpoint_timer > scalpel_state.checkpointing_interval && (q_length != 0 || atomic_load_explicit(&scalpel_state.validated_files, memory_order_acquire) - validated > 0)) ||
          (atomic_load_explicit(&scalpel_state.validated_files, memory_order_acquire) - validated >= scalpel_state.validation_cp_threshold)) {

        // periodic checkpoint

	// only "use up" one initial checkpoint if it occurred for reasons other than validated
	// files hitting the cap
	if (num_initial_checkpoints > 0 &&
	    (atomic_load_explicit(&scalpel_state.validated_files, memory_order_acquire) -
	     validated >= scalpel_state.validation_cp_threshold)) {
	  num_initial_checkpoints--;
	}

        atomic_store_explicit(&TAKE_PERIODIC_CHECKPOINT, true, memory_order_release);
      }

      if (now - recovery_checkpoint_timer > RECOVERY_CHECKPOINTING_INTERVAL) {
        // recovery checkpoint
        atomic_store_explicit(&TAKE_RECOVERY_CHECKPOINT, true, memory_order_release);
      }

      // these checkpoints are triggered by exceeding total execution time or the gap between
      // validated files, so upgrade to checkpoint and exit and output additional info
      if (total_wait / 1e9 > scalpel_state.exit_after_secs) {
        frame_message("REASSEMBLY TIME EXCEEDED SPECIFIED LIMIT, WILL CHECKPOINT AND EXIT");
        atomic_store_explicit(&TAKE_CHECKPOINT_AND_EXIT, true, memory_order_release);
      }
      else if (last_validation_gap > scalpel_state.exit_after_val_gap) {
        frame_message("TIME SINCE LAST VALIDATION EXCEEDED SPECIFIED LIMIT, WILL CHECKPOINT AND EXIT");
        atomic_store_explicit(&TAKE_CHECKPOINT_AND_EXIT, true, memory_order_release);
      }

      // any checkpoint flags set?
      if (atomic_load_explicit(&TAKE_CHECKPOINT_AND_EXIT, memory_order_acquire)
          || atomic_load_explicit(&TAKE_RECOVERY_CHECKPOINT, memory_order_acquire)
          || atomic_load_explicit(&TAKE_PERIODIC_CHECKPOINT, memory_order_acquire)
          || atomic_load_explicit(&TAKE_PROGRESS_CHECKPOINT, memory_order_acquire)) {

        // these flags control operations during checkpoint
        write_checkpoint_data = false;
        write_inprogress = false;
        swap_blockmaps = false;

        // different checkpoints induce different behaviors. Periodic checkpoints simply sync
        // internal state; recovery & exit checkpoints write checkpoint data to disk; and progress
        // checkpoints update the INPROGRESS directory

        if (atomic_load_explicit(&TAKE_CHECKPOINT_AND_EXIT, memory_order_acquire)) {
          sprintf(buf, "REASSEMBLY PHASE PAUSED BECAUSE OF CHECKPOINT AND EXIT EVENT");
          frame_message(buf);
          write_checkpoint_data = true;
          swap_blockmaps = true;
        }
        else {
          if (atomic_load_explicit(&TAKE_RECOVERY_CHECKPOINT, memory_order_acquire)) {
            sprintf(buf, "REASSEMBLY PHASE PAUSED BECAUSE OF RECOVERY CHECKPOINT EVENT");
            frame_message(buf);
	    write_checkpoint_data = true;
            swap_blockmaps = true;
	    if (scalpel_state.write_inprogress) {
	      write_inprogress = true;
	    }
          }

          if (atomic_load_explicit(&TAKE_PERIODIC_CHECKPOINT, memory_order_acquire)) {
	    if (num_initial_checkpoints >= 1) {
	      sprintf(buf, "REASSEMBLY PHASE PAUSED BECAUSE OF SWEEPING PERIODIC CHECKPOINT EVENT");
	    }
	    else {
	      sprintf(buf, "REASSEMBLY PHASE PAUSED BECAUSE OF PERIODIC CHECKPOINT EVENT");
	    }
            frame_message(buf);
            swap_blockmaps = true;
	    if (scalpel_state.write_inprogress) {
	      write_inprogress = true;
	    }
          }

          if (atomic_load_explicit(&TAKE_PROGRESS_CHECKPOINT, memory_order_acquire)) {
            sprintf(buf, "REASSEMBLY PHASE PAUSED BECAUSE OF PROGRESS CHECKPOINT EVENT");
            frame_message(buf);
            write_inprogress = true;
          }
        }

        // alert threads that a checkpoint is being taken, which forces them to dump work back into
        // the promising queue and return to an idle state ASAP
        atomic_store_explicit(&REASS_RETURN_TO_IDLE, true, memory_order_release);

        // wait for threads to be idle--similar to non-checkpointing idle check for reassembly
        // threads, except that it's ok for the promising queue to still contain elements, as
        // threads respond to REASS_RETURN_TO_IDLE by returning their current work to the promising
        // queue

        // ---------- thread group synchronization point ----------- //
        // ---------- thread group synchronization point ----------- //
        if (scalpel_state.mode_verbose) {
          lock_fprintf(stdout, "\nWaiting for all reassembly threads to become idle.\n");
        }

        then = time(NULL);
        do {
          f_load = filemirror_load(scalpel_state.filemirror);
          pending_reassemblies = scalpel_state.max_reassembly_threads
                                 - atomic_load_explicit(&num_idle_reassembly_threads, memory_order_acquire);
          load = f_load + pending_reassemblies;

          // chill on the progress display
          now = time(NULL);
          if (now - then > 1 && ! scalpel_state.mode_verbose) {
            lock_fprintf(stdout, "%s+%s", RED, BLACK);
            fflush(stdout);
            then = now;
          }
	  sched_yield();
        } while (load > 0);

        lock_fputc('\n', stdout);
        if (scalpel_state.mode_verbose) {
          lock_fprintf(stdout, "\nAll reassembly threads are now idle.\n");
        }

        frame_message("ALL REASSEMBLY THREADS ARE IDLE");

        if (swap_blockmaps) {
          // if any files were validated before the checkpoint was taken, swap blockmaps, prune the
          // header/footer database, try carving contiguous files again before waking up the
          // reassembly threads. This may potentially reduce the search space for fragmented files.
          if (atomic_load_explicit(&scalpel_state.validated_files, memory_order_acquire) - validated > 0) {
            if (scalpel_state.mode_verbose) {
              lock_fprintf(stdout, "\nReassembly status before filemirror swap: %" PRIu64 " elements in promising queue.\n",
                           nolock_queue_length(&promising_queue));
            }

            // some files were validated by the reassembly threads, so try carving contiguous files
            // again with a new blockmap
            frame_message("UPDATING BLOCKMAP");
            filemirror_swap_blockmaps(scalpel_state.filemirror);

            // prune header/footer database of headers and footers in covered blocks
            frame_message("PRUNING HEADER/FOOTER DATABASE");
            prune_header_footer_database();

            // validate all fragments in the promising queue
            frame_message("VALIDATING QUEUED PROMISING CANDIDATES");
            sync_and_validate_queues();

            // final carve phase is skipped on checkpoint and exit
            if (! atomic_load_explicit(&TAKE_CHECKPOINT_AND_EXIT, memory_order_acquire)) {
	      // it's possible files were validated after the checkpoint was started
	      if (atomic_load_explicit(&scalpel_state.validated_files, memory_order_acquire) > last_seen_validated) {
		clock_gettime(CLOCK_MONOTONIC, &last_validation);
	      }

              last_seen_validated = atomic_load_explicit(&scalpel_state.validated_files, memory_order_acquire);
	      // try "traditional" carving again
              carve_logically_contiguous_files(PRIORITY_FLOOR);

              if (scalpel_state.mode_verbose) {
                lock_fprintf(stdout, "\nReassembly status after filemirror swap: %" PRIu64 " elements in promising queue.\n",
                             nolock_queue_length(&promising_queue));
              }

              // reset validated counter
              validated = atomic_load_explicit(&scalpel_state.validated_files, memory_order_acquire);
              // only reset validation timer if contiguous carving actually validated new files
              if (validated > last_seen_validated) {
                clock_gettime(CLOCK_MONOTONIC, &last_validation);
              }
	      last_seen_validated = validated;
            }
          }

          // write checkpoint data if this is a recovery checkpoint
          if (write_checkpoint_data) {
            save_checkpoint();
          }
        }

        // update INPROGRESS data if appropriate
        if (write_inprogress) {
          update_inprogress_directories();
        }

        if (atomic_load_explicit(&TAKE_CHECKPOINT_AND_EXIT, memory_order_acquire)) {
          // threads won't be resumed since we are exiting
          stop = true;
          // cause while (load > 0 ...) loop to exit and bypass thread reawakening below
          continue;
        }

        // reset periodic checkpoint timer on all checkpoint types except progress
        if (swap_blockmaps) {
          checkpoint_timer = time(NULL);
          atomic_store_explicit(&TAKE_PERIODIC_CHECKPOINT, false, memory_order_release);
        }

        // reset recovery checkpoint timer only if this was a recovery checkpoint
        if (write_checkpoint_data) {
          recovery_checkpoint_timer = time(NULL);
          atomic_store_explicit(&TAKE_RECOVERY_CHECKPOINT, false, memory_order_release);
        }

        if (write_inprogress) {
          atomic_store_explicit(&TAKE_PROGRESS_CHECKPOINT, false, memory_order_release);
        }

        // signal that checkpoint is complete
        frame_message("CHECKPOINT IS COMPLETE");

        // allow threads to leave idle state
        atomic_store_explicit(&REASS_RETURN_TO_IDLE, false, memory_order_release);

        // signal that work is available
        MUTEX_ERROR_CHECK(pthread_mutex_lock(&reassembly_work_is_available), __LINE__, __FILE__);
        pthread_cond_broadcast(&reassembly_check_work_available);
        MUTEX_ERROR_CHECK(pthread_mutex_unlock(&reassembly_work_is_available), __LINE__, __FILE__);

        // bottom of 'time to take a checkpoint' conditional
      }

      // recalculate load
      q_length = nolock_queue_length(&promising_queue);
      f_load = filemirror_load(scalpel_state.filemirror);
      pending_reassemblies = scalpel_state.max_reassembly_threads
                             - atomic_load_explicit(&num_idle_reassembly_threads, memory_order_acquire);
      load = q_length + f_load + pending_reassemblies;

      if (scalpel_state.memory_profiling) {
        memory_footprint("periodic frag reassembly");
      }
    }  // bottom of load-checking loop

    // skip additional processing on checkpoint and exit, otherwise see if another round of
    // contiguous validation generates any activity
    if (! atomic_load_explicit(&TAKE_CHECKPOINT_AND_EXIT, memory_order_acquire)) {
      // reassembly threads have no more work to do, but if they validated any files since the last
      // checkpoint, contiguous recovery is run again to see if any data coalesced.
      if (atomic_load_explicit(&scalpel_state.validated_files, memory_order_acquire) - validated > 0) {
        // reset validated counter to account for reassembly-thread validations
        validated = atomic_load_explicit(&scalpel_state.validated_files, memory_order_acquire);

        frame_message("UPDATING BLOCKMAP");
        filemirror_swap_blockmaps(scalpel_state.filemirror);

        frame_message("PRUNING HEADER/FOOTER DATABASE");
        prune_header_footer_database();

        frame_message("VALIDATING QUEUED PROMISING CANDIDATES");
        sync_and_validate_queues();

	if (atomic_load_explicit(&scalpel_state.validated_files, memory_order_acquire) > last_seen_validated) {
	  clock_gettime(CLOCK_MONOTONIC, &last_validation);
	}

        last_seen_validated = atomic_load_explicit(&scalpel_state.validated_files, memory_order_acquire);
        carve_logically_contiguous_files(PRIORITY_FLOOR);
        // only reset validation timer if contiguous carving actually validated new files
        if (atomic_load_explicit(&scalpel_state.validated_files, memory_order_acquire) > last_seen_validated) {
          clock_gettime(CLOCK_MONOTONIC, &last_validation);
        }
      }

      // if the last phase of contiguous recovery added any new candidates to the promising queue,
      // restart fragmented reassembly, otherwise done

      reassembly_complete = atomic_load_explicit(&scalpel_state.validated_files, memory_order_acquire) == validated;
    }
  }

  // time to exit?
  if (atomic_load_explicit(&TAKE_CHECKPOINT_AND_EXIT, memory_order_acquire)) {
    // threads won't be resumed on this kind of checkpoint
    frame_message("CHECKPOINT IS COMPLETE.  EXITING");
  }
}


// populate promising queue with any remaining header-only and footer-only candidates
static void insert_F2_reassembly_candidates(FILE_DEFRAG_PRIORITY priority) {

  SearchSpec *currentfilespec = 0;
  CarveInfo *candidate;
  uint32_t needlenum, i = 0;
  uint64_t start;
  uuid_string_t uuidp;
  uuid_string_t uuidc;
  uint64_t count = 0;
  static char buf[MAX_STRING_LENGTH * 2];

  for (needlenum = 0; needlenum < scalpel_state.num_specs; needlenum++) {
    currentfilespec = &scalpel_state.search_specs[needlenum];

    // skip MASTER file types and types marked NO_DEFRAG
    if (currentfilespec->MASTER || currentfilespec->NO_DEFRAG || scalpel_state.no_defrag) {
      continue;
    }

    if (! scalpel_state.prioritize_types || priority == currentfilespec->PRIORITY) {
      // insert header-only candidates
      for (i = 0; i < currentfilespec->offsets.numheaders; i++) {
        start = filemirror_apparent_location(scalpel_state.filemirror, currentfilespec->offsets.headers[i]);

        if (start % scalpel_state.blocksize != 0 || currentfilespec->offsets.deposited[i]) {
          continue;  // skip non-block aligned headers and headers that have
                     // already been a part of a previously deposited candidate
        }

        // create structure for carving candidate
        candidate = (CarveInfo *)calloc(1, sizeof(CarveInfo));
        check_memory_allocation(candidate, __LINE__, __FILE__, "candidate");

        candidate->workload = VALIDATE_FILE;
        candidate->b = NULL;
        candidate->start = start;
        candidate->stop = start + scalpel_state.blocksize - 1;
        candidate->filetype = scalpel_state.search_specs[needlenum].FILETYPE;
        candidate->searchtype = scalpel_state.search_specs[needlenum].SEARCHTYPE;
        candidate->needleidx = needlenum;
        candidate->chopped = false;
        candidate->cloned = false;
        candidate->clone = false;
        candidate->deposited = false;
        candidate->best_validates_to = 0;
        candidate->newblock = -1;
        candidate->block_choice_start = -2;
        candidate->no_initial_block_extension = false;
        candidate->fastpath = false;
        candidate->qposition = 0;
        uuid_generate_random(candidate->binuuid);
        uuid_clear(candidate->clone_binuuid);
        uuid_unparse_lower(candidate->binuuid, uuidp);
        uuid_unparse_lower(candidate->clone_binuuid, uuidc);
        gen_carve_hash_key(candidate->carvehashkey, candidate);
        candidate->best_choices = malloc(sizeof(Queue));
        check_memory_allocation(candidate->best_choices, __LINE__, __FILE__, "candidate->best_choices");
        init_queue(candidate->best_choices, sizeof(int64_t), true, NULL, true);

        if (scalpel_debug_trace_candidate(candidate)) {
          scalpel_debug_trace("[candbg] f2-header-seed start=%" PRIu64
                              " stop=%" PRIu64 " len=%" PRIu64
                              " type=%s",
                              candidate->start / scalpel_state.blocksize,
                              candidate->stop / scalpel_state.blocksize,
                              candidate->stop - candidate->start + 1,
                              candidate->filetype);
        }

        // update stats

        // for this needle
        currentfilespec->candidates++;

        // all time
        scalpel_state.candidates++;

        count++;

        if (scalpel_state.mode_verbose) {
          lock_fprintf(stdout,
                       "\nF2: Depositing new header-only candidate with "
                       "blockvector %p and UUIDs\n%s / %s\n"
                       "into promising queue.\n",
                       candidate->b, uuidp, uuidc);
        }

        // drop the candidate into the queue
        add_to_queue_priority_relaxed(&promising_queue, &candidate, candidate->qposition);
      }

      if (currentfilespec->SEARCHTYPE != SEARCHTYPE_BACKWARD) {
        continue;
      }

      // insert footer-only candidates
      for (i = 0; i < currentfilespec->offsets.numfooters; i++) {
        start = filemirror_apparent_location(scalpel_state.filemirror, currentfilespec->offsets.footers[i]);

        // create structure for carving candidate
        candidate = (CarveInfo *)calloc(1, sizeof(CarveInfo));
        check_memory_allocation(candidate, __LINE__, __FILE__, "candidate");

        candidate->workload = VALIDATE_FILE;
        candidate->b = NULL;
        candidate->start = start;
        candidate->stop = start + currentfilespec->offsets.footerlens[i] - 1;
        candidate->filetype = scalpel_state.search_specs[needlenum].FILETYPE;
        candidate->searchtype = scalpel_state.search_specs[needlenum].SEARCHTYPE;
        candidate->needleidx = needlenum;
        candidate->chopped = false;
        candidate->cloned = false;
        candidate->clone = false;
        candidate->deposited = false;
        candidate->qposition = 0;
        candidate->best_validates_to = 0;
        candidate->newblock = -1;
        candidate->block_choice_start = -2;
        candidate->no_initial_block_extension = false;
        candidate->fastpath = false;
        uuid_generate_random(candidate->binuuid);
        uuid_clear(candidate->clone_binuuid);
        uuid_unparse_lower(candidate->binuuid, uuidp);
        uuid_unparse_lower(candidate->clone_binuuid, uuidc);
        gen_carve_hash_key(candidate->carvehashkey, candidate);
        candidate->best_choices = malloc(sizeof(Queue));
        check_memory_allocation(candidate->best_choices, __LINE__, __FILE__, "candidate->best_choices");
        init_queue(candidate->best_choices, sizeof(int64_t), true, NULL, true);

        if (scalpel_debug_trace_candidate(candidate)) {
          scalpel_debug_trace("[candbg] f2-footer-seed start=%" PRIu64
                              " stop=%" PRIu64 " len=%" PRIu64
                              " type=%s",
                              candidate->start / scalpel_state.blocksize,
                              candidate->stop / scalpel_state.blocksize,
                              candidate->stop - candidate->start + 1,
                              candidate->filetype);
        }

        // update stats

        // for this needle
        currentfilespec->candidates++;

        // all time
        scalpel_state.candidates++;

        count++;

        if (scalpel_state.mode_verbose) {
          lock_fprintf(stdout,
                       "\nF2: Depositing new footer-only candidate with "
                       "blockvector %p and UUIDs\n%s / %s\n"
                       "into promising queue.\n",
                       candidate->b, uuidp, uuidc);
        }

        // drop the candidate into the queue
        add_to_queue_priority_relaxed(&promising_queue, &candidate, candidate->qposition);
      }
    }
  }

  sprintf(buf, "F2: INSERTED %" PRIu64 " NEW HEADER/FOOTER-ONLY CANDIDATES", count);
  frame_message(buf);
}


//
// ***************************************************************
// ***************************************************************
// ****** REASSEMBLY THREAD IMPLEMENTATION--THIS FUNCTION ********
// ****** EXECUTES EITHER THE DEFAULT OR A CUSTOM         ********
// ****** REASSEMBLY FUNCTION TO PROCESS A SINGLE CANDIDATE ******
// ***************************************************************
// ***************************************************************
//
// each reassembly thread monitors the promising queue for work and when is available, chooses the
// appropriate reassembly function for a candidate and executes the correct reassembly function
static void *reassembly_thread(void *args) {

  ThreadWork *work = (ThreadWork *)args;
  CarveInfo *candidate;      // carving candidate to process
  uuid_string_t text_uuidp;  // primary and clone UUIDs for candidate
  uuid_string_t text_uuidc;

  atomic_store_explicit(&work->thread_running, true, memory_order_release);

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Reassembly thread # %1d initialized.\n", work->id);
  }

  // *******************************************************
  // ****** CONTINUE UNTIL THREAD IS SIGNALED TO STOP ******
  // *******************************************************

  while (! atomic_load_explicit(&work->thread_stop, memory_order_acquire)) {
    // *******************************************
    // ****** GET A CANDIDATE TO REASSEMBLE ******
    // *******************************************

    if (! get_reassembly_candidate(work, &candidate)) {
      // thread was signaled to exit
      goto done;
    }

    // track runtime of on this candidate--updated runtime is used to prioritize selection of
    // candidates with the least runtime to date
    clock_gettime(CLOCK_MONOTONIC, &candidate->last_start);

    // moves creation of blockvector out of main thread
    if (! candidate->b) {
      // init blockvector for carve candidate
      init_contiguous_blockvector(scalpel_state.filemirror, &candidate->b, candidate->start, candidate->stop, false);
    }

    // mirror work assigned to reassembly threads (must be after blockvector init)
    add_to_reassembly_queue(candidate);

    // ********************************************************
    // ****** HAVE A CANDIDATE TO REASSEMBLE.  PREPARE   ******
    // ****** TO EXECUTE APPROPRIATE REASSEMBLY FUNCTION ******
    // ********************************************************

    candidate->flavor = PROMISING;

    // get textual UUIDs for status reports. The textual versions are maintained only when a
    // candidate is actively being improved to save space.
    uuid_unparse_lower(candidate->binuuid, text_uuidp);
    uuid_unparse_lower(candidate->clone_binuuid, text_uuidc);

    // call appropriate reassembly function--the default is the generic L-R reassembly function
    // LR_reassembly
    if (scalpel_state.search_specs[candidate->needleidx].REASSEMBLYFUNC) {
      scalpel_state.search_specs[candidate->needleidx].REASSEMBLYFUNC(work, &candidate, text_uuidp, text_uuidc);
    }
    else {
      LR_reassembly(work, &candidate, text_uuidp, text_uuidc);
    }

    // ***************************************
    // ****** THREAD BECOMES IDLE AGAIN ******
    // ***************************************

    atomic_fetch_add_explicit(&num_idle_reassembly_threads, 1, memory_order_acq_rel);

    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout, "Reassembly thread # %1d completed work.\n", work->id);
    }
  }

  // thread exit
done:
  lock_fprintf(stdout, "Reassembly thread # %1d exiting.\n", work->id);
  atomic_store_explicit(&work->thread_running, false, memory_order_release);

  return 0;
}


// block until a new reassembly candidate can be returned or the calling thread is ordered to stop.
// Returns false if the thread has been ordered to stop.
static bool get_reassembly_candidate(ThreadWork *work, CarveInfo **candidate) {

  CarveInfo **c;

  // wait for work to do
  c = NULL;
  while (! c && ! atomic_load_explicit(&work->thread_stop, memory_order_acquire)) {
    c = NULL;
    MUTEX_ERROR_CHECK(pthread_mutex_lock(&reassembly_work_is_available), __LINE__, __FILE__);

    if ((atomic_load_explicit(&promising_initialized, memory_order_acquire)
         && atomic_load_explicit(&kill_queue_initialized, memory_order_acquire))
        && ! atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
      c = remove_from_front_sync(&promising_queue, candidate, &num_idle_reassembly_threads, -1);
    }

    if (! c && ! atomic_load_explicit(&work->thread_stop, memory_order_acquire)) {
      if (scalpel_state.mode_verbose) {
        lock_fprintf(stdout, "Reassembly thread # %1d waiting for work, sleeping.\n", work->id);
      }

      pthread_cond_wait(&reassembly_check_work_available, &reassembly_work_is_available);
    }

    MUTEX_ERROR_CHECK(pthread_mutex_unlock(&reassembly_work_is_available), __LINE__, __FILE__);
  }

  if (atomic_load_explicit(&work->thread_stop, memory_order_acquire)) {
    // thread should exit
    return false;
  }
  else {
    return true;
  }
}


// create an EssentialCarveInfo structure from a CarveInfo structure and insert it into the
// reassembly queue, to mirror work assigned to reassembly threads
static void add_to_reassembly_queue(CarveInfo *c) {

  EssentialCarveInfo e;

  strcpy(e.filetype, scalpel_state.search_specs[c->needleidx].FILETYPE);
  e.numblocks = blockvector_get_num_blocks(c->b);
  e.qposition = c->qposition;
  memcpy(e.binuuid, c->binuuid, sizeof(c->binuuid));
  memcpy(e.clone_binuuid, c->clone_binuuid, sizeof(c->clone_binuuid));
  e.active = true;
  add_to_queue_priority_relaxed(&reassembly_queue, &e, e.qposition);
}


// delete any elements from reassembly queue that match UUIDs of 'c'
void delete_from_reassembly_queue(CarveInfo *c) {

  EssentialCarveInfo e;

  memcpy(e.binuuid, c->binuuid, sizeof(c->binuuid));
  memcpy(e.clone_binuuid, c->clone_binuuid, sizeof(c->clone_binuuid));
  delete_from_queue(&reassembly_queue, &e);
}


//
// global state API functions. These functions allow file validators / reassembly threads and block
// validators access to global state. The functions gen_block_hash_key() and gen_carve_hash_key()
// are used to create hash keys. These functions are thread-safe, as the underlying hashtable
// implementation is thread-safe.
//

// retrieve and return state associated with a carving operation.
// IMPORTANT: returns a heap-allocated COPY.  Caller MUST free() (or use
// the file type's FREECARVESTATEFUNC) when done.  Modifications must be
// written back via carve_put_state().
void *carve_get_state(void *carvehashkey) {

  uint32_t needleidx = 0;

  if (carve_hash_key_valid(carvehashkey)) {
    // extract needleidx from key
    memcpy(&needleidx, carvehashkey, sizeof(needleidx));
    return oa_hash_get_copy(scalpel_state.search_specs[needleidx].carve_state, carvehashkey);
  }

  return NULL;
}


// save (or overwrite) global state associated with a carving operation
void carve_put_state(void *carvehashkey, void *state) {

  uint32_t needleidx = 0;

  if (carve_hash_key_valid(carvehashkey)) {
    // extract needleidx from key
    memcpy(&needleidx, carvehashkey, sizeof(needleidx));
    oa_hash_put(scalpel_state.search_specs[needleidx].carve_state, carvehashkey, state);
  }
}


// free state associated with a carving operation
void carve_free_state(void *carvehashkey) {

  uint32_t needleidx = 0;

  if (carve_hash_key_valid(carvehashkey)) {
    // extract needleidx from key
    memcpy(&needleidx, carvehashkey, sizeof(needleidx));
    oa_hash_delete(scalpel_state.search_specs[needleidx].carve_state, carvehashkey);
  }
}


// retrieve and return state associated with a block hash key.
// IMPORTANT: returns a heap-allocated COPY.  Caller MUST free() (or use
// the file type's FREEBLOCKSTATEFUNC) when done.  Modifications must be
// written back via block_put_state().
void *block_get_state(void *blockhashkey) {

  uint32_t needleidx = 0;

  if (block_hash_key_valid(blockhashkey)) {
    // extract needleidx from key
    memcpy(&needleidx, blockhashkey, sizeof(needleidx));
    return oa_hash_get_copy(scalpel_state.search_specs[needleidx].block_state, blockhashkey);
  }

  return NULL;
}


// save (or overwrite) global state associated with a block hash key
void block_put_state(void *blockhashkey, void *state) {

  uint32_t needleidx = 0;

  if (block_hash_key_valid(blockhashkey)) {
    // extract needleidx from key
    memcpy(&needleidx, blockhashkey, sizeof(needleidx));

    if (scalpel_state.block_validation_complete) {
      handle_error(SCALPEL_ERROR_BLOCK_STATE_IS_READ_ONLY, scalpel_state.search_specs[needleidx].FILETYPE, __LINE__, __FILE__);
    }

    oa_hash_put(scalpel_state.search_specs[needleidx].block_state, blockhashkey, state);
  }
}


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
// binary search helper functions for quickly locating appropriate footers
static size_t lower_bound_u64(const uint64_t *a, uint64_t n, uint64_t key) {

  size_t lo = 0, hi = n;

  while (lo < hi) {
    size_t mid = lo + ((hi - lo) >> 1);

    if (a[mid] < key) {
      lo = mid + 1;
    }
    else {
      hi = mid;
    }
  }
  return lo;  // first index with a[idx] >= key
}


static size_t upper_bound_u64(const uint64_t *a, uint64_t n, uint64_t key) {

  size_t lo = 0, hi = n;

  while (lo < hi) {
    size_t mid = lo + ((hi - lo) >> 1);

    if (a[mid] <= key) {
      lo = mid + 1;
    }
    else {
      hi = mid;
    }
  }
  return lo;  // first index with a[idx] > key
}
#pragma GCC diagnostic pop


static uint64_t read_u64_unaligned(const void *ptr) {

  uint64_t val;

  memcpy(&val, ptr, sizeof(uint64_t));
  return val;
}


static uint32_t read_u32_unaligned(const void *ptr) {

  uint32_t val;

  memcpy(&val, ptr, sizeof(uint32_t));
  return val;
}


static uint16_t read_u16_unaligned(const void *ptr) {

  uint16_t val;

  memcpy(&val, ptr, sizeof(uint16_t));
  return val;
}

// comparison function for queue holding integers
static int int_compare(const void *a, const void *b) {

  const int ia = *((const int *)a);
  const int ib = *((const int *)b);

  if (ia > ib) {
    return 1;
  }
  else if (ia == ib) {
    return 0;
  }
  else {
    return -1;
  }
}

