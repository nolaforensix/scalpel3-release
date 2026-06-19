//
// Scalpel3 is Copyright(C) 2021 - 2026 by Golden G.Richard III and contributors.
//
// This program is free software : you can redistribute it and / or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <https://www.gnu.org/licenses/>.
//
//-----------------------------
// Additional Integration Terms
// ----------------------------
//
// Linking or embedding Scalpel3 (statically or dynamically) into another
// program such that the resulting executable or library forms a single
// combined work constitutes creation of a derivative work under the GPL.
// Any party distributing such a combined work must make the entire source
// code available under the terms of the GPL as well.
//
// Commercial entities wishing to use Scalpel3 in a closed-source or proprietary
// product or requiring support must obtain a separate commercial license.
//
// For commercial licensing or questions about integration, contact:
// Golden G. Richard III (golden@cct.lsu.edu).
//
// Please see LICENSE.md and README.md for further information.
//
//
// scalpel3 is a complete rewrite of the open source scalpel, which was
// originally developed by Golden G. Richard III in 2005 and then enhanced by
// both Vico Marziale and Golden G. Richard until ~2013. Earlier versions of
// scalpel had their roots in Foremost 0.69.  The emphasis of scalpel3 is on
// *practical* solutions to solving file fragmentation for selected file types
// and making this process as fast as possible on modern hardware.
//
// Yes, the authors know this is an NP-hard problem.  We will not be deterred.
// :)
//
// IMPORTANT: scalpel3 internals differ completely from earlier versions of
// scalpel and the configuration for scalpel3 is NOT at all compatible with
// earlier versions.
//

#if ! defined(SCALPEL_H)
#define SCALPEL_H

/////////////////////////////////////////////////////////////////
//                 CONFIGURABLE PARAMETERS                     //
/////////////////////////////////////////////////////////////////

// define > 0 this ONLY to test the backtrace facility!  Setting > 0 will cause scalpel to
// immediately crash and generate a backtrace.
#define TEST_BACKTRACE 0

// per-file type file validator performance statistics.  Disabled if 0.  Atomics are now used to
// limit the overhead of leaving this on, but there is at least some minimal performance impact, so
// leave it off if you don't need it.
#define VALIDATOR_PERFORMANCE_STATS 1

// per-file type file validator performance statistics.  Disabled if 0.  Atomics are now used to
// limit the overhead of leaving this on, but there is at least some minimal performance impact, so
// leave it off if you don't need it.
#define BLOCK_SELECTION_PERFORMANCE_STATS 1

// default periodic checkpointing interval (in seconds).  Checkpoints are taken every
// CHECKPOINT_INTERVAL seconds if at least one file has been validated by reassembly threads.  This
// should be balanced with VALIDATION_CP_THRESHOLD so that checkpointing happens frequently enough
// to take advantage of blockmap swaps, without "thrashing" and eliminating opportunities for
// reassembly threads to make progress.  Periodic checkpoints only sync internal state to increase
// performance--they are distinct from recovery checkpoints, which ensure restartability.
//
// IMPORTANT: This parameter can drastically impact performance and more testing needs to be done to
// justify a default value.
#define PERIODIC_CHECKPOINTING_INTERVAL (5 * 60)

// default initial periodic checkpointing interval (in seconds).  To ensure that every candidate
// gets some initial processing time (so that easily assembled candidates are eliminated quickly), a
// wave of progress checkpoints every INITIAL_CHECKPOINTING_INTERVAL seconds occurs at the beginning
// of reassembly, to provide a sweep over all reassembly candidates.
//
// IMPORTANT: This parameter can drastically impact performance and more testing needs to be done to
// justify a default value.
#define INITIAL_PERIODIC_CHECKPOINTING_INTERVAL (120)

// default number of validated files during fragmented reassembly to trigger a blockmap swap and
// periodic checkpoint.
//
// IMPORTANT: This parameter can drastically impact performance and more testing needs to be done to
// justify a default value.
#define VALIDATION_CP_THRESHOLD 10000

// if fragmented reassembly has validated files since the last periodic checkpoint
// but then stops validating new files, trigger a blockmap sync without waiting for
// the full periodic interval.
#define VALIDATION_STALL_CP_INTERVAL 30

// recovery checkpoints are taken every RECOVERY_CHECKPOINT seconds regardless of whether reassembly
// threads have validated files.  This has no command line option override and ensures that large
// amounts of work are not lost on power failure.
#define RECOVERY_CHECKPOINTING_INTERVAL (15 * 60)

// because scalpel3 cannot be expected to finish execution on large workloads, it can be configured
// to checkpoint and terminate after a specified number of seconds in the fragmented reassembly
// phase.
#define EXIT_AFTER_SECONDS INT_MAX

// because scalpel3 cannot be expected to finish execution on large workloads, it can be configured
// to checkpoint and terminate after a specified number of seconds have elapsed since the last
// validation in the fragmented reassembly phase.
#define EXIT_AFTER_VAL_GAP INT_MAX

// forces even more verbose output
#define FORCE_VERBOSE_MODE 0

// if > 0, causes block state debugging information to be displayed
#define PRINT_BLOCK_STATE 0

// if > 0, causes carve state debugging information to be displayed
#define PRINT_CARVE_STATE 0

// default block size--override with -q command line option.  In general, fragmented reassembly will
// perform poorly for most file types if a small block sizes is used.
#define SCALPEL_BLOCK_SIZE 512

// controls how quickly gallop mode in fragmented reassembly increases the number of blocks added
// per configuration.  If SCALPEL_GALLOP_FACTOR is zero, gallop mode is disabled.  This is only the
// default value--it can be overridden with the -g command line option.
#define SCALPEL_GALLOP_FACTOR 16

// maximum number of contiguous blocks to add per configuration in fragmented reassembly.  Has no
// impact unless SCALPEL_GALLOP_FACTOR > 0.  This is only the default value--it can be overrided
// with the -G command line option.
#define SCALPEL_GALLOP_LIMIT 16384

// size of single file mirror readahead buffer in bytes
#define FILEMIRROR_BUFFER_SIZE 1000000000

// # of readahead buffers maintained by the file mirror
#define READAHEAD_BUFFERS 5

// organize carved files into this many (maximum) per subdirectory
#define MAX_FILES_PER_SUBDIRECTORY 5000

// # of clones that can be created to share work with reassembly threads each time
// a candidate is improved
// #define MAX_REASSEMBLY_SHARES            ((int)(log2((double)scalpel_state.max_reassembly_threads)) / 2)
#define MAX_REASSEMBLY_SHARES 1

// default output directory
#define SCALPEL_DEFAULT_OUTPUT_DIR "scalpel-output"

// if > 0, turns on memory profiling. Disabled if 0.
#define MAC_MEMORY_PROFILING 0

// if > 0, choose most distant reasonable footer when matching headers and footers, otherwise choose
// closest footer.  If 0 and -f is used to carve only contiguous files, then many files will not be
// recovered.
#define USE_MOST_DISTANT_FOOTER 1


/////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////
// NOTHING BELOW SHOULD BE MODIFIED WITHOUT A DEEP UNDERSTANDING OF WHAT WILL BE IMPACTED! //
/////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////

// IMPORTANT: Since you're still reading, changes to scalpel3 data structures typically require
// modifications to the checkpointing functions to ensure proper operation.  Familiarize yourself
// with the checkpointing architecture before making changes to data structures or very bad things
// will happen.

#define _GNU_SOURCE 1
#if ! defined(__APPLE__)
typedef char uuid_string_t[37];
#endif

#if defined(__APPLE__)
#include <mach/mach.h>
#include <sys/sysctl.h>
#endif

// *** DO NOT CHANGE THIS *** or regular expression searches will break!
#define PCRE2_CODE_UNIT_WIDTH 8

#include <backtrace.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <locale.h>
#include <math.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <pcre2.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdnoreturn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/timeb.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include "scalpelv.h"
#include "blockmap.h"
#include "colors.h"
#include "prioque.h"
#define XXH_INLINE_ALL
#include "xxhash.h"
#include "hashv4.h"
#if !defined(SCALPEL3_EXTERNAL)
#include "dirname.h"
#include "filemirror.h"
#include "scalpelsimd.h"
#include "exe_vision/unix/elf_onnx_global.h"
#endif

// set default mutex type
// #define PTHREAD_MUTEX_TYPE PTHREAD_MUTEX_ADAPTIVE_NP
#define PTHREAD_MUTEX_TYPE PTHREAD_MUTEX_ERRORCHECK
// #define PTHREAD_MUTEX_TYPE PTHREAD_MUTEX_NORMAL

#define CEILDIV(n, d) (((n) + (d) - 1) / (d))

// only 64-bit platforms are supported
#define off64_t off_t

#if ! defined(STATE_SERIALIZATION_DEF)
#define STATE_SERIALIZATION_DEF
// serialization mode for reading/writing scalpel state
typedef enum StateSerialization {
  SERIALIZE = 1,
  DESERIALIZE = 2,
} StateSerialization;
#endif

// these are defined in filemirror.h
typedef struct FileMirror FileMirror;
typedef struct BlockVector BlockVector;
typedef struct EssentialBlockVector EssentialBlockVector;


// defines header/footer search strategy for file type
typedef enum SearchType {
  // default carve strategy--start at header, the most distant footer within max
  // file size (or max file size, in case of no footer) forms a starting point
  // for candidate
  SEARCHTYPE_FORWARD = 0,  //  MUST be zero--DO NOT CHANGE THIS

  // carve candidate consists of the block(s) containing the footer.  This
  // strategy *requires* a custom reassembly thread that can process the footer
  // and discover other blocks.  No contiguous carving attempts will be made for
  // SEARCHTYPE_BACKWARD file types.
  SEARCHTYPE_BACKWARD = 1,

  // special case, in which blocks are carved individually and no attempt is
  // made to reassemble them
  SEARCHTYPE_BLOCK_ONLY = 2
} SearchType;


// LARGEST_REGEXP_OVERLAP specifies the largest regular expression overlap
// across the boundaries of SIZE_OF_BUFFER-sized chunks of the disk image.  This
// is also used internally as the maximum "size" of a regular expression and
// affects the mininum disk image size that can be processed.  Large values will
// have negative impacts on performance.
#define LARGEST_REGEXP_OVERLAP 1024

// pruning period for kill queue (in seconds)
#define KILL_QUEUE_PRUNE_TIME (PERIODIC_CHECKPOINTING_INTERVAL * 2)

#define MAX_STRING_LENGTH (4096 + 1)
#define MAX_MATCHES_PER_BUFFER 1000000

// scalpel3 IPC commands and responses
#define SOCKBUFSIZE (32 * 1024 * 1024)

#define HELLO_CMD "HELLO"
#define HELLO_CMD_LEN (strlen(HELLO_CMD) + 1)
#define HELLO_RESPONSE \
  "Your greeting was received. IPC communication is operational."
#define HELLO_RESPONSE_LEN (strlen(HELLO_RESPONSE) + 1)

#define KILL_CMD "KILL"
#define KILL_CMD_LEN (strlen(KILL_CMD) + 1)
#define KILL_RESPONSE \
  "Kill request received. If a job with that UUID exists, it will be terminated."
#define KILL_RESPONSE_LEN (strlen(KILL_RESPONSE) + 1)
#define BAD_KILL_RESPONSE "Kill request received, but UUID format is not valid."
#define BAD_KILL_RESPONSE_LEN (strlen(BAD_KILL_RESPONSE) + 1)
#define NOT_READY_KILL_RESPONSE \
  "Kill request received, but kill queue is not ready. Try again in a few minutes."
#define NOT_READY_KILL_RESPONSE_LEN (strlen(NOT_READY_KILL_RESPONSE) + 1)

#define PROMISINGQUEUE_CMD "PROMISINGQUEUE"
#define PROMISINGQUEUE_CMD_LEN (strlen(PROMISINGQUEUE_CMD) + 1)
#define NOT_READY_PROMISINGQUEUE_RESPONSE \
  "Queues are not yet initialized.  Try again in a few minutes."
#define NOT_READY_PROMISINGQUEUE_RESPONSE_LEN (strlen(NOT_READY_PROMISINGQUEUE_RESPONSE) + 1)

#define REASSEMBLYQUEUE_CMD "REASSEMBLYQUEUE"
#define REASSEMBLYQUEUE_CMD_LEN (strlen(REASSEMBLYQUEUE_CMD) + 1)
#define NOT_READY_REASSEMBLYQUEUE_RESPONSE NOT_READY_PROMISINGQUEUE_RESPONSE
#define NOT_READY_REASSEMBLYQUEUE_RESPONSE_LEN NOT_READY_PROMISINGQUEUE_RESPONSE_LEN

#define KILLQUEUE_CMD "KILLQUEUE"
#define KILLQUEUE_CMD_LEN (strlen(KILLQUEUE_CMD) + 1)
#define NOT_READY_KILLQUEUE_RESPONSE \
  "Kill queue is not ready. Try again in a few minutes."
#define NOT_READY_KILLQUEUE_RESPONSE_LEN (strlen(NOT_READY_KILLQUEUE_RESPONSE) + 1)

#define CHECKPOINTEXIT_CMD "CHECKPOINTEXIT"
#define CHECKPOINTEXIT_CMD_LEN (strlen(CHECKPOINTEXIT_CMD) + 1)
#define CHECKPOINTEXIT_RESPONSE \
  "Checkpoint and exit queued by scalpel3. Shutting down soon. Please be patient."
#define CHECKPOINTEXIT_RESPONSE_LEN (strlen(CHECKPOINTEXIT_RESPONSE) + 1)

#define PROGRESSCHECKPOINT_CMD "PROGRESS"
#define PROGRESSCHECKPOINT_CMD_LEN (strlen(PROGRESSCHECKPOINT_CMD) + 1)
#define PROGRESSCHECKPOINT_RESPONSE_NACK \
  "A checkpointing operation is in progress. Please try again later."
#define PROGRESSCHECKPOINT_RESPONSE_NACK_LEN (strlen(PROGRESSCHECKPOINT_RESPONSE_NACK) + 1)
#define PROGRESSCHECKPOINT_RESPONSE_ACK                                                 \
  "All current candidates written to INPROGRESS directories.\n"
#define PROGRESSCHECKPOINT_RESPONSE_ACK_LEN (strlen(PROGRESSCHECKPOINT_RESPONSE_ACK) + 1)

#define BLOCKMAP_CMD "BLOCKMAP"
#define BLOCKMAP_CMD_LEN (strlen(BLOCKMAP_CMD) + 1)

#define STATUS_CMD "STATUS"
#define STATUS_CMD_LEN (strlen(STATUS_CMD) + 1)

// sizes for opaque carve and block hash keys
#define CARVE_HASH_KEY_SIZE (sizeof(int32_t) + sizeof(uuid_t) * 2 + 1)
#define CARVE_HASH_KEY_PRINTABLE_SIZE (2 * CARVE_HASH_KEY_SIZE + 1)
#define BLOCK_HASH_KEY_SIZE (sizeof(int32_t) + sizeof(int64_t) + 1)
#define BLOCK_HASH_KEY_PRINTABLE_SIZE (2 * BLOCK_HASH_KEY_SIZE + 1)

// defines all scalpel error codes
typedef enum ScalpelError {
  SCALPEL_OK,
  SCALPEL_GENERAL_ABORT,
  SCALPEL_ERROR_FILE_OPEN,
  SCALPEL_ERROR_FILE_READ,
  SCALPEL_ERROR_FILE_WRITE,
  SCALPEL_ERROR_FILE_CLOSE,
  SCALPEL_ERROR_MMAP_FAILURE,
  SCALPEL_ERROR_TOO_MANY_TYPES,
  SCALPEL_ERROR_BAD_REGEX,
  SCALPEL_ERROR_BAD_HEADER_OR_FOOTER,
  SCALPEL_ERROR_THREADING_MODEL_BROKEN,
  SCALPEL_ERROR_FILE_TOO_SMALL,
  SCALPEL_ERROR_BAD_OUTPUT_DIRECTORY,
  SCALPEL_ERROR_PTHREAD_FAILURE,
  SCALPEL_ERROR_MUTEX_FAILURE,
  SCALPEL_ERROR_TOO_MANY_MATCHES,
  SCALPEL_ERROR_BLOCKSIZE,
  SCALPEL_ERROR_BAD_BLOCKSIZE,
  SCALPEL_ERROR_IMAGE_BLOCKFILESIZE,
  SCALPEL_ERROR_FILETYPE_SIZE,
  SCALPEL_ERROR_UNINITIALIZED_BLOCKVECTOR,
  SCALPEL_ERROR_MEMORY_LEAK,
  SCALPEL_ERROR_BAD_BLOCKMAP_BLOCK_NUMBER,
  SCALPEL_ERROR_MASTER_HEADERFUNC,
  SCALPEL_ERROR_BACKWARD_FOOTER,
  SCALPEL_ERROR_FORWARD_HEADER,
  SCALPEL_ERROR_MISSING_BLOCK_VALIDATOR,
  SCALPEL_ERROR_CHECKPOINT,
  SCALPEL_ERROR_CHECKPOINT_IMAGE,
  SCALPEL_ERROR_CHECKPOINT_MISMATCH,
  SCALPEL_ERROR_IPC,
  SCALPEL_ERROR_NO_BLOCKMAP,
  SCALPEL_ERROR_BLOCKMAP_FORMAT,
  SCALPEL_ERROR_MISSING_CARVE_STATE_FUNCTION,
  SCALPEL_ERROR_MISSING_BLOCK_STATE_FUNCTION,
  SCALPEL_ERROR_SUBTYPE_ERROR,
  SCALPEL_ERROR_BLOCK_STATE_IS_READ_ONLY,
  SCALPEL_ERROR_BAD_START_END_BLOCKS,
} ScalpelError;

#define SCALPEL_WILDCARD_CHAR '?'

#define SCALPEL_COPYRIGHT_STRING \
  "scalpel3 is (c) 2021-2026 by Golden G. Richard III (@nolaforensix) and contributors.\n"

#define SCALPEL_BANNER_STRING \
  "scalpel3 v%s", SCALPEL_VERSION


// search state for string searches
typedef union SearchState {
  size_t bm_table[UCHAR_MAX + 1];
  pcre2_code *re;
} SearchState;


// result of block evaluation for block validator functions--this value MUST be representable with 4
// bits and BLOCK_CONFIDENCE_INVALID MUST BE ZERO.  The value indicates confidence that the block is
// of a specific file type.
typedef enum BlockValidationDecision {
  BLOCK_CONFIDENCE_INVALID = 0,  // block ABSOLUTELY DOES NOT validate as type ** MUST BE ZERO **
  BLOCK_CONFIDENCE_LOW = 1,      // possibly validates as type with low confidence
  BLOCK_CONFIDENCE_VALID = 15    // validates as type with highest possible confidence
} BlockValidationDecision;


// when file type prioritization is on, a complete set of file carving passes is
// performed for each set of file types with the same priority, starting with
// *highest* numerical priority.  This allows file types with better validators
// to cover blocks first that are more likely to actually belong to recovered
// files.  Priorities assigned to file types must be non-negative integers.
typedef enum FILE_DEFRAG_PRIORITY {
  PRIORITY_HIGHEST = 999,  // highest possible priority
  PRIORITY_SIGMA = 200,    // easier defrag, higher
  PRIORITY_PI = 100,       // harder defrag, lower priority
  PRIORITY_LOW = 0,        // hardest, lowest priority
  /////////////////////////////////////////////////////////////////////////
  PRIORITY_FLOOR = -1      // for internal use only--do not assign to file types
} FILE_DEFRAG_PRIORITY;


// this structure bundles information for threads that work on global queues.
// They only need an ID and data related to synchronization.
typedef struct ThreadWork {
  int id;
  atomic_bool thread_running;  // thread is alive?
  atomic_bool thread_stop;     // if true, should exit
} ThreadWork;


// type of validation being performed by thread
typedef enum ValidateWorkload {
  NO_WORKLOAD = 0,
  VALIDATE_FILE = 1,
  VALIDATE_BLOCK = 2
} ValidateWorkload;


// tracks info about one block validation task.  BlockInfo intentionally carries
// only the state needed by validate_block(); file carving and reassembly
// candidates use CarveInfo.
typedef struct BlockInfo {
  int64_t apparent_block;  // apparent block number in the current file mirror view
  int64_t actual_block;    // actual source block backing apparent_block
  int32_t needleidx;       // index of file type in scalpel_state.search_specs[]
  char *filetype;          // quick access to file type
  SearchType searchtype;   // quick access to search type for file type
  char blockhashkey[BLOCK_HASH_KEY_SIZE];  // key for per-block validator state

  // block-validation callbacks copied from SearchSpec before queueing, since
  // scalpel_state.search_specs must be locked before access during block
  // validation.
  uint32_t (*blockvalidator)(char *data, uint64_t length,
                             BlockValidationDecision *decision,
                             uint64_t *validates_to, uint32_t needleidx,
                             uint32_t blocksize, void *blockhashkey);
  void (*printblockstatefunc)(const void *state);  // optional block-state printer
} BlockInfo;


// type of CarveInfo candidate to write
typedef enum CarveInfoFlavor {
  NO_FLAVOR = 0,
  VALIDATED = 1,
  PROMISING = 2,
  INPROGRESS = 3
} CarveInfoFlavor;


// tracks info about one file carving candidate.  Note that many of these fields are present to
// support the default LR_reassembly() function.
typedef struct CarveInfo {
  BlockVector *b;                   // blockvector associated with file
  int32_t needleidx;                // index of file type in scalpel_state.search_specs[]
  uint64_t best_validates_to;       // best validates_to so far, for reassembly
                                    // threads that need to track this
  int64_t newblock;                 // **actual** block currently under consideration for
                                    // extending the candidate.  Storing the actual
                                    // blocknumber is necessary for the block number
                                    // to survive blockmap changes
  int64_t block_choice_start;       // starting point for search for next apparent block number
  ValidateWorkload workload;        // type of validation work assigned to thread
  char *filetype;                   // quick access to file type
  SearchType searchtype;            // quick access to searchtype for file type
  bool chopped;                     // is carved file's length constrained
                                    // by max file size for type? (i.e., could
                                    // the file actually be longer?)
  bool cloned;                      // did this candidate get cloned for work sharing?
  bool clone;                       // is this candidate a work-sharing clone?
  bool deposited;                   // candidate with this header previously deposited for
                                    // fragmented reassembly?
  bool partial_artifact_written;    // has PROMISING/INPROGRESS output been written?
  int64_t qposition;                // CPU-time-decay scheduling priority in promising queue
                                    // (relaxed priority; not strict FIFO among equal priorities)
  CarveInfoFlavor flavor;           // files only: validated, promising, or in progress
  bool no_initial_block_extension;  // if true, checkpoint interrupted best block selection
  bool fastpath;                    // if true, newly appended block maximizes best_validated_to
  Queue *best_choices;              // queue of best choices for current blockvector index
  uuid_t binuuid;                   // unique identifier for this candidate
  uuid_t clone_binuuid;             // clones created during reassembly work sharing get
                                    // a new uuid
  struct timespec last_start;       // time at start of current reassembly effort

  char carvehashkey[CARVE_HASH_KEY_SIZE];
  uint64_t start, stop;                        // temporary byte range used to create
                                               // the initial contiguous blockvector
                                               // before candidate->b exists.
  char inprogress_pathname[MAX_STRING_LENGTH]; // fixed pathname for writing inprogress version
                                               // of candidate. This field is not checkpointed.
} CarveInfo;


typedef struct ValidationInfo {
  ValidateWorkload workload;
  union {
    CarveInfo *candidate;
    BlockInfo block;
  };
} ValidationInfo;


// essential components of a CarveInfo candidate that do not depend on internal scalpel3 or
// filemirror state.  This structure is used for sharing info with IPC-based tools to support
// human-in-the-loop decisions.
typedef struct EssentialCarveInfo {
  char filetype[MAX_STRING_LENGTH];
  uint64_t numblocks;    // number of blocks in candidate blockvector
  int64_t qposition;     // candidate processing priority
  uuid_t binuuid;        // primary UUID
  uuid_t clone_binuuid;  // clone UUID
  bool active;           // assigned to a thread for reassembly?
} EssentialCarveInfo;


// stores the absolute locations of all matching headers and footers for a particular file type.
typedef struct SearchSpecOffsets {
  // header info
  uint64_t *headers;           // absolute offsets of discovered headers
  size_t *headerlens;          // lengths of discovered headers
  bool *deposited;             // candidate with this header already deposited
                               // in promising queue?
  uint64_t headerstorage;      // space allocated for this many header offsets
  uint64_t numheaders;         // # stored header positions
  pthread_mutex_t headerlock;  // lock for adding headers

  // footer info
  uint64_t *footers;           // absolte offsets of discovered footers
  size_t *footerlens;          // lengths of discovered footers
  uint64_t footerstorage;      // space allocated for this many footer offsets
  uint64_t numfooters;         // # stored footer positions
  pthread_mutex_t footerlock;  // lock for adding footers

} SearchSpecOffsets;


// only the essential fields of the header/footer database are stored in this structure, for
// consumption outside scalpel3.
typedef struct EssentialSearchSpecOffsets {
  char *filetype;              // ASCII file type

  // header info
  uint64_t *headers;           // absolute offsets of discovered headers
  size_t *headerlens;          // lengths of discovered headers
  uint64_t numheaders;         // # headers

  // footer info
  uint64_t *footers;           // absolute offsets of discovered footers
  size_t *footerlens;          // lengths of discovered footers
  uint64_t numfooters;         // # footers
} EssentialSearchSpecOffsets;


// in the following structure, uppercased fields are specified as configuration
// data in scalpelconf.h.  The rest are initialized in copy_search_spec().
// Adding or deleting fields in this structure requires modification of
// copy_search_spec() in util.c!
typedef struct SearchSpec {
  // specified in scalpelconf.c, NULL if not specified:
  char FILETYPE[MAX_STRING_LENGTH];  // unique type for file
  bool MASTER;                       // master file type that creates subtypes?
  bool CASESENSITIVE;                // header and footer are case-sensitive?
  uint64_t MAXIMUMSIZE;              // maximum file size to carve
  uint64_t MINIMUMSIZE;              // minimum file size to carve
  char HEADER[MAX_STRING_LENGTH];    // textual header for file type
  char FOOTER[MAX_STRING_LENGTH];    // textual footer for file type
  SearchType SEARCHTYPE;             // see SearchType declaration above


  // header validation function
  char *(*HEADERFUNC)(char *base,              // base address of buffer to search
		      uint64_t offset,         // offset at which search should start
                      uint64_t remaining,      // bytes remaining to search
                      char **matchpos,         // location at which match occurred or NULL
                      uint32_t *matchlen,      // length of match
                      uint32_t blocksize);     // image file blocksize

  // footer validation function
  char *(*FOOTERFUNC)(char *base,              // base address of buffer to search
		      uint64_t offset,         // offset at which search should start
                      uint64_t remaining,      // bytes remaining to search
                      char **matchpos,         // location at which match occurred or NULL
                      uint32_t *matchlen,      // length of match
                      uint32_t blocksize);     // image file blocksize

  // block validation function
  uint32_t (*BLOCKVALIDATOR)(char *data,                         // pointer to block of data to evaluate
                             uint64_t length,                    // length of data block
                             BlockValidationDecision *decision,  // decision regarding block data
                             uint64_t *validates_to,             // index at which certainty drops to zero
                             uint32_t needleidx,                 // index into scalpel_state.search_specs() for file type
                             uint32_t blocksize,                 // block size of image file
                             void *blockhashkey);                // hash key for block validator global storage

  // file validation function
  void (*FILEVALIDATOR)(char *data,                              // pointer to buffer containing data to evaluate
                        uint64_t length,                         // length of buffer
                        bool *validates,                         // true if perfect validation, otherwise false
                        uint64_t *validates_to,                  // index at which certainty drops to zero
                        bool *promising,                         // if true, imperfect validation, but worthy of consideration
                        uint32_t needleidx,                      // index into scalpel_state.search_specs() for file type
                        uint32_t blocksize,                      // block size of image file
                        void *carvehashkey);                     // hash key for file validator global storage

  // don't carve function
  bool (*DONTCARVE)(char *data,                                  // pointer to buffer containing data to evaluate
                    uint64_t length,                             // length of buffer
                    char *sha256);                               // SHA256 hash of data

  // custom fragmented reassembly function
  void (*REASSEMBLYFUNC)(ThreadWork *work,                       // work assigned to reassembly function
                         CarveInfo **c,                          // candidate to reassemble
                         uuid_string_t uuidp,                    // primary UIID of candidate
                         uuid_string_t uuidc);                   // clone UUID of candidate

  // The file type-specific functions SERIALIZECARVESTATEFUNC,
  // CLONECARVESTATEFUNC, and FREECARVESTATEFUNC must be provided if the
  // carve_get_state() or carve_put_state() functions in the global state API
  // are used by a file validator or custom reassembly thread.
  // PRINTCARVESTATEFUNC and SIZEOFCARVESTATEFUNC are optional.

  // serialize or deserialize state associated with a carving operation.  The
  // function should return false or terminate with a fatal error on failure.
  bool (*SERIALIZECARVESTATEFUNC)(void **state, FILE *fp, StateSerialization mode);

  // clone state associated with a carving operation and return pointer to
  // cloned state.  This function must perform a deep copy that results in a clone that is free from internal
  void *(*CLONECARVESTATEFUNC)(const void *srcstate);

  // free all resources associated with state for a carving operation.  This
  // function should then set *state to NULL.
  void (*FREECARVESTATEFUNC)(void **state);

  // The following function is optional, but allows optimization of state storage
  // and retrieval for a *specific class* of state types.  You should only define
  // this function if the state you are storing has a fixed size and a call to
  // memcpy() results in a fully-independent clone.  If your CLONECARVESTATEFUNC
  // boils down to performing a single memcpy(), then you should define
  // SIZEOFCARVESTATEFUNC.  This function should NOT be defined for complex types
  // with internal pointers.

  size_t (*SIZEOFCARVESTATEFUNC)(const void *state);

  // (optional) display a representation of 'state' to stdout.
  void (*PRINTCARVESTATEFUNC)(const void *state);

  // The file type-specific functions SERIALIZEBLOCKSTATEFUNC,
  // CLONEBLOCKSTATEFUNC, and FREEBLOCKSTATEFUNC must be provided if the
  // block_get_state() or block_put_state() functions in the global state API
  // are used by a block validator.  PRINTBLOCKSTATEFUNC and
  // SIZEOFBLOCKSTATEFUNC are optional.

  // serialize or deserialize state associated with a block.  The function
  // should return false or terminate with a fatal error on failure.
  bool (*SERIALIZEBLOCKSTATEFUNC)(void **state, FILE *fp, StateSerialization mode);

  // clone state associated with a block and return pointer to cloned state
  void *(*CLONEBLOCKSTATEFUNC)(const void *srcstate);

  // free all resources associated with state for a block.  This function should
  // then set *state to NULL.
  void (*FREEBLOCKSTATEFUNC)(void **state);

  // The following function is optional, but allows optimization of state storage
  // and retrieval for a *specific class* of state types.  You should only define
  // this function if the state you are storing has a fixed size and a call to
  // memcpy() results in a fully-independent clone.  If your CLONEBLOCKSTATEFUNC
  // boils down to performing a single memcpy(), then you should define
  // SIZEOFBLOCKSTATEFUNC.  This function should NOT be defined for complex types
  // with internal pointers.

  // returns the value of sizeof() applied to the base type for block state.
  size_t (*SIZEOFBLOCKSTATEFUNC)(const void *state);

  // (optional) display a representation of 'state' to stdout.
  void (*PRINTBLOCKSTATEFUNC)(const void *state);

  FILE_DEFRAG_PRIORITY PRIORITY;  // supports prioritization of file types

  bool NO_DEFRAG;  // if true, no attempt is made to
                   // defragment files of this type

  /////////////////////////////////////////////
  // fields initialized in copy_search_spec():
  /////////////////////////////////////////////

  // related to headers:
  char begin[MAX_STRING_LENGTH];  // translate()-d header
  uint32_t beginlength;           // length of header
  bool begin_is_RE;               // header is a regular expression?
  SearchState beginstate;

  // related to footers:
  char end[MAX_STRING_LENGTH];  // translate()-d footer
  uint32_t endlength;           // length of footer
  bool end_is_RE;               // footer is a regular expression?
  SearchState endstate;

  // checkpoint / subtype support:
  int32_t mastertype;  // index into INITIAL_SEARCH_SPECS to
                       // support subtype identification and
                       // restoration of function pointers
                       // during checkpoint restoration

  // carving stats:
  uint64_t per_pass_candidates;   // # of carving candidates of this type
                                  // for a single carving pass
  uint64_t candidates;            // # of carving candidates of this type
  uint64_t chopped;               // # of files of this type chopped
  atomic_ulong validated_files;   // # of validated files carved of this type
  uint64_t validated_in_subdir;   // # of validated items in current subdir
  uint64_t promising_in_subdir;   // # of promising items in current subdir
  uint64_t inprogress_in_subdir;  // # of in progress items in current subdir
  atomic_ullong backtracked;      // number of backtracking operations for this type

  // subdirectory control for carving:
  uint64_t v_organize_dir_num;      // subdirectory number for validated output
  uint64_t p_organize_dir_num;      // subdirectory number for promising output
  uint64_t i_organize_dir_num;      // subdirectory number for inprogress output
  char v_current_subdir[PATH_MAX];  // current output subdir for validated files
  char p_current_subdir[PATH_MAX];  // current output subdir for promising files
  char i_current_subdir[PATH_MAX];  // current output subdir for in progress files
  pthread_mutex_t filewritelock;    // lock for filename/subdir generation

#if defined(VALIDATOR_PERFORMANCE_STATS)
  //  per-run file validator performance statistics:  *** NOT CHECKPOINTED ***
  atomic_ullong FV_calls;    // number of calls to validator during reassembly
  atomic_ullong FV_total;    // total time spent in validator in ns
  atomic_ullong FV_longest;  // longest time spent in validator in ns
#endif

#if defined(BLOCK_SELECTION_PERFORMANCE_STATS)
  //  per-run block selection performance statistics:  *** NOT CHECKPOINTED ***
  atomic_ullong BLK_calls;        // number of calls to block selection during reassembly
  atomic_ullong BLK_total;        // total time spent in block selection in ns
  atomic_ullong BLK_longest;      // longest time spent in block selection in ns
  atomic_ullong BLK_most_blocks;  // largest number of blocks considered to make a choice
#endif

  // associated header and footer locations:
  SearchSpecOffsets offsets;  // header/footer database for this file type

  // global state support
  oa_hash *block_state;  // global state for blocks of this type
  oa_hash *carve_state;  // global state for carving operations
                         // associated with this type
} SearchSpec;


// main Scalpel state
// (C) = field is serialized/deserialized during checkpointing
// (O) = value can be overriden by command line options during checkpoint restart
typedef struct ScalpelState {
  unsigned char sha256[32];               // SHA256 of current scalpel3 executable        (C)
  FileMirror *filemirror;                 // file mirror used for image file
  char image_pathname[PATH_MAX];          // name of image file being processed           (C)
  char blockmap_pathname[PATH_MAX];       // blockmap associated with image file          (C)
  uint32_t blocksize;                     // blocksize for image file                     (C)
  char output_directory[PATH_MAX];        // dir for carved files and fragments
  char base_output_directory[PATH_MAX];   // copy of initial base output dir pathname
  FILE *audit_file;                       // file handle for audit file
  uint32_t num_specs;                     // number of file types                         (C)
  pthread_mutex_t search_specs_lock;      // lock for adding subtypes
  SearchSpec *search_specs;               // specifications of file types to carve        (C)
  uint32_t longest_footer;                // length in bytes of longest footer            (C)
  uint64_t largest_maxfilesize;           // longest max file size in scalpelconf.h       (C)
  atomic_ulong files_written;             // total # of files written                     (C)
  atomic_ulong validated_files;           // total # of validated files carved            (C)
  uint64_t candidates;                    // total # of carving candidates                (C)
  uint64_t chopped;                       // total # of chopped files of this type        (C)
  bool mode_verbose;                      // if set, output additional debugging info     (O)
  bool reduce_aggressive_allocation;      // if set, use less aggressive mem allocation   (C)
  bool write_blockvectors;                // if set, write blockvectors for carved files  (C)
  bool write_promising;                   // write unvalidated but promising candidates?  (C)
  char invocation[MAX_STRING_LENGTH];     // command line used to invoke scalpel
  bool organize_subdirectories;           // organize output into subdirs?                (C)
  int32_t max_search_threads;             // max # of carving threads                     (C)(O)
  int32_t max_validation_threads;         // max # of block/file validation threads       (C)(O)
  int32_t max_reassembly_threads;         // max # of reassembly threads                  (C)(O)
  int32_t max_filemirror_threads;         // max # of threads per file mirror thread pool (C)(O)
  bool share_reassembly;                  // implement thread reassembly sharing?         (C)
  bool contig_header_reuse;               // reuse covered contiguous headers?             (C)
  bool no_defrag;                         // turns fragmented recovery off for all file
                                          // types                                        (C)
  bool hf_only;                           // write header/footer database and exit?       (O)
  bool backtrack;                         // backtracking during reassembly phases?       (C)
  uint64_t start_block;                   // if > 1, consider blocks before this block    (C)
                                          // number as covered and do not modify regions
                                          // of the blockmap outside this window
  uint64_t end_block;                     // if > 0, consider blocks after this block     (C)
                                          // number as covered and do not modify regions
                                          // of the blockmap outside this window
  bool reservations;                      // use block reservations?                      (C)
  bool memory_profiling;                  // should memory profiling be performed?        (C)(O)
  bool disable_shadow_peeking;            // disable peek at shadow blockmaps?            (C)(O)
  bool disable_backtrace;                 // should backtrace on crash be disabled?       (C)(O)
  bool prioritize_types;                  // use priorities for file types?               (C)
  bool write_inprogress;                  // write INPROGRESS on all checkpoints          (C)
  uint64_t gallop_factor;                 // gallop factor for fragmented reassembly      (C)
  uint64_t gallop_limit;                  // gallop limit for fragmented reassembly       (C)
  FILE_DEFRAG_PRIORITY current_priority;  // current carving priority being processed     (C)
  bool restore_from_checkpoint;           // restoring from checkpoint on this run?
  uint32_t checkpointing_interval;        // periodic checkpointing interval in seconds
  uint32_t validation_cp_threshold;       // # of files that must be validated before
                                          // a checkpoint is triggered
  uint32_t exit_after_secs;               // create checkpoint and exit after this many
                                          // seconds
  uint32_t exit_after_val_gap;            // create checkpoint and exit after this many
                                          // seconds without a new validation

  // the following indicate which phases were complete and assist in
  // lock optimization and checkpoint restart
  bool block_validation_complete;         // has block validation completed?              (C)
  bool contiguous_recovery_complete;      // has initial contiguous recovery completed?   (C)
  bool F1_initiated;                      // F1 reassembly yet for current priority?      (C)
  bool F2_initiated;                      // F2 reassembly yet for current priority?      (C)
  // misc non-checkpointed state
  int neon;                               // shhhhhhhh.                                   (O)
  bool no_cp_validation;                  // allow checkpoint restart w/o checkpoint      (O)
                                          // validation
} ScalpelState;


// prototypes for visible carve.c functions

void restore_checkpointed_scalpel_state(void);
void restore_checkpointed_promising_queue(void);
void save_checkpoint(void);
void remove_checkpoint(void);
uint32_t add_file_subtype(uint32_t masteridx, char *filetype);
void carve_files(void);
void write_candidate(CarveInfo **candidate, bool preserve);
void destroy_candidate(CarveInfo **candidate);
void *carve_get_state(void *hashkey);
void carve_put_state(void *hashkey, void *state);
void *block_get_state(void *hashkey);
void block_put_state(void *hashkey, void *state);
void delete_from_reassembly_queue(CarveInfo *c);

// prototypes for visible common.c functions

int get_terminal_width(void);
void portable_srandom(uint64_t seed);
uint64_t portable_random(void);
void check_memory_allocation(void *ptr, int line, const char *file,
                             const char *structure);
bool read_essential_carveinfo_element(EssentialCarveInfo *element,
                                      FILE *fp);
bool read_essential_carveinfo_queue(Queue *q, FILE *fp, bool init);
bool read_essential_carveinfo_queue_h(Queue *q, int handle, bool init);
bool kill_queue_element_serialization(void **element, int64_t *priority,
                                      FILE *fp, StateSerialization mode);
int carveinfo_match_both_uuids(const void *c1, const void *c2);
int compare_uuids(const void *u1, const void *u2);
int carveinfo_match_either_uuid(const void *c1, const void *c2);
int essentialcarveinfo_match_both_uuids(const void *c1, const void *c2);
void delete_files_recursive(const char *base_dir, const char *pattern);
EssentialSearchSpecOffsets *deserialize_essential_offsets(char *filename, uint32_t *num_specs_out);


// prototypes for visible util.c functions

void scalpel_logo(void);
void setup_sigint_handler(void);
void generate_backtrace(void);
void sigint_signal_handler(int sig);
void sigsegv_signal_handler(int sig);
void bt_error_callback(void *data,
                       const char *message,
                       int error_number);
char *append_stars(char *p, size_t n);
void lock_fprintf(FILE *stream, const char *format, ...) __attribute__((format(printf, 2, 3)));
void lock_fprintf_argp(FILE *stream, const char *format, va_list argp);
void lock_fputc(char c, FILE *stream);
void frame_message(const char *msg);
void catch_alarm(int signum);
void copy_search_spec(SearchSpec *d, SearchSpec *s);
char *string_tolower(char *s);
char *string_toupper(char *s);
void ignore_nonprintable(char *s, uint64_t *len);
void init_output_directory(void);
char *sprinthex(char *buf, char *s, int len, bool backslashes);
bool is_regular_expression(char *s);
void scalpel_log(const char *format, ...);
void scalpel_log_err(const char *format, ...);
int memwildcardcmp(const void *s1, const void *s2,
                   size_t n, bool casesensitive);
void set_program_name(char *s);
void init_bm_table(char *needle, size_t table[UCHAR_MAX + 1],
                   size_t len, bool casesensitive);
uint32_t find_longest_footer(void);
pcre2_match_data *find_regular_expression(pcre2_code *needle,
					  char *haystack, size_t haystack_len);
char *find_binary_string(char *needle, size_t needle_len,
                         char *haystack, size_t haystack_len,
                         size_t table[UCHAR_MAX + 1],
                         bool casesensitive);
uint64_t translate(char *str, char *filetype, bool re);
char *skip_white_space(char *str);
void open_audit_file(void);
void close_audit_file(void);
void MUTEX_ERROR_CHECK(int ret, int line, const char *file);
void memory_footprint(const char *s);
char *identify_src_lang(char *data, uint64_t *length);
void identify_single_src_file(void);
void oa_binary_key_free(void **key);
uint64_t oa_block_key_hash(const void *blockhashkey);
size_t oa_block_key_sizeof(const void *blockhashkey);
uint64_t oa_carve_key_hash(const void *carvehashkey);
size_t oa_carve_key_sizeof(const void *carvehashkey);
void *oa_block_key_cp(const void *blockhashkey);
void *oa_carve_key_cp(const void *carvehashkey);
bool oa_block_key_eq(const void *blockhashkey1, const void *blockhashkey2);
bool oa_carve_key_eq(const void *carvehashkey1, const void *carvehashkey2);
bool oa_block_key_ser(void **blockhashkey, FILE *fp, StateSerialization mode);
bool oa_carve_key_ser(void **carvehashkey, FILE *fp, StateSerialization mode);
bool gen_carve_hash_key(void *carvehashkey, CarveInfo *c);
bool gen_block_hash_key(void *blockhashkey, uint32_t needleidx, int64_t actualblocknum);
bool carve_hash_key_valid(void *carvehashkey);
bool block_hash_key_valid(void *blockhashkey);
char *displayable_block_hash_key(void *blockhashkey,
                                 char output[BLOCK_HASH_KEY_PRINTABLE_SIZE]);
char *displayable_carve_hash_key(void *carvehashkey,
                                 char output[CARVE_HASH_KEY_PRINTABLE_SIZE]);
int num_physical_cores(void);
int num_logical_cores(void);
bool atomic_max_u64_pub(atomic_ullong *a, uint64_t b);
void crash(void);
noreturn void handle_error(ScalpelError error, char *str, int line, const char *file);

// prototypes for visible reassembly.c functions
void reassembly_share_work(int id, CarveInfo *candidate);
bool reassembly_check_kill_queue(int id,
                                 CarveInfo **candidate,
                                 uuid_string_t uuidp,
                                 uuid_string_t uuidc);
bool reassembly_check_max_size(int id,
                               CarveInfo *candidate,
                               uuid_string_t uuidp,
                               uuid_string_t uuidc);
bool reassembly_check_validation(int id,
                                 CarveInfo *candidate,
                                 uint64_t *validates_to,
                                 uuid_string_t uuidp,
                                 uuid_string_t uuidc);
bool reassembly_time_to_checkpoint(int id,
                                   CarveInfo *candidate,
                                   uuid_string_t uuidp,
                                   uuid_string_t uuidc);
void LR_reassembly(ThreadWork *work,
                   CarveInfo **c,
                   uuid_string_t uuidp,
                   uuid_string_t uuidc);

// GLOBALS

//  backtrace state
extern struct backtrace_state *bt_state;

// fprintf() lock
extern pthread_mutex_t printf_is_available;

// controls checkpoint and exit events
extern atomic_bool TAKE_CHECKPOINT_AND_EXIT;

// controls periodic checkpoints
extern atomic_bool TAKE_RECOVERY_CHECKPOINT;

// controls periodic checkpoints
extern atomic_bool TAKE_PERIODIC_CHECKPOINT;

// controls progress checkpoints
extern atomic_bool TAKE_PROGRESS_CHECKPOINT;

// flag that induces reassembly threads to flush work and go back into
// idle state during a periodic or user-initiated checkpoint
extern atomic_bool REASS_RETURN_TO_IDLE;

// queue that holds promising carve candidates
extern Queue promising_queue;

// queue that mirrors candidates currently being processed by reassembly threads
extern Queue reassembly_queue;

// queue that holds UUIDs for candidates to be destroyed
extern Queue kill_queue;

// thread synchronization data
extern atomic_bool carvelist_initialized;
extern atomic_bool promising_initialized;
extern atomic_bool kill_queue_initialized;
extern pthread_mutex_t reassembly_work_is_available;
extern pthread_cond_t reassembly_check_work_available;
extern atomic_uint num_idle_reassembly_threads;

// scalpel3 prog name
extern char *__progname;

// main scalpel state variable
extern ScalpelState scalpel_state;

// filemirror that provides disk image view
extern FileMirror *filemirror;

// last checkpoint and start time for current run
extern struct timespec last_checkpoint;
extern struct timespec starttime;

// IPC config
extern int ipcsocket;  // scalpel3 IPC socket
extern bool no_IPC;    // IPC is disabled if no_IPC is true

// command line overrides for thread pool sizes
extern uint32_t max_filemirror_threads_override;
extern uint32_t max_reassembly_threads_override;
extern uint32_t max_search_threads_override;
extern uint32_t max_validation_threads_override;

// perceived numbers of CPU cores
extern int NC;

// configuration for supported file types

extern SearchSpec INITIAL_SEARCH_SPECS[];

#endif /* SCALPEL_H */

