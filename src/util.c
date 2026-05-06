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

#include "scalpel.h"

#if defined(__linux__)
// used in determining physical core count
typedef struct {
  int pkg;
  int core;
} pkg_core_t;
#endif

// GLOBALS

// lock for lock_fprintf()
pthread_mutex_t printf_is_available = PTHREAD_MUTEX_INITIALIZER;

// backtrace state
struct backtrace_state *bt_state;

// signal handling thread
static pthread_t signal_handler_thread;


// function prototypes for private util.c functions
static void *sigint_handler_thread(void *arg);
static unsigned char s3_fold_byte(unsigned char c, bool cs);
static char *s3_bitap_wildcard_u64(char *needle, size_t m, char *hay, size_t n, bool casesensitive, size_t start_pos);
static bool characters_match(char a, char b, bool casesensitive);
static char *bm_baseline(char *needle, size_t needle_len, char *haystack, size_t haystack_len, size_t table[UCHAR_MAX + 1],
                         bool casesensitive);
static size_t strlen_skip_color(const char *s);
static int bt_full_callback(void *data, uintptr_t pc, const char *pathname, int line_number, const char *function);
#if defined(__APPLE__)
static int sysctl_int_by_name(const char *name, int *out);
static int sysctl_str_by_name(const char *name, char *out, size_t out_sz);
static int get_physical_cores_macos(void);
#else
static int is_number(const char *s);
static int pair_exists(pkg_core_t *arr, size_t n, int pkg, int core);
static int get_physical_cores_linux(void);
static int read_int_file(const char *path, int *out);
#endif


// calls free() for a previously malloc()-ed hash table key
void oa_binary_key_free(void **key) {

  free(*key);
  *key = NULL;
}


// returns the size of a block hash key
size_t oa_block_key_sizeof(const void *key) {
  (void)key;
  return BLOCK_HASH_KEY_SIZE;
}


// serializes or deserializes a block hash key to a file 'fp'. Returns true on success, otherwise
// aborts with a fatal error.
bool oa_block_key_ser(void **blockhashkey, FILE *fp, StateSerialization mode) {

  size_t (*fb)(void *ptr, size_t size, size_t nitems,
               FILE *stream) = mode == SERIALIZE ? (size_t (*)(void *ptr, size_t size, size_t nitems, FILE *stream))fwrite
                                                 : (size_t (*)(void *ptr, size_t size, size_t nitems, FILE *stream))fread;

  if (mode == DESERIALIZE) {
    *blockhashkey = malloc(BLOCK_HASH_KEY_SIZE);
    check_memory_allocation(*blockhashkey, __LINE__, __FILE__, "blockhashkey");
  }

  if (fb(*blockhashkey, BLOCK_HASH_KEY_SIZE, 1, fp) != 1) {
    perror("block key");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  return true;
}


// clones and returns a block hash key
void *oa_block_key_cp(const void *blockhashkey) {

  void *ret = malloc(BLOCK_HASH_KEY_SIZE);
  check_memory_allocation(ret, __LINE__, __FILE__, "ret");
  memcpy(ret, blockhashkey, BLOCK_HASH_KEY_SIZE);

  return ret;
}


// compares two block hash keys
bool oa_block_key_eq(const void *blockhashkey1, const void *blockhashkey2) {

  return memcmp(blockhashkey1, blockhashkey2, BLOCK_HASH_KEY_SIZE) ? false : true;
}


// computes hash over block hash key
uint64_t oa_block_key_hash(const void *blockhashkey) { return XXH3_64bits(blockhashkey, BLOCK_HASH_KEY_SIZE); }

// returns the size of a carve hash key
size_t oa_carve_key_sizeof(const void *key) {
  (void)key;
  return CARVE_HASH_KEY_SIZE;
}


// serializes or deserializes a carve hash key to a file 'fp'. Returns true on success, otherwise
// aborts with a fatal error.
bool oa_carve_key_ser(void **carvehashkey, FILE *fp, StateSerialization mode) {

  size_t (*fb)(void *ptr, size_t size, size_t nitems,
               FILE *stream) = mode == SERIALIZE ? (size_t (*)(void *ptr, size_t size, size_t nitems, FILE *stream))fwrite
                                                 : (size_t (*)(void *ptr, size_t size, size_t nitems, FILE *stream))fread;

  if (mode == DESERIALIZE) {
    *carvehashkey = malloc(CARVE_HASH_KEY_SIZE);
    check_memory_allocation(*carvehashkey, __LINE__, __FILE__, "carvehashkey");
  }

  if (fb(*carvehashkey, CARVE_HASH_KEY_SIZE, 1, fp) != 1) {
    perror("carve key");
    // fatal
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    return false;
  }

  return true;
}


// clones and returns a carve hash key
void *oa_carve_key_cp(const void *carvehashkey) {

  void *ret = malloc(CARVE_HASH_KEY_SIZE);
  check_memory_allocation(ret, __LINE__, __FILE__, "ret");
  memcpy(ret, carvehashkey, CARVE_HASH_KEY_SIZE);

  return ret;
}


// compares two carve hash keys
bool oa_carve_key_eq(const void *carvehashkey1, const void *carvehashkey2) {

  return memcmp(carvehashkey1, carvehashkey2, CARVE_HASH_KEY_SIZE) ? false : true;
}


// compute hash over carve hash key
uint64_t oa_carve_key_hash(const void *carvehashkey) {
  return XXH3_64bits(carvehashkey, CARVE_HASH_KEY_SIZE);
}


// generate a block hash key based on a specific *actual* blocknumber and needleidx.
//
// IMPORTANT: block hashes *always* refer to the exemplar for a block--this means that duplicate
// blocks always have the same associated state.
bool gen_block_hash_key(void *blockhashkey, uint32_t needleidx, int64_t actualblocknum) {
  // if the appropriate support functions weren't provided for this file type, then the global state
  // API for blocks is disabled. In this case, generate a invalid hash key that indicates no state
  // is available.  true is returned if a valid key was generated, otherwise false is returned.

  // it's necessary to hold a lock to access *anything* in scalpel_state.search_specs if block
  // validation hasn't completed yet.

  bool locked = false;
  bool api_enabled;
  bool ret = true;
  char *key = blockhashkey;

  // use the exemplar in case of duplicate blocks
  actualblocknum = filemirror_get_exemplar(scalpel_state.filemirror, actualblocknum);

  if (! scalpel_state.block_validation_complete) {
    MUTEX_ERROR_CHECK(pthread_mutex_lock(&scalpel_state.search_specs_lock), __LINE__, __FILE__);
    locked = true;
  }

  api_enabled = scalpel_state.search_specs[needleidx].block_state ? true : false;

  if (locked) {
    MUTEX_ERROR_CHECK(pthread_mutex_unlock(&scalpel_state.search_specs_lock), __LINE__, __FILE__);
  }

  if (! api_enabled) {
    // a zero key is invalid
    memset(blockhashkey, 0, BLOCK_HASH_KEY_SIZE);
    ret = false;
  }
  else {
    memcpy(key, &needleidx, sizeof(needleidx));
    memcpy(key + sizeof(needleidx), &actualblocknum, sizeof(int64_t));
    // set last char to 1 to indicate valid
    key[BLOCK_HASH_KEY_SIZE - 1] = 1;
  }

  return ret;
}


// generate a displayable version of a block hash key
char *displayable_block_hash_key(void *blockhashkey, char output[BLOCK_HASH_KEY_PRINTABLE_SIZE]) {

  if (! blockhashkey || ! ((char *)blockhashkey)[BLOCK_HASH_KEY_SIZE - 1]) {
    sprintf(output, "** INVALID KEY **");
  }
  else {
    sprinthex(output, blockhashkey, BLOCK_HASH_KEY_SIZE, false);
  }

  return output;
}


// create a carve hash key from a CarveInfo struct.  If the appropriate support functions weren't
// provided for this file type, then the global state API for carve candidates is disabled. In
// this case, generate a invalid hash key that indicates no state is available.  true is returned
// if a valid key is generated, otherwise false.
bool gen_carve_hash_key(void *carvehashkey, CarveInfo *c) {

  char *key = carvehashkey;
  bool ret = true;

  if (! scalpel_state.search_specs[c->needleidx].carve_state) {
    // a zero key is invalid
    memset(carvehashkey, 0, CARVE_HASH_KEY_SIZE);
    return false;
  }

  memcpy(key, &c->needleidx, sizeof(c->needleidx));
  memcpy(key + sizeof(c->needleidx), c->binuuid, sizeof(uuid_t));
  memcpy(key + sizeof(c->needleidx) + sizeof(uuid_t), c->clone_binuuid, sizeof(uuid_t));
  // set last char to 1 to indicate valid
  key[CARVE_HASH_KEY_SIZE - 1] = 1;

  return ret;
}


// generate a displayable version of a carve hash key
char *displayable_carve_hash_key(void *carvehashkey, char output[CARVE_HASH_KEY_PRINTABLE_SIZE]) {

  if (! carvehashkey || ! ((char *)carvehashkey)[CARVE_HASH_KEY_SIZE - 1]) {
    sprintf(output, "** INVALID KEY **");
  }
  else {
    sprinthex(output, carvehashkey, CARVE_HASH_KEY_SIZE, false);
  }

  return output;
}


// determine if a carve hash key is valid (support functions are available)
bool carve_hash_key_valid(void *carvehashkey) { return carvehashkey && ((char *)carvehashkey)[CARVE_HASH_KEY_SIZE - 1]; }

// determine if a block hash key is valid (support functions are available)
bool block_hash_key_valid(void *blockhashkey) { return blockhashkey && ((char *)blockhashkey)[BLOCK_HASH_KEY_SIZE - 1]; }

// return length of a string with color formatting data omitted
static size_t strlen_skip_color(const char *s) {

  size_t i;
  size_t origlen;
  size_t len = 0;
  bool colorskip = false;

  origlen = strlen(s);
  for (i = 0; i < origlen; i++) {
    if (s[i] == 27) {
      colorskip = true;
      continue;
    }
    else if (colorskip && s[i] == 'm') {
      colorskip = false;
      continue;
    }
    else if (colorskip) {
      continue;
    }
    else {
      len++;
    }
  }
  return len;
}


// output a character subject to locking to prevent thread-related overlap
void lock_fputc(char c, FILE *stream) {

  MUTEX_ERROR_CHECK(pthread_mutex_lock(&printf_is_available), __LINE__, __FILE__);

  fputc(c, stream);

  MUTEX_ERROR_CHECK(pthread_mutex_unlock(&printf_is_available), __LINE__, __FILE__);
}


// output a string subject to locking to prevent thread-related overlap
void lock_fprintf_argp(FILE *stream, const char *format, va_list argp) {

  static char BUF[8192];
  static size_t length;
  static char color[100];
  static bool colorskip;
  static size_t i;

#if defined(__APPLE__)
  static char say[100];
  static char word[4000];
  static int32_t len;

#endif

  MUTEX_ERROR_CHECK(pthread_mutex_lock(&printf_is_available), __LINE__, __FILE__);

  if (! scalpel_state.neon) {
    vfprintf(stream, format, argp);
  }
  else {
    vsnprintf(BUF, 8192, format, argp);

    colorskip = false;
#if defined(__APPLE__)
    bzero(word, 100);
    len = 0;
#endif

    length = strlen(BUF);
    for (i = 0; i < length; i++) {
      if (BUF[i] == 27) {
        colorskip = true;
        continue;
      }
      else if (colorskip && BUF[i] == 'm') {
        colorskip = false;
        continue;
      }
      else if (colorskip) {
        continue;
      }
      else {
        sprintf(color, "\x1b[38;5;%1dm", (int)(random() % 252 + 2));
        fprintf(stream, "%s", color);
        fputc(BUF[i], stream);
#if defined(__APPLE__)
        if (scalpel_state.neon > 3) {
          if ((isalnum(BUF[i]) || BUF[i] == '.' || BUF[i] == ',' || BUF[i] == '/' || BUF[i] == '=') && len < 98) {
            word[len++] = BUF[i];
            word[len] = 0;
          }

          if ((isspace(BUF[i]) || i == length - 1) && len > 0) {
            sprintf(say, "say %s", word);
            system(say);
            len = 0;
          }
        }
#endif
      }
      fprintf(stream, "%s", BLACK);
    }
  }
  MUTEX_ERROR_CHECK(pthread_mutex_unlock(&printf_is_available), __LINE__, __FILE__);
}


// output a string subject to locking to prevent thread-related overlap
void lock_fprintf(FILE *stream, const char *format, ...) {

  va_list argp;

  va_start(argp, format);
  lock_fprintf_argp(stream, format, argp);
  va_end(argp);
}


// initialize signal handling thread and block SIGINT/SIGUSR1 on all other threads
void setup_sigint_handler(void) {

  sigset_t sigset;
  sigemptyset(&sigset);
  sigaddset(&sigset, SIGINT);
  sigaddset(&sigset, SIGUSR1);

  // block SIGINT/SIGUSR1 in all threads
  pthread_sigmask(SIG_BLOCK, &sigset, NULL);

  // create handler thread, which will unblock SIGINT/SIGUSR1
  pthread_create(&signal_handler_thread, NULL, sigint_handler_thread, NULL);
}


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"

// thread that handles control-C and SIGUSR1 (checkpoint and exit)
static void *sigint_handler_thread(void *arg) {

  sigset_t sigset;
  int sig;
  char c;
  char sockname[PATH_MAX];

  (void)arg;

  // only this thread sees SIGINT / SIGUSR1
  sigemptyset(&sigset);
  sigaddset(&sigset, SIGINT);
  sigaddset(&sigset, SIGUSR1);

  // construct path to scalpel3 Unix domain socket endpoint
  snprintf(sockname, PATH_MAX, "%s/.scalpel3IPC", scalpel_state.base_output_directory);

  while (1) {
    // block until SIGINT or SIGUSR1 is received
    sigwait(&sigset, &sig);

    // temporarily block SIGINT / SIGUSR1
    pthread_sigmask(SIG_BLOCK, &sigset, NULL);

    if (sig == SIGUSR1) {
      // non-interactive checkpoint and exit ASAP. Remove IPC endpoint file if it exists to stop IPC
      // then set checkpoint flag
      unlink(sockname);
      atomic_store(&TAKE_CHECKPOINT_AND_EXIT, true);
    }
    else {
      MUTEX_ERROR_CHECK(pthread_mutex_lock(&printf_is_available), __LINE__, __FILE__);

      fprintf(stderr, "%s", RED);
      fprintf(stderr, "\n\nREALLY quit? Type Y to quit, N to continue, or C to checkpoint before quitting.\n"
		      "Important: Only C will output end-of-execution stats.  Y will exit immediately without cleanup.\n"
		      "Generally C is the best choice.\n\n"
                      "(Y[es] / N[o] / C[heckpoint]) ? ");
      fprintf(stderr, "%s", BLACK);

      c = getchar();

      if (c == 'y' || c == 'Y') {
        // remove IPC endpoint file if it exists, to stop IPC
        unlink(sockname);
        _exit(-1);
      }
      else if (c == 'c' || c == 'C') {
        // remove IPC endpoint file if it exists to stop IPC
        unlink(sockname);
        atomic_store(&TAKE_CHECKPOINT_AND_EXIT, true);
      }

      MUTEX_ERROR_CHECK(pthread_mutex_unlock(&printf_is_available), __LINE__, __FILE__);
    }
  }
}


#pragma GCC diagnostic pop


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

// callbacks for backtrace
void bt_error_callback(void *data, const char *message, int error_number) {

  fprintf(stderr, "%s", BLACK);

  if (error_number == -1) {
    fprintf(stderr, "Backtraces require compilation with -g.\n");
  }
  else {
    fprintf(stderr, "Backtrace error %d: %s\n", error_number, message);
  }
}


// GGRIII: In some cases, backtrace reports line numbers that are not accurate, e.g., several lines
// off from a crash in a debugger. This needs further investigation. Optimization artifact?

static int bt_full_callback(void *data, uintptr_t pc, const char *pathname, int line_number, const char *function) {

  char *filename;

  // filter backtrace generating and handling functions
  if ((pathname != NULL || function != NULL || line_number != 0) && (! function || strcmp(function, "sigsegv_signal_handler"))
      && (! function || strcmp(function, "crash")) && (! function || strcmp(function, "generate_backtrace"))
      && (! function || strcmp(function, "handle_error"))) {
    filename = rindex(pathname, '/');
    filename = (filename ? filename + 1 : (char *)pathname);
    fprintf(stderr, "%25s\t%40s\t\t%4d\n", filename, function, line_number);
  }
  return 0;
}


#pragma GCC diagnostic pop

// generate backtrace but don't exit
void generate_backtrace(void) {
  // grab lock to attempt to prevent garbled output from active threads
  MUTEX_ERROR_CHECK(pthread_mutex_lock(&printf_is_available), __LINE__, __FILE__);

  fprintf(stderr, "%s", BLUE);

  fprintf(stderr, "\n\n\n");
  fprintf(stderr, "* * * * * * * * * * * * * * * * * * * * * * * * * * *\n");
  fprintf(stderr, "* * * * * * * * * * * * * * * * * * * * * * * * * * *\n");
  fprintf(stderr, "Backtrace:\n\n");
  fprintf(stderr, "%25s\t%40s\t\t%4s\n", "Source file", "Function", "Line");
  fprintf(stderr, "%25s\t%40s\t\t%4s\n", "-----------", "--------", "----");

  backtrace_full(bt_state, 0, bt_full_callback, bt_error_callback, NULL);

  fprintf(stderr, "%s", BLACK);

  // unlock output
  MUTEX_ERROR_CHECK(pthread_mutex_unlock(&printf_is_available), __LINE__, __FILE__);
}


// segmentation fault signal handler
void sigsegv_signal_handler(int sig) {
  // temporarily ignore signal
  signal(sig, SIG_IGN);

  // NOTE: no mutex here — pthread_mutex_lock is not async-signal-safe
  // and will deadlock if the crashing thread already holds the lock.
  // Output may be garbled but at least the backtrace will appear.

  fprintf(stderr, "%s", RED);

  fprintf(stderr, "\n\n\n");
  fprintf(stderr, "* * * * * * * * * * * * * * * * * * * * * * * * * * *\n");
  fprintf(stderr, "* * * * * * * * * * * * * * * * * * * * * * * * * * *\n");
  fprintf(stderr, "\nscalpel3 is crashing and trying hard to create a backtrace, "
                  "but this may fail.\n"
                  "Additionally, the backtrace may be interspersed with other output "
                  "as scalpel3 shuts down.\n"
                  "Please report the backtrace information, which appears in red text,"
                  " to the authors via\n"
                  "email to golden@cct.lsu.edu.\n\n");
  fprintf(stderr, "Backtrace:\n\n");
  fprintf(stderr, "%25s\t%40s\t\t%4s\n", "Source file", "Function", "Line");
  fprintf(stderr, "%25s\t%40s\t\t%4s\n", "-----------", "--------", "----");

  backtrace_full(bt_state, 0, bt_full_callback, bt_error_callback, NULL);

  fprintf(stderr, "%s", BLACK);

  // IMPORTANT: output is NOT unlocked, so crash dump will be more visible! Must exit here.

  // // grab lock to attempt to prevent garbled output from active threads
  // MUTEX_ERROR_CHECK(pthread_mutex_unlock(&printf_is_available), __LINE__, __FILE__);

  // die
  exit(-1);
}


// append 'n' stars at 'p'.
char *append_stars(char *p, size_t n) {

  if (n) {
    memset(p, '*', n);
  }
  return p + n;
}


// frame an important message in a box of stars
void frame_message(const char *msg) {

  if (! msg) {
    msg = "(null)";
  }

  size_t width = get_terminal_width();

  if (width > 132) {
    width = 132;
  }

  size_t visible = strlen_skip_color(msg);  // used for centering only
  size_t msglen = strlen(msg);              // raw bytes to copy
  size_t inner = (width >= 2) ? (width - 2) : 0;

  // compute padding based on *visible* length
  size_t pad = (inner > (visible + 2)) ? (inner - (visible + 2)) : 0;
  size_t left = pad / 2;
  size_t right = pad - left;

  // bound the raw bytes that can fit between the spaces
  size_t max_msg = (inner >= 2) ? (inner - 2) : 0;

  if (msglen > max_msg) {
    msglen = max_msg;                        // may cut ANSI sequences
  }

  enum { MAX_W = 132, BUF_SZ = 4 * MAX_W };  // proven upper bound

  char buf[BUF_SZ];
  char *p = buf;

  *p++ = '\n';
  p = append_stars(p, width);
  *p++ = '\n';

  *p++ = '*';
  p = append_stars(p, left);
  *p++ = ' ';
  memcpy(p, msg, msglen);
  p += msglen;
  *p++ = ' ';
  p = append_stars(p, right);
  *p++ = '*';
  *p++ = '\n';

  p = append_stars(p, width);
  *p++ = '\n';
  *p = '\0';

  lock_fprintf(stdout, "%s%s%s", BLUE, buf, BLACK);
}


/*
// generates a row of asterisks of a specified width into buf starting at the end of buf.
void stars(char *buf, int width) {

  char *p = buf + strlen(buf);
  memset(p, '*', width);
  p[width] = '\0';
}


// frames an important message to stdout in bars of asterisks
void frame_message(char *msg) {

  uint64_t width;
  char buf[MAX_STRING_LENGTH * 10];
  char middle[MAX_STRING_LENGTH * 10];
  uint64_t len = strlen_skip_color(msg);

  width = get_terminal_width();
  width = width > 132 ? 132 : width;
  buf[0] = 0;
  middle[0] = 0;
  strcpy(buf, "\n");
  stars(buf, width);
  strcat(buf, "\n");
  stars(middle, (width - len - 2) / 2);
  strcat(middle, " ");
  strcat(middle, msg);
  strcat(middle, " ");
  stars(middle, (width - len - 2) / 2);
  if (strlen_skip_color(middle) != width) {
    strcat(middle, "*");
  }
  strcat(buf, middle);
  strcat(buf, "\n");
  stars(buf, width);
  strcat(buf, "\n");
  lock_fprintf(stdout, "%s%s%s", BLUE, buf, BLACK);
  }
*/


// validate, copy and finalize initialization of a single search specification (aka file type) and
// track largest file size specified.
void copy_search_spec(SearchSpec *d, SearchSpec *s) {

  int err;                         // tracks regex compilation success
  PCRE2_SIZE erroffset;            // offset of error in regular expression compilation
  char errmsg[MAX_STRING_LENGTH];  // scratch for err msg generation


  memset(d, 0, sizeof(SearchSpec));

  // fields specified in scalpelconf.c
  strcpy(d->FILETYPE, s->FILETYPE);
  d->MASTER = s->MASTER;
  d->CASESENSITIVE = s->CASESENSITIVE;
  d->MAXIMUMSIZE = s->MAXIMUMSIZE;
  d->MINIMUMSIZE = s->MINIMUMSIZE;
  strcpy(d->HEADER, s->HEADER);
  d->HEADERFUNC = s->HEADERFUNC;
  strcpy(d->FOOTER, s->FOOTER);
  d->FOOTERFUNC = s->FOOTERFUNC;
  d->SEARCHTYPE = s->SEARCHTYPE;
  d->BLOCKVALIDATOR = s->BLOCKVALIDATOR;
  d->FILEVALIDATOR = s->FILEVALIDATOR;
  d->DONTCARVE = s->DONTCARVE;
  d->REASSEMBLYFUNC = s->REASSEMBLYFUNC;
  d->SERIALIZECARVESTATEFUNC = s->SERIALIZECARVESTATEFUNC;
  d->CLONECARVESTATEFUNC = s->CLONECARVESTATEFUNC;
  d->FREECARVESTATEFUNC = s->FREECARVESTATEFUNC;
  d->SIZEOFCARVESTATEFUNC = s->SIZEOFCARVESTATEFUNC;
  d->PRINTCARVESTATEFUNC = s->PRINTCARVESTATEFUNC;
  d->SERIALIZEBLOCKSTATEFUNC = s->SERIALIZEBLOCKSTATEFUNC;
  d->CLONEBLOCKSTATEFUNC = s->CLONEBLOCKSTATEFUNC;
  d->FREEBLOCKSTATEFUNC = s->FREEBLOCKSTATEFUNC;
  d->SIZEOFBLOCKSTATEFUNC = s->SIZEOFBLOCKSTATEFUNC;
  d->PRINTBLOCKSTATEFUNC = s->PRINTBLOCKSTATEFUNC;
  d->PRIORITY = s->PRIORITY;
  d->NO_DEFRAG = s->NO_DEFRAG;

  // other fields
  d->offsets.headers = NULL;
  d->offsets.headerlens = NULL;
  d->offsets.deposited = NULL;
  d->offsets.footers = NULL;
  d->offsets.footerlens = NULL;
  d->offsets.numheaders = 0;
  d->offsets.numfooters = 0;
  d->offsets.headerstorage = 0;
  d->offsets.footerstorage = 0;

  if (pthread_mutex_init(&d->offsets.headerlock, NULL)) {
    // fatal
    handle_error(SCALPEL_ERROR_MUTEX_FAILURE, "copy_search_spec()", __LINE__, __FILE__);
  }
  if (pthread_mutex_init(&d->offsets.footerlock, NULL)) {
    // fatal
    handle_error(SCALPEL_ERROR_MUTEX_FAILURE, "copy_search_spec()", __LINE__, __FILE__);
  }

  d->candidates = 0;
  d->per_pass_candidates = 0;
  d->chopped = 0;
  atomic_init(&d->validated_files, 0);
  d->validated_in_subdir = 0;
  d->promising_in_subdir = 0;
  d->inprogress_in_subdir = 0;
  atomic_init(&d->backtracked, 0);
  d->v_organize_dir_num = 0;
  d->p_organize_dir_num = 0;
  d->i_organize_dir_num = 0;
  d->v_current_subdir[0] = 0;
  d->p_current_subdir[0] = 0;
  d->i_current_subdir[0] = 0;

#if VALIDATOR_PERFORMANCE_STATS > 0
  atomic_init(&d->FV_calls, 0);
  atomic_init(&d->FV_longest, 0);
  atomic_init(&d->FV_total, 0);
#endif

#if BLOCK_SELECTION_PERFORMANCE_STATS > 0
  atomic_init(&d->BLK_calls, 0);
  atomic_init(&d->BLK_longest, 0);
  atomic_init(&d->BLK_total, 0);
  atomic_init(&d->BLK_most_blocks, 0);
#endif

  if (pthread_mutex_init(&d->filewritelock, NULL)) {
    // fatal
    handle_error(SCALPEL_ERROR_MUTEX_FAILURE, "copy_search_spec()", __LINE__, __FILE__);
  }

  if (! d->FILETYPE[0] || d->FILETYPE[0] == '-') {
    snprintf(errmsg, MAX_STRING_LENGTH,
             "Invalid FILETYPE \"%s\" in scalpelconf.c. FILETYPE must not be empty or begin with '-'.",
             d->FILETYPE);
    handle_error(SCALPEL_GENERAL_ABORT, errmsg, __LINE__, __FILE__);
  }

  // positive minimum and maximum file sizes are required for all file types except special case
  // SEARCHTYPE == SEARCHTYPE_BLOCK_ONLY
  if ((! d->MINIMUMSIZE || ! d->MAXIMUMSIZE) && d->SEARCHTYPE != SEARCHTYPE_BLOCK_ONLY) {
    // fatal
    handle_error(SCALPEL_ERROR_FILETYPE_SIZE, d->FILETYPE, __LINE__, __FILE__);
  }

  // no longer required, as there's a default behavior now when the BLOCKVALIDATOR is missing.
  /*
  // a block validator is required for every file type
  if (! d->BLOCKVALIDATOR) {
    // fatal
    handle_error(SCALPEL_ERROR_MISSING_BLOCK_VALIDATOR, d->FILETYPE,
                 __LINE__, __FILE__);
                 }
   */

  // MASTER file types must use a header function except for the single block carving case
  if (d->MASTER && (! d->HEADERFUNC || d->HEADER[0]) && d->SEARCHTYPE != SEARCHTYPE_BLOCK_ONLY) {
    // fatal
    handle_error(SCALPEL_ERROR_MASTER_HEADERFUNC, d->FILETYPE, __LINE__, __FILE__);
  }

  // SEARCHTYPE_FORWARD file types must have a header or header function

  if (d->SEARCHTYPE == SEARCHTYPE_FORWARD && ! d->HEADER[0] && ! d->HEADERFUNC) {
    // fatal
    handle_error(SCALPEL_ERROR_FORWARD_HEADER, d->FILETYPE, __LINE__, __FILE__);
  }

  // SEARCHTYPE_BACKWARD file types must have a footer or footer function and they must also have a
  // custom reassembly function

  if (d->SEARCHTYPE == SEARCHTYPE_BACKWARD && ((! d->FOOTER[0] && ! d->FOOTERFUNC) || ! d->REASSEMBLYFUNC)) {
    // fatal
    handle_error(SCALPEL_ERROR_BACKWARD_FOOTER, d->FILETYPE, __LINE__, __FILE__);
  }

  // GGRIII: file subtypes are added dynamically as they are discovered, which means that the
  // maximum file size isn't known until after block type evaluation--if this is used for something
  // interesting before all blocks are evaluated, this will need to be addressed

  // remember largest maximum size
  if (d->MAXIMUMSIZE > scalpel_state.largest_maxfilesize) {
    scalpel_state.largest_maxfilesize = d->MAXIMUMSIZE;
  }

  if ((d->HEADER[0] && d->HEADERFUNC) || (d->FOOTER[0] && d->FOOTERFUNC)) {
    // fatal: cannot specify both HEADER and HEADERFUNC or FOOTER and FOOTERFUNC
    snprintf(errmsg, MAX_STRING_LENGTH,
             "Specify only one of HEADER/HEADERFUNC or FOOTER/FOOTERFUNC\n"
             "for file type \"%s\" in scalpelconf.c.",
             d->FILETYPE);
    handle_error(SCALPEL_ERROR_BAD_HEADER_OR_FOOTER, errmsg, __LINE__, __FILE__);
  }

  // header processing

  if (d->HEADER[0]) {
    if (is_regular_expression(d->HEADER)) {
      if (scalpel_state.mode_verbose) {
        lock_fprintf(stdout, "Compiling regular expression for header of type \"%s\".\n", d->FILETYPE);
      }
      // copy RE, zap leading/training '/' and prepare for for regular expression compilation
      d->begin_is_RE = true;
      d->beginlength = translate(d->HEADER, d->FILETYPE, true);
      memcpy(d->begin, d->HEADER + 1, d->beginlength);

      // compile regular expression
      d->beginstate.re = pcre2_compile((PCRE2_SPTR8)d->begin, d->beginlength, PCRE2_CASELESS * (! d->CASESENSITIVE), &err,
                                       &erroffset, NULL);

      if (! d->beginstate.re) {
        snprintf(errmsg, MAX_STRING_LENGTH, "Header of file type \"%s\" in \"scalpelconf.c\".\n", d->FILETYPE);
        // fatal
        handle_error(SCALPEL_ERROR_BAD_REGEX, errmsg, __LINE__, __FILE__);
      }
    }
    else {
      // non-regular expression header
      d->begin_is_RE = false;

      if (d->HEADER[0] != '|') {
        // fatal: missing delimiter for header
        snprintf(errmsg, MAX_STRING_LENGTH, "missing delimeter for HEADER for file type \"%s\"", d->FILETYPE);
        handle_error(SCALPEL_ERROR_BAD_HEADER_OR_FOOTER, errmsg, __LINE__, __FILE__);
      }

      // d->HEADER is a string literal and embedded control chars have already been translated--need
      // length of string within bracketing '|' chars
      d->beginlength = translate(d->HEADER, d->FILETYPE, false);
      memcpy(d->begin, d->HEADER + 1, d->beginlength);
      init_bm_table(d->begin, d->beginstate.bm_table, d->beginlength, d->CASESENSITIVE);
    }
  }

  // footer processing
  if (d->FOOTER[0]) {
    if (is_regular_expression(d->FOOTER)) {
      if (scalpel_state.mode_verbose) {
        lock_fprintf(stdout, "Compiling regular expression for footer of type %s with length %1lu.\n", d->FILETYPE,
                     strlen(d->FOOTER));
      }
      // copy RE, zap leading/training '/' and prepare for for regular expression compilation
      d->end_is_RE = true;
      d->endlength = translate(d->FOOTER, d->FILETYPE, true);
      memcpy(d->end, d->FOOTER + 1, d->endlength);

      // compile regular expression
      d->endstate.re = pcre2_compile((PCRE2_SPTR8)d->end, d->endlength, PCRE2_CASELESS * (! d->CASESENSITIVE), &err, &erroffset,
                                     NULL);

      if (! d->endstate.re) {
        snprintf(errmsg, MAX_STRING_LENGTH, "Footer of file type \"%s\" in \"scalpelconf.c\".\n", d->FOOTER);
        // fatal
        handle_error(SCALPEL_ERROR_BAD_REGEX, errmsg, __LINE__, __FILE__);
      }
    }
    else {
      d->end_is_RE = false;
      // d->FOOTER is a string literal and embedded control chars have already been translated--need
      // length of string within bracketing '|' chars

      if (d->FOOTER[0] != '|') {
        // fatal: missing delimiter for header
        snprintf(errmsg, MAX_STRING_LENGTH, "Missing delimeter for FOOTER for file type \"%s\"", d->FILETYPE);
        handle_error(SCALPEL_ERROR_BAD_HEADER_OR_FOOTER, errmsg, __LINE__, __FILE__);
      }

      d->endlength = translate(d->FOOTER, d->FILETYPE, false);
      memcpy(d->end, d->FOOTER + 1, d->endlength);
      init_bm_table(d->end, d->endstate.bm_table, d->endlength, d->CASESENSITIVE);
    }

    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout, "For file type \"%s\", beginlength = %d, endlength = %d.\n", d->FILETYPE, d->beginlength, d->endlength);
    }
  }

  // initialize hash tables for global carving candidate / block info if the API will be used by
  // this file type

  int score = (d->SERIALIZECARVESTATEFUNC != 0) + (d->CLONECARVESTATEFUNC != 0) + (d->FREECARVESTATEFUNC != 0);

  if (score != 0 && score != 3) {
    handle_error(SCALPEL_ERROR_MISSING_CARVE_STATE_FUNCTION, d->FILETYPE, __LINE__, __FILE__);
  }

  score = (d->SERIALIZEBLOCKSTATEFUNC != 0) + (d->CLONEBLOCKSTATEFUNC != 0) + (d->FREEBLOCKSTATEFUNC != 0);

  if (score != 0 && score != 3) {
    handle_error(SCALPEL_ERROR_MISSING_BLOCK_STATE_FUNCTION, d->FILETYPE, __LINE__, __FILE__);
  }

  if (d->SERIALIZECARVESTATEFUNC) {
    oa_key_ops *key_ops = malloc(sizeof(oa_key_ops));
    check_memory_allocation(key_ops, __LINE__, __FILE__, "oa_key_ops");
    oa_val_ops *val_ops = malloc(sizeof(oa_val_ops));
    check_memory_allocation(val_ops, __LINE__, __FILE__, "oa_val_ops");
    *key_ops = (oa_key_ops){.hash = oa_carve_key_hash,
                            .cp = oa_carve_key_cp,
                            .free = oa_binary_key_free,
                            .eq = oa_carve_key_eq,
                            .serialize = oa_carve_key_ser,
                            .size_of = oa_carve_key_sizeof};
    *val_ops = (oa_val_ops){.cp = d->CLONECARVESTATEFUNC,
                            .free = d->FREECARVESTATEFUNC,
                            .serialize = d->SERIALIZECARVESTATEFUNC,
                            .size_of = d->SIZEOFCARVESTATEFUNC};
    d->carve_state = oa_hash_new(*key_ops, *val_ops);
  }
  else {
    d->carve_state = NULL;
  }

  if (d->SERIALIZEBLOCKSTATEFUNC) {
    oa_key_ops *key_ops = malloc(sizeof(oa_key_ops));
    check_memory_allocation(key_ops, __LINE__, __FILE__, "oa_key_ops");
    oa_val_ops *val_ops = malloc(sizeof(oa_val_ops));
    check_memory_allocation(val_ops, __LINE__, __FILE__, "oa_val_ops");
    *key_ops = (oa_key_ops){.hash = oa_block_key_hash,
                            .cp = oa_block_key_cp,
                            .free = oa_binary_key_free,
                            .eq = oa_block_key_eq,
                            .serialize = oa_block_key_ser,
                            .size_of = oa_block_key_sizeof};
    *val_ops = (oa_val_ops){.cp = d->CLONEBLOCKSTATEFUNC,
                            .free = d->FREEBLOCKSTATEFUNC,
                            .serialize = d->SERIALIZEBLOCKSTATEFUNC,
                            .size_of = d->SIZEOFBLOCKSTATEFUNC};
    d->block_state = oa_hash_new(*key_ops, *val_ops);
  }
  else {
    d->block_state = NULL;
  }
}


// scan a binary string and adjust len so that non-printable characters are omitted
void ignore_nonprintable(char *s, uint64_t *len) {

  char *p = s;

  while (p < s + *len) {
    if (! isprint(*p) && ! isspace(*p)) {
      *len = (uint64_t)p - (uint64_t)s;
      break;
    }
    p++;
  }
}


// check for pthreads mutex lock/unlock error. Errors are fatal.
void MUTEX_ERROR_CHECK(int ret, int line, const char *file) {

  if (! ret) {
    return;
  }
  else {
    switch (ret) {
    case EINVAL:
      scalpel_log("EINVAL: Calling thread's priority is higher than mutex's\n"
                  "priority ceiling or mutex not initialized.\n");
      break;

    case EBUSY:
      scalpel_log("EBUSY: The mutex was already locked.\n");
      break;

    case EAGAIN:
      scalpel_log("EAGAIN: Maximum number of recursive locks exceeded.\n");
      break;

    case EDEADLK:
      scalpel_log("EDEADLK: The current thread already owns this mutex.\n");
      break;

    case EPERM:
      scalpel_log("EPERM: The current thread does not own this mutex.\n");
      break;
    default:
      scalpel_log("??? Unknown mutex error.\n");
      break;
    }
    handle_error(SCALPEL_ERROR_MUTEX_FAILURE, NULL, line, file);
  }
}


// write hex notation for chars in 's' to 'buf'
char *sprinthex(char *buf, char *s, int len, bool backslashes) {

  char temp[5];
  int i;

  buf[0] = 0;
  for (i = 0; i < len; i++) {
    if (backslashes) {
      snprintf(temp, 5, "\\x%.2x", (unsigned char)s[i]);
    }
    else {
      snprintf(temp, 5, "%.2x", (unsigned char)s[i]);
    }
    strcat(buf, temp);
  }

  return buf;
}


// determine if a string begins and ends with '/' characters
bool is_regular_expression(char *s) { return (s && s[0] && s[0] == '/' && s[strlen(s) - 1] == '/'); }


#ifndef __GLIBC__
void set_program_name(char *s) {

  char *fn = (char *)malloc(sizeof(char) * PATH_MAX);
  check_memory_allocation(fn, __LINE__, __FILE__, "fn");
  if (realpath(s, fn) == NULL) {
    __progname = strdup("scalpel3");
    return;
  }

  __progname = base_name(fn);
}


#endif /* ifndef __GLIBC__ */


void scalpel_log_err(const char *format, ...) {

  va_list argp;

  va_start(argp, format);
  lock_fprintf(stderr, "%s", RED);
  lock_fprintf_argp(stderr, format, argp);
  lock_fprintf(stderr, "%s", BLACK);
  va_end(argp);

  if (scalpel_state.audit_file) {
    va_start(argp, format);
    vfprintf(scalpel_state.audit_file, format, argp);
    fflush(scalpel_state.audit_file);
    va_end(argp);
  }
}


void scalpel_log(const char *format, ...) {

  va_list argp;

  va_start(argp, format);
  lock_fprintf_argp(stdout, format, argp);
  va_end(argp);

  if (scalpel_state.audit_file) {
    va_start(argp, format);
    vfprintf(scalpel_state.audit_file, format, argp);
    fflush(scalpel_state.audit_file);
    va_end(argp);
  }
}


// determine if two characters match, with optional case insensitivity. If a is the Scalpel wildcard
// character, then a and b will always match.
static bool characters_match(char a, char b, bool caseSensitive) {

  if (a == SCALPEL_WILDCARD_CHAR || a == b) {
    return 1;
  }
  if (caseSensitive) {
    return 0;
  }

  return (a >= 'A' && a <= 'Z' && a + 32 == b)
      || (a >= 'a' && a <= 'z' && a - 32 == b);
}


// memwildcardcmp is a memcmp() clone, except that single character wildcards are supported. A
// wildcard in s1 will match any single character in s2.
int memwildcardcmp(const void *s1, const void *s2, size_t n, bool case_sensitive) {

  if (n != 0) {
    register const unsigned char *p1 = (const unsigned char *)s1, *p2 = (const unsigned char *)s2;

    do {
      if (! characters_match(*p1++, *p2++, case_sensitive)) {
        return (*--p1 - *--p2);
      }
    } while (--n != 0);
  }
  return 0;
}


// bitap/shift-and (wildcards, <=64B)
static char *s3_bitap_wildcard_u64(char *needle, size_t m, char *hay, size_t n, bool casesensitive, size_t start_pos) {

  if (m == 0) {
    return hay;
  }

  if (n < m || m > 64) {
    return NULL;
  }

  uint64_t M[256];
  for (int c = 0; c < 256; ++c) {
    M[c] = 0;
  }

  for (size_t i = 0; i < m; ++i) {
    unsigned char nc = (unsigned char)needle[i];

    if (nc == (unsigned char)SCALPEL_WILDCARD_CHAR) {
      for (int c = 0; c < 256; ++c) {
        M[c] |= (UINT64_C(1) << i);
      }
    }
    else {
      M[s3_fold_byte(nc, casesensitive)] |= (UINT64_C(1) << i);
    }
  }

  uint64_t D = 0;
  const uint64_t match_bit = (UINT64_C(1) << (m - 1));
  const unsigned char *H = (const unsigned char *)hay;

  size_t accept_from = start_pos;

  if (accept_from < m - 1) {
    accept_from = m - 1;
  }

  for (size_t j = 0; j < n; ++j) {
    unsigned char hj = s3_fold_byte(H[j], casesensitive);

    D = ((D << 1) | UINT64_C(1)) & M[hj];
    if (j >= accept_from && (D & match_bit)) {
      size_t start = j + 1 - m;
      return (char *)(H + start);
    }
  }
  return NULL;
}


// top-level search function, that branches into different implementations for different situations
char *find_binary_string(char *needle, size_t needle_len, char *haystack, size_t haystack_len, size_t table[UCHAR_MAX + 1],
                         bool casesensitive) {
  size_t start_pos = needle_len - 1;

  if (needle_len == 0) {
    return haystack;
  }

  if (haystack_len < needle_len) {
    return NULL;
  }

  const bool has_wildcard = (memchr(needle, (unsigned char)SCALPEL_WILDCARD_CHAR, needle_len) != NULL);

  if (! has_wildcard && casesensitive) {
    return s3_exact_simd_or_scalar(needle, needle_len, haystack, haystack_len, start_pos);
  }
  if ((has_wildcard || ! casesensitive) && needle_len <= 64) {
    return s3_bitap_wildcard_u64(needle, needle_len, haystack, haystack_len, casesensitive, start_pos);
  }

  return bm_baseline(needle, needle_len, haystack, haystack_len, table, casesensitive);
}


// initialize Boyer-Moore "jump table" for search. This is from Foremost 0.69, written by Jesse
// Kornblum.
void init_bm_table(char *needle, size_t table[UCHAR_MAX + 1], size_t len, bool casesensitive) {

  size_t i = 0, j = 0, currentindex = 0;

  for (i = 0; i <= UCHAR_MAX; i++) {
    table[i] = len;
  }

  for (i = 0; i < len; i++) {
    currentindex = len - i - 1;
    if (needle[i] == SCALPEL_WILDCARD_CHAR) {
      for (j = 0; j <= UCHAR_MAX; j++) {
        table[j] = currentindex;
      }
    }
    table[(unsigned char)needle[i]] = currentindex;
    if (! casesensitive && needle[i] > 0) {
      table[tolower(needle[i])] = currentindex;
      table[toupper(needle[i])] = currentindex;
    }
  }
}


// this Boyer/Moore binary string search code from Foremost 0.69, written by Jesse Kornblum
static char *bm_baseline(char *needle, size_t needle_len, char *haystack, size_t haystack_len, size_t table[UCHAR_MAX + 1],
                         bool casesensitive) {
  register size_t shift = 0;
  register size_t pos = needle_len - 1;
  char *here;

  if (needle_len == 0) {
    return haystack;
  }

  while (pos < haystack_len) {
    while (pos < haystack_len && (shift = table[(unsigned char)haystack[pos]]) > 0) {
      pos += shift;
    }
    if (0 == shift) {
      if (0 == memwildcardcmp(needle, here = (char *)&haystack[pos - needle_len + 1], needle_len, casesensitive)) {
        return here;
      }
      else {
        pos++;
      }
    }
  }
  return NULL;
}


static unsigned char s3_fold_byte(unsigned char c, bool cs) { return cs ? c : (unsigned char)tolower((int)c); }

// find longest footer. Footers which are regular expressions are assigned LARGEST_REGEXP_OVERLAP
// lengths.
uint32_t find_longest_footer(void) {

  uint32_t longest = 0;
  uint32_t i = 0;
  uint32_t lene;
  for (i = 0; scalpel_state.search_specs[i].FILETYPE[0]; i++) {
    if (scalpel_state.search_specs[i].FOOTER[0]) {
      lene = scalpel_state.search_specs[i].end_is_RE ? LARGEST_REGEXP_OVERLAP : scalpel_state.search_specs[i].endlength;
      if (lene > longest) {
        longest = lene;
      }
    }
  }
  return longest;
}


// do a regular expression search using based on a previously compiled regular expression 'needle'.
// The caller must free memory associated with the returned regmatch_t structure.
pcre2_match_data *find_regular_expression(pcre2_code *needle, char *haystack, size_t haystack_len) {

  pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(needle, NULL);

  if (pcre2_match(needle, (PCRE2_SPTR8)haystack, haystack_len, 0, 0, match_data, NULL) > 0) {
    return match_data;
  }
  else {
    // no match
    pcre2_match_data_free(match_data);
    return NULL;
  }
}


uint64_t translate(char *str, char *filetype, bool re) {

  uint64_t len = 0;
  char errmsg[MAX_STRING_LENGTH];  // scratch for err msg generation

  str++;
  while (*str != (re ? '/' : '|')) {
    str++;
    len++;
    if (len > scalpel_state.blocksize) {
      // fatal: headers and footers cannot exceed block size
      snprintf(errmsg, MAX_STRING_LENGTH, "string exceeds block size for file type \"%s\"", filetype);

      handle_error(SCALPEL_ERROR_BAD_HEADER_OR_FOOTER, errmsg, __LINE__, __FILE__);
    }
  }
  return len;
}


// try to set up the output directory. Because of the new checkpointing facility, scalpel3 no longer
// requires that the output directory be empty, but timestamped directories corresponding to
// individual invocations are created inside the main output directory.
void init_output_directory(void) {

  char temp[PATH_MAX];
  time_t t;
  struct tm *lt;
  char current[PATH_MAX];

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"

  // create directory--this will fail silently if it already exists, which is fine.
  mkdir(scalpel_state.output_directory, 0755);

  // create timestamped directory inside main directory
  time(&t);
  lt = localtime(&t);
  if (! strftime(current, sizeof(current), "%H-%M-%S-%Z-%m-%d-%y", lt)) {
    handle_error(SCALPEL_ERROR_BAD_OUTPUT_DIRECTORY, NULL, __LINE__, __FILE__);
  }
  snprintf(temp, PATH_MAX, "%s/%s", scalpel_state.output_directory, current);
  if (mkdir(temp, 0755)) {
    handle_error(SCALPEL_ERROR_BAD_OUTPUT_DIRECTORY, NULL, __LINE__, __FILE__);
  }

  // now create PROMISING, INPROGRESS, AND VALIDATED subdirs
  snprintf(temp, PATH_MAX, "%s/%s/PROMISING", scalpel_state.output_directory, current);
  if (mkdir(temp, 0755)) {
    handle_error(SCALPEL_ERROR_BAD_OUTPUT_DIRECTORY, NULL, __LINE__, __FILE__);
  }
  snprintf(temp, PATH_MAX, "%s/%s/INPROGRESS", scalpel_state.output_directory, current);
  if (mkdir(temp, 0755)) {
    handle_error(SCALPEL_ERROR_BAD_OUTPUT_DIRECTORY, NULL, __LINE__, __FILE__);
  }
  snprintf(temp, PATH_MAX, "%s/%s/VALIDATED", scalpel_state.output_directory, current);
  if (mkdir(temp, 0755)) {
    handle_error(SCALPEL_ERROR_BAD_OUTPUT_DIRECTORY, NULL, __LINE__, __FILE__);
  }

  // update output directory to include timestamped subdir, but save a copy of the base dir for
  // storage of non-timestamped state
  strcpy(scalpel_state.base_output_directory, scalpel_state.output_directory);
  snprintf(temp, PATH_MAX, "%s/%s/", scalpel_state.output_directory, current);
  strcpy(scalpel_state.output_directory, temp);

#pragma GCC diagnostic pop
}


// write out invocation information to scalpel-output directory
void open_audit_file(void) {

  time_t now = time(NULL);
  char *timestring = ctime(&now);
  char fn[PATH_MAX];

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"

  if (strlen(timestring) > 0) {
    timestring[strlen(timestring) - 1] = 0;  // zap newline
  }

  snprintf(fn, PATH_MAX, "%s/audit.txt", scalpel_state.output_directory);

  if (! (scalpel_state.audit_file = fopen(fn, "a"))) {
    // fatal
    handle_error(SCALPEL_ERROR_FILE_WRITE, "audit.txt", __LINE__, __FILE__);
  }

  lock_fprintf(scalpel_state.audit_file,
               "Scalpel version %s %sstarted on %s with the\n"
               "following command line:\n",
               SCALPEL_VERSION, scalpel_state.restore_from_checkpoint ? "re-" : "", timestring);
  lock_fprintf(scalpel_state.audit_file, "%s\n", scalpel_state.invocation);

#pragma GCC diagnostic pop
}


// convert string to all lowercase. Returns string.
char *string_tolower(char *s) {

  char *r = s;
  for (; *s; ++s) {
    *s = tolower(*s);
  }
  return r;
}


// convert string to all uppercase. Returns string.
char *string_toupper(char *s) {

  char *r = s;
  for (; *s; ++s) {
    *s = toupper(*s);
  }
  return r;
}


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

// output current memory footprint
//
// GGRIII: TODO: generalize this to allow query via IPC
void memory_footprint(const char *s) {
#if defined(__APPLE__)
  struct task_basic_info t_info;
  mach_msg_type_number_t t_info_count = TASK_BASIC_INFO_COUNT;

  if (KERN_SUCCESS != task_info(mach_task_self(), TASK_BASIC_INFO, (task_info_t)&t_info, &t_info_count)) {
    lock_fprintf(stderr, "Failed to get memory footprint information.\n");
  }
  else {
    lock_fprintf(stdout, "Scalpel memory footprint (%s): %lu [resident] / %lu [virtual]\n", s, t_info.resident_size,
                 t_info.virtual_size);
  }
#elif defined(__linux__)
  FILE *fp = fopen("/proc/self/status", "r");
  char line[256];
  unsigned long vmsize = 0;
  unsigned long vmrss = 0;
  unsigned long rssanon = 0;
  unsigned long rssfile = 0;
  unsigned long rssshmem = 0;

  if (! fp) {
    lock_fprintf(stderr, "Failed to get memory footprint information from /proc/self/status.\n");
    return;
  }

  while (fgets(line, sizeof(line), fp)) {
    unsigned long value = 0;
    if (sscanf(line, "VmSize: %lu kB", &value) == 1) {
      vmsize = value;
    }
    else if (sscanf(line, "VmRSS: %lu kB", &value) == 1) {
      vmrss = value;
    }
    else if (sscanf(line, "RssAnon: %lu kB", &value) == 1) {
      rssanon = value;
    }
    else if (sscanf(line, "RssFile: %lu kB", &value) == 1) {
      rssfile = value;
    }
    else if (sscanf(line, "RssShmem: %lu kB", &value) == 1) {
      rssshmem = value;
    }
  }

  fclose(fp);

  lock_fprintf(stdout,
               "Scalpel memory footprint (%s): VmRSS=%lu kB, RssAnon=%lu kB, "
               "RssFile=%lu kB, RssShmem=%lu kB, VmSize=%lu kB\n",
               s, vmrss, rssanon, rssfile, rssshmem, vmsize);
#endif
}


#pragma GCC diagnostic pop

// display ASCII graphics scalpel3 logo
void scalpel_logo(void) {

  char *logo[] = {
      "\n",
      "\n",
      " ......................................................................................\n",
      ".                                                                                      .\n",
      ".   .rGGGGr.   .\\\\\\\\\\\\\\        \\\\\\\\\\ \\\\\\      \\\\\\\\\\\\\\\\\\  \\\\\\\\\\\\\\\\\\\\ \\\\\\      _______   .\n",
      ".  rGGG  GGGr rGGG  \\\\\\\\      \\\\\\\\\\\\ \\\\\\      \\\\\\   \\\\\\\\ \\\\\\        \\\\\\      `   ///   .\n",
      ".  GGGr.      GGG    GGG     rG\\\\\\\\\\ \\\\\\      \\\\\\    \\\\\\ \\\\\\        \\\\\\         ///    .\n",
      ".   \"GGGGr.   GGG           rGGG GGG GG\\      \\\\\\   \\\\\\\\ \\\\\\\\\\\\\\    \\\\\\        ///     .\n",
      ".      \"GGGr. GGG          rGGG  GGG GGG      G\\\\\\\\\\\\\\\\  \\\\\\        \\\\\\       \\\\\\      .\n",
      ".        \"GGG GGG    GGG  rGGG   GGG GGG      GGG        G\\\\        \\\\\\        )))     .\n",
      ".  GGGr  rGGG GGGr  rGGG rGGGGGGGGGG GGG      GGG        GGG        \\\\\\        ///     .\n",
      ".   \"GGGGGG\"   \"GGGGGG\" rGGG     GGG GGGGGGGG GGG        GGGGGGGGGG GGGGGGGG  ///      .\n",
      ".                                                                            //'       .\n",
      " .........................................................................  // ........\n",
      "                                                                           /'           \n",
      ""};

  int i = 0;
  size_t j;
  size_t len;

  // only display logo if the terminal is wide enough
  if (get_terminal_width() < 88) {
    return;
  }

  while (logo[i][0]) {
    len = strlen(logo[i]);
    for (j = 0; j < len; j++) {
      if (isspace(logo[i][j]) || i < 3 || (i == 13 && j != 77 && j != 76) || j == 0 || j > 86) {
        fprintf(stdout, "%s", BLACK);
      }
      else if (i > 9 || j > 72) {
        fprintf(stdout, "%s%s", BOLD, LOGOR);
      }
      else if (logo[i][j] == '\\' || logo[i][j] == '\'' || logo[i][j] == '`' || logo[i][j] == '/' || logo[i][j] == ')'
               || logo[i][j] == '_' || logo[i][j] == '-') {
        fprintf(stdout, "%s%s", BOLD, LOGOP);
      }
      else {
        fprintf(stdout, "%s%s", BOLD, LOGOR);
      }
      fputc(logo[i][j], stdout);
      fprintf(stdout, "%s", BLACK);
    }
    i++;
  }

  fputc('\n', stdout);
}


// returns the number of *logical* CPU cores
int num_logical_cores(void) {
 return sysconf(_SC_NPROCESSORS_ONLN);
}

// returns the number of *physical* CPU cores on Linux or Mac systems
int num_physical_cores(void) {

  return NC > 0 ? NC :

#if defined(__APPLE__)
                get_physical_cores_macos();
#else
                get_physical_cores_linux();
#endif
}


#if defined(__linux__)
static int is_number(const char *s) {

  if (! s || ! *s) {
    return 0;
  }
  for (const char *p = s; *p; ++p) {
    if (! isdigit((unsigned char)*p)) {
      return 0;
    }
  }
  return 1;
}


static int read_int_file(const char *path, int *out) {

  FILE *f = fopen(path, "r");
  char buf[64] = {0};

  if (! f) {
    return -1;
  }

  if (! fgets(buf, sizeof(buf), f)) {
    fclose(f);
    return -1;
  }

  fclose(f);

  // trim trailing whitespace
  char *end = buf + strlen(buf);
  while (end > buf && isspace((unsigned char)end[-1])) {
    *--end = '\0';
  }

  // accept optional leading '-'
  if (! is_number(buf) && ! (buf[0] == '-' && is_number(buf + 1))) {
    return -1;
  }
  *out = (int)strtol(buf, NULL, 10);
  return 0;
}


#endif

#if defined(__APPLE__)

static int sysctl_int_by_name(const char *name, int *out) {

  size_t sz = sizeof(int);

  if (sysctlbyname(name, out, &sz, NULL, 0) == 0 && sz == sizeof(int)) {
    return 0;
  }
  return -1;
}


static int sysctl_str_by_name(const char *name, char *out, size_t out_sz) {

  size_t sz = out_sz;

  if (sysctlbyname(name, out, &sz, NULL, 0) == 0 && sz > 0 && sz <= out_sz) {
    out[sz - 1] = '\0';
    return 0;
  }
  return -1;
}


// Walk hw.perflevelN.* and sum physicalcpu across every tier whose name is not "Efficiency".  This
// handles the M5 Max case (Super + Performance, no E-cores -> use all) and the M1-M4 case
// (Performance + Efficiency -> drop E-cores) without naming any chip.  Falls back to
// hw.physicalcpu on Intel Macs or if perflevels are unavailable.
static int get_physical_cores_macos(void) {

  int n_levels = -1;
  int total = -1;

  if (sysctl_int_by_name("hw.nperflevels", &n_levels) == 0 && n_levels > 0) {
    int sum = 0;
    for (int i = 0; i < n_levels; ++i) {
      char key[64];
      char name[64];
      int  cores = -1;

      snprintf(key, sizeof(key), "hw.perflevel%d.name", i);
      if (sysctl_str_by_name(key, name, sizeof(name)) != 0) {
        sum = 0;
        break;
      }
      // case-insensitive match for "fficien" covers "Efficiency"/"Efficient"
      if (strcasestr(name, "fficien") != NULL) {
        continue;
      }
      snprintf(key, sizeof(key), "hw.perflevel%d.physicalcpu", i);
      if (sysctl_int_by_name(key, &cores) != 0 || cores <= 0) {
        sum = 0;
        break;
      }
      sum += cores;
    }
    if (sum > 0) {
      return sum;
    }
  }

  if (sysctl_int_by_name("hw.physicalcpu", &total) == 0 && total > 0) {
    return total;
  }

  if (sysctl_int_by_name("hw.physicalcpu_max", &total) == 0 && total > 0) {
    return total;
  }

  return -1;
}


#elif defined(__linux__)

static int pair_exists(pkg_core_t *arr, size_t n, int pkg, int core) {

  for (size_t i = 0; i < n; ++i) {
    if (arr[i].pkg == pkg && arr[i].core == core) {
      return 1;
    }
  }
  return 0;
}


static int get_physical_cores_linux(void) {
  // unumerate /sys/devices/system/cpu/cpu*/topology/{physical_package_id,core_id} count unique
  // (package, core) pairs for *online* CPUs.
  const char *cpu_root = "/sys/devices/system/cpu";
  DIR *dir = opendir(cpu_root);
  if (! dir) {
    return -1;
  }

  pkg_core_t *seen = NULL;
  size_t seen_cap = 0, seen_len = 0;

  struct dirent *de;

  while ((de = readdir(dir))) {
    if (strncmp(de->d_name, "cpu", 3) != 0) {
      continue;
    }
    const char *idx = de->d_name + 3;

    if (! is_number(idx)) {
      continue;  // skip "cpufreq", etc.
    }

    char path_pkg[512], path_core[512], path_online[512];

    snprintf(path_pkg, sizeof(path_pkg), "%s/%s/topology/physical_package_id", cpu_root, de->d_name);
    snprintf(path_core, sizeof(path_core), "%s/%s/topology/core_id", cpu_root, de->d_name);
    snprintf(path_online, sizeof(path_online), "%s/%s/online", cpu_root, de->d_name);

    // If an "online" file exists and says 0, skip this logical CPU
    int online_val = 1;
    FILE *fon = fopen(path_online, "r");
    if (fon) {
      char buf[16] = {0};

      if (fgets(buf, sizeof(buf), fon)) {
        online_val = atoi(buf);
      }
      fclose(fon);
    }
    if (! online_val) {
      continue;
    }

    int pkg = -1, core = -1;

    if (read_int_file(path_pkg, &pkg) != 0 || read_int_file(path_core, &core) != 0) {
      continue;  // topology not available in some environments
    }

    if (! pair_exists(seen, seen_len, pkg, core)) {
      if (seen_len == seen_cap) {
        size_t new_cap = seen_cap ? seen_cap * 2 : 64;
        pkg_core_t *tmp = (pkg_core_t *)realloc(seen, new_cap * sizeof(pkg_core_t));
        if (! tmp) {
          free(seen);
          closedir(dir);
          return -1;
        }
        seen = tmp;
        seen_cap = new_cap;
      }
      seen[seen_len].pkg = pkg;
      seen[seen_len].core = core;
      seen_len++;
    }
  }
  closedir(dir);

  long result = (seen_len > 0) ? (long)seen_len : -1;

  free(seen);
  return result;
}


#endif


// atomic set max function for atomic_ullong. Set a to b if b > a.
bool atomic_max_u64_pub(atomic_ullong *a, uint64_t b) {

  uint64_t cur = atomic_load_explicit(a, memory_order_relaxed);

  while (cur < b
         && ! atomic_compare_exchange_weak_explicit(a, &cur, b,
                                                    memory_order_release,  // publish prior writes if updating
                                                    memory_order_relaxed))
    ;
  return (cur < b);
}


// describe Scalpel error conditions. ALL ERRORS HANDLED BY THIS FUNCTION ARE FATAL. The function
// does not return.
void handle_error(ScalpelError error, char *str, int line, const char *file) {

  char location[MAX_STRING_LENGTH];
  bool backtrace = false;

  snprintf(location, MAX_STRING_LENGTH, "At line %1d in source file %s:\n", line, file);
  scalpel_log_err(location, NULL);

  switch (error) {
  case SCALPEL_ERROR_BLOCKMAP_FORMAT:
    // fatal
    scalpel_log_err("Couldn't parse blockmap file. It should be recreated using"
                    " crblockmap. Aborting.\n");
    goto fatal;

    break;

  case SCALPEL_ERROR_NO_BLOCKMAP:
    // fatal
    scalpel_log_err("No blockmap file found. Use crblockmap to create a blockmap and"
                    " then run scalpel3\n"
                    "again. Aborting.\n",
                    NULL);
    goto fatal;

    break;

  case SCALPEL_ERROR_IPC:
    // fatal
    scalpel_log_err("IPC error. Aborting.\n", NULL);
    goto fatal;

    break;

  case SCALPEL_ERROR_CHECKPOINT:
    // fatal
    scalpel_log_err("Checkpoint integrity failure.  Aborting.\n", NULL);
    goto fatal;

    break;

  case SCALPEL_ERROR_CHECKPOINT_MISMATCH:
    // fatal
    scalpel_log_err("The checkpoint data doesn't match the current version of scalpel3 and cannot be used.\n"
                    "This generally happens when scalpel3 was recompiled after a checkpoint was saved or the \n"
                    "checkpoint data is corrupted.\n",
                    NULL);
    goto fatal;

    break;

  case SCALPEL_ERROR_CHECKPOINT_IMAGE:
    // fatal
    scalpel_log_err("Checkpointing error: %s.  Aborting.\n", str);
    goto fatal;

    break;

  case SCALPEL_ERROR_BAD_REGEX:
    // fatal
    scalpel_log_err("Bad regular expression: %s. Aborting.\n", str);
    goto fatal;

    break;

  case SCALPEL_ERROR_BAD_HEADER_OR_FOOTER:
    // fatal
    scalpel_log_err("Bad header or footer: %s. Aborting.\n", str);
    goto fatal;

    break;

  case SCALPEL_ERROR_MMAP_FAILURE:
    // fatal
    scalpel_log_err("mmap() failed for memory mapping of image file. Aborting.\n");
    goto fatal;

    break;

  case SCALPEL_ERROR_UNINITIALIZED_BLOCKVECTOR:
    // fatal
    scalpel_log_err("Uninitialized block vector in function %s. Aborting.\n", str);
    backtrace = true;
    goto fatal;

    break;

  case SCALPEL_ERROR_MEMORY_LEAK:
    // fatal
    scalpel_log_err("Memory leak in function %s. Aborting.\n", str);
    backtrace = true;
    goto fatal;

    break;

  case SCALPEL_ERROR_PTHREAD_FAILURE:
    // fatal
    scalpel_log_err("Scalpel was unable to create threads in function %s. Aborting.\n", str);
    goto fatal;

    break;

  case SCALPEL_ERROR_THREADING_MODEL_BROKEN:
    // fatal
    scalpel_log_err("Threading model consistency check failure. Aborting.\n", NULL);
    backtrace = true;
    goto fatal;

    break;

  case SCALPEL_ERROR_BLOCKSIZE:
    // fatal
    scalpel_log_err("The blocksize in the blockmap file does not match the blocksize\n"
                    "in use by Scalpel. Aborting.\n");
    goto fatal;

    break;

  case SCALPEL_ERROR_BAD_BLOCKSIZE:
    // fatal
    scalpel_log_err("The specified blocksize must be divisible by 512. Aborting.\n");
    goto fatal;

    break;

  case SCALPEL_ERROR_FILETYPE_SIZE:
    // fatal
    scalpel_log_err("Size constraints for the following file type are invalid: \"%s\". Aborting.\n", str);
    goto fatal;

    break;

  case SCALPEL_ERROR_MUTEX_FAILURE:
    // fatal
    scalpel_log_err("Scalpel was unable to create/initialize/use a mutex. Aborting.\n");
    backtrace = true;
    goto fatal;

    break;

  case SCALPEL_ERROR_FILE_OPEN:
    // fatal
    scalpel_log_err("Scalpel was unable to open the file: \"%s\". Aborting.\n", str);
    goto fatal;

    break;

  case SCALPEL_ERROR_FILE_TOO_SMALL:
    // fatal
    scalpel_log_err("The file \"%s\" is smaller than the longest header/footer. Aborting.\n", str);
    goto fatal;

    break;

  case SCALPEL_ERROR_FILE_READ:
    // fatal
    scalpel_log_err("Scalpel was unable to read the file: \"%s\". Aborting.\n", str);
    goto fatal;

    break;

  case SCALPEL_ERROR_BAD_OUTPUT_DIRECTORY:
    // fatal
    scalpel_log_err("Scalpel was unable to process output directory. Aborting.\n", NULL);
    goto fatal;

    break;

  case SCALPEL_ERROR_FILE_WRITE:
    // fatal--unable to write files, which may mean that disk space is exhausted or that too many
    // files are open
    scalpel_log_err("Scalpel was unable to write to file \"%s\". Aborting.\n", str);
    goto fatal;

    break;

  case SCALPEL_ERROR_TOO_MANY_MATCHES:
    // fatal
    scalpel_log_err("Scalpel encountered too many header/footer matches within one buffer.\n");
    scalpel_log_err("To solve this problem, you need to increase MAX_MATCHES_PER_BUFFER in\n");
    scalpel_log_err("scalpel.h and recompile. Offending file type: \"%s\". Aborting.\n", str);
    goto fatal;

    break;

  case SCALPEL_ERROR_BAD_BLOCKMAP_BLOCK_NUMBER:
    // fatal
    scalpel_log_err("Bad block number or location in function: \"%s\". Aborting.\n", str);
    backtrace = true;
    goto fatal;

    break;

  case SCALPEL_GENERAL_ABORT:
    // fatal
    scalpel_log_err("Scalpel will abort: %s\n", str);
    backtrace = true;
    goto fatal;

    break;

  case SCALPEL_ERROR_MASTER_HEADERFUNC:
    // fatal
    scalpel_log_err("MASTER file type \"%s\" must use a header function and not a static"
                    " header. Aborting.\n",
                    str);
    goto fatal;

    break;

  case SCALPEL_ERROR_MISSING_BLOCK_VALIDATOR:
    // fatal
    scalpel_log_err("Missing BLOCKVALIDATOR for file type \"%s\". Aborting.\n", str);
    goto fatal;

    break;

  case SCALPEL_ERROR_BACKWARD_FOOTER:
    // fatal
    scalpel_log_err("File type \"%s\" has SEARCHTYPE = SEARCHTYPE_BACKWARD and therefore must have\n"
                    "a FOOTER or FOOTERFUNC *and* a custom REASSEMBLYFUNC specified. Aborting.\n",
                    str);
    goto fatal;

    break;

  case SCALPEL_ERROR_FORWARD_HEADER:
    // fatal
    scalpel_log_err("File type \"%s\" has SEARCHTYPE = SEARCHTYPE_FORWARD and therefore must have\n"
                    "a HEADER or HEADERFUNC specified. Aborting.\n",
                    str);
    goto fatal;

    break;

  case SCALPEL_ERROR_MISSING_CARVE_STATE_FUNCTION:
    scalpel_log_err("Configuration error: SERIALIZECARVESTATEFUNC, CLONECARVESTATEFUNC, and FREECARVESTATEFUNC\n"
                    "for file type \"%s\" must ALL be provided if the global state API for carving operation\n"
                    "s will be used. Aborting.\n",
                    str);
    // fatal
    backtrace = true;
    goto fatal;

    break;

  case SCALPEL_ERROR_MISSING_BLOCK_STATE_FUNCTION:
    scalpel_log_err("Configuration error: SERIALIZEBLOCKSTATEFUNC, CLONEBLOCKSTATE, and FREEBLOCKSTATEFUNC\n"
                    "for file type \"%s\" must ALL be provided if the global state API for block state will\n"
                    "be used. Aborting.\n",
                    str);

    // fatal
    backtrace = true;
    goto fatal;

    break;

  case SCALPEL_ERROR_SUBTYPE_ERROR:
    scalpel_log_err("File subtypes can only be added during the block validation phase. Aborting.\n");

    // fatal
    backtrace = true;
    goto fatal;

    break;

  case SCALPEL_ERROR_BLOCK_STATE_IS_READ_ONLY:
    scalpel_log_err("Block state is read-only after the block validation phase is complete. Aborting.\n");

    // fatal
    backtrace = true;
    goto fatal;

    break;

  case SCALPEL_ERROR_BAD_START_END_BLOCKS:
    scalpel_log_err("Start block must be <= end block and both must be <= the number of blocks\n"
                    "in the image file for -j and -k options. Aborting.\n");

    // fatal
    backtrace = false;
    goto fatal;

    break;

  case SCALPEL_ERROR_IMAGE_BLOCKFILESIZE:
    scalpel_log_err("The number of blocks represented by the blockmap must be exactly the same as \n"
                    "the number of blocks in the image file.\n");

    // fatal
    backtrace = false;
    goto fatal;

    break;

  default:
    // fatal
    scalpel_log_err("Scalpel encountered an unknown error and will abort.\n");
    backtrace = true;
    goto fatal;

    break;
  }

fatal:
  // try to close the audit file
  close_audit_file();

  if (backtrace) {
    crash();
  }
  exit(-1);
}


// write final completion message and close the audit file, if it's open
void close_audit_file(void) {

  if (scalpel_state.audit_file) {
    fclose(scalpel_state.audit_file);
  }
}


// used to deliberately induce backtraces by causing a segfault
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
#if defined(__GNUC__) && ! defined(__clang__)
#pragma GCC diagnostic ignored "-Wstringop-overflow"
#endif
void crash(void) { strcpy((char *)10, (char *)100800); }

#pragma GCC diagnostic pop
