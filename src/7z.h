//
// Scalpel3 is Copyright(C) 2021 - 2025 by Golden G.Richard III and
// contributors.
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
//
//------------------------------------------------------------------------
// Additional Integration Terms
// ------------------------------------------------------------------------
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

/**
* @author Mingyang Li
* @discussion
*
* This file contains functionality for various .7z file and block
* validation. ".7z" is a widely used modern compression format
* https://7-zip.org
*
* PHASE 1 (current): signature header validated field-by-field with
* byte-precise validates_to; header database parsed via libarchive.
* Stream body content is NOT validated (archive_read_data_skip only).
*
* PHASE 2 (planned): custom skeleton-first reassembly (template: 123.h).
* PHASE 3 (planned): self-written header database parser + LZMA2
* chunk-level block classification.
*
* 7z signature header layout (32 bytes total):
*   [0x00..0x05]  magic  37 7A BC AF 27 1C
*   [0x06]        version major (0x00)
*   [0x07]        version minor (0x04)
*   [0x08..0x0B]  StartHeaderCRC  = CRC32 of bytes [0x0C..0x1F]
*   [0x0C..0x13]  NextHeaderOffset (relative to END of signature header!)
*   [0x14..0x1B]  NextHeaderSize
*   [0x1C..0x1F]  NextHeaderCRC   = CRC32 of the header database
*
* Header database location: data + 32 + NextHeaderOffset, length
* NextHeaderSize. Total file size = 32 + NextHeaderOffset + NextHeaderSize.
*

* Functions for the block validator and file validator are contained
* in this file, then they are installed into scalplel3 by modifying
* the "scalpelconf.c" file.
*
* Standalone unit test (Step 0):
*   gcc -DSEVENZ_TEST -x c 7z.h -o sevenz_test -larchive -lz
*   ./sevenz_test t02_lzma2.7z

*
**/

#if !defined (SCALPEL_SEVENZ_H)
#define SCALPEL_SEVENZ_H

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-parameter"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <zconf.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include <zlib.h>//CRC
#include <archive.h>
#include <archive_entry.h>//Libarchive


#ifdef SEVENZ_TEST

#define SEVENZ_LOG(...) fprintf(stdout, __VA_ARGS__)
typedef enum BlockValidationDecision {
  BLOCK_CONFIDENCE_VALID = 0,
  BLOCK_CONFIDENCE_INVALID = 1
  
} BlockValidationDecision;
#else
// #include "scalpel.h"
// #define SEVENZ_LOG(...) lock_fprintf(stdout, __VA_ARGS__)
#endif // SEVENZ_TEST
#define SEVENZ_MAGIC_SIZE 6
#define SEVENZ_SIGNATURE_HEADER_SIZE 32
#define SEVENZ_OFF_VERSION_MAJOR 0x06
#define SEVENZ_OFF_VERSION_MINOR 0x07
#define SEVENZ_OFF_START_CRC 0x08
#define SEVENZ_OFF_NEXT_OFFSET 0x0C
#define SEVENZ_OFF_NEXT_SIZE 0x14
#define SEVENZ_OFF_NEXT_CRC 0x1C
#define SEVENZ_START_CRC_SPAN 20

static const uint8_t sevenz_magic[6] = {0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C};
static const uint8_t version[2] = {0x00, 0x04};


//TODO
// Property IDs
// #define kEnd 		 0x00;
// #define kHeader 		 0x01;
// #define kArchiveProperties 		 0x02;
// #define kAdditionalStreamsInfo 		 0x03;
// #define kMainStreamInfo 		 0x04;
// #define kFilesInfo 		 0x05;
// #define kPackInfo 		 0x06;
// #define kUnPackInfo 		 0x07;
// #define kSubStreamsInfo 		 0x08;
// #define kSize 		 0x09;
// #define kCRC 		 0x0A;
// #define kFolder 		 0x0B;
// #define kCodersUnPackSize 		 0x0C;
// #define kNumUnPackStream 		 0x0D;
// #define kEmptyStream 		 0x0E;
// #define kEmptyFile 		 0x0F;
// #define kAnti 		 0x10;
// #define kName 		 0x11;
// #define kCTime 		 0x12;
// #define kATime 		 0x13;
// #define kMTime 		 0x14;
// #define kWinAttributes 		 0x15;
// #define kComment 		 0x16;
// #define kEncodedHeader 		 0x17;
// #define kStartPos 		 0x18;
// #define kDummy 		 0x19;


enum sevenz_property_id{
  SEVENZ_kEND                 = 0x00
};

static uint32_t sevenz_read_u32_le(char *p){
    return  ((uint32_t)(unsigned char)p[0]) |
            ((uint32_t)((unsigned char)p[1]) << 8) |
            ((uint32_t)((unsigned char)p[2]) << 16) |
            ((uint32_t)((unsigned char)p[3]) << 24);
}

static uint64_t sevenz_read_u64_le(char *p){
    return  ((uint64_t)(unsigned char)p[0]) |
            ((uint64_t)((unsigned char)p[1]) << 8) |
            ((uint64_t)((unsigned char)p[2]) << 16) |
            ((uint64_t)((unsigned char)p[3]) << 24) |
            ((uint64_t)((unsigned char)p[4]) << 32) |
            ((uint64_t)((unsigned char)p[5]) << 40) |
            ((uint64_t)((unsigned char)p[6]) << 48) |
            ((uint64_t)((unsigned char)p[7]) << 56);
}



// typedef struct mainStreamInfo{
//     char propertyID;        //== 04h
//
// } mainStreamInfo;
//
// typedef struct folderInfo {
//     char propertyID;       //== 0bh
// } folderInfo;
//


/**
* @discussion          Compares stored crc in file and from calculation to see if matches
*
* @param               storedCRC: Stored crc in file. use read_u32_le to pass
*
* @param               startPosition: Pointer to start of the original data
*
* @param               length: Length of data to be validated
*
* @return
*/
// static bool sevenz_crc_matches(uint32_t storedCRC, char* startPosition, int length){
//     uLong crc = crc32(0L, Z_NULL, 0);
//     crc = crc32(crc, (unsigned char*)startPosition, length);
//     return (crc == storedCRC);
// }

static bool sevenz_crc_matches(uint32_t stored_crc,
                               const char *start,
                               uint64_t length) {
  uLong crc = crc32(0L, Z_NULL, 0);
  const uint64_t CHUNK = 1u << 30;   /* 1 GiB, well under uInt max */
 
  while (length > 0) {
    uInt n = (uInt)(length > CHUNK ? CHUNK : length);
    crc = crc32(crc, (const unsigned char *)start, n);
    start  += n;
    length -= n;
  }
  return (uint32_t)crc == stored_crc;
}

// static la_ssize_t buf_read_cb(struct archive *a, void *ctx, const void **block)
// {
//     (void)a;
// }



// #define SEVENZ_TEST


// FUNCTION PROTOTYPES
#define SEVENZ_READ_BLOCK_SIZE 4096

typedef struct sevenzCtx {
    const char* data;
    uint64_t length;
    uint64_t pos;
} sevenzCtx;

static la_ssize_t sevenz_read_cb(struct archive *a, void *vctx, const void** block){
  (void)a;
  sevenzCtx *ctx = (sevenzCtx *)vctx;

  if (ctx->pos >= ctx ->length){
    return 0;
  }

  *block = ctx->data + ctx->pos;
  uint64_t remaining = ctx->length - ctx->pos;
  la_ssize_t n = (la_ssize_t)(remaining < SEVENZ_READ_BLOCK_SIZE
                              ? remaining
                              : SEVENZ_READ_BLOCK_SIZE);
  ctx->pos += (uint64_t)n;
  return n;

}


static la_int64_t sevenz_seek_cb(struct archive *a, void *vctx,
                                 la_int64_t offset, int whence) {
  (void)a;
  sevenzCtx *ctx = (sevenzCtx *)vctx;
  la_int64_t newpos;
 
  switch (whence) {
    case SEEK_SET: newpos = offset;                              break;
    case SEEK_CUR: newpos = (la_int64_t)ctx->pos + offset;       break;
    case SEEK_END: newpos = (la_int64_t)ctx->length + offset;    break;
    default:       return ARCHIVE_FATAL;
  }
 
  if (newpos < 0) {
    return ARCHIVE_FATAL;
  }
  ctx->pos = (uint64_t)newpos;
  return newpos;
}
 
static int sevenz_close_cb(struct archive *a, void *vctx) {
  (void)a; (void)vctx;
  return ARCHIVE_OK;      /* buffer is owned by the caller */
}


static inline uint32_t sevenz_block_validate(char *data,
                                             uint64_t length,
                                             BlockValidationDecision *decision,
                                             uint64_t *validates_to,
                                             uint32_t needleidx,
                                             uint32_t blocksize,
                                             void *blockhashkey) {
  (void)data; (void)blocksize; (void)blockhashkey;
 
  *decision     = BLOCK_CONFIDENCE_VALID;
  *validates_to = (length > 0) ? length - 1 : 0;
 
  return needleidx;
}

/**
 * Validates whether `data` is a complete 7z archive, or a promising
 * prefix of one.
 *
 * Output contract (consumed by LR reassembly as its feedback gradient):
 *
 *   validates      true only if libarchive walked every entry to EOF
 *   promising      true as soon as the 6-byte magic matches; false is
 *                  the definitive "this is not a 7z" signal
 *   validates_to   index of the last byte confirmed valid, advancing
 *                  through these checkpoints:
 *                    5   magic ok, version bytes missing/bad
 *                    6   major ok, minor missing/bad
 *                    7   version ok, header incomplete or StartCRC bad
 *                    31  signature header fully verified (CRC ok);
 *                        candidate shorter than predicted total length,
 *                        OR NextHeaderCRC failed, OR libarchive failed
 *                        before consuming past the signature header
 *                    N   libarchive consumed N+1 bytes before failing
 *                    length-1   full success
 */
static inline void sevenz_file_validate(char *data,
                                        uint64_t length,
                                        bool *validates,
                                        uint64_t *validates_to,
                                        bool *promising,
                                        uint32_t needleidx,
                                        uint32_t blocksize,
                                        void *carvehashkey) {
  (void)needleidx; (void)blocksize; (void)carvehashkey;
 
  *validates    = false;
  *promising    = false;
  *validates_to = 0;
 
  /* ---- magic ---------------------------------------------------------- */
  if (length < SEVENZ_MAGIC_SIZE ||
      memcmp(sevenz_magic, data, SEVENZ_MAGIC_SIZE) != 0) {
    /* the only outcome where promising stays false */
    return;
  }
 
  /* ---- version major: data[6] == 0x00 --------------------------------- */
  if (length < SEVENZ_OFF_VERSION_MAJOR + 1 ||
      data[SEVENZ_OFF_VERSION_MAJOR] != '\x00') {
    *promising    = true;
    *validates_to = SEVENZ_MAGIC_SIZE - 1;                       /* 5 */
    return;
  }
 
  /* ---- version minor: data[7] == 0x04 ---------------------------------
   * (earlier revision re-tested data[6] here, rejecting every valid
   * archive -- the minor version lives at data[7])                       */
  if (length < SEVENZ_OFF_VERSION_MINOR + 1 ||
      data[SEVENZ_OFF_VERSION_MINOR] != '\x04') {
    *promising    = true;
    *validates_to = SEVENZ_MAGIC_SIZE;                           /* 6 */
    return;
  }
 
  /* ---- full signature header present? ---------------------------------- */
  if (length < SEVENZ_SIGNATURE_HEADER_SIZE) {
    *promising    = true;
    *validates_to = SEVENZ_OFF_VERSION_MINOR;                    /* 7 */
    return;
  }
 
  /* ---- StartHeaderCRC: data[8..11] covers data[12..31] ------------------ */
  if (!sevenz_crc_matches(sevenz_read_u32_le(data + SEVENZ_OFF_START_CRC),
                          data + SEVENZ_OFF_NEXT_OFFSET,
                          SEVENZ_START_CRC_SPAN)) {
    *promising    = true;
    /* magic + both version bytes verified => last good byte is data[7] */
    *validates_to = SEVENZ_OFF_VERSION_MINOR;                    /* 7 */
    return;
  }
 
  /* Signature header is now trusted: extract the length oracle. */
  uint64_t next_header_offset = sevenz_read_u64_le(data + SEVENZ_OFF_NEXT_OFFSET);
  uint64_t next_header_size   = sevenz_read_u64_le(data + SEVENZ_OFF_NEXT_SIZE);
  uint32_t next_header_crc    = sevenz_read_u32_le(data + SEVENZ_OFF_NEXT_CRC);
 
  /* Overflow guard before forming the sum (both values are attacker /
   * corruption controlled). */
  if (next_header_offset > UINT64_MAX - SEVENZ_SIGNATURE_HEADER_SIZE ||
      next_header_offset + SEVENZ_SIGNATURE_HEADER_SIZE
          > UINT64_MAX - next_header_size) {
    *promising    = true;
    *validates_to = SEVENZ_OFF_VERSION_MINOR;
    return;
  }
 
  uint64_t expected_total = SEVENZ_SIGNATURE_HEADER_SIZE
                            + next_header_offset + next_header_size;
 
  /* ---- bounds check BEFORE touching the header database -----------------
   * This is simultaneously (a) the fix for an out-of-bounds read when the
   * candidate is shorter than the archive, and (b) the core LR feedback:
   * "signature header good, keep appending blocks until expected_total". */
  if (length < expected_total) {
    *promising    = true;
    *validates_to = SEVENZ_SIGNATURE_HEADER_SIZE - 1;            /* 31 */
    return;
  }
 
  /* ---- NextHeaderCRC: base is END of signature header (offset 32) -------
   * NOT the end of the magic (offset 6) -- using +6 here made the CRC
   * fail on every well-formed archive.                                   */
  if (!sevenz_crc_matches(next_header_crc,
                          data + SEVENZ_SIGNATURE_HEADER_SIZE + next_header_offset,
                          next_header_size)) {
    *promising    = true;
    *validates_to = SEVENZ_SIGNATURE_HEADER_SIZE - 1;            /* 31 */
    return;                              /* was missing -> fell through */
  }
 
  /* ================= libarchive: header database ======================== */
 
  struct archive *a = archive_read_new();
  if (!a) {
    *promising    = true;
    *validates_to = SEVENZ_SIGNATURE_HEADER_SIZE - 1;
    return;
  }
 
  archive_read_support_format_7zip(a);
 
  sevenzCtx ctx = {
    .data   = data,
    .length = length,
    .pos    = 0
  };
 
  archive_read_set_read_callback (a, sevenz_read_cb);
  archive_read_set_seek_callback (a, sevenz_seek_cb);
  archive_read_set_close_callback(a, sevenz_close_cb);
  archive_read_set_callback_data (a, &ctx);
 
  int r = archive_read_open1(a);
  if (r != ARCHIVE_OK) {
    SEVENZ_LOG("7z_file_validate: open failed: %s\n",
               archive_error_string(a));
    archive_read_free(a);
    *promising    = true;
    *validates_to = SEVENZ_SIGNATURE_HEADER_SIZE - 1;
    return;
  }
 
  struct archive_entry *entry;
  int n_entries = 0;
 
  /* '=' not '==' -- the comparison typo froze r at its initial value */
  while ((r = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
    const char *path = archive_entry_pathname(entry);
    if (!path || path[0] == '\0') {
      r = ARCHIVE_FATAL;
      break;
    }
    /* metadata pass only: skip, don't decompress-and-verify (Phase 1) */
    if (archive_read_data_skip(a) != ARCHIVE_OK) {
      r = ARCHIVE_FATAL;
      break;
    }
    n_entries++;
  }
 
  /* Bytes libarchive actually consumed from our callbacks. More reliable
   * than ctx.pos for validates_to: ctx.pos jumps around under seeks,
   * while filter bytes track true parsing progress. */
  int64_t consumed = archive_filter_bytes(a, -1);
 
  if (r == ARCHIVE_EOF) {
    /* every entry enumerated -- full structural validation */
    *validates    = true;
    *promising    = true;
    *validates_to = length - 1;
    SEVENZ_LOG("7z_file_validate: VALID, %d entries, %" PRIu64 " bytes\n",
               n_entries, length);
  } else {
    /* ARCHIVE_WARN is NOT success: warnings mean the result may be
     * incomplete (bad Unicode paths, odd timestamps, ...). Treating WARN
     * as validated would write structurally unverified candidates as
     * final carving results and silently inflate recall. WARN, FAILED,
     * FATAL, RETRY all land here: promising, not validated. */
    *validates = false;
    *promising = true;
 
    if (consumed > (int64_t)SEVENZ_SIGNATURE_HEADER_SIZE) {
      *validates_to = (uint64_t)consumed - 1;
    } else {
      /* never regress below the manually-verified signature header */
      *validates_to = SEVENZ_SIGNATURE_HEADER_SIZE - 1;
    }
 
    SEVENZ_LOG("7z_file_validate: stopped after %d entries at byte %" PRId64
               " (rc=%d): %s\n",
               n_entries, consumed, r,
               archive_error_string(a) ? archive_error_string(a) : "(none)");
  }
 
  archive_read_free(a);
}

#ifdef SEVENZ_TEST
 
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
 
static void run_case(const char *label, char *buf, uint64_t len,
                     bool expect_validates, uint64_t expect_vto,
                     bool has_expectation, int *failures) {
  bool validates = false, promising = false;
  uint64_t validates_to = 0;
 
  sevenz_file_validate(buf, len, &validates, &validates_to, &promising,
                       0, 4096, NULL);
 
  printf("%-28s len=%-10" PRIu64 " validates=%d promising=%d "
         "validates_to=%" PRIu64 "\n",
         label, len, validates, promising, validates_to);
 
  if (has_expectation) {
    if (validates != expect_validates || validates_to != expect_vto) {
      printf("  ^^ FAIL: expected validates=%d validates_to=%" PRIu64 "\n",
             expect_validates, expect_vto);
      (*failures)++;
    }
  }
}
 
int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "USAGE: %s file.7z\n", argv[0]);
    return 2;
  }
 
  struct stat st;
  if (stat(argv[1], &st) != 0) {
    perror("stat");
    return 2;
  }
  uint64_t len = (uint64_t)st.st_size;
 
  char *buf = malloc(len);
  if (!buf) { perror("malloc"); return 2; }
 
  int fd = open(argv[1], O_RDONLY);
  if (fd < 0) { perror("open"); free(buf); return 2; }
  if (read(fd, buf, len) != (ssize_t)len) {
    perror("read"); close(fd); free(buf); return 2;
  }
  close(fd);
 
  int failures = 0;
 
  printf("=== 7z validator unit test: %s ===\n\n", argv[1]);
 
  /* full file must validate end-to-end */
  run_case("full file", buf, len, true, len - 1, true, &failures);
 
  /* truncation sweep -- expectations per the validates_to contract */
  if (len > 20) {
    run_case("trunc @20 (partial sig)", buf, 20, false, 7, true, &failures);
  }
  if (len > 32) {
    run_case("trunc @32 (sig only)", buf, 32, false, 31, true, &failures);
  }
  if (len > 64) {
    run_case("trunc @len/2", buf, len / 2, false, 31, true, &failures);
  }
  if (len > 4) {
    /* header database tail clipped: NextHeaderCRC region incomplete,
     * so length < expected_total -> stop at 31 */
    run_case("trunc @len-4", buf, len - 4, false, 31, true, &failures);
  }
 
  /* corruption: flip a byte inside the header database (last 2 bytes are
   * inside it for any realistic archive) -> NextHeaderCRC must fail */
  if (len > 2) {
    char *corrupt = malloc(len);
    memcpy(corrupt, buf, len);
    corrupt[len - 2] ^= 0xFF;
    run_case("corrupt header db byte", corrupt, len, false, 31, true,
             &failures);
    free(corrupt);
  }
 
  /* non-7z input must give promising=false */
  {
    char junk[64];
    memset(junk, 'X', sizeof(junk));
    bool v = true, p = true;
    uint64_t vto = 999;
    sevenz_file_validate(junk, sizeof(junk), &v, &vto, &p, 0, 4096, NULL);
    printf("%-28s len=%-10zu validates=%d promising=%d "
           "validates_to=%" PRIu64 "\n", "non-7z junk", sizeof(junk),
           v, p, vto);
    if (v || p || vto != 0) {
      printf("  ^^ FAIL: expected validates=0 promising=0 validates_to=0\n");
      failures++;
    }
  }
 
  free(buf);
 
  printf("\n=== %s: %d failure(s) ===\n",
         failures ? "FAILED" : "PASSED", failures);
  return failures ? 1 : 0;
}
 
#endif /* SEVENZ_TEST */
 

#pragma GCC diagnostic pop
#endif
