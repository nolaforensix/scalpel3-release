//
// Scalpel3 is Copyright(C) 2021 - 2026 by Golden G.Richard III and
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
// scalpel3's read-only, blockmap-aware FUSE filesystem.
// (c) Golden G. Richard III (@nolaforensix), 2021-5.
//
// Updated 4/2024 to handle scalpel3's new blockmap format, documented
// in "blockmap.h".
//
// Updated 2/2025 to use hashv2.
//
// Updated 9/2025 to use hashv4.
//
// Requirements:
//
// FUSE (Linux) or macFUSE (Intel or Apple Silicon Macs) must be
// installed before using blockmapfs.
//
// Compile with:
//
//  gcc -O2 -D_FILE_OFFSET_BITS=64 -Wall blockmapfs.c blockmap.c hashv2.c `pkg-config fuse --cflags --libs` -o blockmapfs -lm
//
// If you see any error messages, it's likely that you don't have a recent version of FUSE installed
// or there's a FUSE configuration problem.  On Macs using macFUSE, it's common to accidentally omit
// the necessary configuration of PKG_CONFIG_PATH.  Be sure the following line is in ~/.bashrc:
//
// export PKG_CONFIG_PATH="$PKG_CONFIG_PATH:/usr/local/lib/pkgconfig/"
//
// To use:
//
// o Each file in the ROOT directory MUST have an associated, valid blockmap, following the naming
// convention <filename>.blockmap. These blockmap files can be created with the crblockmap utility.
//
// o Files in the ROOT directory being sourced for blockmapfs, including the blockmaps, MUST NOT be
// modified while the blockmapfs filesystem is mounted!  Blockmap data is cached for performance
// reasons and blockmap changes while the filesystem is mounted will not be handled correctly.  The
// blockmapfs filesystem must be unmounted, changes made, and then remounted after changes to files
// are made.
//
// Copyright message for FUSE:
//
/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  Copyright (C) 2011       Sebastian Pipping <sebastian@pipping.org>

  This program can be distributed under the terms of the GNU GPLv2.
  See the file COPYING.
*/
//

// set VERBOSE_BLOCKMAPFS to:
// 0 for silence and background mode
// 1 to enable foreground mode with limited debugging info
// 2 to enable foreground mode with standard debugging info
// 3 to enable foreground mode with extended debugging info

#define VERBOSE_BLOCKMAPFS 0

#define FUSE_USE_VERSION 26

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE 1
#include <fuse.h>

#ifdef HAVE_LIBULOCKMGR
#include <ulockmgr.h>
#endif

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif
#define SCALPEL3_EXTERNAL 1
#include "scalpel.h"
#include "blockmap.h"
#include "colors.h"
#include "hashv4.h"
#include "scalpelv.h"
#include <math.h>
#include <sys/file.h> /* flock(2) */
#include <sys/ioctl.h>

#define BLOCKMAPFS_BANNER_STRING                       \
  "blockmapfs v%s -- "                                 \
  "Written by Golden G. Richard III (@nolaforensix).", \
      SCALPEL_VERSION

#define MAX_STRING_LENGTH (4096 + 1)

// private info per file

typedef struct File {
  Blockmap *blockmap;       // tracks covered blocks
  int64_t filesize;         // size of file reflected by
                            // ...*uncovered* blocks
  char pathname[PATH_MAX];  // pathname of file in root dir
  int handle;               // file handle for file
} File;

// GLOBALS

char ROOTDIR[PATH_MAX];  // source directory containing files that
                         // will be accessed through the mount point

char MOUNTDIR[PATH_MAX];  // mount point

oa_hash *HASHTABLE = NULL;  // hash table to work around gettattr() et al not
                            // not passing the fuse_file_info struct (grrrr)

// END OF GLOBALS

// blockmapfs FUSE callback functions
static void *bmfs_init(struct fuse_conn_info *conn);
static int bmfs_getattr(const char *path, struct stat *stbuf);
static int bmfs_fgetattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi);
static int bmfs_open(const char *path, struct fuse_file_info *fi);
static int bmfs_read(const char *path, char *buf, size_t size, off_t seekpos,
                     struct fuse_file_info *fi);
static int bmfs_release(const char *path, struct fuse_file_info *fi);
static int bmfs_access(const char *path, int mask);
static int bmfs_opendir(const char *path, struct fuse_file_info *fi);
static inline struct bmfs_dirp *get_dirp(struct fuse_file_info *fi);
static int bmfs_readdir(const char *p, void *buf, fuse_fill_dir_t filler,
                        off_t offset, struct fuse_file_info *fi);
static int bmfs_releasedir(const char *path, struct fuse_file_info *fi);

// other function prototypes
static void *oa_File_cp(const void *data);
static void blockmapfs_logo(void);
static void *oa_File_cp(const void *data);
static void oa_File_free(void **data);


// operations for *read-only* blockmapfs filesystem
static const struct fuse_operations bmfs_operations = {
    .init = bmfs_init,
    .getattr = bmfs_getattr,
    .fgetattr = bmfs_fgetattr,
    .access = bmfs_access,
    .opendir = bmfs_opendir,
    .readdir = bmfs_readdir,
    .releasedir = bmfs_releasedir,
    .open = bmfs_open,
    .read = bmfs_read,
    .release = bmfs_release,
    //	.lseek		= bmfs_lseek,   // GGRIII:  Trying to not need this
};


static void blockmapfs_logo(void) {
  char *logo[] = {
      "\n",
      "\n",
      " ................................................................................................\n",
      ".                                                                                                .\n",
      ".  888      888                   888                                      8888888888 .d8888b.   .\n",
      ".  888      888                   888                                      888       d88P  Y88b  .\n",
      ".  888      888                   888                                      888       Y88b.       .\n",
      ".  88888b.  888  .d88b.   .d8888b 888  888 88888b.d88b.   8888b.  88888b.  8888888    \"Y888b.    .\n",
      ".  888 \"88b 888 d88\"\"88b d88P\"    888 .88P 888 \"888 \"88b     \"88b 888 \"88b 888           \"Y88b.  .\n",
      ".  888  888 888 888  888 888      888888K  888  888  888 .d888888 888  888 888             \"888  .\n",
      ".  888 d88P 888 Y88..88P Y88b.    888 \"88b 888  888  888 888  888 888 d88P 888       Y88b  d88P  .\n",
      ".  88888P\"  888  \"Y88P\"   \"Y8888P 888  888 888  888  888 \"Y888888 88888P\"  888        \"Y8888P\"   .\n",
      ".                                                                 888                            .\n",
      ".                                                                 888                            .\n",
      ".                                                                 888                            .\n",
      " ................................................................................................\n",
      ""};

  int i = 0;
  size_t j;
  size_t len;

  // only display logo if the terminal is wide enough
  if (get_terminal_width() < 98) {
    return;
  }

  while (logo[i][0]) {
    len = strlen(logo[i]);
    for (j = 0; j < len; j++) {
      if (isspace(logo[i][j]) || i < 3 || i > 14 || j < 2 || j > 94) {
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


// functions to accomodate storage of File structures in hash tables

// copy a File structure
static void *oa_File_cp(const void *data) {
  File *f = (File *)data;
  File *result = malloc(sizeof(File));

  if (result) {
    strcpy(result->pathname, f->pathname);
    result->handle = f->handle;
    result->filesize = f->filesize;
    result->blockmap = NULL;
    clone_blockmap(f->blockmap, &result->blockmap);
  }

  return result;
}


// free a File structure
static void oa_File_free(void **data) {
  File **f = (File **)data;

  free_blockmap(&((*f)->blockmap));
  free(*f);
  *f = NULL;
}


// blockmapfs FUSE callback functions

static void *bmfs_init(struct fuse_conn_info *conn
                       /*struct fuse_config *cfg*/) {
  (void)conn;

  if (VERBOSE_BLOCKMAPFS > 1) {
    fprintf(stdout, "bmfs_init() entry.\n");
  }

  // only for fuse3
  //  cfg->use_ino = 1;
  //  cfg->nullpath_ok = 1;
  //  cfg->attr_timeout = 99999999;
  //  cfg->entry_timeout = 99999999;
  //  cfg->negative_timeout = 99999999;
  //  cfg->auto_cache = 1;

  if (VERBOSE_BLOCKMAPFS > 1) {
    fprintf(stdout, "bmfs_init() exit.\n");
  }
  return NULL;
}


// simply calls bmfs_getattr()
static int bmfs_fgetattr(const char *path, struct stat *stbuf,
                         struct fuse_file_info *fi) {
  (void)fi;
  return bmfs_getattr(path, stbuf);
}


// bmfs_getattr() is more expensive than typical getattr calls,
// because it's necessary to open files to get access to the coverage
// blockmap so we can lie appropriately about the apparent file size.
// We can't use the fuse_file_info structure, because (grrrr) this
// isn't passed to the getattr callback in fuse2, so we have to resort
// to using a global hashtable as a conduit to and from open().
static int bmfs_getattr(const char *path, struct stat *stbuf
                        /*struct fuse_file_info *fi*/) {
  char pathname[PATH_MAX];  // pathname of file in root dir
  char bm[PATH_MAX];        // pathname for associated blockmap file
  int res = 0;
  File *f = NULL;
  FILE *fp;
  char *dot;

  bzero(stbuf, sizeof(struct stat));
  if (snprintf(pathname, sizeof(pathname), "%s%s", ROOTDIR, path) >= (int)sizeof(pathname)) {
    res = -ENAMETOOLONG;
    goto done;
  }

  if (VERBOSE_BLOCKMAPFS > 1) {
    fprintf(stdout, "bmfs_getattr() entry for \"%s\".\n", pathname);
  }

  // start with a regular stat
  res = stat(pathname, stbuf);

  if (res) {
    // stat() failed, done
    goto done;
  }

  // if the filename name ends in ".blockmap" or the file isn't a
  // regular file then no blockmap processing is required, so the
  // plain stat() suffices

  dot = strrchr(pathname, '.');
  if ((dot && ! strcmp(dot, ".blockmap")) || ! S_ISREG(stbuf->st_mode)) {
    // not a regular file or ends in ".blockmap", so done
    goto done;
  }

  // there's one more elimination check--if the filename doesn't sit
  // next to an associated file with the extension ".blockmap", then
  // the regular stat() suffices.  Files in the blockmapfs mount
  // directory only require a blockmap if they are opened.

  if (snprintf(bm, sizeof(bm), "%s.blockmap", pathname) >= (int)sizeof(bm)) {
    goto done;
  }

  fp = fopen(bm, "r");
  if (! fp) {
    // no associated blockmap, done
    goto done;
  }
  fclose(fp);

  // here: regular file that doesn't end in ".blockmap" and has an
  // associated ".blockmap" friend

  // see if the File structure corresponding to this file is already
  // in the global hashtable
  f = oa_hash_get(HASHTABLE, pathname);

  if (! f) {
    // file is not already open.  This requires a bunch of overhead,
    // as the file must be opened first so the blockmap can be
    // processed.  But the blockmap processing is cached, so if the
    // file is opened in the future, that's all done.
    if (VERBOSE_BLOCKMAPFS > 1) {
      fprintf(stdout, "bmfs_getattr() calling open() to process the blockmap for %s.\n",
              pathname);
    }

    // call open, but we don't have a fuse_file_info to pass
    // (otherwise all this effort wouldn't be necessary in the first
    // place :)
    res = bmfs_open(path, NULL);

    if (res) {
      goto done;
    }

    // now use the hash table and try once again to get access to the
    // file info
    f = oa_hash_get(HASHTABLE, pathname);
  }

  if (! f) {
    if (VERBOSE_BLOCKMAPFS > 1) {
      fprintf(stdout, "bmfs_getattr(): \"%s\" doesn't exist.\n", pathname);
    }
    res = -ENOENT;
    goto done;
  }

  // override file size returned by stat() with size not that doesn't
  // count covered blocks
  stbuf->st_size = f->filesize;

done:

  if (VERBOSE_BLOCKMAPFS > 1) {
    fprintf(stdout, "bmfs_getattr() exit for \"%s\".\n", pathname);
  }

  return res;
}


// implements open callback for FUSE.  If fi is NULL, an internal call
// to open() with the intention of processing the blockmap is assumed,
// otherwise it's a real file open operation.
static int bmfs_open(const char *path, struct fuse_file_info *fi) {
  int64_t i;
  int fd;                   // temporary file handle, allows file not
                            // found failure before memory allocation
                            // for File structure
  char pathname[PATH_MAX];  // temp full pathname for files
  File *f = NULL;           // private info for file stored in
                            // fuse_file_info struct and in hashtable
  bool empty;               // blockmap file missing?
  int64_t expected_size;    // expected size of blockmap
  FILE *fn;                 // used to open blockmap
  int res = 0;              // return value for function
  struct stat s;            // used to evaluate size of source file
                            // for comparision with blockmap size

  // all files in blockmapfs are contained in the root directory
  // as specified using a command line option
  if (snprintf(pathname, sizeof(pathname), "%s%s", ROOTDIR, path) >= (int)sizeof(pathname)) {
    res = -ENAMETOOLONG;
    goto done;
  }

  if (VERBOSE_BLOCKMAPFS > 1) {
    fprintf(stdout, "bmfs_open() entry for \"%s\".\n", pathname);
  }

  if (! (f = oa_hash_get(HASHTABLE, pathname))) {
    // file is not already open--try to open the corresponding file
    // and process the blockmap.  blockmapfs is read-only, so we
    // ignore the flags provided by FUSE
    fd = open(pathname, O_RDONLY /*fi->flags*/);
    if (fd == -1) {
      res = -errno;
      if (VERBOSE_BLOCKMAPFS) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "Couldn't open \"%s\" in bmfs_open().\n", pathname);
        fprintf(stderr, "%s", BLACK);
      }
      goto done;
    }

    f = malloc(sizeof(File));
    f->handle = fd;
    f->blockmap = NULL;
    // this is for debugging, so we can see which file is being
    // manipulated in other functions
    strcpy(f->pathname, pathname);

    // the open callback is also called by getattr() to process the
    // blockmap--in that case, there is no valid fuse_info structure,
    // so we can't stash the File structure there, so it's necessary to check
    // for a valid fuse_info pointer.
    if (fi) {
      fi->fh = (uint64_t)f;
    }

    // now handle blockmap for file.  We insist that there be a
    // blockmap, or an error is returned.  This may seem annoying, but
    // a blockmap can't be created automatically, because there's no
    // way to know the associated blocksize and defaults don't really
    // make sense.

    // the name of the blockmap is just pathname + ".blockmap"
    if (snprintf(pathname, sizeof(pathname), "%s.blockmap", f->pathname) >= (int)sizeof(pathname)) {
      if (VERBOSE_BLOCKMAPFS) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "Pathname too long in bmfs_open().\n");
        fprintf(stderr, "%s", BLACK);
      }
      res = -ENAMETOOLONG;
      goto done;
    }

    // stat() to get actual file size
    res = fstat(f->handle, &s);
    if (res) {
      res = -errno;
      if (VERBOSE_BLOCKMAPFS) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "Couldn't stat blockmap for file \"%s\".\n"
                        "Blockmaps are required for every file in blockmapfs.\n",
                f->pathname);
        fprintf(stderr, "%s", BLACK);
      }
      goto done;
    }

    // initially *apparent* filesize is the *actual* size of the file
    f->filesize = s.st_size;

    empty = ((fn = fopen(pathname, "rb")) == NULL);

    if (empty) {
      if (VERBOSE_BLOCKMAPFS) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "Couldn't open blockmap for file \"%s\".\n"
                        "Blockmaps are required for every file in blockmapfs.\n",
                f->pathname);
        fprintf(stderr, "%s", BLACK);
      }
      res = -EIO;
      goto done;
    }

    if (! read_blockmap(&f->blockmap, fn, true)) {
      if (VERBOSE_BLOCKMAPFS) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "Couldn't read blockmap for file \"%s\".\n",
                f->pathname);
        fprintf(stderr, "%s", BLACK);
      }
      res = -EIO;
      goto done;
    }

    if (VERBOSE_BLOCKMAPFS) {
      fprintf(stdout, "# of blocks represented by blockmap \"%s\" is %" PRIu64 ".\n",
              pathname, f->blockmap->numblocks);
      fprintf(stdout, "Blocksize for blockmap is %u.\n", f->blockmap->blocksize);
    }

    // sanity check--source file size must be fully represented by size
    // of blockmap
    expected_size = CEILDIV(f->filesize, f->blockmap->blocksize);

    if (expected_size != (int64_t)f->blockmap->numblocks) {
      if (VERBOSE_BLOCKMAPFS) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr,
                "Size of blockmap %" PRIu64 " does not match expected size of %" PRId64 " for source file for \"%s\".\n",
                f->blockmap->numblocks,
                expected_size,
                f->pathname);
        fprintf(stderr, "%s", BLACK);
      }
      res = -EIO;
      goto done;
    }

    // now reduce apparent file size by # of blocks that are
    // covered. Only the last block is a special case, as it may not
    // be completely full of valid data

    if (VERBOSE_BLOCKMAPFS) {
      fprintf(stdout, "Adjusting filesize (= %" PRId64 ") for \"%s\".\n", f->filesize, f->pathname);
    }

    for (i = 0; i < (int64_t)f->blockmap->numblocks - 1; i++) {
      if (is_block_covered(f->blockmap, i)) {
        f->filesize -= f->blockmap->blocksize;
      }
    }

    // last block
    if (is_block_covered(f->blockmap, f->blockmap->numblocks - 1)) {
      if (! (f->filesize % f->blockmap->blocksize)) {
        f->filesize -= f->blockmap->blocksize;
      }
      else {
        f->filesize -= (f->filesize % f->blockmap->blocksize);
      }
    }

    if (VERBOSE_BLOCKMAPFS) {
      fprintf(stdout, "Finished adjusting filesize (= %" PRId64 ") for \"%s\".\n",
              f->filesize, f->pathname);
    }

    fclose(fn);

    if (VERBOSE_BLOCKMAPFS > 1) {
      fprintf(stdout, "Finished setting up blockmap for \"%s\".\n", f->pathname);
      fprintf(stdout, "bmfs_open() exit for \"%s\".\n", pathname);
    }

    // remember File struct in hashtable
    oa_hash_put(HASHTABLE, f->pathname, f);
  }
  else {
    // file is already open (possibly because of getattr() call)--be
    // sure File struct is stashed in fuse_file_info structure
    if (fi) {
      fi->fh = (uint64_t)f;
    }
    if (VERBOSE_BLOCKMAPFS > 1) {
      fprintf(stdout, "bmfs_open() exit. \"%s\" is already open.\n", pathname);
    }
  }

done:
  // prevent memory leakage on errors
  if (res && f) {
    free_blockmap(&f->blockmap);
    free(f);
  }
  return res;
}


// the read callback silently skips covered blocks (blocks with their
// corresponding bit set in the coverage blockmap), but otherwise
// behaves like the standard C read() function.
static int bmfs_read(const char *path, char *buf, size_t size, off_t seekpos,
                     struct fuse_file_info *fi) {
  (void)path;

  int64_t curblock, neededbytes = size, bytestoskip, bytestoread,
                    bytesread, totalbytesread = 0;
  off_t curpos;
  bool shortread;
  File *f = (File *)fi->fh;

  curblock = 0;
  shortread = false;
  bytestoskip = 0;

  // there's no notion of "current file position" for FUSE
  // filesystems--an absolute offset is provided for every read.

  curpos = seekpos;

  if (VERBOSE_BLOCKMAPFS > 1) {
    fprintf(stdout, "bmfs_read() entry for \"%s\", size = %lu, seekpos = %" PRId64 ".\n",
            f->pathname, size, (int64_t)seekpos);
  }

  while (curblock < (int64_t)f->blockmap->numblocks && curpos >= 0) {
    // block is covered?
    if (is_block_covered(f->blockmap, curblock)) {
      // yes, block doesn't count toward seek position
      bytestoskip += f->blockmap->blocksize;
    }
    else {
      // no, this block counts in the offset
      bytestoskip += f->blockmap->blocksize;
      curpos -= f->blockmap->blocksize;
    }

    curblock++;
  }

  if (curblock == (int64_t)f->blockmap->numblocks &&
      is_block_covered(f->blockmap, f->blockmap->numblocks - 1)) {
    // seekpos is outside uncovered data in the source file, so nothing to read
    shortread = true;
  }
  else {
    curblock--;
    bytestoskip -= (f->blockmap->blocksize - seekpos % f->blockmap->blocksize);
    // establish valid current position
    lseek(f->handle, bytestoskip, SEEK_SET);
  }

  while (totalbytesread < neededbytes &&
         curblock < (int64_t)f->blockmap->numblocks && ! shortread) {
    bytestoread = 0;
    bytestoskip = 0;

    // accumulate uncovered blocks for read
    while (curblock < (int64_t)f->blockmap->numblocks &&
           ! is_block_covered(f->blockmap, curblock) &&
           totalbytesread + bytestoread <= neededbytes) {
      bytestoread += f->blockmap->blocksize;
      curblock++;
    }

    // cap read size, because we increased bytestoread in blocksize increments
    if (totalbytesread + bytestoread > neededbytes) {
      bytestoread = neededbytes - totalbytesread;
    }

    while (bytestoread > 0 && ! shortread) {
      bytesread = read(f->handle, ((char *)buf) + totalbytesread, bytestoread);
      if (bytesread < 0) {
        if (VERBOSE_BLOCKMAPFS) {
          fprintf(stderr, "%s", RED);
          fprintf(stderr, "Read failed in bmfs_read().\n");
          fprintf(stderr, "%s", BLACK);
        }
        return -EIO;  // something really bad happened
      }
      else if (bytesread == 0) {
        shortread = true;
      }
      else {
        bytestoread -= bytesread;
        totalbytesread += bytesread;
      }
    }

    if (! shortread) {
      // skip covered blocks to establish position for next read
      bytestoskip = 0;
      while (curblock < (int64_t)f->blockmap->numblocks &&
             is_block_covered(f->blockmap, curblock)) {
        bytestoskip += f->blockmap->blocksize;
        curblock++;
      }

      if (curblock == (int64_t)f->blockmap->numblocks) {
        // ran out of blocks before finding an uncovered block
        shortread = true;
      }
      else {
        // establish new valid current position
        lseek(f->handle, bytestoskip, SEEK_CUR);
      }
    }
  }

  if (VERBOSE_BLOCKMAPFS > 1) {
    fprintf(stdout, "bmfs_read() exit for \"%s\".\n", f->pathname);
  }

  return (int)totalbytesread;
}


// the release callback implements close file.  Since blockmapfs
// doesn't close files, this function does nothing.
static int bmfs_release(const char *path, struct fuse_file_info *fi) {
  char pathname[PATH_MAX];

  if (snprintf(pathname, sizeof(pathname), "%s%s", ROOTDIR, path) >= (int)sizeof(pathname)) {
    return -ENAMETOOLONG;
  }

  if (VERBOSE_BLOCKMAPFS > 1) {
    fprintf(stdout, "bmfs_release() entry for \"%s\".\n",
            ((File *)fi->fh)->pathname);
  }

  if (VERBOSE_BLOCKMAPFS > 1) {
    fprintf(stdout, "bmfs_release() exit.\n");
  }

  return 0;
}


// implements the access callback by calling access() on the file
// outside the FUSE filesystem.
static int bmfs_access(const char *path, int mask) {
  char pathname[PATH_MAX];  // pathname of file in root dir
  int res;

  if (snprintf(pathname, sizeof(pathname), "%s%s", ROOTDIR, path) >= (int)sizeof(pathname)) {
    if (VERBOSE_BLOCKMAPFS) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr, "Pathname too long in bmfs_access().\n");
      fprintf(stderr, "%s", BLACK);
    }
    return -ENAMETOOLONG;
  }

  if (VERBOSE_BLOCKMAPFS > 2) {
    fprintf(stdout, "bmfs_access() entry for \"%s\".\n", pathname);
  }

  res = access(pathname, mask);
  if (res == -1) {
    if (VERBOSE_BLOCKMAPFS > 2) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr, "Couldn't access() for \"%s\" in bmfs_access().\n", pathname);
      fprintf(stderr, "%s", BLACK);
      perror("");
    }
    return -errno;
  }

  if (VERBOSE_BLOCKMAPFS > 2) {
    fprintf(stdout, "bmfs_access() exit for \"%s\".\n", pathname);
  }

  return 0;
}

//
// essential but complex directory handling functions follow
//

struct bmfs_dirp {
  DIR *dp;
  struct dirent *entry;
  off_t offset;
};

static int bmfs_opendir(const char *path, struct fuse_file_info *fi) {
  int res;
  char pathname[PATH_MAX];  // pathname of file in root dir

  if (snprintf(pathname, sizeof(pathname), "%s%s", ROOTDIR, path) >= (int)sizeof(pathname)) {
    if (VERBOSE_BLOCKMAPFS) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr, "Pathname too long in bmfs_access().\n");
      fprintf(stderr, "%s", BLACK);
    }
    return -ENAMETOOLONG;
  }

  if (VERBOSE_BLOCKMAPFS > 2) {
    fprintf(stdout, "bmfs_opendir() entry for \"%s\".\n", pathname);
  }

  struct bmfs_dirp *d = malloc(sizeof(struct bmfs_dirp));
  if (d == NULL) {
    return -ENOMEM;
  }

  d->dp = opendir(pathname);
  if (d->dp == NULL) {
    perror("Error in bmfs_opendir:");
    res = -errno;
    free(d);
    return res;
  }
  d->offset = 0;
  d->entry = NULL;

  fi->fh = (uint64_t)d;

  if (VERBOSE_BLOCKMAPFS > 2) {
    fprintf(stdout, "bmfs_opendir() exit for \"%s\".\n", pathname);
  }

  return 0;
}


static inline struct bmfs_dirp *get_dirp(struct fuse_file_info *fi) {
  return (struct bmfs_dirp *)(uintptr_t)fi->fh;
}


static int bmfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                        off_t offset, struct fuse_file_info *fi
                        /*enum fuse_readdir_flags flags*/) {
  struct bmfs_dirp *d = get_dirp(fi);
  char pathname[PATH_MAX];  // pathname of file in root dir

  if (snprintf(pathname, sizeof(pathname), "%s%s", ROOTDIR, path) >= (int)sizeof(pathname)) {
    if (VERBOSE_BLOCKMAPFS) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr, "Pathname too long in bmfs_access().\n");
      fprintf(stderr, "%s", BLACK);
    }
    return -ENAMETOOLONG;
  }

  if (VERBOSE_BLOCKMAPFS > 2) {
    fprintf(stdout, "bmfs_readdir() entry for \"%s\".\n", pathname);
  }

  if (offset != d->offset) {
#ifndef __FreeBSD__
    seekdir(d->dp, offset);
#else
    /* Subtract the one that we add when calling
       telldir() below */
    seekdir(d->dp, offset - 1);
#endif
    d->entry = NULL;
    d->offset = offset;
  }
  while (1) {
    struct stat st;
    off_t nextoff;
    //    enum fuse_fill_dir_flags fill_flags = 0;

    if (! d->entry) {
      d->entry = readdir(d->dp);
      if (! d->entry) {
        break;
      }
    }
    /*
#ifdef HAVE_FSTATAT
    if (flags & FUSE_READDIR_PLUS) {
      int res;

      res = fstatat(dirfd(d->dp), d->entry->d_name, &st,
                    AT_SYMLINK_NOFOLLOW);
      if (res != -1)
        fill_flags |= FUSE_FILL_DIR_PLUS;
    }
#endif
    */
    //    if (!(fill_flags & FUSE_FILL_DIR_PLUS)) {
    memset(&st, 0, sizeof(st));
    st.st_ino = d->entry->d_ino;
    st.st_mode = d->entry->d_type << 12;
    //    }
    nextoff = telldir(d->dp);
#ifdef __FreeBSD__
    /* Under FreeBSD, telldir() may return 0 the first time
       it is called. But for libfuse, an offset of zero
       means that offsets are not supported, so we shift
       everything by one. */
    nextoff++;
#endif
    if (filler(buf, d->entry->d_name, &st, nextoff)) {
      break;
    }

    d->entry = NULL;
    d->offset = nextoff;
  }

  if (VERBOSE_BLOCKMAPFS > 2) {
    fprintf(stdout, "bmfs_readdir() exit for \"%s\".\n", pathname);
  }

  return 0;
}


static int bmfs_releasedir(const char *path, struct fuse_file_info *fi) {
  char pathname[PATH_MAX];  // pathname of file in root dir

  if (snprintf(pathname, sizeof(pathname), "%s%s", ROOTDIR, path) >= (int)sizeof(pathname)) {
    if (VERBOSE_BLOCKMAPFS) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr, "Pathname too long in bmfs_access().\n");
      fprintf(stderr, "%s", BLACK);
    }
    return -ENAMETOOLONG;
  }

  if (VERBOSE_BLOCKMAPFS > 2) {
    fprintf(stdout, "bmfs_releasedir() exit for \"%s\".\n", pathname);
  }

  struct bmfs_dirp *d = get_dirp(fi);
  closedir(d->dp);
  free(d);

  if (VERBOSE_BLOCKMAPFS > 2) {
    fprintf(stdout, "bmfs_releasedir() exit for \"%s\".\n", pathname);
  }

  return 0;
}


int main(int argc, char *argv[]) {
  umask(0);
  char **newargv;
  char *mnt;
  char *root;

#if DISABLE_COLOR > 0
  DISABLE_ALL_COLOR;
#endif

  // don't use color for redirected output
  if (! isatty(1) || ! isatty(2)) {
    DISABLE_ALL_COLOR;
  }

  blockmapfs_logo();
  fprintf(stderr, "%s", BLUE);
  fprintf(stderr, BLOCKMAPFS_BANNER_STRING);
  fprintf(stderr, "%s", BLACK);
  fprintf(stderr, "\n\n");

  if ((argc != 3) || (argv[argc - 2][0] == '-') || (argv[argc - 1][0] == '-')) {
    fprintf(stderr, "%s", BLUE);
    fprintf(stderr, "Usage: blockmapfs mnt root\n\n");
    fprintf(stderr, "%s", BLACK);
    return -1;
  }
  else {
    mnt = realpath(argv[argc - 2], NULL);
    root = realpath(argv[argc - 1], NULL);
    if (! mnt) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr, "Specified mount point not found, aborting.\n");
      fprintf(stderr, "%s", BLACK);
      return -1;
    }
    else if (! root) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr, "Specified root directory not found, aborting.\n");
      fprintf(stderr, "%s", BLACK);
      return -1;
    }
    else {
      if (snprintf(MOUNTDIR, sizeof(MOUNTDIR), "%s/", mnt) >= (int)sizeof(MOUNTDIR) ||
          snprintf(ROOTDIR, sizeof(ROOTDIR), "%s/", root) >= (int)sizeof(ROOTDIR)) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "Resolved paths too long, aborting.\n");
        fprintf(stderr, "%s", BLACK);
        free(mnt);
        free(root);
        return -1;
      }
      free(mnt);
      free(root);
    }
  }

  // initialize global hash table that maps pathnames to File
  // structures. This is required for FUSE callbacks that don't pass
  // the struct fuse_file_info argument, which is used to maintain
  // info about open files.

  oa_key_ops oa_key_ops_file = {
      .hash = oa_string_hash,
      .cp = oa_string_cp,
      .free = oa_string_free,
      .eq = oa_string_eq,
      .serialize = NULL,
      .size_of = oa_string_sizeof};

  oa_val_ops oa_val_ops_file = {
      .cp = oa_File_cp,
      .free = oa_File_free,
      .serialize = NULL,
      .size_of = NULL};

  HASHTABLE = oa_hash_new(oa_key_ops_file, oa_val_ops_file);

  // construct new argv[] for fuse_main that turns off multithreading
  // and provides mount point.
  //
  // Multithreading likely won't result in much improvement for the
  // typical use cases for blockmapfs, and would require locks to
  // protect hash table and blockmap updates, which would tremendously
  // complicate the design.  Thus: DO NOT remove the "-s" or very bad
  // things will happen, as the current FUSE callback functions and
  // hash table implementation are NOT thread-safe.

  fprintf(stdout, "%s", BLUE);
  fprintf(stdout, "Greetings from the blockmapfs filesystem on mount point \n\"%s\" with source \n\"%s\".\n",
          MOUNTDIR, ROOTDIR);
  fprintf(stdout, "%s", BLACK);

  newargv = malloc(sizeof(char *) * (VERBOSE_BLOCKMAPFS ? 4 : 3));
  newargv[0] = argv[0];
  newargv[1] = "-s";

  if (! VERBOSE_BLOCKMAPFS) {
    newargv[2] = MOUNTDIR;
  }
  else {
    newargv[2] = VERBOSE_BLOCKMAPFS < 3 ? "-f" : "-d";
    newargv[3] = MOUNTDIR;
  }

  return fuse_main(VERBOSE_BLOCKMAPFS ? 4 : 3 /*argc*/, newargv, &bmfs_operations, NULL);

  oa_hash_free(&HASHTABLE);
}

