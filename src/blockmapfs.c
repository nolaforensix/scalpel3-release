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

// scalpel3's read-only, blockmap-aware FUSE filesystem.
//
// updated 4/2024 to handle scalpel3's new blockmap format, documented
// in "blockmap.h".
//
// updated 2/2025 to use hashv2.
//
// updated 9/2025 to use hashv4.
//
// updated 7/2026 for FUSE 3, multithreaded dispatch, compact immutable
// blockmap caching, and independent per-open file handles.
//
// Install FUSE 3 development files on Linux or macFUSE with FUSE 3 support on
// macOS before using blockmapfs. The build includes this optional utility when
// the platform development files are available.
//
// build with the platform Makefile selected by init_scalpel3.sh.
//
// regular files are exposed only when an adjacent regular file named
// <filename>.blockmap exists. Blockmaps, unmapped files, and symbolic links
// are hidden from the mounted view.
//
// source files and blockmaps must not be modified while blockmapfs is mounted.
// immutable effective coverage and offset indexes are cached after first
// access. Unmount, make changes, and remount to publish a new view.
//
// set VERBOSE_BLOCKMAPFS to:
// 0 for normal background operation
// 1 or 2 for foreground operation with blockmapfs diagnostics
// 3 or greater for foreground operation with libfuse debugging

#ifndef VERBOSE_BLOCKMAPFS
#define VERBOSE_BLOCKMAPFS 0
#endif

#define FUSE_USE_VERSION 31

#ifdef __APPLE__
#define FUSE_DARWIN_ENABLE_EXTENSIONS 0
#endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE 1
#include <fuse.h>

#if FUSE_MAJOR_VERSION < 3
#error "blockmapfs requires FUSE 3"
#endif

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>
#define SCALPEL3_EXTERNAL 1
#include "scalpel.h"
#include "blockmap.h"
#include "blockmapfs_index.h"
#include "colors.h"
#include "hashv4.h"
#include "scalpelv.h"
#define BLOCKMAPFS_BANNER_STRING \
  "blockmapfs v%s -- Written by Golden G. Richard III (@nolaforensix)."

#define BLOCKMAP_SUFFIX ".blockmap"

#ifndef NAME_MAX
#define NAME_MAX 255
#endif

// immutable metadata cached for a mapped source file
typedef struct CachedFile {
  atomic_uint_fast64_t references;
  unsigned char *coverage;
  BmfsOffsetIndex offset_index;
  struct stat source_identity;
  struct stat blockmap_identity;
} CachedFile;

// private state for one successful FUSE open operation
typedef struct OpenFile {
  atomic_bool ready;
  CachedFile *cached;
  int fd;
} OpenFile;

// source and companion blockmap opened relative to the configured root
typedef struct OpenedMappedFile {
  int source_fd;
  int blockmap_fd;
  struct stat source_stat;
  struct stat blockmap_stat;
} OpenedMappedFile;

// state owned for the complete lifetime of one mounted filesystem
typedef struct BmfsState {
  char *root_path;
  char *mount_path;
  int root_fd;
  oa_hash *cache;
  pthread_mutex_t cache_load_lock;
} BmfsState;

// private state for one successful FUSE opendir operation
typedef struct BmfsDirectory {
  atomic_bool ready;
  DIR *dp;
  struct dirent *entry;
  off_t offset;
  pthread_mutex_t lock;
} BmfsDirectory;

// blockmapfs FUSE callback functions
static void *bmfs_init(struct fuse_conn_info *conn, struct fuse_config *cfg);
static int bmfs_getattr(const char *path, struct stat *stbuf,
                        struct fuse_file_info *fi);
static int bmfs_open(const char *path, struct fuse_file_info *fi);
static OpenFile *bmfs_get_open_file(struct fuse_file_info *fi);
static int bmfs_read(const char *path, char *buf, size_t size, off_t seekpos,
                     struct fuse_file_info *fi);
static int bmfs_release(const char *path, struct fuse_file_info *fi);
static int bmfs_statfs(const char *path, struct statvfs *stbuf);
static int bmfs_opendir(const char *path, struct fuse_file_info *fi);
static BmfsDirectory *bmfs_get_directory(struct fuse_file_info *fi);
static int bmfs_readdir(const char *p, void *buf, fuse_fill_dir_t filler,
                        off_t offset, struct fuse_file_info *fi,
                        enum fuse_readdir_flags flags);
static int bmfs_releasedir(const char *path, struct fuse_file_info *fi);

// other function prototypes
static void blockmapfs_logo(void);
static void *oa_cached_file_cp(const void *data);
static void oa_cached_file_free(void **data);
static bool bmfs_block_covered(void *context, uint64_t blocknumber);
static bool bmfs_capture_block_coverage(void *context, uint64_t blocknumber);
static int bmfs_directory_contains(int ancestor_fd, int directory_fd,
                                   bool *contains);


// operations for *read-only* blockmapfs filesystem
static const struct fuse_operations bmfs_operations = {
    .init = bmfs_init,
    .getattr = bmfs_getattr,
    .opendir = bmfs_opendir,
    .readdir = bmfs_readdir,
    .releasedir = bmfs_releasedir,
    .open = bmfs_open,
    .read = bmfs_read,
    .release = bmfs_release,
    .statfs = bmfs_statfs,
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


// cache and path helpers

typedef struct CoverageCapture {
  Blockmap *blockmap;
  CachedFile *cached;
} CoverageCapture;


// return the mount-owned state associated with the current FUSE request.
static BmfsState *bmfs_get_state(void) {
  struct fuse_context *context = fuse_get_context();

  return context ? (BmfsState *)context->private_data : NULL;
}


// determine whether a directory entry has the reserved blockmap suffix.
static bool bmfs_has_blockmap_suffix(const char *name) {
  size_t length;
  size_t suffix_length = strlen(BLOCKMAP_SUFFIX);

  if (! name) {
    return false;
  }
  length = strlen(name);
  return length >= suffix_length
         && ! strcmp(name + length - suffix_length, BLOCKMAP_SUFFIX);
}


// compare the identity and modification state of two open filesystem objects.
static bool bmfs_same_file(const struct stat *left, const struct stat *right) {
  if (! left || ! right
      || left->st_dev != right->st_dev
      || left->st_ino != right->st_ino
      || left->st_mode != right->st_mode
      || left->st_size != right->st_size) {
    return false;
  }

#if defined(__APPLE__)
  return left->st_mtimespec.tv_sec == right->st_mtimespec.tv_sec
         && left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec
         && left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec
         && left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec;
#elif defined(__linux__)
  return left->st_mtim.tv_sec == right->st_mtim.tv_sec
         && left->st_mtim.tv_nsec == right->st_mtim.tv_nsec
         && left->st_ctim.tv_sec == right->st_ctim.tv_sec
         && left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
#else
  return true;
#endif
}


// determine directory ancestry from open descriptors rather than path spelling.
static int bmfs_directory_contains(int ancestor_fd, int directory_fd,
                                   bool *contains) {
  struct stat ancestor_stat;
  int current_fd = -1;
  int result = 0;

  if (ancestor_fd < 0 || directory_fd < 0 || ! contains) {
    return -EINVAL;
  }
  *contains = false;

  if (fstat(ancestor_fd, &ancestor_stat)) {
    return -errno;
  }
  current_fd = openat(directory_fd, ".",
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (current_fd < 0) {
    return -errno;
  }

  while (1) {
    struct stat current_stat;
    struct stat parent_stat;
    int parent_fd;

    if (fstat(current_fd, &current_stat)) {
      result = -errno;
      break;
    }
    if (ancestor_stat.st_dev == current_stat.st_dev
        && ancestor_stat.st_ino == current_stat.st_ino) {
      *contains = true;
      break;
    }

    parent_fd = openat(current_fd, "..",
                       O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (parent_fd < 0) {
      result = -errno;
      break;
    }
    if (fstat(parent_fd, &parent_stat)) {
      result = -errno;
      close(parent_fd);
      break;
    }
    if (parent_stat.st_dev == current_stat.st_dev
        && parent_stat.st_ino == current_stat.st_ino) {
      close(parent_fd);
      break;
    }

    close(current_fd);
    current_fd = parent_fd;
  }

  close(current_fd);
  return result;
}


// resolve every parent component without following symbolic links.
static int bmfs_resolve_parent(const BmfsState *state, const char *path,
                               int *parent_fd, char name[NAME_MAX + 1]) {
  const char *cursor;
  int current_fd;

  if (! state || state->root_fd < 0 || ! path || path[0] != '/'
      || ! parent_fd || ! name) {
    return -EINVAL;
  }

  *parent_fd = -1;
  name[0] = '\0';
  current_fd = openat(state->root_fd, ".",
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (current_fd < 0) {
    return -errno;
  }

  cursor = path + 1;
  while (*cursor == '/') {
    cursor++;
  }
  if (! *cursor) {
    *parent_fd = current_fd;
    return 0;
  }

  while (*cursor) {
    const char *start = cursor;
    const char *next;
    char component[NAME_MAX + 1];
    size_t length;
    int next_fd;

    while (*cursor && *cursor != '/') {
      cursor++;
    }
    length = (size_t)(cursor - start);
    if (! length || length > NAME_MAX) {
      close(current_fd);
      return -ENAMETOOLONG;
    }
    memcpy(component, start, length);
    component[length] = '\0';
    if (! strcmp(component, ".") || ! strcmp(component, "..")) {
      close(current_fd);
      return -EINVAL;
    }

    next = cursor;
    while (*next == '/') {
      next++;
    }
    if (! *next) {
      memcpy(name, component, length + 1);
      *parent_fd = current_fd;
      return 0;
    }

    next_fd = openat(current_fd, component,
                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (next_fd < 0) {
      int saved_errno = errno;

      close(current_fd);
      return -saved_errno;
    }
    close(current_fd);
    current_fd = next_fd;
    cursor = next;
  }

  close(current_fd);
  return -EINVAL;
}


// read attributes without following a final symbolic link.
static int bmfs_stat_path(const BmfsState *state, const char *path,
                          struct stat *stbuf) {
  char name[NAME_MAX + 1];
  int parent_fd;
  int result;

  result = bmfs_resolve_parent(state, path, &parent_fd, name);
  if (result) {
    return result;
  }

  if (! name[0]) {
    result = fstat(parent_fd, stbuf);
  }
  else {
    result = fstatat(parent_fd, name, stbuf, AT_SYMLINK_NOFOLLOW);
  }
  if (result) {
    result = -errno;
  }
  close(parent_fd);
  return result;
}


// open a directory below the root without following symbolic links.
static int bmfs_open_directory(const BmfsState *state, const char *path) {
  char name[NAME_MAX + 1];
  int parent_fd;
  int result;
  int fd;

  result = bmfs_resolve_parent(state, path, &parent_fd, name);
  if (result) {
    return result;
  }
  if (! name[0]) {
    return parent_fd;
  }

  fd = openat(parent_fd, name,
              O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0) {
    result = -errno;
  }
  close(parent_fd);
  return fd < 0 ? result : fd;
}


// close every descriptor owned by a mapped-file pair.
static void bmfs_close_mapped_file(OpenedMappedFile *opened) {
  if (! opened) {
    return;
  }
  if (opened->source_fd >= 0) {
    close(opened->source_fd);
  }
  if (opened->blockmap_fd >= 0) {
    close(opened->blockmap_fd);
  }
  memset(opened, 0, sizeof(*opened));
  opened->source_fd = -1;
  opened->blockmap_fd = -1;
}


// open a regular source and its adjacent regular blockmap without following links.
static int bmfs_open_mapped_file(const BmfsState *state, const char *path,
                                 OpenedMappedFile *opened) {
  char blockmap_name[NAME_MAX + 1];
  char name[NAME_MAX + 1];
  struct stat source_lstat;
  struct stat blockmap_lstat;
  size_t name_length;
  size_t suffix_length = strlen(BLOCKMAP_SUFFIX);
  int parent_fd = -1;
  int result;

  if (! opened) {
    return -EINVAL;
  }
  memset(opened, 0, sizeof(*opened));
  opened->source_fd = -1;
  opened->blockmap_fd = -1;

  result = bmfs_resolve_parent(state, path, &parent_fd, name);
  if (result) {
    return result;
  }
  if (! name[0] || bmfs_has_blockmap_suffix(name)) {
    result = -ENOENT;
    goto done;
  }

  if (fstatat(parent_fd, name, &source_lstat, AT_SYMLINK_NOFOLLOW)) {
    result = -errno;
    goto done;
  }
  if (! S_ISREG(source_lstat.st_mode)) {
    result = -ENOENT;
    goto done;
  }

  opened->source_fd =
      openat(parent_fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (opened->source_fd < 0) {
    result = -errno;
    goto done;
  }
  if (fstat(opened->source_fd, &opened->source_stat)) {
    result = -errno;
    goto done;
  }
  if (! bmfs_same_file(&source_lstat, &opened->source_stat)) {
    result = -ESTALE;
    goto done;
  }

  name_length = strlen(name);
  if (name_length > NAME_MAX - suffix_length) {
    result = -ENAMETOOLONG;
    goto done;
  }
  memcpy(blockmap_name, name, name_length);
  memcpy(blockmap_name + name_length, BLOCKMAP_SUFFIX, suffix_length + 1);

  if (fstatat(parent_fd, blockmap_name, &blockmap_lstat,
              AT_SYMLINK_NOFOLLOW)) {
    result = -errno;
    goto done;
  }
  if (! S_ISREG(blockmap_lstat.st_mode)) {
    result = -ENOENT;
    goto done;
  }

  opened->blockmap_fd =
      openat(parent_fd, blockmap_name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (opened->blockmap_fd < 0) {
    result = -errno;
    goto done;
  }
  if (fstat(opened->blockmap_fd, &opened->blockmap_stat)) {
    result = -errno;
    goto done;
  }
  if (! bmfs_same_file(&blockmap_lstat, &opened->blockmap_stat)) {
    result = -ESTALE;
    goto done;
  }

  result = 0;

done:
  if (parent_fd >= 0) {
    close(parent_fd);
  }
  if (result) {
    bmfs_close_mapped_file(opened);
  }
  return result;
}


// retain one reference to immutable cached metadata.
static void bmfs_cached_file_retain(CachedFile *cached) {
  if (cached) {
    atomic_fetch_add_explicit(&cached->references, 1, memory_order_relaxed);
  }
}


// release one reference and destroy unreferenced cached metadata.
static void bmfs_cached_file_release(CachedFile **cached_ptr) {
  CachedFile *cached;

  if (! cached_ptr || ! *cached_ptr) {
    return;
  }
  cached = *cached_ptr;
  *cached_ptr = NULL;
  if (atomic_fetch_sub_explicit(&cached->references, 1,
                                memory_order_acq_rel) != 1) {
    return;
  }

  free(cached->coverage);
  bmfs_offset_index_destroy(&cached->offset_index);
  free(cached);
}


// retain immutable metadata when hashv4 copies a cache value.
static void *oa_cached_file_cp(const void *data) {
  CachedFile *cached = (CachedFile *)data;

  bmfs_cached_file_retain(cached);
  return cached;
}


// release immutable metadata when hashv4 destroys a cache value.
static void oa_cached_file_free(void **data) {
  CachedFile *cached = data ? (CachedFile *)*data : NULL;

  bmfs_cached_file_release(&cached);
  if (data) {
    *data = NULL;
  }
}


// report immutable effective coverage through the offset-index interface.
static bool bmfs_block_covered(void *context, uint64_t blocknumber) {
  CachedFile *cached = (CachedFile *)context;

  return ! cached || blocknumber >= cached->offset_index.numblocks
         || (cached->coverage[blocknumber / 8]
             & (unsigned char)(1U << (blocknumber % 8)));
}


// capture final deduplication-aware coverage while the full blockmap is private.
static bool bmfs_capture_block_coverage(void *context, uint64_t blocknumber) {
  CoverageCapture *capture = (CoverageCapture *)context;
  bool covered;

  covered = blocknumber >= capture->blockmap->numblocks
            || is_block_covered(capture->blockmap,
                                (int64_t)blocknumber);
  if (covered && blocknumber < capture->blockmap->numblocks) {
    capture->cached->coverage[blocknumber / 8] |=
        (unsigned char)(1U << (blocknumber % 8));
  }
  return covered;
}


// verify that cached metadata still describes the opened backing objects.
static bool bmfs_cached_file_matches(const CachedFile *cached,
                                     const OpenedMappedFile *opened) {
  return cached && opened
         && bmfs_same_file(&cached->source_identity, &opened->source_stat)
         && bmfs_same_file(&cached->blockmap_identity,
                           &opened->blockmap_stat);
}


// parse a blockmap and convert it to immutable compact cache metadata.
static int bmfs_load_cached_file(const char *path,
                                 const OpenedMappedFile *opened,
                                 CachedFile **cached_ptr) {
  Blockmap *blockmap = NULL;
  CachedFile *cached = NULL;
  CoverageCapture capture;
  struct stat final_blockmap_stat;
  struct stat final_source_stat;
  uint64_t coverage_length;
  uint64_t expected_blocks;
  int result = -EIO;

  if (! path || ! opened || opened->source_fd < 0
      || opened->blockmap_fd < 0 || opened->source_stat.st_size < 0
      || ! cached_ptr) {
    return -EINVAL;
  }
  *cached_ptr = NULL;

  cached = (CachedFile *)calloc(1, sizeof(*cached));
  if (! cached) {
    return -ENOMEM;
  }
  atomic_init(&cached->references, 1);

  errno = 0;
  if (! read_blockmap_h(&blockmap, opened->blockmap_fd)) {
    result = errno == ENOMEM ? -ENOMEM : -EIO;
    goto done;
  }

  expected_blocks = opened->source_stat.st_size
                        ? 1 + ((uint64_t)opened->source_stat.st_size - 1)
                                  / blockmap->blocksize
                        : 0;
  if (expected_blocks != blockmap->numblocks) {
    if (VERBOSE_BLOCKMAPFS) {
      fprintf(stderr,
              "Blockmap for \"%s\" contains %" PRIu64
              " blocks; source requires %" PRIu64 ".\n",
              path, blockmap->numblocks, expected_blocks);
    }
    goto done;
  }

  coverage_length =
      blockmap->numblocks / 8 + (blockmap->numblocks % 8 != 0);
  if (coverage_length != (size_t)coverage_length) {
    result = -EOVERFLOW;
    goto done;
  }
  cached->coverage = (unsigned char *)calloc(
      coverage_length ? (size_t)coverage_length : 1, 1);
  if (! cached->coverage) {
    result = -ENOMEM;
    goto done;
  }

  capture.blockmap = blockmap;
  capture.cached = cached;
  errno = 0;
  if (! bmfs_offset_index_build(&cached->offset_index,
                                blockmap->numblocks,
                                blockmap->blocksize,
                                (uint64_t)opened->source_stat.st_size,
                                bmfs_capture_block_coverage,
                                &capture)) {
    result = errno == ENOMEM ? -ENOMEM : -EIO;
    goto done;
  }

  if (fstat(opened->source_fd, &final_source_stat)
      || fstat(opened->blockmap_fd, &final_blockmap_stat)) {
    result = -errno;
    goto done;
  }
  if (! bmfs_same_file(&opened->source_stat, &final_source_stat)
      || ! bmfs_same_file(&opened->blockmap_stat,
                          &final_blockmap_stat)) {
    result = -ESTALE;
    goto done;
  }

  cached->source_identity = opened->source_stat;
  cached->blockmap_identity = opened->blockmap_stat;
  *cached_ptr = cached;
  cached = NULL;
  result = 0;

done:
  free_blockmap(&blockmap);
  bmfs_cached_file_release(&cached);
  return result;
}


// retrieve or atomically publish one immutable cache entry for a pathname.
static int bmfs_get_cached_file(BmfsState *state, const char *path,
                                const OpenedMappedFile *opened,
                                CachedFile **cached_ptr) {
  CachedFile *cached;
  int lock_result;
  int result;

  if (! state || ! path || ! opened || ! cached_ptr) {
    return -EINVAL;
  }
  *cached_ptr = NULL;

  cached = (CachedFile *)oa_hash_get_copy(state->cache, path);
  if (cached) {
    if (! bmfs_cached_file_matches(cached, opened)) {
      bmfs_cached_file_release(&cached);
      return -ESTALE;
    }
    *cached_ptr = cached;
    return 0;
  }

  lock_result = pthread_mutex_lock(&state->cache_load_lock);
  if (lock_result) {
    return -lock_result;
  }

  cached = (CachedFile *)oa_hash_get_copy(state->cache, path);
  if (cached) {
    if (! bmfs_cached_file_matches(cached, opened)) {
      bmfs_cached_file_release(&cached);
      result = -ESTALE;
      goto done;
    }
    *cached_ptr = cached;
    result = 0;
    goto done;
  }

  result = bmfs_load_cached_file(path, opened, &cached);
  if (result) {
    goto done;
  }
  if (! oa_hash_put(state->cache, path, cached)) {
    result = -ENOMEM;
    bmfs_cached_file_release(&cached);
    goto done;
  }

  *cached_ptr = cached;
  result = 0;

done:
  pthread_mutex_unlock(&state->cache_load_lock);
  return result;
}


// replace source size fields with their compacted visible values.
static void bmfs_set_visible_stat(struct stat *stbuf,
                                  const CachedFile *cached) {
  uint64_t visible_size = cached->offset_index.visible_size;

  stbuf->st_size = (off_t)visible_size;
  stbuf->st_blocks =
      (blkcnt_t)(visible_size / 512 + (visible_size % 512 != 0));
}


// blockmapfs FUSE callback functions

// enable stable kernel caching for the documented immutable backing view.
static void *bmfs_init(struct fuse_conn_info *conn, struct fuse_config *cfg) {
  struct fuse_context *context = fuse_get_context();

  (void)conn;
  cfg->kernel_cache = 1;
  return context ? context->private_data : NULL;
}


// return source attributes with the blockmap-compacted visible size.
static int bmfs_getattr(const char *path, struct stat *stbuf,
                        struct fuse_file_info *fi) {
  BmfsState *state = bmfs_get_state();
  OpenedMappedFile opened;
  CachedFile *cached = NULL;
  struct stat source_stat;
  const char *name;
  int result;

  if (! state || ! path || ! stbuf) {
    return -EINVAL;
  }
  memset(stbuf, 0, sizeof(*stbuf));

  if (fi && fi->fh) {
    OpenFile *open_file = bmfs_get_open_file(fi);

    if (! open_file) {
      return -EIO;
    }
    if (fstat(open_file->fd, &source_stat)) {
      return -errno;
    }
    if (! bmfs_same_file(&open_file->cached->source_identity,
                         &source_stat)) {
      return -ESTALE;
    }
    *stbuf = source_stat;
    bmfs_set_visible_stat(stbuf, open_file->cached);
    return 0;
  }

  result = bmfs_stat_path(state, path, &source_stat);
  if (result) {
    return result;
  }
  if (S_ISDIR(source_stat.st_mode)) {
    *stbuf = source_stat;
    return 0;
  }
  name = strrchr(path, '/');
  name = name ? name + 1 : path;
  if (! S_ISREG(source_stat.st_mode)
      || bmfs_has_blockmap_suffix(name)) {
    return -ENOENT;
  }

  result = bmfs_open_mapped_file(state, path, &opened);
  if (result) {
    return result;
  }
  result = bmfs_get_cached_file(state, path, &opened, &cached);
  if (! result) {
    *stbuf = opened.source_stat;
    bmfs_set_visible_stat(stbuf, cached);
  }

  bmfs_cached_file_release(&cached);
  bmfs_close_mapped_file(&opened);
  return result;
}


// create one independent read-only handle for each successful FUSE open.
static int bmfs_open(const char *path, struct fuse_file_info *fi) {
  BmfsState *state = bmfs_get_state();
  OpenedMappedFile opened;
  CachedFile *cached = NULL;
  OpenFile *open_file = NULL;
  int result;

  if (! state || ! path || ! fi) {
    return -EINVAL;
  }
  if ((fi->flags & O_ACCMODE) != O_RDONLY
      || (fi->flags & (O_APPEND | O_TRUNC))) {
    return -EROFS;
  }

  result = bmfs_open_mapped_file(state, path, &opened);
  if (result) {
    return result;
  }
  result = bmfs_get_cached_file(state, path, &opened, &cached);
  if (result) {
    goto done;
  }

  open_file = (OpenFile *)calloc(1, sizeof(*open_file));
  if (! open_file) {
    result = -ENOMEM;
    goto done;
  }
  atomic_init(&open_file->ready, false);
  open_file->fd = opened.source_fd;
  opened.source_fd = -1;
  open_file->cached = cached;
  cached = NULL;

  atomic_store_explicit(&open_file->ready, true, memory_order_release);
  fi->fh = (uint64_t)(uintptr_t)open_file;
  fi->keep_cache = 1;
  result = 0;

done:
  bmfs_cached_file_release(&cached);
  bmfs_close_mapped_file(&opened);
  if (result) {
    free(open_file);
  }
  return result;
}


// acquire initialization published by the FUSE open callback.
static OpenFile *bmfs_get_open_file(struct fuse_file_info *fi) {
  OpenFile *open_file;

  if (! fi || ! fi->fh) {
    return NULL;
  }
  open_file = (OpenFile *)(uintptr_t)fi->fh;
  return atomic_load_explicit(&open_file->ready, memory_order_acquire)
             ? open_file
             : NULL;
}


// read the compacted view using immutable metadata and a per-open descriptor.
static int bmfs_read(const char *path, char *buf, size_t size, off_t seekpos,
                     struct fuse_file_info *fi) {
  OpenFile *open_file;
  ssize_t bytesread;
  int saved_errno;

  (void)path;

  if (! buf) {
    return -EINVAL;
  }
  if (seekpos < 0) {
    return -EINVAL;
  }
  if (size > INT_MAX) {
    size = INT_MAX;
  }

  open_file = bmfs_get_open_file(fi);
  if (! open_file) {
    return -EIO;
  }
  bytesread =
      bmfs_offset_index_pread(&open_file->cached->offset_index,
                              open_file->fd, buf, size,
                              (uint64_t)seekpos,
                              bmfs_block_covered,
                              open_file->cached);
  if (bytesread < 0) {
    saved_errno = errno ? errno : EIO;
    return -saved_errno;
  }
  return (int)bytesread;
}


// close and release exactly the resources allocated by one open callback.
static int bmfs_release(const char *path, struct fuse_file_info *fi) {
  OpenFile *open_file;
  int result = 0;

  (void)path;

  if (! fi || ! fi->fh) {
    return 0;
  }
  open_file = bmfs_get_open_file(fi);
  if (! open_file) {
    return -EIO;
  }
  fi->fh = 0;

  if (close(open_file->fd)) {
    result = -errno;
  }
  bmfs_cached_file_release(&open_file->cached);
  free(open_file);
  return result;
}


// report the backing filesystem capacity while preserving read-only semantics.
static int bmfs_statfs(const char *path, struct statvfs *stbuf) {
  BmfsState *state = bmfs_get_state();

  (void)path;

  if (! state || ! stbuf) {
    return -EINVAL;
  }
  if (fstatvfs(state->root_fd, stbuf)) {
    return -errno;
  }
#ifdef ST_RDONLY
  stbuf->f_flag |= ST_RDONLY;
#endif
  return 0;
}


// allocate an independent directory stream for one FUSE directory handle.
static int bmfs_opendir(const char *path, struct fuse_file_info *fi) {
  BmfsState *state = bmfs_get_state();
  BmfsDirectory *directory = NULL;
  int lock_result;
  int fd;

  if (! state || ! path || ! fi) {
    return -EINVAL;
  }
  fd = bmfs_open_directory(state, path);
  if (fd < 0) {
    return fd;
  }

  directory = (BmfsDirectory *)calloc(1, sizeof(*directory));
  if (! directory) {
    close(fd);
    return -ENOMEM;
  }
  atomic_init(&directory->ready, false);
  lock_result = pthread_mutex_init(&directory->lock, NULL);
  if (lock_result) {
    close(fd);
    free(directory);
    return -lock_result;
  }
  directory->dp = fdopendir(fd);
  if (! directory->dp) {
    int saved_errno = errno;

    close(fd);
    pthread_mutex_destroy(&directory->lock);
    free(directory);
    return -saved_errno;
  }

  atomic_store_explicit(&directory->ready, true, memory_order_release);
  fi->fh = (uint64_t)(uintptr_t)directory;
  return 0;
}


// return the private directory state associated with a FUSE handle.
static BmfsDirectory *bmfs_get_directory(struct fuse_file_info *fi) {
  BmfsDirectory *directory;

  if (! fi || ! fi->fh) {
    return NULL;
  }
  directory = (BmfsDirectory *)(uintptr_t)fi->fh;
  return atomic_load_explicit(&directory->ready, memory_order_acquire)
             ? directory
             : NULL;
}


// determine whether a directory entry belongs in the mounted view.
static int bmfs_directory_entry_visible(int directory_fd, const char *name,
                                        struct stat *entry_stat) {
  char blockmap_name[NAME_MAX + 1];
  struct stat blockmap_stat;
  size_t length;
  size_t suffix_length = strlen(BLOCKMAP_SUFFIX);

  if (fstatat(directory_fd, name, entry_stat, AT_SYMLINK_NOFOLLOW)) {
    return -errno;
  }
  if (S_ISDIR(entry_stat->st_mode)) {
    return 1;
  }
  if (! S_ISREG(entry_stat->st_mode) || bmfs_has_blockmap_suffix(name)) {
    return 0;
  }

  length = strlen(name);
  if (length > NAME_MAX - suffix_length) {
    return 0;
  }
  memcpy(blockmap_name, name, length);
  memcpy(blockmap_name + length, BLOCKMAP_SUFFIX, suffix_length + 1);
  if (fstatat(directory_fd, blockmap_name, &blockmap_stat,
              AT_SYMLINK_NOFOLLOW)) {
    return errno == ENOENT || errno == ENOTDIR ? 0 : -errno;
  }
  return S_ISREG(blockmap_stat.st_mode) ? 1 : 0;
}


// enumerate visible directory entries with a serialized per-handle cursor.
static int bmfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                        off_t offset, struct fuse_file_info *fi,
                        enum fuse_readdir_flags flags) {
  BmfsDirectory *directory = bmfs_get_directory(fi);
  int lock_result;
  int result = 0;

  (void)path;
  (void)flags;

  if (! directory || ! buf || ! filler) {
    return -EINVAL;
  }
  lock_result = pthread_mutex_lock(&directory->lock);
  if (lock_result) {
    return -lock_result;
  }

  if (offset != directory->offset) {
#ifndef __FreeBSD__
    seekdir(directory->dp, offset);
#else
    // subtract the offset adjustment applied after telldir() below.
    seekdir(directory->dp, offset - 1);
#endif
    directory->entry = NULL;
    directory->offset = offset;
  }

  while (1) {
    struct stat entry_stat;
    struct stat filler_stat;
    off_t next_offset;
    int visible;

    if (! directory->entry) {
      errno = 0;
      directory->entry = readdir(directory->dp);
      if (! directory->entry) {
        result = errno ? -errno : 0;
        break;
      }
    }

    errno = 0;
    next_offset = telldir(directory->dp);
    if (next_offset == (off_t)-1 && errno) {
      result = -errno;
      break;
    }
#ifdef __FreeBSD__
    // reserve zero to mean that directory offsets are unsupported.
    next_offset++;
#endif

    visible = bmfs_directory_entry_visible(
        dirfd(directory->dp), directory->entry->d_name, &entry_stat);
    if (visible < 0) {
      result = visible;
      break;
    }
    if (! visible) {
      directory->entry = NULL;
      directory->offset = next_offset;
      continue;
    }

    memset(&filler_stat, 0, sizeof(filler_stat));
    filler_stat.st_ino = entry_stat.st_ino;
    filler_stat.st_mode = entry_stat.st_mode;
    if (filler(buf, directory->entry->d_name, &filler_stat, next_offset,
               (enum fuse_fill_dir_flags)0)) {
      break;
    }

    directory->entry = NULL;
    directory->offset = next_offset;
  }

  pthread_mutex_unlock(&directory->lock);
  return result;
}


// close and release exactly the resources allocated by one opendir callback.
static int bmfs_releasedir(const char *path, struct fuse_file_info *fi) {
  BmfsDirectory *directory = bmfs_get_directory(fi);
  int result = 0;

  (void)path;

  if (! directory) {
    return 0;
  }
  fi->fh = 0;
  if (closedir(directory->dp)) {
    result = -errno;
  }
  pthread_mutex_destroy(&directory->lock);
  free(directory);
  return result;
}


int main(int argc, char *argv[]) {
  BmfsState state = {
      .root_fd = -1,
  };
  char *fuse_argv[6];
  bool contains;
  int check_result;
  int fuse_argc = 0;
  int lock_result;
  int mount_fd = -1;
  int result = EXIT_FAILURE;

#if DISABLE_COLOR > 0
  DISABLE_ALL_COLOR;
#endif

  // don't use color for redirected output
  if (! isatty(1) || ! isatty(2)) {
    DISABLE_ALL_COLOR;
  }

  blockmapfs_logo();
  fprintf(stderr, "%s", BLUE);
  fprintf(stderr, BLOCKMAPFS_BANNER_STRING, SCALPEL_VERSION);
  fprintf(stderr, "%s", BLACK);
  fprintf(stderr, "\n\n");

  if (argc != 3 || argv[1][0] == '-' || argv[2][0] == '-') {
    fprintf(stderr, "%s", BLUE);
    fprintf(stderr, "Usage: blockmapfs mnt root\n\n");
    fprintf(stderr, "%s", BLACK);
    return EXIT_FAILURE;
  }

  state.mount_path = realpath(argv[1], NULL);
  if (! state.mount_path) {
    fprintf(stderr, "%sSpecified mount point is unavailable: %s.%s\n",
            RED, strerror(errno), BLACK);
    goto done;
  }
  state.root_path = realpath(argv[2], NULL);
  if (! state.root_path) {
    fprintf(stderr, "%sSpecified root directory is unavailable: %s.%s\n",
            RED, strerror(errno), BLACK);
    goto done;
  }
  mount_fd = open(state.mount_path,
                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (mount_fd < 0) {
    fprintf(stderr, "%sCould not open the mount point: %s.%s\n",
            RED, strerror(errno), BLACK);
    goto done;
  }
  state.root_fd = open(state.root_path,
                       O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (state.root_fd < 0) {
    fprintf(stderr, "%sCould not open the root directory: %s.%s\n",
            RED, strerror(errno), BLACK);
    goto done;
  }

  check_result = bmfs_directory_contains(state.root_fd, mount_fd, &contains);
  if (! check_result && ! contains) {
    check_result =
        bmfs_directory_contains(mount_fd, state.root_fd, &contains);
  }
  if (check_result) {
    fprintf(stderr, "%sCould not validate directory ancestry: %s.%s\n",
            RED, strerror(-check_result), BLACK);
    goto done;
  }
  if (contains) {
    fprintf(stderr,
            "%sMount point and root directory must not overlap.%s\n",
            RED, BLACK);
    goto done;
  }
  close(mount_fd);
  mount_fd = -1;

  oa_key_ops oa_key_ops_file = {
      .hash = oa_string_hash,
      .cp = oa_string_cp,
      .free = oa_string_free,
      .eq = oa_string_eq,
      .serialize = NULL,
      .size_of = oa_string_sizeof};

  oa_val_ops oa_val_ops_file = {
      .cp = oa_cached_file_cp,
      .free = oa_cached_file_free,
      .serialize = NULL,
      .size_of = NULL};

  state.cache = oa_hash_new(oa_key_ops_file, oa_val_ops_file);
  if (! state.cache) {
    fprintf(stderr, "%sCould not allocate the blockmap cache.%s\n",
            RED, BLACK);
    goto done;
  }
  lock_result = pthread_mutex_init(&state.cache_load_lock, NULL);
  if (lock_result) {
    fprintf(stderr, "%sCould not initialize the blockmap cache: %s.%s\n",
            RED, strerror(lock_result), BLACK);
    goto done;
  }

  fprintf(stdout, "%s", BLUE);
  fprintf(stdout,
          "Greetings from the blockmapfs filesystem on mount point\n"
          "\"%s\" with source\n\"%s\".\n",
          state.mount_path, state.root_path);
  fprintf(stdout, "%s", BLACK);

  // mount read-only and let FUSE use its normal multithreaded dispatcher.
  fuse_argv[fuse_argc++] = argv[0];
  fuse_argv[fuse_argc++] = "-o";
  fuse_argv[fuse_argc++] = "ro,default_permissions";
  if (VERBOSE_BLOCKMAPFS) {
    fuse_argv[fuse_argc++] = VERBOSE_BLOCKMAPFS < 3 ? "-f" : "-d";
  }
  fuse_argv[fuse_argc++] = state.mount_path;
  fuse_argv[fuse_argc] = NULL;

  fflush(NULL);
  result = fuse_main(fuse_argc, fuse_argv, &bmfs_operations, &state);

  pthread_mutex_destroy(&state.cache_load_lock);
done:
  oa_hash_free(&state.cache);
  if (mount_fd >= 0) {
    close(mount_fd);
  }
  if (state.root_fd >= 0) {
    close(state.root_fd);
  }
  free(state.root_path);
  free(state.mount_path);
  return result == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

