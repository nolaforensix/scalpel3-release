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

// Complete rewrite of prior hashv2.c by GGRIII. This version uses verstable and xxhash to increase
// performance.
//

struct oa_bucket; /* forward */

#define NAME vt_u64_bucket_map
#define KEY_TY uint64_t
#define VAL_TY struct oa_bucket *

#include "hashv4.h"
#include <sys/stat.h>
#include <unistd.h>
#include "verstable.h"
#define XXH_INLINE_ALL
#include "xxhash.h"

#if HASH_LOCK_KIND == RW
#define HASH_LOCK_T pthread_rwlock_t
#define HASH_LOCK_INIT(L) pthread_rwlock_init((L), NULL)
#define HASH_LOCK_RD(L) pthread_rwlock_rdlock((L))
#define HASH_LOCK_WR(L) pthread_rwlock_wrlock((L))
#define HASH_UNLOCK(L) pthread_rwlock_unlock((L))
#define HASH_LOCK_DESTROY(L) pthread_rwlock_destroy((L))
#elif HASH_LOCK_KIND == MUTEX
#define HASH_LOCK_T pthread_mutex_t
#define HASH_LOCK_INIT(L) pthread_mutex_init((L), NULL)
#define HASH_LOCK_RD(L) pthread_mutex_lock((L))
#define HASH_LOCK_WR(L) pthread_mutex_lock((L))
#define HASH_UNLOCK(L) pthread_mutex_unlock((L))
#define HASH_LOCK_DESTROY(L) pthread_mutex_destroy((L))
#else
#error "HASH_LOCK_KIND must be RW or MUTEX"
#endif

// hash table entry layout with optional inline storage
typedef struct {
  uint8_t k_inline[HASH_KEY_INLINE_MAX];
  uint8_t v_inline[HASH_VAL_INLINE_MAX];
  uint16_t ksz; /* 0 => pointer */
  uint16_t vsz; /* 0 => pointer */
  void *kptr;
  void *vptr;
} oa_kv;

// one hash bucket
struct oa_bucket {
  size_t n, cap;
  oa_kv *items;
};

// hash table type
struct oa_hash_s {
  atomic_size_t count;
  oa_key_ops key_ops;
  oa_val_ops val_ops;
  vt_u64_bucket_map shard[OA_SHARDS];
  HASH_LOCK_T rw[OA_SHARDS];
};

static inline void kv_set_new(oa_hash *h, oa_kv *e, const void *key, const void *val);
static bool hash_read_field(oa_serialize_fn deserialize, void **value, FILE *fp, uint64_t size);
static inline void kv_replace_val(oa_hash *h, oa_kv *e, const void *val);
static inline void kv_free(oa_hash *h, oa_kv *e);
static inline struct oa_bucket *get_or_make_bucket(oa_hash *h, size_t s, uint64_t hash);
static inline size_t shard_of(uint64_t h);
static inline struct oa_bucket *bucket_new(void);
static void hash_lock_all_rd(oa_hash *h);
static void hash_unlock_all(oa_hash *h);
static void hash_lock_all_wr(oa_hash *h);

oa_hash *oa_hash_new(oa_key_ops key_ops, oa_val_ops val_ops) {
  if (! key_ops.hash || ! key_ops.cp || ! key_ops.free || ! key_ops.eq || ! val_ops.cp || ! val_ops.free) {
    fprintf(stderr, "oa_hash_new: hash/cp/free/eq  required for key and "
                    "cp/free required for value types\n");
    exit(-1);
  }

  oa_hash *h = (oa_hash *)calloc(1, sizeof(*h));
  if (! h) {
    return NULL;
  }

  h->key_ops = key_ops;
  h->val_ops = val_ops;

  for (size_t i = 0; i < OA_SHARDS; i++) {
    vt_init(&h->shard[i]);
    HASH_LOCK_INIT(&h->rw[i]);
  }
  return h;
}


void oa_hash_free(oa_hash **hp) {
  if (! hp || ! *hp) {
    return;
  }
  oa_hash *h = *hp;
  for (size_t s = 0; s < OA_SHARDS; s++) {
    HASH_LOCK_WR(&h->rw[s]);
    for (vt_u64_bucket_map_itr it = vt_first(&h->shard[s]); ! vt_is_end(it); it = vt_next(it)) {
      struct oa_bucket *b = it.data->val;
      if (b && b->items) {
        for (size_t i = 0; i < b->n; i++) {
          kv_free(h, &b->items[i]);
        }
      }
      free(b ? b->items : NULL);
      free(b);
    }
    vt_cleanup(&h->shard[s]);
    HASH_UNLOCK(&h->rw[s]);
    HASH_LOCK_DESTROY(&h->rw[s]);
  }
  free(h);
  *hp = NULL;
}


static inline void *kv_key_ptr(oa_kv *e) { return e->ksz ? (void *)e->k_inline : e->kptr; }

static inline bool key_eq(oa_hash *h, const void *a, const void *b) { return h->key_ops.eq(a, b); }

static inline uint64_t key_hash(oa_hash *h, const void *key) { return h->key_ops.hash(key); }

static inline size_t shard_of(uint64_t x) { return x & (OA_SHARDS - 1); }

static inline struct oa_bucket *bucket_new(void) {
  struct oa_bucket *b = (struct oa_bucket *)calloc(1, sizeof(*b));
  return b;
}


static inline bool bucket_reserve(struct oa_bucket *b, size_t need) {
  if (need <= b->cap) {
    return true;
  }
  size_t ncap = b->cap ? b->cap * 2 : 4;
  while (ncap < need) {
    ncap *= 2;
  }
  oa_kv *tmp = (oa_kv *)realloc(b->items, ncap * sizeof(oa_kv));
  if (! tmp) {
    return false;
  }
  b->items = tmp;
  b->cap = ncap;
  return true;
}


bool oa_hash_put(oa_hash *h, const void *key, const void *val) {
  uint64_t hash = key_hash(h, key);
  size_t s = shard_of(hash);
  HASH_LOCK_WR(&h->rw[s]);

  struct oa_bucket *b = get_or_make_bucket(h, s, hash);
  if (! b) {
    HASH_UNLOCK(&h->rw[s]);
    return false;
  }

  for (size_t i = 0; i < b->n; i++) {
    if (i + 1 < b->n) {
      __builtin_prefetch(&b->items[i + 1], 0, 1);
    }
    if (key_eq(h, kv_key_ptr(&b->items[i]), key)) {
      // Update existing value — count unchanged.
      kv_replace_val(h, &b->items[i], val);
      HASH_UNLOCK(&h->rw[s]);
      return true;
    }
  }

  // New key: grow and append
  if (! bucket_reserve(b, b->n + 1)) {
    HASH_UNLOCK(&h->rw[s]);
    return false;
  }
  kv_set_new(h, &b->items[b->n], key, val);
  b->n++;
  atomic_fetch_add_explicit(&h->count, 1, memory_order_relaxed);
  HASH_UNLOCK(&h->rw[s]);
  return true;
}


void *oa_hash_get(oa_hash *h, const void *key) {
  uint64_t hash = key_hash(h, key);
  size_t s = shard_of(hash);
  HASH_LOCK_RD(&h->rw[s]);
  vt_u64_bucket_map_itr it = vt_get(&h->shard[s], hash);
  if (vt_is_end(it)) {
    HASH_UNLOCK(&h->rw[s]);
    return NULL;
  }
  struct oa_bucket *b = it.data->val;
  for (size_t i = 0; i < b->n; i++) {
    if (i + 1 < b->n) {
      __builtin_prefetch(&b->items[i + 1], 0, 1);
    }
    if (key_eq(h, kv_key_ptr(&b->items[i]), key)) {
      void *ret = (b->items[i].vsz ? (void *)b->items[i].v_inline : b->items[i].vptr);
      HASH_UNLOCK(&h->rw[s]);
      return ret;
    }
  }
  HASH_UNLOCK(&h->rw[s]);
  return NULL;
}


void *oa_hash_get_copy(oa_hash *h, const void *key) {
  uint64_t hash = key_hash(h, key);
  size_t s = shard_of(hash);
  HASH_LOCK_RD(&h->rw[s]);
  vt_u64_bucket_map_itr it = vt_get(&h->shard[s], hash);
  if (vt_is_end(it)) {
    HASH_UNLOCK(&h->rw[s]);
    return NULL;
  }
  struct oa_bucket *b = it.data->val;
  for (size_t i = 0; i < b->n; i++) {
    if (i + 1 < b->n) {
      __builtin_prefetch(&b->items[i + 1], 0, 1);
    }
    if (key_eq(h, kv_key_ptr(&b->items[i]), key)) {
      oa_kv *e = &b->items[i];
      void *src = e->vsz ? (void *)e->v_inline : e->vptr;
      void *ret = h->val_ops.cp(src);
      HASH_UNLOCK(&h->rw[s]);
      return ret;
    }
  }
  HASH_UNLOCK(&h->rw[s]);
  return NULL;
}


void oa_hash_delete(oa_hash *h, const void *key) {
  uint64_t hash = key_hash(h, key);
  size_t s = shard_of(hash);
  HASH_LOCK_WR(&h->rw[s]);
  vt_u64_bucket_map_itr it = vt_get(&h->shard[s], hash);
  if (! vt_is_end(it)) {
    struct oa_bucket *b = it.data->val;
    for (size_t i = 0; i < b->n; i++) {
      if (key_eq(h, kv_key_ptr(&b->items[i]), key)) {
        kv_free(h, &b->items[i]);
        b->items[i] = b->items[b->n - 1];
        b->n--;
        atomic_fetch_sub_explicit(&h->count, 1, memory_order_relaxed);
        if (b->n == 0) {
          free(b->items);
          b->items = NULL;
          b->cap = 0;
          vt_erase(&h->shard[s], hash);
          free(b);
        }
        break;
      }
    }
  }
  HASH_UNLOCK(&h->rw[s]);
}


size_t oa_hash_size(oa_hash *h) { return atomic_load_explicit(&h->count, memory_order_relaxed); }

// crude capacity estimate
size_t oa_hash_capacity(oa_hash *h) {
  size_t cap = 0;
  for (size_t s = 0; s < OA_SHARDS; s++) {
    HASH_LOCK_RD(&h->rw[s]);
    for (vt_u64_bucket_map_itr it = vt_first(&h->shard[s]); ! vt_is_end(it); it = vt_next(it)) {
      struct oa_bucket *b = it.data->val;
      cap += b ? b->cap : 0;
    }
    HASH_UNLOCK(&h->rw[s]);
  }
  return cap;
}


size_t oa_hash_stripes(oa_hash *h) {
  (void)h;
  return OA_SHARDS;
}


bool oa_hash_serialize(oa_hash *h, FILE *fp) {
  if (! h || ! fp) {
    errno = EINVAL;
    return false;
  }
  if (! h->key_ops.serialize || ! h->val_ops.serialize) {
    errno = ENOTSUP;
    fprintf(stderr, "oa_hash_serialize: serialize callbacks missing\n");
    return false;
  }
  // lock all shards for reading; blocks writers
  hash_lock_all_rd(h);

  oa_hash_disk_header hdr = { .magic = OA_HASH_DISK_MAGIC,
                              .version = OA_HASH_DISK_VERSION,
                              .shards = OA_SHARDS,
                              .total = atomic_load_explicit(&h->count, memory_order_relaxed) };

  if (fwrite(&hdr, sizeof(hdr), 1, fp) != 1) {
    perror("oa_hash_serialize: header write");
    goto fail;
  }

  for (size_t s = 0; s < OA_SHARDS; s++) {
    for (vt_u64_bucket_map_itr it = vt_first(&h->shard[s]); ! vt_is_end(it); it = vt_next(it)) {
      struct oa_bucket *b = it.data->val;
      if (! b) {
        continue;
      }
      for (size_t i = 0; i < b->n; i++) {
        oa_kv *e = &b->items[i];
        void *kptr = e->ksz ? (void *)e->k_inline : e->kptr;
        void *vptr = e->vsz ? (void *)e->v_inline : e->vptr;
        oa_hash_disk_entry entry = {0};
        off_t start = ftello(fp);
        // Socket/pipe users cannot backpatch. Buffer only one entry for those streams.
        if (start < 0) {
          char *bytes = NULL;
          size_t size = 0;
          FILE *memory = open_memstream(&bytes, &size);
          if (! memory) {
            goto fail;
          }
          bool ok = h->key_ops.serialize(&kptr, memory, SERIALIZE);
          off_t key_end = ftello(memory);
          ok = ok && key_end > 0 && h->val_ops.serialize(&vptr, memory, SERIALIZE);
          ok = fclose(memory) == 0 && ok;
          if (ok && size > (uint64_t)key_end) {
            entry.key_size = (uint64_t)key_end;
            entry.value_size = size - (size_t)key_end;
            ok = fwrite(&entry, sizeof(entry), 1, fp) == 1
                 && fwrite(bytes, 1, size, fp) == size;
          }
          else {
            ok = false;
          }
          free(bytes);
          if (! ok) {
            goto fail;
          }
          continue;
        }
        if (fwrite(&entry, sizeof(entry), 1, fp) != 1) {
          goto fail;
        }
        off_t key_start = ftello(fp);
        if (! h->key_ops.serialize(&kptr, fp, SERIALIZE)) {
          perror("oa_hash_serialize: key");
          goto fail;
        }
        off_t value_start = ftello(fp);
        if (! h->val_ops.serialize(&vptr, fp, SERIALIZE)) {
          perror("oa_hash_serialize: val");
          goto fail;
        }
        off_t end = ftello(fp);
        if (key_start < 0 || value_start <= key_start || end <= value_start) {
          errno = EPROTO;
          goto fail;
        }
        entry.key_size = (uint64_t)(value_start - key_start);
        entry.value_size = (uint64_t)(end - value_start);
        if (fseeko(fp, start, SEEK_SET) != 0
            || fwrite(&entry, sizeof(entry), 1, fp) != 1
            || fseeko(fp, end, SEEK_SET) != 0) {
          goto fail;
        }
      }
    }
  }
  hash_unlock_all(h);
  return true;
fail:
  hash_unlock_all(h);
  return false;
}


// reject impossible entry counts for regular files before invoking callbacks.
// Non-regular streams cannot be preflighted and remain callback-validated.
//
static bool serialized_count_fits_regular_file(FILE *fp, uint64_t count) {

  struct stat statbuf;
  off_t position;
  int handle = fileno(fp);

  if (handle < 0 || fstat(handle, &statbuf) != 0 || ! S_ISREG(statbuf.st_mode)) {
    return true;
  }

  position = ftello(fp);
  return position >= 0 && statbuf.st_size >= position
         && count <= (uint64_t)(statbuf.st_size - position);
}


// Verify callback consumption on seekable streams and retain pipe/socket support.
static bool hash_read_field(oa_serialize_fn deserialize, void **value, FILE *fp, uint64_t size) {
  off_t start = ftello(fp);
  if (start >= 0) {
    if (! deserialize(value, fp, DESERIALIZE)) {
      return false;
    }
    off_t end = ftello(fp);
    if (end < start || (uint64_t)(end - start) != size) {
      errno = EPROTO;
      return false;
    }
    return true;
  }
  if (! size || size > SIZE_MAX) {
    errno = EPROTO;
    return false;
  }
  void *bytes = malloc((size_t)size);
  if (! bytes) {
    return false;
  }
  if (fread(bytes, 1, (size_t)size, fp) != size) {
    free(bytes);
    return false;
  }
  FILE *memory = fmemopen(bytes, (size_t)size, "rb");
  bool ok = memory && deserialize(value, memory, DESERIALIZE)
            && ftello(memory) >= 0 && (uint64_t)ftello(memory) == size;
  if (memory) {
    fclose(memory);
  }
  free(bytes);
  return ok;
}


bool oa_hash_deserialize(oa_hash *h, FILE *fp) {
  if (! h || ! fp) {
    errno = EINVAL;
    return false;
  }
  if (! h->key_ops.serialize || ! h->val_ops.serialize) {
    errno = ENOTSUP;
    fprintf(stderr, "oa_hash_deserialize: serialize callbacks missing\n");
    return false;
  }

  oa_hash_disk_header hdr;

  if (fread(&hdr, sizeof(hdr), 1, fp) != 1) {
    perror("oa_hash_deserialize: header read");
    return false;
  }

  if (hdr.magic != OA_HASH_DISK_MAGIC || hdr.version != OA_HASH_DISK_VERSION
      || hdr.shards != (uint32_t)OA_SHARDS || hdr.reserved || hdr.reserved2) {
    errno = EPROTO;
    fprintf(stderr, "oa_hash_deserialize: header mismatch (magic=%08x ver=%u shards=%u)\n", hdr.magic, hdr.version, hdr.shards);
    return false;
  }
  if (hdr.total > UINT64_MAX / (sizeof(oa_hash_disk_entry) + 2)
      || ! serialized_count_fits_regular_file(fp, hdr.total * (sizeof(oa_hash_disk_entry) + 2))) {
    errno = EPROTO;
    fprintf(stderr, "oa_hash_deserialize: entry count exceeds remaining input\n");
    return false;
  }

  // Build into a temporary table, then splice atomically into h.
  oa_hash tmp = (oa_hash){0};
  tmp.key_ops = h->key_ops;
  tmp.val_ops = h->val_ops;

  for (size_t s = 0; s < OA_SHARDS; s++) {
    vt_init(&tmp.shard[s]);
    HASH_LOCK_INIT(&tmp.rw[s]);  // needed because we use oa_hash_put(&tmp,...)
  }
  atomic_store_explicit(&tmp.count, 0, memory_order_relaxed);

  for (uint64_t i = 0; i < hdr.total; i++) {
    void *kptr = NULL, *vptr = NULL;
    oa_hash_disk_entry entry;
    if (fread(&entry, sizeof(entry), 1, fp) != 1
        || ! entry.key_size || ! entry.value_size
        || entry.key_size > UINT64_MAX - entry.value_size
        || ! serialized_count_fits_regular_file(fp, entry.key_size + entry.value_size)) {
      errno = EPROTO;
      goto fail_tmp;
    }
    if (! hash_read_field(tmp.key_ops.serialize, &kptr, fp, entry.key_size)) {
      perror("oa_hash_deserialize: key deserialize");
      if (kptr && tmp.key_ops.free) {
        tmp.key_ops.free(&kptr);
      }
      goto fail_tmp;
    }
    if (! hash_read_field(tmp.val_ops.serialize, &vptr, fp, entry.value_size)) {
      perror("oa_hash_deserialize: val deserialize");
      if (kptr && tmp.key_ops.free) {
        tmp.key_ops.free(&kptr);
      }
      if (vptr && tmp.val_ops.free) {
        tmp.val_ops.free(&vptr);
      }
      goto fail_tmp;
    }

    // put copies then free the temps
    bool ok = oa_hash_put(&tmp, kptr, vptr);

    if (kptr && tmp.key_ops.free) {
      tmp.key_ops.free(&kptr);
    }
    if (vptr && tmp.val_ops.free) {
      tmp.val_ops.free(&vptr);
    }

    if (! ok) {
      perror("oa_hash_deserialize: insert failed");
      goto fail_tmp;
    }
  }

  // Splice tmp -> h under a global write barrier.
  hash_lock_all_wr(h);

  // Free existing contents of h
  for (size_t s = 0; s < OA_SHARDS; s++) {
    for (vt_u64_bucket_map_itr it = vt_first(&h->shard[s]); ! vt_is_end(it); it = vt_next(it)) {
      struct oa_bucket *b = it.data->val;
      if (! b) {
        continue;
      }
      if (b->items) {
        for (size_t j = 0; j < b->n; j++) {
          kv_free(h, &b->items[j]);
        }
        free(b->items);
      }
      free(b);
    }
    vt_cleanup(&h->shard[s]);
  }

  // Move shards from tmp -> h and detach tmp.
  for (size_t s = 0; s < OA_SHARDS; s++) {
    h->shard[s] = tmp.shard[s];
    vt_init(&tmp.shard[s]);  // prevent double-free in fail path
  }

  // Count as actually computed by tmp.
  atomic_store_explicit(&h->count, atomic_load_explicit(&tmp.count, memory_order_relaxed), memory_order_relaxed);

  hash_unlock_all(h);

  // Destroy tmp locks now that tmp is detached.
  for (size_t s = 0; s < OA_SHARDS; s++) {
    HASH_LOCK_DESTROY(&tmp.rw[s]);
  }

  return true;

fail_tmp:
  // Best-effort cleanup of partially-built tmp.
  for (size_t s = 0; s < OA_SHARDS; s++) {
    for (vt_u64_bucket_map_itr it = vt_first(&tmp.shard[s]); ! vt_is_end(it); it = vt_next(it)) {
      struct oa_bucket *b = it.data->val;
      if (! b) {
        continue;
      }
      if (b->items) {
        for (size_t j = 0; j < b->n; j++) {
          kv_free(&tmp, &b->items[j]);
        }
        free(b->items);
      }
      free(b);
    }
    vt_cleanup(&tmp.shard[s]);
    HASH_LOCK_DESTROY(&tmp.rw[s]);
  }
  return false;
}


uint64_t oa_string_hash(const void *s) {
  const char *str = (const char *)s;
  if (! str) {
    return 0;
  }
  return XXH3_64bits(str, strlen(str));
}


void *oa_string_cp(const void *s) {
  const char *input = (const char *)s;
  char *result;
  if (! input) {
    input = "";
  }
  result = calloc(strlen(input) + 1, 1);
  if (! result) {
    fprintf(stderr, "malloc() failed in file %s at line # %d.", __FILE__, __LINE__);
    exit(-11);
  }
  strcpy(result, input);
  return result;
}


bool oa_string_eq(const void *s1, const void *s2) {
  const char *a = (const char *)s1;
  const char *b = (const char *)s2;

  if (a == NULL && b == NULL) {
    return true;
  }
  if (a == NULL || b == NULL) {
    return false;
  }

  return strcmp(a, b) == 0;
}


void oa_string_free(void **s) {
  if (*s) {
    free(*s);
  }
  *s = NULL;
}


bool oa_string_serialize(void **s, FILE *fp, StateSerialization mode) {
  if (! s || ! fp) {
    return false;
  }

  size_t (*fb)(void *ptr, size_t size, size_t nitems,
               FILE *stream) = (mode == SERIALIZE) ? (size_t (*)(void *ptr, size_t size, size_t nitems, FILE *stream))fwrite
                                                   : (size_t (*)(void *ptr, size_t size, size_t nitems, FILE *stream))fread;
  char **string = (char **)s;
  uint32_t len32 = 0;

  if (mode == SERIALIZE) {
    size_t len = (*string) ? strlen(*string) : 0;
    if (len > UINT32_MAX) {
      errno = EOVERFLOW;
      return false;
    }
    len32 = (uint32_t)len;
  }

  if (fb(&len32, sizeof(len32), 1, fp) != 1) {
    perror("error (de)serializing string length");
    return false;
  }

  if (mode == SERIALIZE) {
    if (len32 > 0) {
      if (fb(*string, 1, len32, fp) != len32) {
        perror("error serializing string bytes");
        return false;
      }
    }
  }
  else {  // DESERIALIZE
    char *buf = (char *)calloc(len32 + 1, 1);
    if (! buf) {
      perror("alloc string");
      return false;
    }
    if (len32 > 0 && fb(buf, 1, len32, fp) != len32) {
      perror("error deserializing string bytes");
      free(buf);
      return false;
    }
    // return newly allocated string to caller
    *string = buf;
  }

  return true;
}


void oa_string_print(const void *s) { printf("%s", (const char *)s); }

size_t oa_string_sizeof(const void *s) {
  if (! s) {
    return 0;
  }
  return strlen((const char *)s) + 1;
}


static inline void kv_set_new(oa_hash *h, oa_kv *e, const void *key, const void *val) {
  e->ksz = 0;
  e->vsz = 0;
  e->kptr = NULL;
  e->vptr = NULL;

  size_t ksz = 0, vsz = 0;
  if (h->key_ops.size_of) {
    ksz = h->key_ops.size_of(key);
  }
  if (h->val_ops.size_of) {
    vsz = h->val_ops.size_of(val);
  }

  if (ksz && ksz <= HASH_KEY_INLINE_MAX) {
    memcpy(e->k_inline, key, ksz);
    e->ksz = (uint16_t)ksz;
  }
  else {
    e->kptr = h->key_ops.cp(key);
  }

  if (vsz && vsz <= HASH_VAL_INLINE_MAX) {
    memcpy(e->v_inline, val, vsz);
    e->vsz = (uint16_t)vsz;
  }
  else {
    e->vptr = h->val_ops.cp(val);
  }
}


static inline void kv_replace_val(oa_hash *h, oa_kv *e, const void *val) {
  size_t vsz = 0;
  if (h->val_ops.size_of) {
    vsz = h->val_ops.size_of(val);
  }
  if (vsz && vsz <= HASH_VAL_INLINE_MAX) {
    if (e->vsz == 0 && e->vptr && h->val_ops.free) {
      h->val_ops.free(&e->vptr);
      e->vptr = NULL;
    }
    memcpy(e->v_inline, val, vsz);
    e->vsz = (uint16_t)vsz;
  }
  else {
    if (e->vsz == 0 && e->vptr && h->val_ops.free) {
      h->val_ops.free(&e->vptr);
    }
    e->vptr = h->val_ops.cp(val);
    e->vsz = 0;
  }
}


static inline void kv_free(oa_hash *h, oa_kv *e) {
  if (e->ksz == 0 && e->kptr && h->key_ops.free) {
    h->key_ops.free(&e->kptr);
  }
  if (e->vsz == 0 && e->vptr && h->val_ops.free) {
    h->val_ops.free(&e->vptr);
  }
}


static inline struct oa_bucket *get_or_make_bucket(oa_hash *h, size_t s, uint64_t hash) {
  vt_u64_bucket_map_itr it = vt_get(&h->shard[s], hash);
  if (! vt_is_end(it)) {
    return it.data->val;
  }
  struct oa_bucket *b = bucket_new();
  vt_u64_bucket_map_itr it2 = vt_insert(&h->shard[s], hash, b);
  if (vt_is_end(it2)) {
    free(b);
    return NULL;
  }
  return b;
}


// acquire all shard locks in a fixed order; RD blocks writers, allows readers.
static void hash_lock_all_rd(oa_hash *h) {
  for (size_t s = 0; s < OA_SHARDS; s++) {
    HASH_LOCK_RD(&h->rw[s]);
  }
}


// unlock all shard locks in a fixed order
static void hash_unlock_all(oa_hash *h) {
  for (size_t s = OA_SHARDS; s-- > 0;) {
    HASH_UNLOCK(&h->rw[s]);
  }
}


// lock all shard for writing
static void hash_lock_all_wr(oa_hash *h) {
  for (size_t s = 0; s < OA_SHARDS; s++) {
    HASH_LOCK_WR(&h->rw[s]);
  }
}


size_t oa_hash_clear(oa_hash *h) {
  size_t cleared = 0;
  for (size_t s = 0; s < OA_SHARDS; s++) {
    HASH_LOCK_WR(&h->rw[s]);
    // Walk all buckets, free their items and the bucket itself,
    // then clear the map but keep it initialized/usable.
    for (vt_u64_bucket_map_itr it = vt_first(&h->shard[s]); ! vt_is_end(it); it = vt_next(it)) {
      struct oa_bucket *b = it.data->val;
      if (! b) {
        continue;
      }
      if (b->items) {
        for (size_t j = 0; j < b->n; j++) {
          kv_free(h, &b->items[j]);
          cleared++;
        }
        free(b->items);
      }
      free(b);
    }
    vt_clear(&h->shard[s]);  // drop all (hash->bucket) bindings, keep table usable
    HASH_UNLOCK(&h->rw[s]);
  }
  atomic_store_explicit(&h->count, 0, memory_order_relaxed);
  return cleared;
}

