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

// Complete rewrite of prior hashv2.c by GGRIII. This version uses verstable and xxhash to increase
// performance.
//

#pragma once

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if ! defined(STATE_SERIALIZATION_DEF)
#define STATE_SERIALIZATION_DEF
// serialization mode for reading/writing scalpel state
typedef enum StateSerialization {
  SERIALIZE = 1,
  DESERIALIZE = 2,
} StateSerialization;
#endif

// callback types
typedef uint64_t (*oa_hash_fn)(const void *key);
typedef void *(*oa_cp_fn)(const void *p);
typedef void (*oa_free_fn)(void **p);
typedef bool (*oa_eq_fn)(const void *a, const void *b);
typedef bool (*oa_serialize_fn)(void **ptr, FILE *fp, StateSerialization mode);
typedef size_t (*oa_sizeof_fn)(const void *p);

// ops for keys/values (optional fields appear at the end. These may be set to NULL or memset() the
// entire structure to zero before initialization. Other operations are required.)
typedef struct {
  oa_hash_fn hash;
  oa_cp_fn cp;
  oa_free_fn free;
  oa_eq_fn eq;
  // optional serialization function; each serialized key must consume at least one byte
  oa_serialize_fn serialize;
  oa_sizeof_fn size_of;       // optional sizeof function: <= HASH_KEY_INLINE_MAX enables inline allocation (keys)
} oa_key_ops;

typedef struct {
  oa_cp_fn cp;
  oa_free_fn free;
  // optional serialization function; each serialized value must consume at least one byte
  oa_serialize_fn serialize;
  oa_sizeof_fn size_of;       // optional sizeof function: <= HASH_VAL_INLINE_MAX enables inline allocation (values)
} oa_val_ops;

// Tunables (override with -D at compile time)
#ifndef OA_SHARDS
#define OA_SHARDS 256u
#endif

#ifndef HASH_KEY_INLINE_MAX
#define HASH_KEY_INLINE_MAX 64
#endif
#ifndef HASH_VAL_INLINE_MAX
#define HASH_VAL_INLINE_MAX 64
#endif

#ifndef RW
#define RW 1
#endif
#ifndef MUTEX
#define MUTEX 2
#endif
#ifndef HASH_LOCK_KIND
#define HASH_LOCK_KIND RW /* RW or MUTEX */
#endif

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert((OA_SHARDS & (OA_SHARDS - 1)) == 0, "OA_SHARDS must be a power of two");
#endif

// hash table type is opaque
typedef struct oa_hash_s oa_hash;

// Native checkpoint table framing, also read by mergecps without validator callbacks.
#define OA_HASH_DISK_MAGIC 0x48534833u
#define OA_HASH_DISK_VERSION 2u
typedef struct {
  uint32_t magic;
  uint16_t version;
  uint16_t reserved;
  uint32_t shards;
  uint32_t reserved2;
  uint64_t total;
} oa_hash_disk_header;

typedef struct {
  uint64_t key_size;
  uint64_t value_size;
} oa_hash_disk_entry;


// ownership model:
//
// * oa_hash_put() deep-copies the key and value using key_ops.cp and val_ops.cp.
//   the caller retains ownership of the inputs and may modify or free them immediately.
//
// * oa_hash_get_copy() returns a newly allocated copy using val_ops.cp.
//   the caller owns the copy and is responsible for freeing it with val_ops.free.
//
// * oa_hash_get() returns a non-owning pointer to the table's internal value.
//   the caller must not free the pointer. It may be read or modified in place only when
//   the caller guarantees that no concurrent operation can access or mutate that value.
//   a subsequent put, delete, or table destruction may invalidate the pointer. Use
//   oa_hash_get_copy() when the table may be accessed concurrently.
//

// public API
oa_hash *oa_hash_new(oa_key_ops key_ops, oa_val_ops val_ops);
void oa_hash_free(oa_hash **hp);

bool oa_hash_put(oa_hash *h, const void *key, const void *val);
void *oa_hash_get(oa_hash *h, const void *key);
void *oa_hash_get_copy(oa_hash *h, const void *key);
void oa_hash_delete(oa_hash *h, const void *key);

size_t oa_hash_size(oa_hash *h);
size_t oa_hash_capacity(oa_hash *h);
size_t oa_hash_stripes(oa_hash *h);

bool oa_hash_serialize(oa_hash *h, FILE *fp);
bool oa_hash_deserialize(oa_hash *h, FILE *fp);

uint64_t oa_string_hash(const void *s);
void *oa_string_cp(const void *s);
bool oa_string_eq(const void *s1, const void *s2);
void oa_string_free(void **s);
bool oa_string_serialize(void **s, FILE *fp, StateSerialization mode);
void oa_string_print(const void *s);
size_t oa_string_sizeof(const void *s);
size_t oa_hash_clear(oa_hash *h);

