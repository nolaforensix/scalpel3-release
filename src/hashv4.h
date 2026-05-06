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
  oa_serialize_fn serialize;  // optional serialization function
  oa_sizeof_fn size_of;       // optional sizeof function: <= HASH_KEY_INLINE_MAX enables inline allocation (keys)
} oa_key_ops;

typedef struct {
  oa_cp_fn cp;
  oa_free_fn free;
  oa_serialize_fn serialize;  // optional serialization function
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


// IMPORTANT: Ownership model:
//
// * - oa_hash_put(h, key, val) deep-copies key and value using key_ops.cp/val_ops.cp.
//
// The caller retains ownership of inputs and may free/modify them immediately.
//
// * - oa_hash_get_copy(h, key) returns a freshly allocated copy of the value using val_ops.cp.
//
// The caller may owns the copy and is responsible for freeing it.
//
// * - oa_hash_get() returns an internal pointer to allow in-place modifications.
//
// The hash table owns the copy and you must not call free on the pointer returned from
// oa_hash_get().
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

