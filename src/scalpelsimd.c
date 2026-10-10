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

// Scalpel3 SIMD operations
//

#include "scalpelsimd.h"
#include "scalpel_output.h"
#define SIMDE_ENABLE_NATIVE_ALIASES
#include "simde/simde/arm/neon.h"
#include "simde/simde/x86/avx2.h"
#include "simde/simde/x86/avx512.h"
#include "simde/simde/x86/sse2.h"

typedef enum { S3_SIMD_SCALAR = 0, S3_SIMD_SSE2, S3_SIMD_NEON, S3_SIMD_AVX2, S3_SIMD_AVX512 } s3_simd_mode_t;

static inline const char *s3_simd_mode_name(s3_simd_mode_t m) {

  switch (m) {
  case S3_SIMD_AVX512:
    return "AVX-512";
  case S3_SIMD_AVX2:
    return "AVX2";
  case S3_SIMD_NEON:
    return "NEON";
  case S3_SIMD_SSE2:
    return "SSE2";
  default:
    return "Scalar";
  }
}


static inline s3_simd_mode_t s3_compiled_backend(void) {
#if defined(__AVX512F__) && defined(__AVX512BW__)
  return S3_SIMD_AVX512;

#elif defined(__AVX2__)
  return S3_SIMD_AVX2;

#elif defined(__ARM_NEON) || defined(__aarch64__)
  return S3_SIMD_NEON;

#elif defined(__SSE2__)
  return S3_SIMD_SSE2;

#else
  return S3_SIMD_SCALAR;

#endif
}


static inline s3_simd_mode_t s3_runtime_cpu_support(void) {
#if defined(__x86_64__) || defined(__i386)
#if defined(__GNUC__) || defined(__clang__)
  __builtin_cpu_init();
  if (__builtin_cpu_supports("avx512f")) {
    return S3_SIMD_AVX512;
  }
  if (__builtin_cpu_supports("avx2")) {
    return S3_SIMD_AVX2;
  }
  if (__builtin_cpu_supports("sse2")) {
    return S3_SIMD_SSE2;
  }
#endif
  return S3_SIMD_SCALAR;

#elif defined(__aarch64__)
  return S3_SIMD_NEON;

#elif defined(__ARM_NEON)
  return S3_SIMD_NEON;

#else
  return S3_SIMD_SCALAR;

#endif
}


static void s3_print_simd_banner(void) {

  s3_simd_mode_t be = s3_compiled_backend();
  s3_simd_mode_t cpu = s3_runtime_cpu_support();

  int vbytes = (int)(SIMDE_NATURAL_VECTOR_SIZE / 8);

  lock_fprintf(stdout,
               "Scalpel3 SIMD configuration:\n"
               "  Compiled backend:         %s\n"
               "  CPU support:              %s\n"
               "  Vector width:             %d bytes\n",
               s3_simd_mode_name(be), s3_simd_mode_name(cpu), vbytes);
}


void print_simd_banner(void) {
  s3_print_simd_banner();
}

// SIMD backbone of find_binary_string() function
char *s3_exact_simd_or_scalar(char *needle, size_t m, char *hay, size_t n, size_t start_pos) {

  if (m == 0) {
    return hay;
  }
  if (n < m || start_pos >= n) {
    return NULL;
  }

  // clamp so the last-byte scan never starts before the earliest position where an m-byte
  // match can end (offset m - 1). A smaller start_pos would let start_idx = (q - H) + 1 - m
  // underflow (size_t) and slip past the start_idx + m <= n guard into an out-of-bounds read.
  // Mirrors the identical clamp in the bitap sibling (util.c find_binary_string u64 path).
  if (start_pos < m - 1) {
    start_pos = m - 1;
  }

  const unsigned char first = (unsigned char)needle[0];
  const unsigned char last = (unsigned char)needle[m - 1];
  const size_t first_distance = m - 1;
  const unsigned char *H = (const unsigned char *)hay;
  const unsigned char *end = H + n;
  const unsigned char *p = H + start_pos;

#if SCALPEL3_USE_SIMD > 0

#if defined(__AVX512F__) && defined(__AVX512BW__)
  simde__m512i vfirst = simde_mm512_set1_epi8((char)first);
  simde__m512i vlast = simde_mm512_set1_epi8((char)last);

  while (p + 64 <= end) {
    simde__m512i v = simde_mm512_loadu_si512((const simde__m512i *)p);
    simde__mmask64 mask = simde_mm512_cmpeq_epi8_mask(v, vlast);

    if (first_distance > 0) {
      simde__m512i vstarts =
          simde_mm512_loadu_si512((const simde__m512i *)(p - first_distance));
      mask &= simde_mm512_cmpeq_epi8_mask(vstarts, vfirst);
    }

    while (mask) {
      unsigned bit = __builtin_ctzll(mask);
      const unsigned char *q = p + bit;
      size_t start_idx = (size_t)((q - H) + 1 - m);

      if (start_idx + m <= n) {
        const unsigned char *cand = H + start_idx;

        if (m >= 8) {
          uint64_t a, b;

          memcpy(&a, cand, 8);
          memcpy(&b, needle, 8);
          if (a != b) {
            mask &= (mask - 1);
            continue;
          }
        }
        if (memcmp(cand, needle, m) == 0) {
          return (char *)cand;
        }
      }
      mask &= (mask - 1);
    }
    p += 64;
  }

#elif defined(__AVX2__)
  simde__m256i vfirst = simde_mm256_set1_epi8((char)first);
  simde__m256i vlast = simde_mm256_set1_epi8((char)last);

  while (p + 32 <= end) {
    simde__m256i v = simde_mm256_loadu_si256((const simde__m256i *)p);
    simde__m256i cmp = simde_mm256_cmpeq_epi8(v, vlast);

    if (first_distance > 0) {
      simde__m256i vstarts =
          simde_mm256_loadu_si256((const simde__m256i *)(p - first_distance));
      cmp = simde_mm256_and_si256(
          cmp, simde_mm256_cmpeq_epi8(vstarts, vfirst));
    }

    uint32_t mask = (uint32_t)simde_mm256_movemask_epi8(cmp);

    while (mask) {
#if defined(__GNUC__) || defined(__clang__)
      unsigned bit = __builtin_ctz(mask);

#else
      unsigned bit = 0;

      while (bit < 32 && ((mask >> bit) & 1) == 0) {
        bit++;
      }
#endif
      const unsigned char *q = p + bit;
      size_t start_idx = (size_t)((q - H) + 1 - m);

      if (start_idx + m <= n) {
        const unsigned char *cand = H + start_idx;

        if (m >= 8) {
          uint64_t a, b;

          memcpy(&a, cand, 8);
          memcpy(&b, needle, 8);
          if (a != b) {
            mask &= (mask - 1);
            continue;
          }
        }
        if (memcmp(cand, needle, m) == 0) {
          return (char *)cand;
        }
      }
      mask &= (mask - 1);
    }
    p += 32;
  }

#elif defined(__ARM_NEON) || defined(__aarch64__)
  uint8x16_t vfirst = vdupq_n_u8(first);
  uint8x16_t vlast = vdupq_n_u8(last);

  while (p + 16 <= end) {
    uint8x16_t v = vld1q_u8(p);
    uint8x16_t cmp = vceqq_u8(v, vlast);

    if (first_distance > 0) {
      uint8x16_t vstarts = vld1q_u8(p - first_distance);
      cmp = vandq_u8(cmp, vceqq_u8(vstarts, vfirst));
    }

    uint64_t mask_low = vgetq_lane_u64(vreinterpretq_u64_u8(cmp), 0);
    uint64_t mask_high = vgetq_lane_u64(vreinterpretq_u64_u8(cmp), 1);
    for (int i = 0; i < 8 && mask_low; i++) {
      if (mask_low & (0xFFULL << (i * 8))) {
        size_t start_idx = (size_t)((p + i - H) + 1 - m);

        if (start_idx + m <= n) {
          const unsigned char *cand = H + start_idx;

          if (memcmp(cand, needle, m) == 0) {
            return (char *)cand;
          }
        }
      }
    }
    for (int i = 0; i < 8 && mask_high; i++) {
      if (mask_high & (0xFFULL << (i * 8))) {
        size_t start_idx = (size_t)((p + 8 + i - H) + 1 - m);

        if (start_idx + m <= n) {
          const unsigned char *cand = H + start_idx;

          if (memcmp(cand, needle, m) == 0) {
            return (char *)cand;
          }
        }
      }
    }
    p += 16;
  }
#endif

#endif

  for (; p < end; ++p) {
    size_t start_idx = (size_t)((p - H) + 1 - m);

    if (p[0] == last && start_idx + m <= n) {
      const unsigned char *cand = H + start_idx;

      if (memcmp(cand, needle, m) == 0) {
        return (char *)cand;
      }
    }
  }

  return NULL;
}


// SIMD memset functions
inline void *memset_int64_t(int64_t *arr, int64_t val, uint64_t len) {

  uint64_t i = 0;

  if (! val) {
    memset(arr, 0, len * sizeof(val));
  }
  else {
#if SCALPEL3_USE_SIMD > 0
    if (len >= 4) {
      simde__m256i set_val = simde_mm256_set1_epi64x(val);
      for (; i + 4 <= len; i += 4) {
        simde_mm256_storeu_si256((simde__m256i *)&arr[i], set_val);
      }
    }
#endif
    for (; i < len; i++) {
      arr[i] = val;
    }
  }
  return arr;
}


inline void *memset_uint64_t(uint64_t *arr, uint64_t val, uint64_t len) {

  uint64_t i = 0;

  if (! val) {
    memset(arr, 0, len * sizeof(val));
  }
  else {
#if SCALPEL3_USE_SIMD > 0
    if (len >= 4) {
      simde__m256i set_val = simde_mm256_set1_epi64x(val);
      for (; i + 4 <= len; i += 4) {
        simde_mm256_storeu_si256((simde__m256i *)&arr[i], set_val);
      }
    }
#endif
    for (; i < len; i++) {
      arr[i] = val;
    }
  }
  return arr;
}


inline int64_t contains_int64_t(const int64_t *array, uint64_t count, int64_t target) {

  uint64_t i = 0;
  for (; i < count && i < 4; i++) {
    if (array[i] == target) {
      return (int64_t)i;
    }
  }

#if SCALPEL3_USE_SIMD > 0
  if (count >= (uint64_t)SCALPEL3_SIMD_THRESHOLD) {
    simde__m256i target_vec = simde_mm256_set1_epi64x(target);
    for (; i + 4 <= count; i += 4) {
      simde__m256i chunk = simde_mm256_loadu_si256(SIMDE_ALIGN_CAST(const simde__m256i *, &array[i]));
      simde__m256i cmp = simde_mm256_cmpeq_epi64(chunk, target_vec);

      if (! simde_mm256_testz_si256(cmp, cmp)) {
        uint32_t mask = (uint32_t)simde_mm256_movemask_epi8(cmp);

#if defined(__GNUC__) || defined(__clang__)
        int lane = __builtin_ctz(mask) / 8;

#else
        int bit = 0;

        while (bit < 32 && ((mask >> bit) & 1) == 0) {
          bit++;
        }
        int lane = bit / 8;

#endif
        return (int64_t)(i + (uint64_t)lane);
      }
    }
  }
#endif

  for (; i < count; i++) {
    if (array[i] == target) {
      return (int64_t)i;
    }
  }
  return -1;
}


void simd_build_target_vectors(PatternList *pl) {

  if (! pl) {
    return;
  }

  if (pl->num_targets == 0) {
    pl->simd_target_vectors = NULL;
    pl->simd_vector_size = 0;
    return;
  }

#if defined(__AVX512F__) && defined(__AVX512BW__)
  // AVX512: 64-byte vectors, 64-byte alignment
  pl->simd_vector_size = sizeof(simde__m512i) * pl->num_targets;
#if defined(_WIN32)
  pl->simd_target_vectors = _aligned_malloc(pl->simd_vector_size, 64);
#else
  if (posix_memalign(&pl->simd_target_vectors, 64, pl->simd_vector_size) != 0) {
    pl->simd_target_vectors = NULL;
    pl->simd_vector_size = 0;
    return;
  }
#endif

  if (! pl->simd_target_vectors) {
    pl->simd_vector_size = 0;
    return;
  }

  simde__m512i *vecs = (simde__m512i *)pl->simd_target_vectors;
  for (int i = 0; i < pl->num_targets; i++) {
    vecs[i] = simde_mm512_set1_epi8((char)pl->target_array[i]);
  }

#elif defined(__AVX2__)
  // AVX2: 32-byte vectors, 32-byte alignment
  pl->simd_vector_size = sizeof(simde__m256i) * pl->num_targets;
#if defined(_WIN32)
  pl->simd_target_vectors = _aligned_malloc(pl->simd_vector_size, 32);
#else
  if (posix_memalign(&pl->simd_target_vectors, 32, pl->simd_vector_size) != 0) {
    pl->simd_target_vectors = NULL;
    pl->simd_vector_size = 0;
    return;
  }
#endif

  if (! pl->simd_target_vectors) {
    pl->simd_vector_size = 0;
    return;
  }

  simde__m256i *vecs = (simde__m256i *)pl->simd_target_vectors;
  for (int i = 0; i < pl->num_targets; i++) {
    vecs[i] = simde_mm256_set1_epi8((char)pl->target_array[i]);
  }

#else
  // *** NEON / SSE (Fallback) ***
  // use 16-byte vectors and 16-byte alignment
  pl->simd_vector_size = sizeof(simde__m128i) * pl->num_targets;
#if defined(_WIN32)
  pl->simd_target_vectors = _aligned_malloc(pl->simd_vector_size, 16);
#else
  if (posix_memalign(&pl->simd_target_vectors, 16, pl->simd_vector_size) != 0) {
    pl->simd_target_vectors = NULL;
    pl->simd_vector_size = 0;
    return;
  }
#endif

  if (! pl->simd_target_vectors) {
    pl->simd_vector_size = 0;
    return;
  }

  simde__m128i *vecs = (simde__m128i *)pl->simd_target_vectors;
  for (int i = 0; i < pl->num_targets; i++) {
    // Use the 128-bit (SSE/NEON) set function
    vecs[i] = simde_mm_set1_epi8((char)pl->target_array[i]);
  }
#endif
}


void simd_free_target_vectors(void *vectors) {

  if (! vectors) {
    return;
  }

  free(vectors);
}


void simd_get_match_mask_64(const unsigned char *chunk_64_bytes, PatternList *pl, uint64_t *out_mask) {

  if (! pl || ! pl->simd_target_vectors || pl->num_targets == 0) {
    *out_mask = 0;
    return;
  }

  int num_targets = pl->num_targets;

#if defined(__AVX512F__) && defined(__AVX512BW__)

  const simde__m512i *vecs = (const simde__m512i *)pl->simd_target_vectors;
  simde__m512i chunk = simde_mm512_loadu_si512((const simde__m512i *)chunk_64_bytes);
  simde__mmask64 mask = 0;
  for (int i = 0; i < num_targets; i++) {
    mask |= simde_mm512_cmpeq_epi8_mask(chunk, vecs[i]);
  }
  *out_mask = (uint64_t)mask;

#elif defined(__AVX2__)

  const simde__m256i *vecs = (const simde__m256i *)pl->simd_target_vectors;

  simde__m256i chunk1 = simde_mm256_loadu_si256((const simde__m256i *)chunk_64_bytes);
  simde__m256i any_match1 = simde_mm256_setzero_si256();
  for (int i = 0; i < num_targets; i++) {
    any_match1 = simde_mm256_or_si256(any_match1, simde_mm256_cmpeq_epi8(chunk1, vecs[i]));
  }
  uint32_t mask1 = (uint32_t)simde_mm256_movemask_epi8(any_match1);

  simde__m256i chunk2 = simde_mm256_loadu_si256((const simde__m256i *)(chunk_64_bytes + 32));
  simde__m256i any_match2 = simde_mm256_setzero_si256();
  for (int i = 0; i < num_targets; i++) {
    any_match2 = simde_mm256_or_si256(any_match2, simde_mm256_cmpeq_epi8(chunk2, vecs[i]));
  }
  uint32_t mask2 = (uint32_t)simde_mm256_movemask_epi8(any_match2);

  *out_mask = ((uint64_t)mask2 << 32) | (uint64_t)mask1;

#else
  // *** SIMDE FALLBACK (NEON / SSE) PATH ***
  const simde__m128i *vecs = (const simde__m128i *)pl->simd_target_vectors;
  uint64_t final_mask = 0;

  // process 64 bytes in four 16-byte (128-bit) chunks
  for (int chunk_idx = 0; chunk_idx < 4; chunk_idx++) {
    const unsigned char *chunk_ptr = chunk_64_bytes + (chunk_idx * 16);

    simde__m128i chunk = simde_mm_loadu_si128((const simde__m128i *)chunk_ptr);
    simde__m128i any_match = simde_mm_setzero_si128();

    for (int i = 0; i < num_targets; i++) {
      any_match = simde_mm_or_si128(any_match, simde_mm_cmpeq_epi8(chunk, vecs[i]));
    }

    // simde_mm_movemask_epi8 -> simde's fast A64 implementation (fast)
    uint16_t chunk_mask = (uint16_t)simde_mm_movemask_epi8(any_match);

    final_mask |= ((uint64_t)chunk_mask << (chunk_idx * 16));
  }
  *out_mask = final_mask;
#endif
}

