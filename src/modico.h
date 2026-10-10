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

/**
 * @author James Ghawaly
 */

/*
 * modico.h - public C API for the MoDiCo ONNX inference layer.
 *
 * The implementation in modico.c owns ONNX Runtime session lifecycle,
 * CPU, CUDA, and CoreML provider setup, model selection, single-fragment
 * and batched classification, timing and diagnostics, termination, and
 * top-K reporting.
 *
 * An mc_session_t contains mutable scratch buffers, run options, and timing
 * state and must not be used concurrently. Scalpel3 assigns each concurrent
 * MoDiCo classification worker its own session and reuses that session because
 * session creation is expensive.
 */
#ifndef MODICO_H
#define MODICO_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handle. Allocate with mc_create_session, free with mc_destroy_session. */
typedef struct mc_session mc_session_t;

typedef enum {
    MC_INFERENCE_OK = 0,
    MC_INFERENCE_RETRYABLE = 1,
    MC_INFERENCE_FATAL = 2,
    MC_INFERENCE_TERMINATED = 3
} mc_inference_status_t;

typedef struct {
    double session_create_seconds;
    double input_conversion_seconds;
    double first_run_seconds;
    double subsequent_run_seconds;
    double subsequent_run_min_seconds;
    double subsequent_run_max_seconds;
    uint64_t run_count;
} mc_timing_t;

/* Create a session for one ONNX file.
 *
 *   model_path        path to a modico_<block_size>.onnx file
 *   intra_op_threads  0 = ORT default (#cores); 1 = single-threaded
 *                     (good when the outer carving loop is threaded);
 *                     N>1 = ORT parallelises within a single Run.
 *
 * Returns NULL on failure after reporting the ONNX Runtime error. */
mc_session_t *mc_create_session(const char *model_path, int intra_op_threads);

mc_session_t *mc_create_session_with_accelerator(const char *model_path,
                                                 int intra_op_threads,
                                                 const char *accelerator);

mc_session_t *mc_create_session_with_accelerator_device(
                                                 const char *model_path,
                                                 int intra_op_threads,
                                                 const char *accelerator,
                                                 int device_id);

/* The workload-aware variant uses the expected per-device block count to
 * avoid paying a cold TensorRT build cost on short runs. UINT64_MAX preserves
 * the legacy behavior and always permits TensorRT. */
mc_session_t *mc_create_session_with_accelerator_device_for_workload(
                                                 const char *model_path,
                                                 int intra_op_threads,
                                                 const char *accelerator,
                                                 int device_id,
                                                 uint64_t expected_blocks);


/* Which variant of the model an auto-selecting session actually loaded.
 * Useful for logging and for forcing one path or the other in tests. */
typedef enum {
    MC_KIND_AUTO = 0,   /* let the library decide based on CPU capability */
    MC_KIND_FP32 = 1,   /* force the FP32 model                          */
    MC_KIND_INT8 = 2,   /* force the INT8 model (fails if file missing)  */
} mc_session_kind_t;


/* Optional diagnostic info filled in by mc_create_session_auto. */
typedef struct {
    mc_session_kind_t kind_selected;     /* which variant was loaded         */
    int   int8_cpu_supported;            /* CPU has fast INT8 GEMM           */
    int   int8_file_available;           /* _int8.onnx exists at base path   */
    int   cuda_requested;                /* caller requested CUDA EP         */
    int   cuda_enabled;                  /* session uses CUDA EP             */
    int   coreml_requested;              /* caller requested CoreML EP       */
    int   coreml_enabled;                /* session uses CoreML EP           */
    int   device_id;                     /* CUDA device id, or -1 otherwise  */
    char  execution_provider[16];        /* "cuda", "coreml", or "cpu"     */
    char  selected_path[1024];           /* full path actually loaded        */
} mc_session_info_t;


/* Returns 1 if the current CPU has hardware-accelerated INT8 GEMM
 * (AVX-VNNI / AVX-512 VNNI on x86_64, ASIMDDP on aarch64). Otherwise 0.
 *
 * This is what mc_create_session_auto uses to decide whether INT8 is
 * worth loading on this machine — on older CPUs INT8 inference can be
 * SLOWER than FP32 because the runtime has to emulate quantized GEMM.
 *
 * Pure CPUID/auxv read; no allocation, safe to call any time. */
int mc_cpu_supports_fast_int8(void);


/* Create a session, automatically picking FP32 vs INT8 based on the
 * current CPU and which files exist on disk.
 *
 *   model_base_path   Path WITHOUT the .onnx extension. The library
 *                     looks for "<base>.onnx" (FP32) and
 *                     "<base>_int8.onnx" (INT8). A ".onnx" suffix on
 *                     the input is tolerated and stripped.
 *   intra_op_threads  Same semantics as mc_create_session.
 *   prefer            MC_KIND_AUTO for normal use; MC_KIND_FP32 or
 *                     MC_KIND_INT8 force a specific variant.
 *   info_out          Optional; if non-NULL, receives details of which
 *                     file was chosen and why.
 *
 * Selection policy (when prefer == MC_KIND_AUTO):
 *   - If INT8 file exists AND CPU has fast INT8 GEMM -> load INT8
 *   - Else                                            -> load FP32
 *
 * This guarantees that on hardware where INT8 would be a regression,
 * we transparently fall back to FP32. Scalpel should use this, not
 * mc_create_session directly. */
mc_session_t *mc_create_session_auto(const char *model_base_path,
                                     int intra_op_threads,
                                     mc_session_kind_t prefer,
                                     mc_session_info_t *info_out);

mc_session_t *mc_create_session_auto_with_accelerator(
                                     const char *model_base_path,
                                     int intra_op_threads,
                                     mc_session_kind_t prefer,
                                     const char *accelerator,
                                     mc_session_info_t *info_out);

mc_session_t *mc_create_session_auto_with_accelerator_device(
                                     const char *model_base_path,
                                     int intra_op_threads,
                                     mc_session_kind_t prefer,
                                     const char *accelerator,
                                     int device_id,
                                     mc_session_info_t *info_out);

/* Automatic model selection plus the workload-aware provider policy above. */
mc_session_t *mc_create_session_auto_with_accelerator_device_for_workload(
                                     const char *model_base_path,
                                     int intra_op_threads,
                                     mc_session_kind_t prefer,
                                     const char *accelerator,
                                     int device_id,
                                     uint64_t expected_blocks,
                                     mc_session_info_t *info_out);

void mc_destroy_session(mc_session_t *s);

/* Number of output classes the model produces (read from the graph at
 * session-creation time). For all current MoDiCo exports this is 619. */
int mc_get_num_classes(const mc_session_t *s);

const char *mc_execution_provider(const mc_session_t *s);
/* Actual inference engine. This differs from the execution provider when
 * TensorRT runs ahead of CUDA as its fallback provider. */
const char *mc_inference_backend(const mc_session_t *s);
const char *mc_model_path(const mc_session_t *s);
int mc_cuda_device_id(const mc_session_t *s);
int mc_uses_cuda(const mc_session_t *s);
int mc_uses_coreml(const mc_session_t *s);
int mc_uses_tensorrt(const mc_session_t *s);
int mc_uses_native_histograms(const mc_session_t *s);
int mc_static_batch_size(const mc_session_t *s);
/* Keep TensorRT on one compiled batch shape by padding the final call. */
void mc_set_run_batch_size(mc_session_t *s, int batch_size);
int mc_terminate_current_run(mc_session_t *s);
int mc_timing_enabled(const mc_session_t *s);
void mc_get_timing(const mc_session_t *s, mc_timing_t *timing_out);

/* Classify ONE fragment.
 *
 *   bytes        block_size raw bytes (uint8)
 *   block_size   must match the compiled-in input length of the loaded model
 *                (512, 1024, 2048, 4096, 8192, or 16384)
 *   logits_out   caller-owned buffer of length mc_get_num_classes(s)
 *
 * Returns MC_INFERENCE_OK on success. Only MC_INFERENCE_RETRYABLE indicates
 * that a smaller batch may succeed; fatal device errors must not be retried. */
int mc_classify(mc_session_t *s,
                const uint8_t *bytes, int block_size,
                float *logits_out);

/* Classify a BATCH of fragments in a single Run call. This is the high-
 * throughput path — at large batch sizes, ORT amortises kernel launch /
 * fused-attention overhead across the batch dimension.
 *
 *   bytes        batch_size * block_size raw bytes, packed contiguously
 *                (fragment 0 first, then fragment 1, ...)
 *   batch_size   any positive value (the exported ONNX has a dynamic
 *                batch axis)
 *   block_size   must match the loaded model's input length
 *   logits_out   caller-owned buffer of length
 *                batch_size * mc_get_num_classes(s)
 *
 * Returns an mc_inference_status_t value. */
int mc_classify_batch(mc_session_t *s,
                      const uint8_t *bytes,
                      int batch_size, int block_size,
                      float *logits_out);

/* Compute the top-K class indices and their softmax probabilities for
 * a single logits vector of length n. Output arrays receive k entries
 * each, sorted descending by logit.
 *
 * O(n*k); fine for n=619, k=5. */
void mc_topk_softmax(const float *logits, int n, int k,
                     int *out_idx, float *out_softmax);

#ifdef __cplusplus
}
#endif

#endif /* MODICO_H */
