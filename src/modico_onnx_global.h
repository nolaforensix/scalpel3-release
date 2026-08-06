/*
 * modico_onnx_global.h — process-global MoDiCo ONNX session for Scalpel3.
 *
 * MoDiCo is a byte-fragment classifier (619 file-type classes) used to
 * PRIORITIZE block selection during fragmented reassembly. It complements
 * the structural block validators; it never excludes a block (see
 * carve.c block-validation phase + reassembly.c block selection).
 *
 * This mirrors the structure of elf_onnx_global.{c,h}: a single
 * mutex-guarded session created once at startup and shared by the
 * block-validation phase. The underlying session/inference layer is the
 * vendored modico.{c,h} (ORT C API). Unlike the ELF integration, MoDiCo
 * uses the ORT *C* API directly, so there is no separate C++/CABI layer.
 *
 * If no exported model exists for the device's block size, init returns
 * false and the caller runs vanilla Scalpel (MoDiCo disabled). Accelerated
 * provider failures (CUDA or CoreML) fall back to the cpu provider inside
 * init, so a build whose ORT library lacks the provider, or a machine whose
 * driver rejects it, still classifies; scalpel.c turns that downgrade into
 * a fatal error when the provider was requested explicitly with -Y.
 */
#ifndef MODICO_ONNX_GLOBAL_H
#define MODICO_ONNX_GLOBAL_H

#include <stdbool.h>
#include "modico.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize the global MoDiCo session once.
 *
 *   model_base_path   path WITHOUT extension; the loader looks for
 *                     "<base>.onnx" (FP32) and "<base>_int8.onnx" (INT8)
 *                     and auto-selects based on CPU capability
 *                     (mc_create_session_auto).
 *   intra_op_threads  ORT intra-op threads (0 = ORT default). For Scalpel
 *                     the block-validation populate loop is single-threaded
 *                     and batched, so a value >1 here lets ORT parallelize
 *                     within each batched Run.
 *   accelerator       "cuda", "coreml", or "cpu". A NULL/empty/unknown value
 *                     is treated as "cpu".
 *   device_id         GPU device to run on (meaningful for "cuda" only;
 *                     ignored for "coreml"/"cpu").
 *
 * Returns true on success (session ready), false on failure (model missing
 * or load error). On false, the caller should disable MoDiCo and continue.
 * Idempotent: a second call while already initialized returns true. */
bool modico_onnx_global_init(const char *model_base_path,
                             int intra_op_threads,
                             const char *accelerator,
                             int device_id);

/* Tear down the global session (safe to call multiple times / when never
 * initialized). */
void modico_onnx_global_shutdown(void);

/* Returns the global session handle, or NULL if not initialized. The
 * handle is owned by this module — do NOT destroy it directly. */
mc_session_t *modico_onnx_global_get(void);

/* True iff a session is currently initialized and available. Convenience
 * for guarding MoDiCo code paths without holding the handle. */
bool modico_onnx_global_enabled(void);

/* Number of output classes of the loaded model (619 for current exports),
 * or 0 if not initialized. */
int modico_onnx_global_num_classes(void);

const char *modico_onnx_global_provider(void);
const char *modico_onnx_global_model_path(void);
int modico_onnx_global_device_id(void);
bool modico_onnx_global_uses_cuda(void);
bool modico_onnx_global_uses_coreml(void);
int modico_onnx_global_terminate_current_run(void);

#ifdef __cplusplus
}
#endif

#endif /* MODICO_ONNX_GLOBAL_H */
