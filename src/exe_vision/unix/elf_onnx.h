#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

enum elf_onnx_status {
  ELF_ONNX_OK = 0,
  ELF_ONNX_ERR = -1,
  ELF_ONNX_BADARG = -2,
  ELF_ONNX_NOMEM = -3,
  ELF_ONNX_BUF_TOO_SMALL = -4,
  ELF_ONNX_RETRYABLE = -5,
  ELF_ONNX_FATAL = -6,
  ELF_ONNX_TERMINATED = -7
};

enum elf_onnx_decode_mode {
  ELF_ONNX_DECODE_RAW_ARGMAX = 0,       // model argmax -> RLE triplets, no shape post-processing
  ELF_ONNX_DECODE_HEAVY_POSTPROCESS = 1 // current shape-based post-processing -> RLE triplets
};

typedef struct RegionTripletC {
  int32_t cls;
  int32_t offset;  // starting index into the 4096-length map, row-major
  int32_t size;    // run length
} RegionTripletC;

typedef void* elf_onnx_handle_t;

elf_onnx_handle_t elf_onnx_create(const char* model_path, const char* accelerator);

// like elf_onnx_create, but sized for batched inference: up to 'max_batch' 4096-byte
// chunks per ONNX Run (clamped to [1,4096]). CoreML and CUDA execute a fixed
// max_batch shape and elf_onnx_infer_batch pads the final partial Run; on CPU,
// max_batch is the per-Run ceiling. A handle created with max_batch > 1 on
// CoreML serves elf_onnx_infer_batch only.
elf_onnx_handle_t elf_onnx_create_batch(const char* model_path, const char* accelerator,
                                        int max_batch);

// like elf_onnx_create_batch, additionally pinning the session to a GPU device
// (meaningful for "cuda" only; ignored for "coreml"/"cpu")
elf_onnx_handle_t elf_onnx_create_batch_device(const char* model_path,
                                               const char* accelerator,
                                               int max_batch, int device_id);

// like elf_onnx_create_batch_device, with an explicit ONNX Runtime intra-op
// thread budget. A value of zero retains ONNX Runtime's default CPU behavior.
elf_onnx_handle_t elf_onnx_create_batch_device_threads(
    const char* model_path, const char* accelerator, int max_batch,
    int device_id, int intra_op_threads);

// the per-Run ceiling the handle was created with (0 for a NULL handle)
int elf_onnx_max_batch(elf_onnx_handle_t h);

void elf_onnx_destroy(elf_onnx_handle_t h);

int elf_onnx_set_decode_mode(elf_onnx_handle_t h, int mode);

// Set the maximum number of CPU workers used for per-chunk postprocessing. The
// workers are shared across ELF ONNX handles and created lazily.
int elf_onnx_set_decode_threads(elf_onnx_handle_t h, int threads);

// request termination of any in-flight (and all future) Runs on this handle. Safe to
// call from another thread; the terminated Run surfaces as a nonzero inference status.
// Once set it latches for the life of the handle.
int elf_onnx_terminate(elf_onnx_handle_t h);

void elf_onnx_reset_timing(elf_onnx_handle_t h);
int elf_onnx_write_timing_report(elf_onnx_handle_t h, const char* path);

int elf_onnx_infer(elf_onnx_handle_t h,
                   const uint8_t* blob, size_t nbytes,
                   RegionTripletC* out, size_t out_cap,
                   size_t* out_count_needed);

// batched inference over 'n' consecutive 4096-byte chunks in 'blobs' (the caller pads
// short chunks). On success, out_triplets[i] receives a malloc'd array of out_counts[i]
// triplets for chunk i (NULL when the chunk decodes to none); the caller frees each
// non-NULL array with free(). On any failure every output is released/zeroed. Decode
// (argmax, postprocess, RLE) is per chunk and identical to elf_onnx_infer.
int elf_onnx_infer_batch(elf_onnx_handle_t h,
                         const uint8_t* blobs, size_t n,
                         RegionTripletC** out_triplets,
                         size_t* out_counts);

// Optional singleton wrapper for C-only Scalpel integration.
bool elf_onnx_global_init(const char* model_path, const char* accelerator, int decode_mode);

// singleton init sized for batched inference (see elf_onnx_create_batch). Idempotent
// like elf_onnx_global_init: a second call while initialized only updates decode_mode.
bool elf_onnx_global_init_batch(const char* model_path, const char* accelerator,
                                int decode_mode, int max_batch);

// like elf_onnx_global_init_batch, additionally pinning the session's GPU device
// ("cuda" only; ignored otherwise)
bool elf_onnx_global_init_batch_device(const char* model_path, const char* accelerator,
                                       int decode_mode, int max_batch, int device_id);

// thread-budgeted form used by Scalpel's batched block-validation scheduler
bool elf_onnx_global_init_batch_device_threads(
    const char* model_path, const char* accelerator, int decode_mode,
    int max_batch, int device_id, int intra_op_threads);

void elf_onnx_global_shutdown(void);
elf_onnx_handle_t elf_onnx_global_get(void);
int elf_onnx_global_set_decode_mode(int mode);

// terminate any in-flight Run on the global handle (0 on success, nonzero when there
// is no handle or the request failed); safe from any thread
int elf_onnx_global_terminate(void);
void elf_onnx_global_reset_timing(void);
int elf_onnx_global_write_timing_report(const char* path);

#ifdef __cplusplus
} // extern "C"
#endif
