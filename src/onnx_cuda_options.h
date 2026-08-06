// onnx_cuda_options.h: shared CUDA execution-provider resource policy.

#ifndef ONNX_CUDA_OPTIONS_H
#define ONNX_CUDA_OPTIONS_H

#include <stdbool.h>
#include <stddef.h>

#include "onnxruntime_c_api.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct OnnxCudaProviderPolicy {
  int physical_device_id;
  size_t total_bytes;
  size_t free_bytes;
  size_t arena_limit;
  double memory_fraction;
} OnnxCudaProviderPolicy;

// Configure the legacy CUDA provider options used by all Scalpel3 ONNX
// consumers. device_id is an ORT-visible ordinal; policy may be NULL.
bool onnx_cuda_provider_options(int device_id,
                                OrtCUDAProviderOptions *options,
                                OnnxCudaProviderPolicy *policy);

#ifdef __cplusplus
}
#endif

#endif
