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
