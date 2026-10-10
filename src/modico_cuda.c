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

#define _POSIX_C_SOURCE 200809L

#include "modico_cuda.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)

typedef int cuda_error_t;
typedef void *cuda_stream_t;
typedef int nvrtc_result_t;
typedef void *nvrtc_program_t;
typedef int cu_result_t;
typedef void *cu_module_t;
typedef void *cu_function_t;

enum {
    MC_CUDA_SUCCESS = 0,
    MC_CUDA_MEMCPY_HOST_TO_DEVICE = 1,
    MC_CUDA_MEMCPY_DEVICE_TO_HOST = 2,
    MC_CUDA_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR = 75,
    MC_CUDA_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR = 76,
    MC_NVRTC_SUCCESS = 0,
    MC_CU_SUCCESS = 0
};

typedef struct {
    cuda_error_t (*set_device)(int);
    cuda_error_t (*device_get_attribute)(int *, int, int);
    cuda_error_t (*malloc_device)(void **, size_t);
    cuda_error_t (*free_device)(void *);
    cuda_error_t (*malloc_host)(void **, size_t);
    cuda_error_t (*free_host)(void *);
    cuda_error_t (*memcpy_async)(void *, const void *, size_t, int,
                                 cuda_stream_t);
    cuda_error_t (*stream_create)(cuda_stream_t *, unsigned int);
    cuda_error_t (*stream_destroy)(cuda_stream_t);
    cuda_error_t (*stream_synchronize)(cuda_stream_t);
    const char *(*error_string)(cuda_error_t);

    nvrtc_result_t (*nvrtc_create_program)(nvrtc_program_t *, const char *,
                                           const char *, int,
                                           const char *const *,
                                           const char *const *);
    nvrtc_result_t (*nvrtc_compile_program)(nvrtc_program_t, int,
                                            const char *const *);
    nvrtc_result_t (*nvrtc_get_cubin_size)(nvrtc_program_t, size_t *);
    nvrtc_result_t (*nvrtc_get_cubin)(nvrtc_program_t, char *);
    nvrtc_result_t (*nvrtc_get_log_size)(nvrtc_program_t, size_t *);
    nvrtc_result_t (*nvrtc_get_log)(nvrtc_program_t, char *);
    nvrtc_result_t (*nvrtc_destroy_program)(nvrtc_program_t *);
    const char *(*nvrtc_error_string)(nvrtc_result_t);

    cu_result_t (*cu_init)(unsigned int);
    cu_result_t (*cu_module_load_data)(cu_module_t *, const void *);
    cu_result_t (*cu_module_get_function)(cu_function_t *, cu_module_t,
                                          const char *);
    cu_result_t (*cu_module_unload)(cu_module_t);
    cu_result_t (*cu_launch_kernel)(cu_function_t,
                                    unsigned int, unsigned int, unsigned int,
                                    unsigned int, unsigned int, unsigned int,
                                    unsigned int, cuda_stream_t,
                                    void **, void **);
    cu_result_t (*cu_error_name)(cu_result_t, const char **);
} mc_cuda_api_t;

static mc_cuda_api_t mc_cuda_api;
static int mc_cuda_api_state;
static void *mc_cuda_driver_handle;

struct mc_cuda_preprocessor {
    int device_id;
    int run_batch;
    int block_size;
    int num_classes;
    size_t windows;
    cuda_stream_t stream;
    int owns_stream;
    cu_module_t module;
    cu_function_t kernel;
    uint8_t *host_input;
    float *host_output;
    void *device_bytes;
    void *device_input;
    void *device_global;
    void *device_local;
    void *device_output;
};

static const char mc_cuda_kernel_source[] =
    "extern \"C\" __global__ void scalpel3_modico_preprocess("
    "const unsigned char *raw, long long *wide, float *global_hist, "
    "float *local_hist, int block_size, int windows, int actual_batch, "
    "int run_batch) {"
    "  unsigned long long tid = (unsigned long long)blockIdx.x * blockDim.x "
    "                         + threadIdx.x;"
    "  unsigned long long stride = (unsigned long long)blockDim.x * gridDim.x;"
    "  unsigned long long wide_count = (unsigned long long)run_batch "
    "                                * (unsigned long long)block_size;"
    "  for (unsigned long long i = tid; i < wide_count; i += stride) {"
    "    int batch = (int)(i / (unsigned long long)block_size);"
    "    wide[i] = batch < actual_batch ? (long long)raw[i] : 0LL;"
    "  }"
    "  unsigned long long global_count = (unsigned long long)run_batch * 256ULL;"
    "  for (unsigned long long i = tid; i < global_count; i += stride) {"
    "    int batch = (int)(i >> 8);"
    "    int value = (int)(i & 255ULL);"
    "    int count = 0;"
    "    if (batch < actual_batch) {"
    "      const unsigned char *block = raw + (unsigned long long)batch "
    "                                       * (unsigned long long)block_size;"
    "      for (int offset = 0; offset < block_size; offset++) {"
    "        count += block[offset] == value;"
    "      }"
    "    } else if (value == 0) {"
    "      count = block_size;"
    "    }"
    "    global_hist[i] = (float)count;"
    "  }"
    "  unsigned long long local_count = (unsigned long long)run_batch "
    "                                 * (unsigned long long)windows * 256ULL;"
    "  for (unsigned long long i = tid; i < local_count; i += stride) {"
    "    int value = (int)(i & 255ULL);"
    "    unsigned long long cell = i >> 8;"
    "    int window = (int)(cell % (unsigned long long)windows);"
    "    int batch = (int)(cell / (unsigned long long)windows);"
    "    int count = 0;"
    "    if (batch < actual_batch) {"
    "      const unsigned char *start = raw + (unsigned long long)batch "
    "                                      * (unsigned long long)block_size "
    "                                      + (unsigned long long)window * 16ULL;"
    "      for (int offset = 0; offset < 32; offset++) {"
    "        count += start[offset] == value;"
    "      }"
    "    } else if (value == 0) {"
    "      count = 32;"
    "    }"
    "    local_hist[i] = (float)count;"
    "  }"
    "}";

static void mc_cuda_reason(char *reason, size_t reason_size,
                           const char *message)
{
    if (reason && reason_size > 0) {
        snprintf(reason, reason_size, "%s", message ? message : "unknown");
    }
}

static void *mc_cuda_symbol(const char *name)
{
    return dlsym(RTLD_DEFAULT, name);
}

#define MC_CUDA_LOAD_FROM(member, symbol, handle)                            \
    do {                                                                      \
        void *resolved = (handle) ? dlsym((handle), (symbol))                 \
                                  : mc_cuda_symbol(symbol);                   \
        *(void **)(&mc_cuda_api.member) = resolved;                           \
        if (!mc_cuda_api.member) {                                            \
            if (reason && reason_size > 0) {                                  \
                snprintf(reason, reason_size,                                 \
                         "required CUDA symbol %s is unavailable", symbol);  \
            }                                                                 \
            mc_cuda_api_state = -1;                                           \
            return 0;                                                         \
        }                                                                     \
    } while (0)

#define MC_CUDA_LOAD(member, symbol) \
    MC_CUDA_LOAD_FROM(member, symbol, NULL)

#define MC_CUDA_LOAD_DRIVER(member, symbol) \
    MC_CUDA_LOAD_FROM(member, symbol, mc_cuda_driver_handle)

static int mc_cuda_load_api(char *reason, size_t reason_size)
{
    if (mc_cuda_api_state != 0) {
        return mc_cuda_api_state > 0;
    }

    mc_cuda_driver_handle = dlopen("libcuda.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!mc_cuda_driver_handle) {
        mc_cuda_reason(reason, reason_size,
                       "the NVIDIA CUDA driver library is unavailable");
        mc_cuda_api_state = -1;
        return 0;
    }

    MC_CUDA_LOAD(set_device, "cudaSetDevice");
    MC_CUDA_LOAD(device_get_attribute, "cudaDeviceGetAttribute");
    MC_CUDA_LOAD(malloc_device, "cudaMalloc");
    MC_CUDA_LOAD(free_device, "cudaFree");
    MC_CUDA_LOAD(malloc_host, "cudaMallocHost");
    MC_CUDA_LOAD(free_host, "cudaFreeHost");
    MC_CUDA_LOAD(memcpy_async, "cudaMemcpyAsync");
    MC_CUDA_LOAD(stream_create, "cudaStreamCreateWithFlags");
    MC_CUDA_LOAD(stream_destroy, "cudaStreamDestroy");
    MC_CUDA_LOAD(stream_synchronize, "cudaStreamSynchronize");
    MC_CUDA_LOAD(error_string, "cudaGetErrorString");
    MC_CUDA_LOAD(nvrtc_create_program, "nvrtcCreateProgram");
    MC_CUDA_LOAD(nvrtc_compile_program, "nvrtcCompileProgram");
    MC_CUDA_LOAD(nvrtc_get_cubin_size, "nvrtcGetCUBINSize");
    MC_CUDA_LOAD(nvrtc_get_cubin, "nvrtcGetCUBIN");
    MC_CUDA_LOAD(nvrtc_get_log_size, "nvrtcGetProgramLogSize");
    MC_CUDA_LOAD(nvrtc_get_log, "nvrtcGetProgramLog");
    MC_CUDA_LOAD(nvrtc_destroy_program, "nvrtcDestroyProgram");
    MC_CUDA_LOAD(nvrtc_error_string, "nvrtcGetErrorString");
    MC_CUDA_LOAD_DRIVER(cu_init, "cuInit");
    MC_CUDA_LOAD_DRIVER(cu_module_load_data, "cuModuleLoadData");
    MC_CUDA_LOAD_DRIVER(cu_module_get_function, "cuModuleGetFunction");
    MC_CUDA_LOAD_DRIVER(cu_module_unload, "cuModuleUnload");
    MC_CUDA_LOAD_DRIVER(cu_launch_kernel, "cuLaunchKernel");
    MC_CUDA_LOAD_DRIVER(cu_error_name, "cuGetErrorName");

    mc_cuda_api_state = 1;
    return 1;
}

#undef MC_CUDA_LOAD
#undef MC_CUDA_LOAD_DRIVER
#undef MC_CUDA_LOAD_FROM

static int mc_cuda_ok(cuda_error_t result, char *reason, size_t reason_size)
{
    if (result == MC_CUDA_SUCCESS) {
        return 1;
    }
    mc_cuda_reason(reason, reason_size, mc_cuda_api.error_string(result));
    return 0;
}

static int mc_cu_ok(cu_result_t result, char *reason, size_t reason_size)
{
    const char *name = NULL;

    if (result == MC_CU_SUCCESS) {
        return 1;
    }
    mc_cuda_api.cu_error_name(result, &name);
    mc_cuda_reason(reason, reason_size, name ? name : "CUDA driver error");
    return 0;
}

static int mc_cuda_compile_kernel(mc_cuda_preprocessor_t *preprocessor,
                                  char *reason,
                                  size_t reason_size)
{
    nvrtc_program_t program = NULL;
    nvrtc_result_t result;
    char architecture[64];
    const char *options[2];
    char *cubin = NULL;
    size_t cubin_size = 0;
    int major = 0;
    int minor = 0;
    int ok = 0;

    if (!mc_cuda_ok(mc_cuda_api.device_get_attribute(
                        &major,
                        MC_CUDA_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR,
                        preprocessor->device_id), reason, reason_size)
        || !mc_cuda_ok(mc_cuda_api.device_get_attribute(
                           &minor,
                           MC_CUDA_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR,
                           preprocessor->device_id), reason, reason_size)) {
        return 0;
    }
    snprintf(architecture, sizeof(architecture),
             "--gpu-architecture=sm_%d%d", major, minor);
    options[0] = "--std=c++11";
    options[1] = architecture;

    result = mc_cuda_api.nvrtc_create_program(
        &program, mc_cuda_kernel_source, "scalpel3_modico_preprocess.cu",
        0, NULL, NULL);
    if (result != MC_NVRTC_SUCCESS) {
        mc_cuda_reason(reason, reason_size,
                       mc_cuda_api.nvrtc_error_string(result));
        return 0;
    }
    result = mc_cuda_api.nvrtc_compile_program(program, 2, options);
    if (result != MC_NVRTC_SUCCESS) {
        size_t log_size = 0;
        char *log = NULL;

        mc_cuda_api.nvrtc_get_log_size(program, &log_size);
        if (log_size > 1 && log_size < 1024 * 1024) {
            log = malloc(log_size);
            if (log) {
                mc_cuda_api.nvrtc_get_log(program, log);
                mc_cuda_reason(reason, reason_size, log);
                free(log);
            }
        }
        if (!log) {
            mc_cuda_reason(reason, reason_size,
                           mc_cuda_api.nvrtc_error_string(result));
        }
        goto done;
    }
    if (mc_cuda_api.nvrtc_get_cubin_size(program, &cubin_size)
            != MC_NVRTC_SUCCESS
        || cubin_size == 0 || cubin_size > 16 * 1024 * 1024) {
        mc_cuda_reason(reason, reason_size, "NVRTC returned invalid CUBIN");
        goto done;
    }
    cubin = malloc(cubin_size);
    if (!cubin
        || mc_cuda_api.nvrtc_get_cubin(program, cubin) != MC_NVRTC_SUCCESS
        || !mc_cu_ok(mc_cuda_api.cu_module_load_data(&preprocessor->module,
                                                      cubin),
                     reason, reason_size)
        || !mc_cu_ok(mc_cuda_api.cu_module_get_function(
                         &preprocessor->kernel, preprocessor->module,
                         "scalpel3_modico_preprocess"),
                     reason, reason_size)) {
        goto done;
    }
    ok = 1;

done:
    free(cubin);
    mc_cuda_api.nvrtc_destroy_program(&program);
    return ok;
}

int mc_cuda_preprocessor_available(char *reason, size_t reason_size)
{
    return mc_cuda_load_api(reason, reason_size);
}


void *mc_cuda_stream_create(int device_id, char *reason, size_t reason_size)
{
    cuda_stream_t stream = NULL;

    if (!mc_cuda_load_api(reason, reason_size)
        || !mc_cuda_ok(mc_cuda_api.set_device(device_id), reason, reason_size)
        || !mc_cuda_ok(mc_cuda_api.stream_create(&stream, 1),
                       reason, reason_size)) {
        return NULL;
    }
    return stream;
}


void mc_cuda_stream_destroy(int device_id, void *stream)
{
    if (!stream || !mc_cuda_api.stream_destroy) {
        return;
    }
    mc_cuda_api.set_device(device_id);
    mc_cuda_api.stream_destroy((cuda_stream_t)stream);
}


mc_cuda_preprocessor_t *mc_cuda_preprocessor_create(
    int device_id, int run_batch, int block_size, int num_classes,
    void *shared_stream,
    char *reason, size_t reason_size)
{
    mc_cuda_preprocessor_t *preprocessor;
    size_t input_bytes;
    size_t input_elements;
    size_t global_elements;
    size_t local_elements;
    size_t output_elements;
    size_t global_bytes;
    size_t local_bytes;
    size_t output_bytes;

    if (device_id < 0 || run_batch <= 0 || block_size < 32
        || (block_size - 32) % 16 != 0 || num_classes <= 0
        || !mc_cuda_load_api(reason, reason_size)) {
        return NULL;
    }
    size_t batch = (size_t)run_batch;
    size_t block = (size_t)block_size;
    size_t classes = (size_t)num_classes;
    size_t windows = (block - 32u) / 16u + 1u;
    if (batch > SIZE_MAX / block
        || batch > SIZE_MAX / 256u
        || windows > SIZE_MAX / 256u
        || batch > SIZE_MAX / (windows * 256u)
        || batch > SIZE_MAX / classes) {
        mc_cuda_reason(reason, reason_size, "CUDA buffer size overflow");
        return NULL;
    }
    input_elements = batch * block;
    global_elements = batch * 256u;
    local_elements = batch * windows * 256u;
    output_elements = batch * classes;
    if (input_elements > SIZE_MAX / sizeof(int64_t)
        || global_elements > SIZE_MAX / sizeof(float)
        || local_elements > SIZE_MAX / sizeof(float)
        || output_elements > SIZE_MAX / sizeof(float)) {
        mc_cuda_reason(reason, reason_size, "CUDA buffer size overflow");
        return NULL;
    }
    preprocessor = calloc(1, sizeof(*preprocessor));
    if (!preprocessor) {
        mc_cuda_reason(reason, reason_size, "allocation failed");
        return NULL;
    }
    preprocessor->device_id = device_id;
    preprocessor->run_batch = run_batch;
    preprocessor->block_size = block_size;
    preprocessor->num_classes = num_classes;
    preprocessor->windows = windows;
    preprocessor->stream = (cuda_stream_t)shared_stream;
    input_bytes = input_elements;
    global_bytes = global_elements * sizeof(float);
    local_bytes = local_elements * sizeof(float);
    output_bytes = output_elements * sizeof(float);

    if (!mc_cuda_ok(mc_cuda_api.set_device(device_id), reason, reason_size)
        || !mc_cu_ok(mc_cuda_api.cu_init(0), reason, reason_size)) {
        mc_cuda_preprocessor_destroy(preprocessor);
        return NULL;
    }
    if (!preprocessor->stream) {
        if (!mc_cuda_ok(mc_cuda_api.stream_create(&preprocessor->stream, 1),
                        reason, reason_size)) {
            mc_cuda_preprocessor_destroy(preprocessor);
            return NULL;
        }
        preprocessor->owns_stream = 1;
    }
    if (!mc_cuda_ok(mc_cuda_api.malloc_host(
                        (void **)&preprocessor->host_input, input_bytes),
                    reason, reason_size)
        || !mc_cuda_ok(mc_cuda_api.malloc_host(
                           (void **)&preprocessor->host_output, output_bytes),
                       reason, reason_size)
        || !mc_cuda_ok(mc_cuda_api.malloc_device(
                           &preprocessor->device_bytes, input_bytes),
                       reason, reason_size)
        || !mc_cuda_ok(mc_cuda_api.malloc_device(
                           &preprocessor->device_input,
                           input_elements * sizeof(int64_t)),
                       reason, reason_size)
        || !mc_cuda_ok(mc_cuda_api.malloc_device(
                           &preprocessor->device_global, global_bytes),
                       reason, reason_size)
        || !mc_cuda_ok(mc_cuda_api.malloc_device(
                           &preprocessor->device_local, local_bytes),
                       reason, reason_size)
        || !mc_cuda_ok(mc_cuda_api.malloc_device(
                           &preprocessor->device_output, output_bytes),
                       reason, reason_size)
        || !mc_cuda_compile_kernel(preprocessor, reason, reason_size)) {
        mc_cuda_preprocessor_destroy(preprocessor);
        return NULL;
    }
    return preprocessor;
}

void mc_cuda_preprocessor_destroy(mc_cuda_preprocessor_t *preprocessor)
{
    if (!preprocessor) {
        return;
    }
    if (mc_cuda_api.set_device) {
        mc_cuda_api.set_device(preprocessor->device_id);
    }
    if (preprocessor->module && mc_cuda_api.cu_module_unload) {
        mc_cuda_api.cu_module_unload(preprocessor->module);
    }
    if (preprocessor->device_output && mc_cuda_api.free_device) {
        mc_cuda_api.free_device(preprocessor->device_output);
    }
    if (preprocessor->device_local && mc_cuda_api.free_device) {
        mc_cuda_api.free_device(preprocessor->device_local);
    }
    if (preprocessor->device_global && mc_cuda_api.free_device) {
        mc_cuda_api.free_device(preprocessor->device_global);
    }
    if (preprocessor->device_input && mc_cuda_api.free_device) {
        mc_cuda_api.free_device(preprocessor->device_input);
    }
    if (preprocessor->device_bytes && mc_cuda_api.free_device) {
        mc_cuda_api.free_device(preprocessor->device_bytes);
    }
    if (preprocessor->host_output && mc_cuda_api.free_host) {
        mc_cuda_api.free_host(preprocessor->host_output);
    }
    if (preprocessor->host_input && mc_cuda_api.free_host) {
        mc_cuda_api.free_host(preprocessor->host_input);
    }
    if (preprocessor->owns_stream && preprocessor->stream
        && mc_cuda_api.stream_destroy) {
        mc_cuda_api.stream_destroy(preprocessor->stream);
    }
    free(preprocessor);
}

int mc_cuda_preprocessor_prepare(mc_cuda_preprocessor_t *preprocessor,
                                 const uint8_t *bytes,
                                 int batch_size,
                                 char *reason,
                                 size_t reason_size)
{
    size_t input_bytes;
    size_t work_items;
    size_t grid_blocks;
    unsigned int blocks;
    unsigned int threads = 256;
    void *arguments[8];
    int block_size;
    int windows;
    int run_batch;

    if (!preprocessor || !bytes || batch_size <= 0
        || batch_size > preprocessor->run_batch) {
        mc_cuda_reason(reason, reason_size, "invalid CUDA preprocessing batch");
        return 0;
    }
    input_bytes = (size_t)batch_size * (size_t)preprocessor->block_size;
    memcpy(preprocessor->host_input, bytes, input_bytes);
    if (!mc_cuda_ok(mc_cuda_api.set_device(preprocessor->device_id),
                    reason, reason_size)
        || !mc_cuda_ok(mc_cuda_api.memcpy_async(
                           preprocessor->device_bytes,
                           preprocessor->host_input, input_bytes,
                           MC_CUDA_MEMCPY_HOST_TO_DEVICE,
                           preprocessor->stream),
                       reason, reason_size)) {
        return 0;
    }

    block_size = preprocessor->block_size;
    windows = (int)preprocessor->windows;
    run_batch = preprocessor->run_batch;
    arguments[0] = &preprocessor->device_bytes;
    arguments[1] = &preprocessor->device_input;
    arguments[2] = &preprocessor->device_global;
    arguments[3] = &preprocessor->device_local;
    arguments[4] = &block_size;
    arguments[5] = &windows;
    arguments[6] = &batch_size;
    arguments[7] = &run_batch;
    work_items = preprocessor->windows
               * (size_t)preprocessor->run_batch * 256u;
    grid_blocks = (work_items + (size_t)threads - 1u) / (size_t)threads;
    blocks = grid_blocks > 1024u ? 1024u : (unsigned int)grid_blocks;
    if (!mc_cu_ok(mc_cuda_api.cu_launch_kernel(
                      preprocessor->kernel, blocks, 1, 1, threads, 1, 1, 0,
                      preprocessor->stream, arguments, NULL),
                  reason, reason_size)) {
        return 0;
    }
    if (preprocessor->owns_stream
        && !mc_cuda_ok(mc_cuda_api.stream_synchronize(preprocessor->stream),
                       reason, reason_size)) {
        return 0;
    }
    return 1;
}

int mc_cuda_preprocessor_copy_output(mc_cuda_preprocessor_t *preprocessor,
                                     float *logits,
                                     int batch_size,
                                     char *reason,
                                     size_t reason_size)
{
    size_t output_bytes;

    if (!preprocessor || !logits || batch_size <= 0
        || batch_size > preprocessor->run_batch) {
        mc_cuda_reason(reason, reason_size, "invalid CUDA output batch");
        return 0;
    }
    output_bytes = (size_t)batch_size
                 * (size_t)preprocessor->num_classes * sizeof(float);
    if (!mc_cuda_ok(mc_cuda_api.set_device(preprocessor->device_id),
                    reason, reason_size)
        || !mc_cuda_ok(mc_cuda_api.memcpy_async(
                           preprocessor->host_output,
                           preprocessor->device_output, output_bytes,
                           MC_CUDA_MEMCPY_DEVICE_TO_HOST,
                           preprocessor->stream),
                       reason, reason_size)
        || !mc_cuda_ok(mc_cuda_api.stream_synchronize(preprocessor->stream),
                       reason, reason_size)) {
        return 0;
    }
    memcpy(logits, preprocessor->host_output, output_bytes);
    return 1;
}

void *mc_cuda_preprocessor_input(const mc_cuda_preprocessor_t *preprocessor)
{
    return preprocessor ? preprocessor->device_input : NULL;
}

void *mc_cuda_preprocessor_global_histograms(
    const mc_cuda_preprocessor_t *preprocessor)
{
    return preprocessor ? preprocessor->device_global : NULL;
}

void *mc_cuda_preprocessor_local_histograms(
    const mc_cuda_preprocessor_t *preprocessor)
{
    return preprocessor ? preprocessor->device_local : NULL;
}

void *mc_cuda_preprocessor_output(const mc_cuda_preprocessor_t *preprocessor)
{
    return preprocessor ? preprocessor->device_output : NULL;
}

size_t mc_cuda_preprocessor_windows(
    const mc_cuda_preprocessor_t *preprocessor)
{
    return preprocessor ? preprocessor->windows : 0;
}

#else

struct mc_cuda_preprocessor {
    int unused;
};

int mc_cuda_preprocessor_available(char *reason, size_t reason_size)
{
    if (reason && reason_size > 0) {
        snprintf(reason, reason_size, "CUDA preprocessing is Linux-only");
    }
    return 0;
}

void *mc_cuda_stream_create(int device_id, char *reason, size_t reason_size)
{
    (void)device_id;
    mc_cuda_preprocessor_available(reason, reason_size);
    return NULL;
}

void mc_cuda_stream_destroy(int device_id, void *stream)
{
    (void)device_id;
    (void)stream;
}

mc_cuda_preprocessor_t *mc_cuda_preprocessor_create(
    int device_id, int run_batch, int block_size, int num_classes,
    void *shared_stream,
    char *reason, size_t reason_size)
{
    (void)device_id;
    (void)run_batch;
    (void)block_size;
    (void)num_classes;
    (void)shared_stream;
    mc_cuda_preprocessor_available(reason, reason_size);
    return NULL;
}

void mc_cuda_preprocessor_destroy(mc_cuda_preprocessor_t *preprocessor)
{
    (void)preprocessor;
}

int mc_cuda_preprocessor_prepare(mc_cuda_preprocessor_t *preprocessor,
                                 const uint8_t *bytes,
                                 int batch_size,
                                 char *reason,
                                 size_t reason_size)
{
    (void)preprocessor;
    (void)bytes;
    (void)batch_size;
    mc_cuda_preprocessor_available(reason, reason_size);
    return 0;
}

int mc_cuda_preprocessor_copy_output(mc_cuda_preprocessor_t *preprocessor,
                                     float *logits,
                                     int batch_size,
                                     char *reason,
                                     size_t reason_size)
{
    (void)preprocessor;
    (void)logits;
    (void)batch_size;
    mc_cuda_preprocessor_available(reason, reason_size);
    return 0;
}

void *mc_cuda_preprocessor_input(const mc_cuda_preprocessor_t *preprocessor)
{
    (void)preprocessor;
    return NULL;
}

void *mc_cuda_preprocessor_global_histograms(
    const mc_cuda_preprocessor_t *preprocessor)
{
    (void)preprocessor;
    return NULL;
}

void *mc_cuda_preprocessor_local_histograms(
    const mc_cuda_preprocessor_t *preprocessor)
{
    (void)preprocessor;
    return NULL;
}

void *mc_cuda_preprocessor_output(const mc_cuda_preprocessor_t *preprocessor)
{
    (void)preprocessor;
    return NULL;
}

size_t mc_cuda_preprocessor_windows(
    const mc_cuda_preprocessor_t *preprocessor)
{
    (void)preprocessor;
    return 0;
}

#endif
