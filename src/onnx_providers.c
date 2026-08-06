// onnx_providers.c: implementation of unified ONNX execution provider selection. See
// onnx_providers.h for the contract. Capability checking has three layers: the ONNX
// CUDA libraries are selected before provider discovery, the ONNX Runtime build must
// contain the requested provider (GetAvailableProviders), the hardware must be present
// (an NVML-backed gpu_mem_query for CUDA, Apple Silicon for CoreML), and for CUDA a
// throwaway session-options probe must accept the provider. This catches a broken
// driver/runtime pairing at startup without loading any model.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#if defined(__linux__)
#include <dlfcn.h>
#include <glob.h>
#include <unistd.h>
#endif

#include "onnxruntime_c_api.h"
#include "gpu_meminfo.h"
#include "onnx_cuda_options.h"
#include "onnx_providers.h"

static const OrtApi *g_ort = NULL;

// the resolved selection, written by onnx_providers_resolve() before any threads exist
static char g_provider[16] = "cpu";
static int  g_devices[ONNX_MAX_GPU_DEVICES];
static int  g_num_devices = 0;
static bool g_explicit = false;
static char g_note[320] = {0};

// CUDA device ids have two spaces: ONNX Runtime sessions use the CUDA runtime's
// visible-device ordinals, which CUDA_VISIBLE_DEVICES filters and reorders, while the
// NVML queries behind gpu_mem_query() always see physical devices. The map below
// translates visible ordinals to physical ids so that detection, session placement, and
// memory queries all agree with what the sessions actually run on. A g_visible_count of
// -1 means CUDA_VISIBLE_DEVICES is not set and the two spaces coincide.
static int g_visible_map[ONNX_MAX_GPU_DEVICES];
static int g_visible_count = -1;

static int g_cuda_runtime_version = -1;
static size_t g_cudnn_version = 0;
static bool g_cuda_versions_checked = false;
static char g_cuda_runtime_description[2048] = {0};

#define SCALPEL3_CUDA_RUNTIME_DIR "/usr/local/lib/scalpel3-cuda"
#define SCALPEL3_TENSORRT_RUNTIME_DIR \
    SCALPEL3_CUDA_RUNTIME_DIR "/tensorrt_libs"
#define OP_CUDA_RUNTIME_PATH_MAX PATH_MAX

#if defined(__linux__)
static const char *const g_cuda_runtime_library_patterns[] = {
    "nvidia/cu13/lib/libcudart.so.13",
    "nvidia/cu13/lib/libcublasLt.so.13",
    "nvidia/cu13/lib/libcublas.so.13",
    "nvidia/cu13/lib/libcurand.so.10",
    "nvidia/cu13/lib/libcufft.so.12",
    "nvidia/cu13/lib/libnvJitLink.so.13",
    "nvidia/cu13/lib/libnvrtc-builtins.so.13.*",
    "nvidia/cu13/lib/libnvrtc.so.13",
    "nvidia/cudnn/lib/libcudnn_graph.so.9",
    "nvidia/cudnn/lib/libcudnn_ops.so.9",
    "nvidia/cudnn/lib/libcudnn_adv.so.9",
    "nvidia/cudnn/lib/libcudnn_cnn.so.9",
    "nvidia/cudnn/lib/libcudnn_engines_precompiled.so.9",
    "nvidia/cudnn/lib/libcudnn_engines_runtime_compiled.so.9",
    "nvidia/cudnn/lib/libcudnn_engines_tensor_ir.so.9",
    "nvidia/cudnn/lib/libcudnn_ext.so.9",
    "nvidia/cudnn/lib/libcudnn_heuristic.so.9",
    "nvidia/cudnn/lib/libcudnn.so.9"
};
#define OP_CUDA_RUNTIME_LIBRARY_COUNT \
    (sizeof(g_cuda_runtime_library_patterns) / \
     sizeof(g_cuda_runtime_library_patterns[0]))
#define OP_CUDA_CUDART_INDEX 0
#define OP_CUDA_CUDNN_INDEX (OP_CUDA_RUNTIME_LIBRARY_COUNT - 1)
static bool g_cuda_runtime_preload_checked = false;
static bool g_cuda_runtime_is_private = false;
static char g_cuda_runtime_preload_error[320] = {0};
static char g_cuda_runtime_root[OP_CUDA_RUNTIME_PATH_MAX] = {0};
static char g_cuda_runtime_libraries[OP_CUDA_RUNTIME_LIBRARY_COUNT]
                                    [OP_CUDA_RUNTIME_PATH_MAX];
static void *g_cuda_runtime_handles[OP_CUDA_RUNTIME_LIBRARY_COUNT] = {0};

static const char *const g_tensorrt_runtime_library_names[] = {
    "libnvinfer.so.10",
    "libnvinfer_plugin.so.10",
    "libnvonnxparser.so.10"
};
#define OP_TENSORRT_RUNTIME_LIBRARY_COUNT \
    (sizeof(g_tensorrt_runtime_library_names) / \
     sizeof(g_tensorrt_runtime_library_names[0]))
static bool g_tensorrt_runtime_checked = false;
static bool g_tensorrt_runtime_available = false;
static char g_tensorrt_runtime_error[320] = {0};
static char g_tensorrt_runtime_root[OP_CUDA_RUNTIME_PATH_MAX] = {0};
static char g_tensorrt_runtime_libraries[OP_TENSORRT_RUNTIME_LIBRARY_COUNT]
                                        [OP_CUDA_RUNTIME_PATH_MAX];
static void *g_tensorrt_runtime_handles[
    OP_TENSORRT_RUNTIME_LIBRARY_COUNT] = {0};
#endif

static int op_cuda_physical_for_uuid(const char *uuid);
static void op_parse_visible_devices(void);
static int op_cuda_physical(int ordinal);
static bool op_init_api(char *errbuf, size_t errbuf_sz);
static bool op_build_has_provider(const char *ep_name);
static bool op_nvidia_hardware_present(void);
static bool op_cuda_physical_present(int physical);
static bool op_cuda_device_present(int device_id);
static bool op_cuda_resolve_private_library(const char *pattern, char *path,
                                            size_t path_sz, char *errbuf,
                                            size_t errbuf_sz);
static bool op_cuda_preload_runtime(char *errbuf, size_t errbuf_sz);
static bool op_tensorrt_preload_runtime(char *errbuf, size_t errbuf_sz);
static bool op_cuda_resolve_symbol(void *handle, const char *symbol_name,
                                   const char *expected_path,
                                   void **symbol, char *loaded_path,
                                   size_t loaded_path_sz, char *errbuf,
                                   size_t errbuf_sz);
static bool op_cuda_library_versions(char *errbuf, size_t errbuf_sz);
static bool op_cuda_device_healthy(int device_id, char *errbuf,
                                   size_t errbuf_sz);
static bool op_cuda_runtime_usable(int device_id, char *errbuf,
                                   size_t errbuf_sz);
static int op_scan_cuda_devices(int *devices);
static int op_scan_healthy_cuda_devices(int *devices, char *reason,
                                        size_t reason_sz);
static bool op_cuda_probe(int device_id, char *errbuf, size_t errbuf_sz);
static bool op_cuda_confine(int *devices, int num_devices,
                            char *errbuf, size_t errbuf_sz);
static bool op_parse_device_list(const char *list, int *devices,
                                 int *num_devices, char *errbuf,
                                 size_t errbuf_sz);
static void op_commit(const char *provider, const int *devices,
                      int num_devices, const char *note);

// Fill the CUDA provider options shared by every ONNX consumer. The arena limit
// is resolved independently for each physical GPU at session-creation time.
bool onnx_cuda_provider_options(int device_id,
                                OrtCUDAProviderOptions *options,
                                OnnxCudaProviderPolicy *policy) {
  int physical;
  gpu_mem_budget_t memory;

  if (! options) {
    return false;
  }

  physical = op_cuda_physical(device_id);
  if (physical < 0 || ! gpu_mem_budget(physical, 0.0, &memory)
      || ! memory.device.is_gpu || ! memory.device.backend
      || strcmp(memory.device.backend, "cuda")) {
    return false;
  }

  memset(options, 0, sizeof(*options));
  options->device_id = device_id;
  options->cudnn_conv_algo_search = OrtCudnnConvAlgoSearchHeuristic;
  options->gpu_mem_limit = memory.usable_bytes;
  options->arena_extend_strategy = 1;
  options->do_copy_in_default_stream = 1;

  if (policy) {
    policy->physical_device_id = physical;
    policy->total_bytes = memory.device.total_bytes;
    policy->free_bytes = memory.device.free_bytes;
    policy->arena_limit = memory.usable_bytes;
    policy->memory_fraction = memory.fraction;
  }

  return true;
}

// map a GPU UUID from CUDA_VISIBLE_DEVICES to the corresponding physical NVML index
static int op_cuda_physical_for_uuid(const char *uuid) {
  size_t wanted = strlen(uuid);
  int match = -1;

  for (int physical = 0; physical < ONNX_MAX_GPU_DEVICES; physical++) {
    gpu_mem_info_t info;

    if (! gpu_mem_query(physical, &info) || ! info.is_gpu || ! info.uuid[0]) {
      continue;
    }
    if (! strncmp(info.uuid, uuid, wanted)) {
      if (match >= 0) {
        return -1;
      }
      match = physical;
    }
  }
  return match;
}

// parse CUDA_VISIBLE_DEVICES once per resolve. Integer and GPU UUID entries are mapped;
// a MIG UUID or malformed token ends the parsed prefix, mirroring the CUDA runtime's rule
// that an invalid entry hides all later entries.
static void op_parse_visible_devices(void) {
  const char *env = getenv("CUDA_VISIBLE_DEVICES");

  g_visible_count = -1;
  if (! env) {
    return;
  }

  g_visible_count = 0;
  const char *pos = env;

  while (*pos && g_visible_count < ONNX_MAX_GPU_DEVICES) {
    const char *end = strchr(pos, ',');
    size_t token_len = end ? (size_t)(end - pos) : strlen(pos);
    char token[96];
    int physical = -1;

    if (token_len == 0 || token_len >= sizeof(token)) {
      break;
    }
    memcpy(token, pos, token_len);
    token[token_len] = '\0';

    char *number_end = NULL;
    long v = strtol(token, &number_end, 10);
    if (number_end != token && *number_end == '\0' && v >= 0) {
      physical = (int)v;
    }
    else if (! strncmp(token, "GPU-", 4)) {
      physical = op_cuda_physical_for_uuid(token);
    }

    if (physical < 0) {
      break;
    }
    g_visible_map[g_visible_count] = physical;
    g_visible_count++;

    if (! end) {
      break;
    }
    pos = end + 1;
  }
}

// translate an ORT-visible cuda ordinal to its physical device id; -1 when the ordinal
// names no visible device
static int op_cuda_physical(int ordinal) {
  if (g_visible_count < 0) {
    return ordinal;
  }
  if (ordinal < 0 || ordinal >= g_visible_count) {
    return -1;
  }
  return g_visible_map[ordinal];
}

// fetch the ONNX Runtime C API once; fails only on a header/library version mismatch
static bool op_init_api(char *errbuf, size_t errbuf_sz) {
  if (g_ort) {
    return true;
  }
  g_ort = OrtGetApiBase()->GetApi(ORT_API_VERSION);
  if (! g_ort) {
    snprintf(errbuf, errbuf_sz,
             "The linked onnxruntime library does not provide ONNX Runtime API version %d.",
             ORT_API_VERSION);
    return false;
  }
  return true;
}

// true if the linked ONNX Runtime build contains the named execution provider, e.g.
// "CUDAExecutionProvider" or "CoreMLExecutionProvider"
static bool op_build_has_provider(const char *ep_name) {
  char **providers = NULL;
  int count = 0;
  bool found = false;
  OrtStatus *status;

  status = g_ort->GetAvailableProviders(&providers, &count);
  if (status) {
    g_ort->ReleaseStatus(status);
    return false;
  }

  for (int i = 0; i < count; i++) {
    if (providers[i] && ! strcmp(providers[i], ep_name)) {
      found = true;
    }
  }

  status = g_ort->ReleaseAvailableProviders(providers, count);
  if (status) {
    g_ort->ReleaseStatus(status);
  }

  return found;
}

// report NVIDIA display or compute hardware independently of driver health
static bool op_nvidia_hardware_present(void) {
  for (int physical = 0; physical < ONNX_MAX_GPU_DEVICES; physical++) {
    if (op_cuda_physical_present(physical)) {
      return true;
    }
  }

#if defined(__linux__)
  glob_t devices;
  int result;

  memset(&devices, 0, sizeof(devices));
  result = glob("/sys/bus/pci/devices/*/vendor", 0, NULL, &devices);
  if (result != 0) {
    globfree(&devices);
    return false;
  }

  for (size_t i = 0; i < devices.gl_pathc; i++) {
    const char *vendor_path = devices.gl_pathv[i];
    size_t vendor_path_len = strlen(vendor_path);
    char class_path[OP_CUDA_RUNTIME_PATH_MAX];
    uint32_t vendor = 0;
    uint32_t class_code = 0;
    FILE *vendor_file;
    FILE *class_file;

    if (vendor_path_len <= strlen("vendor")) {
      continue;
    }
    if (snprintf(class_path, sizeof(class_path), "%.*sclass",
                 (int)(vendor_path_len - strlen("vendor")), vendor_path)
        >= (int)sizeof(class_path)) {
      continue;
    }

    vendor_file = fopen(vendor_path, "r");
    class_file = fopen(class_path, "r");
    if (vendor_file) {
      if (fscanf(vendor_file, "%" SCNx32, &vendor) != 1) {
        vendor = 0;
      }
      fclose(vendor_file);
    }
    if (class_file) {
      if (fscanf(class_file, "%" SCNx32, &class_code) != 1) {
        class_code = 0;
      }
      fclose(class_file);
    }

    if (vendor == UINT32_C(0x10de)
        && ((class_code >> 16) & UINT32_C(0xff)) == UINT32_C(0x03)) {
      globfree(&devices);
      return true;
    }
  }
  globfree(&devices);
#endif

  return false;
}

// true if the physical device id names a live NVIDIA GPU. gpu_mem_query() never
// hard-fails; an absent device comes back as the cpu fallback backend and is rejected
// here.
static bool op_cuda_physical_present(int physical) {
  gpu_mem_info_t info;

  if (physical < 0 || ! gpu_mem_query(physical, &info)) {
    return false;
  }
  return info.is_gpu && info.backend && ! strcmp(info.backend, "cuda");
}

// true if 'device_id', an ORT-visible cuda ordinal, names a live NVIDIA GPU
static bool op_cuda_device_present(int device_id) {
  return op_cuda_physical_present(op_cuda_physical(device_id));
}

// resolve one library pattern inside the private CUDA runtime
static bool op_cuda_resolve_private_library(const char *pattern, char *path,
                                            size_t path_sz, char *errbuf,
                                            size_t errbuf_sz) {
#if defined(__linux__)
  char full_pattern[OP_CUDA_RUNTIME_PATH_MAX];
  char resolved[OP_CUDA_RUNTIME_PATH_MAX];
  glob_t matches;
  int result;
  int written;

  written = snprintf(full_pattern, sizeof(full_pattern), "%s/%s",
                     g_cuda_runtime_root, pattern);
  if (written < 0 || (size_t)written >= sizeof(full_pattern)) {
    snprintf(errbuf, errbuf_sz,
             "The private CUDA runtime path is too long: %s.",
             g_cuda_runtime_root);
    return false;
  }

  memset(&matches, 0, sizeof(matches));
  result = glob(full_pattern, 0, NULL, &matches);
  if (result != 0 || matches.gl_pathc != 1
      || ! realpath(matches.gl_pathv[0], resolved)) {
    snprintf(errbuf, errbuf_sz,
             "The private CUDA runtime requires exactly one match for %s.",
             full_pattern);
    globfree(&matches);
    return false;
  }
  globfree(&matches);

  if (strlen(resolved) >= path_sz
      || strncmp(resolved, g_cuda_runtime_root, strlen(g_cuda_runtime_root))
      || resolved[strlen(g_cuda_runtime_root)] != '/') {
    snprintf(errbuf, errbuf_sz,
             "The private CUDA runtime resolved an invalid library path for %s.",
             pattern);
    return false;
  }

  snprintf(path, path_sz, "%s", resolved);
  return true;
#else
  (void)pattern;
  (void)path;
  (void)path_sz;
  (void)errbuf;
  (void)errbuf_sz;
  return false;
#endif
}

// preload Scalpel3's private CUDA runtime by absolute path. Keeping these handles open
// lets ONNX Runtime's CUDA provider resolve the same SONAMEs without changing the system
// loader configuration or other processes. When the private runtime is not installed,
// provider resolution continues with the system CUDA libraries.
static bool op_cuda_preload_runtime(char *errbuf, size_t errbuf_sz) {
#if defined(__linux__)
  const char *configured = getenv("SCALPEL3_CUDA_RUNTIME_DIR");
  const char *root = configured && *configured
                   ? configured : SCALPEL3_CUDA_RUNTIME_DIR;
  size_t loaded = 0;

  if (g_cuda_runtime_preload_checked) {
    if (g_cuda_runtime_preload_error[0]) {
      snprintf(errbuf, errbuf_sz, "%s", g_cuda_runtime_preload_error);
      return false;
    }
    return true;
  }
  g_cuda_runtime_preload_checked = true;

  if (access(root, F_OK) != 0) {
    if (configured && *configured) {
      snprintf(g_cuda_runtime_preload_error,
               sizeof(g_cuda_runtime_preload_error),
               "SCALPEL3_CUDA_RUNTIME_DIR names an unavailable directory: %s.",
               root);
      snprintf(errbuf, errbuf_sz, "%s", g_cuda_runtime_preload_error);
      return false;
    }
    return true;
  }

  if (! realpath(root, g_cuda_runtime_root)) {
    snprintf(g_cuda_runtime_preload_error,
             sizeof(g_cuda_runtime_preload_error),
             "The private CUDA runtime path could not be resolved: %s.", root);
    snprintf(errbuf, errbuf_sz, "%s", g_cuda_runtime_preload_error);
    return false;
  }

  for (size_t i = 0; i < OP_CUDA_RUNTIME_LIBRARY_COUNT; i++) {
    if (! op_cuda_resolve_private_library(
            g_cuda_runtime_library_patterns[i],
            g_cuda_runtime_libraries[i],
            sizeof(g_cuda_runtime_libraries[i]),
            g_cuda_runtime_preload_error,
            sizeof(g_cuda_runtime_preload_error))) {
      snprintf(errbuf, errbuf_sz, "%s", g_cuda_runtime_preload_error);
      g_cuda_runtime_root[0] = '\0';
      return false;
    }
  }

  for (size_t i = 0; i < OP_CUDA_RUNTIME_LIBRARY_COUNT; i++) {
    const char *soname = strrchr(g_cuda_runtime_libraries[i], '/');
    void *existing;

    soname = soname ? soname + 1 : g_cuda_runtime_libraries[i];
    existing = dlopen(soname, RTLD_NOW | RTLD_NOLOAD);
    if (existing) {
      dlclose(existing);
      snprintf(g_cuda_runtime_preload_error,
               sizeof(g_cuda_runtime_preload_error),
               "CUDA library %.120s was loaded before Scalpel3 could select its "
               "private runtime; refusing an ambiguous mixed CUDA stack.", soname);
      snprintf(errbuf, errbuf_sz, "%s", g_cuda_runtime_preload_error);
      g_cuda_runtime_root[0] = '\0';
      return false;
    }
  }

  for (size_t i = 0; i < OP_CUDA_RUNTIME_LIBRARY_COUNT; i++) {
    g_cuda_runtime_handles[i] =
        dlopen(g_cuda_runtime_libraries[i], RTLD_NOW | RTLD_GLOBAL);
    if (! g_cuda_runtime_handles[i]) {
      const char *detail = dlerror();

      snprintf(g_cuda_runtime_preload_error,
               sizeof(g_cuda_runtime_preload_error),
               "The private CUDA runtime is incomplete: %.150s could not be "
               "loaded%s%.100s.", g_cuda_runtime_libraries[i],
               detail ? ": " : "", detail ? detail : "");
      break;
    }
    loaded++;
  }

  if (loaded != OP_CUDA_RUNTIME_LIBRARY_COUNT) {
    snprintf(errbuf, errbuf_sz, "%s", g_cuda_runtime_preload_error);
    for (size_t i = 0; i < loaded; i++) {
      dlclose(g_cuda_runtime_handles[i]);
      g_cuda_runtime_handles[i] = NULL;
    }
    g_cuda_runtime_root[0] = '\0';
    return false;
  }
  g_cuda_runtime_is_private = true;
#else
  (void)errbuf;
  (void)errbuf_sz;
#endif
  return true;
}


// preload the optional TensorRT runtime from Scalpel3's private CUDA tree. TensorRT
// remains an optimization: an absent or unusable installation returns false and the
// caller continues with the CUDA execution provider.
static bool op_tensorrt_preload_runtime(char *errbuf, size_t errbuf_sz) {
#if defined(__linux__)
  const char *configured = getenv("SCALPEL3_TENSORRT_RUNTIME_DIR");
  const char *root = configured && *configured
                   ? configured : SCALPEL3_TENSORRT_RUNTIME_DIR;
  size_t loaded = 0;

  if (g_tensorrt_runtime_checked) {
    if (! g_tensorrt_runtime_available && errbuf && errbuf_sz > 0) {
      snprintf(errbuf, errbuf_sz, "%s", g_tensorrt_runtime_error);
    }
    return g_tensorrt_runtime_available;
  }
  g_tensorrt_runtime_checked = true;

  if (! realpath(root, g_tensorrt_runtime_root)) {
    snprintf(g_tensorrt_runtime_error,
             sizeof(g_tensorrt_runtime_error),
             "TensorRT runtime directory is unavailable: %s.", root);
    goto unavailable;
  }

  for (size_t i = 0; i < OP_TENSORRT_RUNTIME_LIBRARY_COUNT; i++) {
    char path[OP_CUDA_RUNTIME_PATH_MAX];
    char resolved[OP_CUDA_RUNTIME_PATH_MAX];
    int written;

    written = snprintf(path, sizeof(path), "%s/%s",
                       g_tensorrt_runtime_root,
                       g_tensorrt_runtime_library_names[i]);
    if (written < 0 || (size_t)written >= sizeof(path)
        || ! realpath(path, resolved)
        || strncmp(resolved, g_tensorrt_runtime_root,
                   strlen(g_tensorrt_runtime_root))
        || resolved[strlen(g_tensorrt_runtime_root)] != '/') {
      snprintf(g_tensorrt_runtime_error,
               sizeof(g_tensorrt_runtime_error),
               "TensorRT library is unavailable: %s.",
               g_tensorrt_runtime_library_names[i]);
      goto unavailable;
    }
    snprintf(g_tensorrt_runtime_libraries[i],
             sizeof(g_tensorrt_runtime_libraries[i]), "%s", resolved);
  }

  for (size_t i = 0; i < OP_TENSORRT_RUNTIME_LIBRARY_COUNT; i++) {
    void *existing =
        dlopen(g_tensorrt_runtime_library_names[i],
               RTLD_NOW | RTLD_NOLOAD);

    if (existing) {
      dlclose(existing);
      snprintf(g_tensorrt_runtime_error,
               sizeof(g_tensorrt_runtime_error),
               "TensorRT library %s was loaded before Scalpel3 could select "
               "its private runtime.",
               g_tensorrt_runtime_library_names[i]);
      goto unavailable;
    }
  }

  for (size_t i = 0; i < OP_TENSORRT_RUNTIME_LIBRARY_COUNT; i++) {
    g_tensorrt_runtime_handles[i] =
        dlopen(g_tensorrt_runtime_libraries[i], RTLD_NOW | RTLD_GLOBAL);
    if (! g_tensorrt_runtime_handles[i]) {
      const char *detail = dlerror();

      snprintf(g_tensorrt_runtime_error,
               sizeof(g_tensorrt_runtime_error),
               "TensorRT library %.120s could not be loaded%s%.120s.",
               g_tensorrt_runtime_library_names[i],
               detail ? ": " : "", detail ? detail : "");
      goto unload;
    }
    loaded++;
  }

  if (! op_build_has_provider("TensorrtExecutionProvider")) {
    snprintf(g_tensorrt_runtime_error,
             sizeof(g_tensorrt_runtime_error),
             "This ONNX Runtime build has no TensorRT execution provider.");
    goto unload;
  }

  g_tensorrt_runtime_available = true;
  return true;

unload:
  for (size_t i = 0; i < loaded; i++) {
    dlclose(g_tensorrt_runtime_handles[i]);
    g_tensorrt_runtime_handles[i] = NULL;
  }

unavailable:
  g_tensorrt_runtime_root[0] = '\0';
  if (errbuf && errbuf_sz > 0) {
    snprintf(errbuf, errbuf_sz, "%s", g_tensorrt_runtime_error);
  }
  return false;
#else
  if (errbuf && errbuf_sz > 0) {
    snprintf(errbuf, errbuf_sz,
             "TensorRT is available only with the CUDA provider on Linux.");
  }
  return false;
#endif
}


// resolve a runtime symbol and verify its defining object when a private path is expected
static bool op_cuda_resolve_symbol(void *handle, const char *symbol_name,
                                   const char *expected_path,
                                   void **symbol, char *loaded_path,
                                   size_t loaded_path_sz, char *errbuf,
                                   size_t errbuf_sz) {
#if defined(__linux__)
  Dl_info info;
  char actual[OP_CUDA_RUNTIME_PATH_MAX];
  char expected[OP_CUDA_RUNTIME_PATH_MAX];

  *symbol = dlsym(handle, symbol_name);
  if (! *symbol || ! dladdr(*symbol, &info) || ! info.dli_fname) {
    snprintf(errbuf, errbuf_sz,
             "The loaded CUDA runtime does not provide %s.", symbol_name);
    return false;
  }

  if (! realpath(info.dli_fname, actual)) {
    snprintf(errbuf, errbuf_sz,
             "The CUDA library defining %s could not be resolved: %s.",
             symbol_name, info.dli_fname);
    return false;
  }
  snprintf(loaded_path, loaded_path_sz, "%s", actual);

  if (expected_path) {
    if (! realpath(expected_path, expected)
        || strcmp(actual, expected)) {
      snprintf(errbuf, errbuf_sz,
               "The CUDA loader selected %s instead of Scalpel3's private library %s.",
               actual, expected_path);
      return false;
    }
  }
  return true;
#else
  (void)handle;
  (void)symbol_name;
  (void)expected_path;
  (void)symbol;
  (void)loaded_path;
  (void)loaded_path_sz;
  (void)errbuf;
  (void)errbuf_sz;
  return false;
#endif
}

// query and record the loaded CUDA and cuDNN user-space libraries without creating a
// CUDA context
static bool op_cuda_library_versions(char *errbuf, size_t errbuf_sz) {
  if (g_cuda_versions_checked) {
    return g_cuda_runtime_version > 0 && g_cudnn_version > 0;
  }
  g_cuda_versions_checked = true;

#if defined(__linux__)
  void *cudart = g_cuda_runtime_is_private
               ? g_cuda_runtime_handles[OP_CUDA_CUDART_INDEX]
               : dlopen("libcudart.so.13", RTLD_NOW | RTLD_LOCAL);
  void *cudnn = NULL;
  void *runtime_symbol = NULL;
  void *cudnn_symbol = NULL;
  char runtime_path[OP_CUDA_RUNTIME_PATH_MAX];
  char cudnn_path[OP_CUDA_RUNTIME_PATH_MAX];
  int (*get_runtime_version)(int *);
  size_t (*get_cudnn_version)(void);
  int version = 0;
  bool ok = false;

  if (! cudart && ! g_cuda_runtime_is_private) {
    cudart = dlopen("libcudart.so.12", RTLD_NOW | RTLD_LOCAL);
  }
  if (! cudart) {
    const char *detail = dlerror();

    snprintf(errbuf, errbuf_sz,
             "The CUDA execution provider requires libcudart.so.13 or "
             "libcudart.so.12%s%s.",
             detail ? ": " : "", detail ? detail : "");
    goto done;
  }
  cudnn = g_cuda_runtime_is_private
        ? g_cuda_runtime_handles[OP_CUDA_CUDNN_INDEX]
        : dlopen("libcudnn.so.9", RTLD_NOW | RTLD_LOCAL);
  if (! cudnn) {
    const char *detail = dlerror();

    snprintf(errbuf, errbuf_sz,
             "The CUDA execution provider requires libcudnn.so.9%s%s.",
             detail ? ": " : "", detail ? detail : "");
    goto done;
  }

  if (! op_cuda_resolve_symbol(
          cudart, "cudaRuntimeGetVersion",
          g_cuda_runtime_is_private
              ? g_cuda_runtime_libraries[OP_CUDA_CUDART_INDEX] : NULL,
          &runtime_symbol, runtime_path, sizeof(runtime_path), errbuf, errbuf_sz)
      || ! op_cuda_resolve_symbol(
          cudnn, "cudnnGetVersion",
          g_cuda_runtime_is_private
              ? g_cuda_runtime_libraries[OP_CUDA_CUDNN_INDEX] : NULL,
          &cudnn_symbol, cudnn_path, sizeof(cudnn_path), errbuf, errbuf_sz)) {
    goto done;
  }

  get_runtime_version = (int (*)(int *))runtime_symbol;
  get_cudnn_version = (size_t (*)(void))cudnn_symbol;
  if (get_runtime_version(&version) != 0 || version <= 0) {
    snprintf(errbuf, errbuf_sz,
             "The loaded CUDA runtime did not report a usable version.");
    goto done;
  }
  g_cuda_runtime_version = version;
  g_cudnn_version = get_cudnn_version();
  if (g_cudnn_version == 0) {
    snprintf(errbuf, errbuf_sz,
             "The loaded cuDNN library did not report a usable version.");
    goto done;
  }

  if (g_cuda_runtime_is_private) {
    snprintf(g_cuda_runtime_description,
             sizeof(g_cuda_runtime_description),
             "CUDA %d.%d, cuDNN %zu.%zu, Scalpel3 private runtime %.1800s",
             g_cuda_runtime_version / 1000,
             (g_cuda_runtime_version % 1000) / 10,
             g_cudnn_version / 10000,
             (g_cudnn_version % 10000) / 100,
             g_cuda_runtime_root);
  }
  else {
    snprintf(g_cuda_runtime_description,
             sizeof(g_cuda_runtime_description),
             "CUDA %d.%d from %.800s, cuDNN %zu.%zu from %.800s",
             g_cuda_runtime_version / 1000,
             (g_cuda_runtime_version % 1000) / 10,
             runtime_path, g_cudnn_version / 10000,
             (g_cudnn_version % 10000) / 100, cudnn_path);
  }
  ok = true;

done:
  if (! g_cuda_runtime_is_private) {
    if (cudnn) {
      dlclose(cudnn);
    }
    if (cudart) {
      dlclose(cudart);
    }
  }
  return ok;
#else
  snprintf(errbuf, errbuf_sz,
           "The CUDA execution provider is not supported on this platform.");
  return false;
#endif
}

// verify that a visible CUDA ordinal names a healthy GPU without loading or calling CUDA
static bool op_cuda_device_healthy(int device_id, char *errbuf, size_t errbuf_sz) {
  int physical = op_cuda_physical(device_id);
  gpu_mem_info_t info;

  if (physical < 0 || ! gpu_mem_query(physical, &info)
      || ! info.is_gpu || ! info.backend || strcmp(info.backend, "cuda")) {
    snprintf(errbuf, errbuf_sz, "CUDA device %d was not detected.", device_id);
    return false;
  }

  if (info.recovery_action > 0) {
    const char *action = "recovery";
    if (info.recovery_action == 1) {
      action = "a GPU reset";
    }
    else if (info.recovery_action == 2) {
      action = "a node reboot";
    }
    else if (info.recovery_action == 3) {
      action = "peer-to-peer drain";
    }
    else if (info.recovery_action == 4) {
      action = "drain and reset";
    }
    snprintf(errbuf, errbuf_sz,
             "CUDA device %d is not healthy; the NVIDIA driver requires %s before "
             "the device can accept new work.", device_id, action);
    return false;
  }

  return true;
}

// verify that the CUDA user-space libraries support the selected GPU. This runs only after
// CUDA_VISIBLE_DEVICES has been finalized, so the first CUDA call observes the confined
// device set.
static bool op_cuda_runtime_usable(int device_id, char *errbuf, size_t errbuf_sz) {
  int physical = op_cuda_physical(device_id);
  gpu_mem_info_t info;

  if (physical < 0 || ! gpu_mem_query(physical, &info)
      || ! info.is_gpu || ! info.backend || strcmp(info.backend, "cuda")) {
    snprintf(errbuf, errbuf_sz, "CUDA device %d was not detected.", device_id);
    return false;
  }

  if (! op_cuda_preload_runtime(errbuf, errbuf_sz)) {
    return false;
  }

  if (! op_cuda_library_versions(errbuf, errbuf_sz)) {
    return false;
  }

  if (info.compute_major >= 10) {
    if (g_cuda_runtime_version < 12080 || g_cudnn_version < 92400) {
      int cuda_major = g_cuda_runtime_version > 0
                     ? g_cuda_runtime_version / 1000 : 0;
      int cuda_minor = g_cuda_runtime_version > 0
                     ? (g_cuda_runtime_version % 1000) / 10 : 0;
      size_t cudnn_major = g_cudnn_version / 10000;
      size_t cudnn_minor = (g_cudnn_version % 10000) / 100;

      snprintf(errbuf, errbuf_sz,
               "CUDA device %d is a Blackwell GPU, but the loaded CUDA %d.%d and "
               "cuDNN %zu.%zu libraries do not meet Scalpel3's Blackwell runtime "
               "requirements; CUDA 12.8 or newer and cuDNN 9.24 or newer are required.",
               device_id, cuda_major, cuda_minor, cudnn_major, cudnn_minor);
      return false;
    }
  }

  return true;
}

// enumerate NVIDIA GPUs into 'devices' (capacity ONNX_MAX_GPU_DEVICES); returns the count
static int op_scan_cuda_devices(int *devices) {
  int count = 0;

  for (int device = 0; device < ONNX_MAX_GPU_DEVICES; device++) {
    if (op_cuda_device_present(device)) {
      devices[count] = device;
      count++;
    }
  }
  return count;
}

// enumerate only GPUs that can safely accept CUDA work; retain the first rejection for
// the auto-selection diagnostic even when another device remains usable
static int op_scan_healthy_cuda_devices(int *devices, char *reason,
                                        size_t reason_sz) {
  int count = 0;
  int limit = g_visible_count >= 0 ? g_visible_count : ONNX_MAX_GPU_DEVICES;

  for (int device = 0; device < limit; device++) {
    char device_reason[256];

    if (! op_cuda_device_present(device)) {
      continue;
    }
    if (op_cuda_device_healthy(device, device_reason, sizeof(device_reason))) {
      devices[count] = device;
      count++;
    }
    else if (reason && reason_sz > 0 && ! reason[0]) {
      snprintf(reason, reason_sz, "%s", device_reason);
    }
  }
  return count;
}

// probe CUDA provider setup by appending it to throwaway session options, using the same
// provider options real sessions use but without loading a model. Model loading and the
// first Run remain the definitive runtime checks.
static bool op_cuda_probe(int device_id, char *errbuf, size_t errbuf_sz) {
  OrtEnv *env = NULL;
  OrtSessionOptions *opts = NULL;
  OrtStatus *status;
  bool ok = true;

  // ONNX Runtime requires an environment before provider initialization so the
  // provider can use the process-wide default logger.
  status = g_ort->CreateEnv(ORT_LOGGING_LEVEL_WARNING,
                            "scalpel3-provider-probe", &env);
  if (status) {
    const char *msg = g_ort->GetErrorMessage(status);

    snprintf(errbuf, errbuf_sz, "The ONNX Runtime environment could not be "
             "created: %s.", msg ? msg : "unknown error");
    g_ort->ReleaseStatus(status);
    return false;
  }

  status = g_ort->CreateSessionOptions(&opts);
  if (status) {
    const char *msg = g_ort->GetErrorMessage(status);

    snprintf(errbuf, errbuf_sz, "ONNX Runtime session options could not be created: %s.",
             msg ? msg : "unknown error");
    g_ort->ReleaseStatus(status);
    g_ort->ReleaseEnv(env);
    return false;
  }

  OrtCUDAProviderOptions cuda_opts;

  if (! onnx_cuda_provider_options(device_id, &cuda_opts, NULL)) {
    snprintf(errbuf, errbuf_sz,
             "The CUDA memory policy could not query device %d.", device_id);
    g_ort->ReleaseSessionOptions(opts);
    g_ort->ReleaseEnv(env);
    return false;
  }

  status = g_ort->SessionOptionsAppendExecutionProvider_CUDA(opts, &cuda_opts);
  if (status) {
    const char *msg = g_ort->GetErrorMessage(status);
    snprintf(errbuf, errbuf_sz,
             "The CUDA execution provider failed to initialize on device %d: %s.",
             device_id, msg ? msg : "unknown error");
    g_ort->ReleaseStatus(status);
    ok = false;
  }

  g_ort->ReleaseSessionOptions(opts);
  g_ort->ReleaseEnv(env);
  return ok;
}

// confine the process to the resolved cuda devices. ONNX Runtime's CUDA pinned-host
// allocator creates its context on visible
// device 0 regardless of session device ids, so without confinement a run pinned to
// device 1 still plants a few hundred MiB of context memory on an excluded device 0.
// CUDA_VISIBLE_DEVICES is written with stable GPU UUIDs rather than NVML indices because
// CUDA's performance-ordered ordinals are not guaranteed to match NVML. The resolved ids
// are then rewritten into the confined visible space.
static bool op_cuda_confine(int *devices, int num_devices,
                            char *errbuf, size_t errbuf_sz) {
  if (num_devices <= 0) {
    snprintf(errbuf, errbuf_sz, "No CUDA devices were selected.");
    return false;
  }

  char list[ONNX_MAX_GPU_DEVICES * 97 + 1];
  size_t off = 0;
  int physicals[ONNX_MAX_GPU_DEVICES];

  for (int i = 0; i < num_devices; i++) {
    int physical = op_cuda_physical(devices[i]);
    gpu_mem_info_t info;
    int written;

    if (physical < 0 || ! gpu_mem_query(physical, &info)
        || ! info.is_gpu || ! info.uuid[0]) {
      snprintf(errbuf, errbuf_sz,
               "CUDA device %d has no stable GPU UUID; refusing ambiguous device "
               "selection.", devices[i]);
      return false;
    }
    physicals[i] = physical;
    written = snprintf(list + off, sizeof(list) - off, "%s%s",
                       i ? "," : "", info.uuid);
    if (written < 0 || (size_t)written >= sizeof(list) - off) {
      snprintf(errbuf, errbuf_sz, "The CUDA device UUID list is too long.");
      return false;
    }
    off += (size_t)written;
  }

  if (setenv("CUDA_VISIBLE_DEVICES", list, 1) != 0) {
    snprintf(errbuf, errbuf_sz,
             "CUDA_VISIBLE_DEVICES could not be set for the selected GPUs.");
    return false;
  }
  g_visible_count = num_devices;
  for (int i = 0; i < num_devices; i++) {
    g_visible_map[i] = physicals[i];
    devices[i] = i;
  }
  return true;
}

// parse a comma separated device list ("0" or "0,2,1"), deduplicating while preserving
// order; returns false with a user-facing reason in errbuf on malformed input
static bool op_parse_device_list(const char *list, int *devices, int *num_devices,
                                 char *errbuf, size_t errbuf_sz) {
  const char *pos = list;
  int count = 0;

  if (! list || ! *list) {
    snprintf(errbuf, errbuf_sz,
             "-Y names an empty device list; use e.g. -Y cuda:0,1.");
    return false;
  }

  while (*pos) {
    char *end = NULL;
    long v = strtol(pos, &end, 10);
    bool already = false;

    if (end == pos || v < 0 || v > 1023) {
      snprintf(errbuf, errbuf_sz,
               "-Y device list \"%s\" is malformed; use comma separated device ids, "
               "e.g. -Y cuda:0,1.", list);
      return false;
    }

    for (int i = 0; i < count; i++) {
      if (devices[i] == (int)v) {
        already = true;
      }
    }
    if (! already) {
      if (count >= ONNX_MAX_GPU_DEVICES) {
        snprintf(errbuf, errbuf_sz, "-Y device list names more than %d devices.",
                 ONNX_MAX_GPU_DEVICES);
        return false;
      }
      devices[count] = (int)v;
      count++;
    }

    pos = end;
    if (*pos == ',') {
      pos++;
      if (! *pos) {
        snprintf(errbuf, errbuf_sz,
                 "-Y device list \"%s\" ends with a comma; use e.g. -Y cuda:0,1.", list);
        return false;
      }
    }
    else {
      if (*pos) {
        snprintf(errbuf, errbuf_sz,
                 "-Y device list \"%s\" is malformed; use comma separated device ids, "
                 "e.g. -Y cuda:0,1.", list);
        return false;
      }
    }
  }

  *num_devices = count;
  return true;
}

// record the final selection. 'stepdown_reason', when non-empty, describes accelerator
// hardware the auto path detected but could not use; it becomes the resolve note.
static void op_commit(const char *provider, const int *devices, int num_devices,
                      const char *stepdown_reason) {
  strncpy(g_provider, provider, sizeof(g_provider) - 1);
  g_provider[sizeof(g_provider) - 1] = '\0';

  if (num_devices > ONNX_MAX_GPU_DEVICES) {
    num_devices = ONNX_MAX_GPU_DEVICES;
  }
  g_num_devices = num_devices;
  for (int i = 0; i < num_devices; i++) {
    g_devices[i] = devices[i];
  }

  if (stepdown_reason && stepdown_reason[0]) {
    size_t reason_len = strlen(stepdown_reason);

    while (reason_len > 0
           && (stepdown_reason[reason_len - 1] == '.'
               || stepdown_reason[reason_len - 1] == ' ')) {
      reason_len--;
    }
    snprintf(g_note, sizeof(g_note), "%.*s. Selected the %s execution provider.",
             (int)reason_len, stepdown_reason, g_provider);
  }
}

bool onnx_providers_resolve(const char *request, char *errbuf, size_t errbuf_sz) {
  bool request_present = request != NULL && *request != '\0';
  char reqcopy[64];
  char provider[32] = {0};
  const char *devlist = NULL;
  int devices[ONNX_MAX_GPU_DEVICES];
  int num_devices = 0;

  g_explicit = false;
  g_note[0] = '\0';

  if (! op_init_api(errbuf, errbuf_sz)) {
    return false;
  }

  op_parse_visible_devices();

  // split "provider[:devicelist]"
  if (request_present) {
    if (strlen(request) >= sizeof(reqcopy)) {
      snprintf(errbuf, errbuf_sz, "-Y argument is too long.");
      return false;
    }
    snprintf(reqcopy, sizeof(reqcopy), "%s", request);

    char *colon = strchr(reqcopy, ':');
    if (colon) {
      *colon = '\0';
      devlist = colon + 1;
    }
    if (strlen(reqcopy) >= sizeof(provider)) {
      snprintf(errbuf, errbuf_sz, "-Y provider name is too long.");
      return false;
    }
    memcpy(provider, reqcopy, strlen(reqcopy) + 1);
  }
  else {
    strncpy(provider, "auto", sizeof(provider) - 1);
  }

  // apple and metal are aliases for coreml
  if (! strcasecmp(provider, "apple") || ! strcasecmp(provider, "metal")) {
    strncpy(provider, "coreml", sizeof(provider) - 1);
  }

  // -Y auto asks for automatic selection just like omitting -Y. Only a named provider is
  // an explicit request that must fail rather than step down.
  g_explicit = strcasecmp(provider, "auto") != 0;

  if (strcasecmp(provider, "cpu") != 0
      && strcasecmp(provider, "cuda") != 0
      && strcasecmp(provider, "coreml") != 0
      && strcasecmp(provider, "auto") != 0) {
    snprintf(errbuf, errbuf_sz,
             "-Y requires cpu, cuda, coreml, or auto, with an optional device list, "
             "e.g. -Y cuda:0,1.");
    return false;
  }

  if (devlist) {
    if (! strcasecmp(provider, "auto")) {
      snprintf(errbuf, errbuf_sz,
               "-Y auto cannot take a device list; name the provider explicitly, "
               "e.g. -Y cuda:0,1.");
      return false;
    }
    if (! strcasecmp(provider, "cpu")) {
      snprintf(errbuf, errbuf_sz, "-Y cpu does not take a device list.");
      return false;
    }
    if (! op_parse_device_list(devlist, devices, &num_devices, errbuf, errbuf_sz)) {
      return false;
    }
  }

  if (! strcasecmp(provider, "cpu")) {
    op_commit("cpu", NULL, 0, NULL);
    return true;
  }

  if (! strcasecmp(provider, "coreml")) {
#if ! (defined(__APPLE__) && defined(__aarch64__))
    snprintf(errbuf, errbuf_sz,
             "The CoreML execution provider requires Apple Silicon; this machine "
             "cannot run -Y coreml.");
    return false;
#else
    if (! op_build_has_provider("CoreMLExecutionProvider")) {
      snprintf(errbuf, errbuf_sz,
               "This scalpel3 build's ONNX Runtime has no CoreML execution provider.");
      return false;
    }
    if (num_devices > 1 || (num_devices == 1 && devices[0] != 0)) {
      snprintf(errbuf, errbuf_sz,
               "CoreML exposes a single device; use -Y coreml or -Y coreml:0.");
      return false;
    }
    devices[0] = 0;
    op_commit("coreml", devices, 1, NULL);
    return true;
#endif
  }

  if (! strcasecmp(provider, "cuda")) {
    if (num_devices == 0) {
      char reason[256] = {0};

      num_devices = op_scan_healthy_cuda_devices(devices, reason, sizeof(reason));
      if (num_devices == 0) {
        if (reason[0]) {
          snprintf(errbuf, errbuf_sz, "%s", reason);
        }
        else if (g_visible_count >= 0) {
          snprintf(errbuf, errbuf_sz,
                   "No CUDA-capable NVIDIA GPU is visible; CUDA_VISIBLE_DEVICES=\"%s\" "
                   "restricts this run.", getenv("CUDA_VISIBLE_DEVICES"));
        }
        else {
          snprintf(errbuf, errbuf_sz, "No CUDA-capable NVIDIA GPU was detected.");
        }
        return false;
      }
    }
    else {
      for (int i = 0; i < num_devices; i++) {
        char reason[256];

        if (! op_cuda_device_healthy(devices[i], reason, sizeof(reason))) {
          if (g_visible_count >= 0) {
            snprintf(errbuf, errbuf_sz,
                     "%s CUDA_VISIBLE_DEVICES=\"%s\" leaves %d visible device%s, "
                     "and -Y device ids name visible devices.", reason,
                     getenv("CUDA_VISIBLE_DEVICES"), g_visible_count,
                     g_visible_count == 1 ? "" : "s");
          }
          else {
            snprintf(errbuf, errbuf_sz, "%s", reason);
          }
          return false;
        }
      }
    }
    if (! op_cuda_preload_runtime(errbuf, errbuf_sz)) {
      return false;
    }
    if (! op_build_has_provider("CUDAExecutionProvider")) {
      snprintf(errbuf, errbuf_sz,
               "This scalpel3 build's ONNX Runtime has no CUDA execution provider.");
      return false;
    }
    if (! op_cuda_confine(devices, num_devices, errbuf, errbuf_sz)) {
      return false;
    }
    for (int i = 0; i < num_devices; i++) {
      if (! op_cuda_runtime_usable(devices[i], errbuf, errbuf_sz)
          || ! op_cuda_probe(devices[i], errbuf, errbuf_sz)) {
        return false;
      }
    }
    op_commit("cuda", devices, num_devices, NULL);
    return true;
  }

  // auto uses CUDA when NVIDIA hardware is present and CPU only on a machine without an
  // accelerator. A detected but unusable NVIDIA configuration is an error because silently
  // selecting CPU would make a GPU run appear valid while changing its performance.
  {
    const char *reason = NULL;
    char probe_err[256];
    char device_reason[256] = {0};
    int present[ONNX_MAX_GPU_DEVICES];
    int npresent = op_scan_cuda_devices(present);
    int nscan = op_scan_healthy_cuda_devices(devices, device_reason,
                                             sizeof(device_reason));
    bool nvidia_hardware = op_nvidia_hardware_present();

    if (nscan > 0) {
      if (! op_cuda_preload_runtime(probe_err, sizeof(probe_err))) {
        reason = probe_err;
      }
      else if (! op_build_has_provider("CUDAExecutionProvider")) {
        reason = "An NVIDIA GPU is present but this ONNX Runtime build has no CUDA "
                 "execution provider";
      }
      else {
        if (! op_cuda_confine(devices, nscan, probe_err, sizeof(probe_err))) {
          reason = probe_err;
        }
        else {
          bool usable = true;

          for (int i = 0; i < nscan; i++) {
            if (! op_cuda_runtime_usable(devices[i], probe_err, sizeof(probe_err))
                || ! op_cuda_probe(devices[i], probe_err, sizeof(probe_err))) {
              usable = false;
              reason = probe_err;
              break;
            }
          }
          if (usable) {
            op_commit("cuda", devices, nscan,
                      device_reason[0] ? device_reason : NULL);
            return true;
          }
        }
      }
    }
    else if (npresent > 0 && device_reason[0]) {
      reason = device_reason;
    }
    else if (g_visible_count >= 0 && op_cuda_physical_present(0)) {
      reason = "NVIDIA GPUs are present but CUDA_VISIBLE_DEVICES hides them";
    }
    else if (nvidia_hardware) {
      reason = "NVIDIA GPU hardware is present, but the NVIDIA driver could not "
               "enumerate a usable CUDA device";
    }

#if defined(__APPLE__) && defined(__aarch64__)
    if (op_build_has_provider("CoreMLExecutionProvider")) {
      devices[0] = 0;
      op_commit("coreml", devices, 1, reason);
      return true;
    }
#endif

    if (reason) {
      size_t reason_len = strlen(reason);

      while (reason_len > 0
             && (reason[reason_len - 1] == '.'
                 || reason[reason_len - 1] == ' ')) {
        reason_len--;
      }
      snprintf(errbuf, errbuf_sz,
               "%.*s. Rerun init_scalpel3.sh to repair ONNX/CUDA support, or "
               "explicitly select -Y cpu for an intentional CPU run.",
               (int)reason_len, reason);
      return false;
    }

    op_commit("cpu", NULL, 0, NULL);
    return true;
  }
}

const char *onnx_resolved_accelerator(void) {
  return g_provider;
}

int onnx_resolved_num_devices(void) {
  return g_num_devices;
}

const int *onnx_resolved_device_list(void) {
  return g_devices;
}

bool onnx_resolved_was_explicit(void) {
  return g_explicit;
}

int onnx_cuda_physical_device(int device_id) {
  if (strcmp(g_provider, "cuda") != 0) {
    return device_id;
  }
  return op_cuda_physical(device_id);
}

const char *onnx_resolve_note(void) {
  return g_note;
}

const char *onnx_cuda_runtime_description(void) {
  return g_cuda_runtime_description;
}

bool onnx_tensorrt_available(char *errbuf, size_t errbuf_sz) {

  if (strcmp(g_provider, "cuda")) {
    if (errbuf && errbuf_sz > 0) {
      snprintf(errbuf, errbuf_sz,
               "TensorRT requires the CUDA execution provider.");
    }
    return false;
  }
  return op_tensorrt_preload_runtime(errbuf, errbuf_sz);
}

bool onnx_runtime_fallback_to_cpu(const char *reason) {
  (void)reason;
  return ! strcmp(g_provider, "cpu");
}
