// onnx_providers.h: unified ONNX execution provider and GPU device selection.
//
// scalpel3 can contain any number of ONNX consumers, but there is one machine, so the
// execution provider and GPU device list are resolved exactly once at startup, driven by
// the -Y provider[:devicelist] command line option, and every consumer reads the result
// through the accessors below. The resolution enforces the -Y contract: an explicit
// request this machine cannot honor is an error. The default auto request selects CUDA
// when usable NVIDIA hardware is present, CoreML on Apple Silicon, and CPU on a machine
// without an accelerator. Detected but unusable NVIDIA hardware is an error rather than
// an implicit CPU run. "Usable" means the ONNX Runtime build contains the provider, the
// hardware is present and healthy, the installed libraries support its architecture, and
// (for CUDA) a throwaway provider probe succeeds.
//
// This header is dependency-free so any translation unit can include it; only the
// implementation talks to the ONNX Runtime C API.

#ifndef ONNX_PROVIDERS_H
#define ONNX_PROVIDERS_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// hard cap on selectable GPU devices for any ONNX consumer
#define ONNX_MAX_GPU_DEVICES 16

// resolve the execution provider and GPU device list for this run. 'request' is the raw -Y
// argument ("provider" or "provider:devicelist", e.g. "cuda:0,1"), or NULL when -Y was not
// given (auto). Returns true on success, after which the accessors below are valid for the
// run. Returns false when the request or automatically selected accelerator cannot be
// honored, with a user-facing reason in 'errbuf'; the caller reports it and terminates.
// Call once, from the main thread, before any ONNX session is created.
bool onnx_providers_resolve(const char *request, char *errbuf, size_t errbuf_sz);

// resolved execution provider: "cpu", "cuda", or "coreml"
const char *onnx_resolved_accelerator(void);

// resolved GPU device list: one or more device ids for cuda, the single device 0 for
// coreml, empty for cpu. CUDA device ids are ORT-visible ordinals. Resolution confines
// CUDA_VISIBLE_DEVICES to stable GPU UUIDs before the CUDA runtime initializes, then
// rewrites the resolved ids into that confined ordinal space. This keeps CUDA session
// placement aligned with NVML even when CUDA orders devices differently.
int onnx_resolved_num_devices(void);
const int *onnx_resolved_device_list(void);

// translate a resolved cuda device id to the physical device id that NVML-backed memory
// queries need. Identity when the resolved provider is not cuda or CUDA_VISIBLE_DEVICES
// is not set; -1 for an ordinal that names no visible device.
int onnx_cuda_physical_device(int device_id);

// true when the provider came from an explicit -Y rather than auto-selection
bool onnx_resolved_was_explicit(void);

// one-line explanation when auto stepped down from detected accelerator hardware (e.g. an
// NVIDIA GPU is present but the ONNX Runtime build has no usable CUDA provider); empty
// string when there is nothing to report
const char *onnx_resolve_note(void);

// verified CUDA and cuDNN versions and library source for the resolved CUDA provider;
// empty when CUDA was not selected
const char *onnx_cuda_runtime_description(void);

// report whether the optional TensorRT runtime is installed and loadable for the
// resolved CUDA provider. TensorRT is an optimization; false leaves CUDA fully
// usable and returns a diagnostic in errbuf when one is supplied.
bool onnx_tensorrt_available(char *errbuf, size_t errbuf_sz);

// report whether the resolved provider is already cpu. This compatibility guard never
// changes providers; accelerator failures are fatal for both explicit and automatic
// selections.
bool onnx_runtime_fallback_to_cpu(const char *reason);

#ifdef __cplusplus
}
#endif

#endif
