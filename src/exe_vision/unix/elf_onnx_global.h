#pragma once
#include <stdbool.h>
#include "elf_seg_onnx_cabi.h"

#ifdef __cplusplus
extern "C" {
#endif

// Initialize global ELF ONNX model/session once.
// Returns true on success; on failure you can abort via handle_error.
bool elf_onnx_global_init(const char* model_path, const char* accelerator);

// Tear down the global handle (safe to call multiple times).
void elf_onnx_global_shutdown(void);

// Returns the global handle (NULL if not initialized).
elf_onnx_handle_t elf_onnx_global_get(void);

// Optional timing-report hook.
void elf_onnx_global_write_timing_report(const char* path);

#ifdef __cplusplus
}
#endif