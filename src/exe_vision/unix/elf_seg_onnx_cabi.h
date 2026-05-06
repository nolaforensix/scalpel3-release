#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum elf_onnx_status {
  ELF_ONNX_OK = 0,
  ELF_ONNX_ERR = -1,
  ELF_ONNX_BADARG = -2,
  ELF_ONNX_NOMEM = -3,
  ELF_ONNX_BUF_TOO_SMALL = -4
};

typedef struct RegionTripletC {
  int32_t cls;
  int32_t offset;  // starting index into the 4096-length map (row-major)
  int32_t size;    // run length
} RegionTripletC;

typedef void* elf_onnx_handle_t;

elf_onnx_handle_t elf_onnx_create(const char* model_path, const char* accelerator);
void elf_onnx_destroy(elf_onnx_handle_t h);

int elf_onnx_infer(elf_onnx_handle_t h,
                   const uint8_t* blob, size_t nbytes,
                   RegionTripletC* out, size_t out_cap,
                   size_t* out_count_needed);

void elf_onnx_write_timing_report(const char* path);

#ifdef __cplusplus
} // extern "C"
#endif