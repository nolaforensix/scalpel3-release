// elf_seg_onnx_cabi.cpp
// Functions as the core adapter between C++ / Scalpel C;
// Implements interface described in elf_seg_onnx_cabi.h

#include "elf_seg_onnx_cabi.h"
#include "elf_seg_onnx.hpp"

#include <new>
#include <string>
#include <vector>

struct ElfOnnxHandle {
  ElfSegmentationModelONNX model;

  ElfOnnxHandle(const char* path, const char* accelerator)
    : model(std::string(path),
            /*intra=*/1,
            /*inter=*/1,
            /*input_name=*/"",
            /*out_bin_name=*/"",
            /*out_multi_name=*/"",
            /*accelerator=*/std::string(accelerator ? accelerator : "cpu"))
  {}
};

extern "C" elf_onnx_handle_t elf_onnx_create(const char* model_path, const char* accelerator)
{
  if (!model_path || !model_path[0]) return nullptr;

  try {
    ElfOnnxHandle* h = new (std::nothrow) ElfOnnxHandle(model_path, accelerator);
    return reinterpret_cast<elf_onnx_handle_t>(h);
  } catch (...) {
    return nullptr;
  }
}

extern "C" void elf_onnx_destroy(elf_onnx_handle_t h)
{
  if (!h) return;
  ElfOnnxHandle* hh = reinterpret_cast<ElfOnnxHandle*>(h);
  delete hh;
}

extern "C" int elf_onnx_infer(elf_onnx_handle_t h,
                              const uint8_t* blob, size_t nbytes,
                              RegionTripletC* out, size_t out_cap,
                              size_t* out_count_needed)
{
  if (out_count_needed) *out_count_needed = 0;
  if (!h) return ELF_ONNX_BADARG;
  if (!blob || nbytes == 0) return ELF_ONNX_BADARG;

  ElfOnnxHandle* hh = reinterpret_cast<ElfOnnxHandle*>(h);

  try {
    std::vector<RegionTriplet> v = hh->model.infer(blob, nbytes);

    if (out_count_needed) *out_count_needed = v.size();

    if (!out && out_cap == 0) {
      // query mode: caller only wants the required count
      return ELF_ONNX_OK;
    }

    if (!out) return ELF_ONNX_BADARG;

    if (v.size() > out_cap) {
      return ELF_ONNX_BUF_TOO_SMALL;
    }

    for (size_t i = 0; i < v.size(); i++) {
      out[i].cls    = v[i].cls;
      out[i].offset = v[i].offset;
      out[i].size   = v[i].size;
    }

    return ELF_ONNX_OK;
  } catch (const std::bad_alloc&) {
    return ELF_ONNX_NOMEM;
  } catch (...) {
    return ELF_ONNX_ERR;
  }
}

extern "C" void elf_onnx_write_timing_report(const char* path)
{
  // No backing timing-report function exists in the uploaded C++ model files.
  // Keep this symbol available so callers compile and link cleanly.
  (void)path;
}