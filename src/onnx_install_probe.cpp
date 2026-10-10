// SPDX-License-Identifier: GPL-3.0-only
// The Scalpel Project is Copyright (C) 2005-2026 by Golden G. Richard III
// and contributors.
//
// Scalpel3 is Copyright (C) 2021-2026 by Golden G. Richard III and the
// contributors listed in AUTHORS.
// See LICENSE.md for licensing and commercial licensing contact information.

// Small installation check, compiled against the selected C/C++ ONNX Runtime.
// Conv and MatMul exercise cuDNN and cuBLAS; CUDA must not fall back to CPU.
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <initializer_list>
#include <stdexcept>
#include <string>
#include <vector>

#include "onnxruntime_cxx_api.h"
#include "onnx_providers.h"
#include "onnx_cuda_options.h"
#include "scalpel_output.h"

static std::string varint(uint64_t value);
static std::string integer(uint32_t field, uint64_t value);
static std::string message(uint32_t field, const std::string &value);
static std::string tensor(const char *name, std::initializer_list<uint64_t> dims);
static std::string model();

// The installation probe does not link the carving backend. Provide its output
// helper locally so the shared GPU planner still emits one locked message.
void lock_fprintf(FILE *stream, const char *format, ...) {
  va_list args;
  va_start(args, format);
  flockfile(stream);
  vfprintf(stream, format, args);
  funlockfile(stream);
  va_end(args);
}

// Encode this tiny ONNX graph directly, without requiring Python ONNX/protobuf packages.
static std::string varint(uint64_t value) {
  std::string result;
  while (value >= 128) {
    result += static_cast<char>((value & 127) | 128);
    value >>= 7;
  }
  result += static_cast<char>(value);
  return result;
}

static std::string integer(uint32_t field, uint64_t value) {
  return varint(field << 3) + varint(value);
}

static std::string message(uint32_t field, const std::string &value) {
  return varint((field << 3) | 2) + varint(value.size()) + value;
}

static std::string tensor(const char *name, std::initializer_list<uint64_t> dims) {
  std::string shape;
  for (uint64_t dim : dims) {
    shape += message(1, integer(1, dim));
  }
  return message(1, name) + message(2, message(1, integer(1, 1) + message(2, shape)));
}

static std::string model() {
  std::string conv = message(1, "x") + message(1, "w") + message(2, "conv")
                   + message(4, "Conv");
  std::string mul = message(1, "a") + message(1, "b") + message(2, "mul")
                  + message(4, "MatMul");
  std::string graph = message(1, conv) + message(1, mul) + message(2, "install-check")
                   + message(11, tensor("x", {1, 1, 4, 4}))
                   + message(11, tensor("w", {1, 1, 3, 3}))
                   + message(11, tensor("a", {4, 4}))
                   + message(11, tensor("b", {4, 4}))
                   + message(12, tensor("conv", {1, 1, 2, 2}))
                   + message(12, tensor("mul", {4, 4}));
  return integer(1, 8) + message(7, graph) + message(8, integer(2, 13));
}

int main(int argc, char **argv) {
  if (argc != 2) {
    lock_fprintf(stderr, "Usage: onnx_install_probe cpu|cuda:DEVICE|inspect\n");
    return 2;
  }
  try {
    Dl_info library = {};
    const OrtApiBase *api = OrtGetApiBase();
    // The returned function pointer avoids executable PLT stubs in non-PIE builds.
    if (! api || ! dladdr(reinterpret_cast<void *>(api->GetVersionString), &library)) {
      throw std::runtime_error("Cannot identify the loaded ONNX Runtime library");
    }
    lock_fprintf(stdout, "ORT_VERSION=%s\nORT_LIBRARY=%s\n", api->GetVersionString(),
                library.dli_fname);
    if (! std::strcmp(argv[1], "inspect")) {
      return 0;
    }
    char error[2048] = {};
    if (! onnx_providers_resolve(argv[1], error, sizeof(error))) {
      throw std::runtime_error(error);
    }
    const char *provider = onnx_resolved_accelerator();
    Ort::Env env(ORT_LOGGING_LEVEL_WARNING, "scalpel3-install");
    Ort::SessionOptions options;
    options.SetIntraOpNumThreads(1);
    options.SetInterOpNumThreads(1);
    options.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_DISABLE_ALL);
    if (! std::strcmp(provider, "cuda")) {
      OrtCUDAProviderOptions cuda = {};
      if (! onnx_cuda_provider_options(0, &cuda, nullptr)) {
        throw std::runtime_error("Cannot set CUDA options");
      }
      cuda.gpu_mem_limit = 64 * 1024 * 1024;
      options.AppendExecutionProvider_CUDA(cuda);
      options.AddConfigEntry("session.disable_cpu_ep_fallback", "1");
    }
    else if (std::strcmp(provider, "cpu")) {
      throw std::runtime_error("Installation check supports CPU and CUDA only");
    }
    std::string bytes = model();
    Ort::Session session(env, bytes.data(), bytes.size(), options);
    auto memory = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
    std::vector<float> x(16, 1.0f), w(9, 1.0f), a(16, 1.0f), b(16, 1.0f);
    const int64_t x_shape[] = {1, 1, 4, 4}, w_shape[] = {1, 1, 3, 3}, m_shape[] = {4, 4};
    std::vector<Ort::Value> inputs;
    inputs.push_back(Ort::Value::CreateTensor<float>(memory, x.data(), x.size(), x_shape, 4));
    inputs.push_back(Ort::Value::CreateTensor<float>(memory, w.data(), w.size(), w_shape, 4));
    inputs.push_back(Ort::Value::CreateTensor<float>(memory, a.data(), a.size(), m_shape, 2));
    inputs.push_back(Ort::Value::CreateTensor<float>(memory, b.data(), b.size(), m_shape, 2));
    const char *input_names[] = {"x", "w", "a", "b"};
    const char *output_names[] = {"conv", "mul"};
    auto outputs = session.Run(Ort::RunOptions{nullptr}, input_names, inputs.data(),
                               inputs.size(), output_names, 2);
    for (size_t output = 0; output < outputs.size(); output++) {
      size_t count = outputs[output].GetTensorTypeAndShapeInfo().GetElementCount();
      if (count != (output == 0 ? 4u : 16u)) {
        throw std::runtime_error("Unexpected inference output shape");
      }
      const float *values = outputs[output].GetTensorData<float>();
      float expected = output == 0 ? 9.0f : 4.0f;
      for (size_t i = 0; i < count; i++) {
        if (! std::isfinite(values[i]) || std::fabs(values[i] - expected) > 0.00001f) {
          throw std::runtime_error("Incorrect inference result");
        }
      }
    }
    lock_fprintf(stdout, "PROVIDER=%s\nRUNTIME=%s\nINFERENCE=PASS\n", provider,
                onnx_cuda_runtime_description());
    return 0;
  }
  catch (const std::exception &error) {
    lock_fprintf(stderr, "ONNX installation check failed: %s\n", error.what());
    return 1;
  }
}
