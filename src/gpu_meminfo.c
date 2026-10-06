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

/**
 * @author James Ghawaly
 */

/*
 * gpu_meminfo.c — implementation of the accelerator-memory query + batch
 * planner declared in gpu_meminfo.h.
 *
 * Backends are selected at compile time by platform and at run time by
 * availability:
 *   - __linux__ : NVML via dlopen("libnvidia-ml.so.1"). No CUDA-toolkit
 *                 headers or link flags; the NVML symbols/types we need are
 *                 declared locally. If the driver library isn't present we
 *                 fall through to the CPU estimate.
 *   - __APPLE__ : Metal's recommendedMaxWorkingSetSize (the device's own GPU
 *                 working-set budget), reached via dlopen + the C objc runtime
 *                 so there is no Metal link or Objective-C build dependency,
 *                 bounded by current mach availability so memory pressure is
 *                 respected. Falls back to sysctl(hw.memsize) + mach host
 *                 stats when Metal is unavailable.
 *   - else      : CPU via sysconf.
 *
 * This file is ORT-free and self-contained (no scalpel.h), so it builds and
 * can be syntax-checked stand-alone.
 */
#include "gpu_meminfo.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__linux__)
#include <dlfcn.h>
#elif defined(__APPLE__)
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <dlfcn.h>
#endif

/* ----------------------------------------------------------------- helpers */

static int clampi(int v, int lo, int hi) {
    if (lo < 1) {
        lo = 1;
    }
    if (v < lo) {
        v = lo;
    }
    if (hi > 0 && v > hi) {
        v = hi;
    }
    return v;
}

static double resolve_fraction(double specv) {
    const char *e = getenv("SCALPEL3_GPU_MEM_FRACTION");
    if (e && *e) {
        double v = atof(e);
        if (v > 0.0 && v <= 1.0) {
            return v;
        }
    }
    if (specv > 0.0 && specv <= 1.0) {
        return specv;
    }
    return 0.5;
}

/* ------------------------------------------------------------- CUDA / NVML */
#if defined(__linux__)

/* Minimal NVML surface, declared locally to avoid a CUDA-toolkit dependency.
 * These match the stable NVML ABI; we only call the v2/handle/memory entries. */
typedef int   nvml_return_t;          /* 0 == NVML_SUCCESS                    */
typedef void *nvml_device_t;
typedef struct {
    unsigned long long total;
    unsigned long long free;
    unsigned long long used;
} nvml_memory_t;

typedef union {
    double dVal;
    int siVal;
    unsigned int uiVal;
    unsigned long ulVal;
    unsigned long long ullVal;
    signed long long sllVal;
} nvml_value_t;

typedef struct {
    unsigned int fieldId;
    unsigned int scopeId;
    long long timestamp;
    long long latencyUsec;
    int valueType;
    nvml_return_t nvmlReturn;
    nvml_value_t value;
} nvml_field_value_t;

#define NVML_FI_DEV_GET_GPU_RECOVERY_ACTION 230

static struct {
    int   tried;
    int   ok;
    void *handle;
    nvml_return_t (*init)(void);
    nvml_return_t (*shutdown)(void);
    nvml_return_t (*get_handle)(unsigned int, nvml_device_t *);
    nvml_return_t (*get_mem)(nvml_device_t, nvml_memory_t *);
    nvml_return_t (*get_uuid)(nvml_device_t, char *, unsigned int);
    nvml_return_t (*get_compute_capability)(nvml_device_t, int *, int *);
    nvml_return_t (*get_field_values)(nvml_device_t, int,
                                      nvml_field_value_t *);
} g_nvml;

static int nvml_load(void) {
    if (g_nvml.tried) {
        return g_nvml.ok;
    }
    g_nvml.tried = 1;

    g_nvml.handle = dlopen("libnvidia-ml.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!g_nvml.handle) {
        g_nvml.handle = dlopen("libnvidia-ml.so", RTLD_NOW | RTLD_LOCAL);
    }
    if (!g_nvml.handle) {
        return (g_nvml.ok = 0);
    }

    g_nvml.init       = (nvml_return_t (*)(void)) dlsym(g_nvml.handle, "nvmlInit_v2");
    g_nvml.shutdown   = (nvml_return_t (*)(void)) dlsym(g_nvml.handle, "nvmlShutdown");
    g_nvml.get_handle = (nvml_return_t (*)(unsigned int, nvml_device_t *))
                        dlsym(g_nvml.handle, "nvmlDeviceGetHandleByIndex_v2");
    g_nvml.get_mem    = (nvml_return_t (*)(nvml_device_t, nvml_memory_t *))
                        dlsym(g_nvml.handle, "nvmlDeviceGetMemoryInfo");
    g_nvml.get_uuid   = (nvml_return_t (*)(nvml_device_t, char *, unsigned int))
                        dlsym(g_nvml.handle, "nvmlDeviceGetUUID");
    g_nvml.get_compute_capability =
        (nvml_return_t (*)(nvml_device_t, int *, int *))
        dlsym(g_nvml.handle, "nvmlDeviceGetCudaComputeCapability");
    g_nvml.get_field_values =
        (nvml_return_t (*)(nvml_device_t, int, nvml_field_value_t *))
        dlsym(g_nvml.handle, "nvmlDeviceGetFieldValues");

    if (!g_nvml.init || !g_nvml.get_handle || !g_nvml.get_mem) {
        return (g_nvml.ok = 0);
    }
    if (g_nvml.init() != 0) {
        return (g_nvml.ok = 0);
    }
    return (g_nvml.ok = 1);
}

static bool query_cuda(int device_id, gpu_mem_info_t *out) {
    if (!nvml_load()) {
        return false;
    }
    nvml_device_t dev;
    if (g_nvml.get_handle((unsigned int) device_id, &dev) != 0) {
        return false;
    }
    nvml_memory_t m;
    if (g_nvml.get_mem(dev, &m) != 0) {
        return false;
    }
    out->device_id   = device_id;
    out->total_bytes = (size_t) m.total;
    out->free_bytes  = (size_t) m.free;
    out->is_gpu      = true;
    out->backend     = "cuda";

    if (g_nvml.get_uuid) {
        if (g_nvml.get_uuid(dev, out->uuid, (unsigned int)sizeof(out->uuid)) != 0) {
            out->uuid[0] = '\0';
        }
    }
    if (g_nvml.get_compute_capability) {
        int major = -1;
        int minor = -1;

        if (g_nvml.get_compute_capability(dev, &major, &minor) == 0) {
            out->compute_major = major;
            out->compute_minor = minor;
        }
    }
    if (g_nvml.get_field_values) {
        nvml_field_value_t value;

        memset(&value, 0, sizeof(value));
        value.fieldId = NVML_FI_DEV_GET_GPU_RECOVERY_ACTION;
        if (g_nvml.get_field_values(dev, 1, &value) == 0
            && value.nvmlReturn == 0) {
            out->recovery_action = (int)value.value.uiVal;
        }
    }
    return true;
}

#endif /* __linux__ */

/* ----------------------------------------------------------- Apple unified */
#if defined(__APPLE__)

/* Metal's recommendedMaxWorkingSetSize is the device's own recommendation for
 * the maximum GPU working set (roughly 75% of unified memory on Apple
 * Silicon). That is the truthful GPU budget on a unified-memory machine,
 * where hw.memsize would overstate what the GPU should ever consume. It is
 * reached with the same discipline as the NVML backend: dlopen at run time
 * (Metal.framework, then objc_msgSend/sel_registerName resolved from the
 * already-loaded objc runtime), so this stays a plain C file with no Metal
 * link dependency. The value is static for the life of the process, so it is
 * queried once and cached. */
static struct {
    int      tried;
    uint64_t recommended_bytes;   /* 0 when the query failed */
} g_metal;

static uint64_t metal_recommended_working_set(void) {
    if (g_metal.tried) {
        return g_metal.recommended_bytes;
    }
    g_metal.tried = 1;

    void *metal = dlopen("/System/Library/Frameworks/Metal.framework/Metal",
                         RTLD_NOW | RTLD_LOCAL);
    if (!metal) {
        return 0;
    }

    void *(*create_device)(void) =
        (void *(*)(void)) dlsym(metal, "MTLCreateSystemDefaultDevice");
    void *(*sel_register)(const char *) =
        (void *(*)(const char *)) dlsym(RTLD_DEFAULT, "sel_registerName");
    uint64_t (*msg_send_u64)(void *, void *) =
        (uint64_t (*)(void *, void *)) dlsym(RTLD_DEFAULT, "objc_msgSend");
    void (*msg_send_void)(void *, void *) =
        (void (*)(void *, void *)) dlsym(RTLD_DEFAULT, "objc_msgSend");

    if (!create_device || !sel_register || !msg_send_u64 || !msg_send_void) {
        return 0;
    }

    void *device = create_device();
    if (!device) {
        return 0;
    }

    g_metal.recommended_bytes =
        msg_send_u64(device, sel_register("recommendedMaxWorkingSetSize"));

    /* MTLCreateSystemDefaultDevice follows the Create rule: release it. */
    msg_send_void(device, sel_register("release"));

    return g_metal.recommended_bytes;
}

static bool query_metal(int device_id, gpu_mem_info_t *out) {
    uint64_t memsize = 0;
    size_t   len     = sizeof(memsize);
    if (sysctlbyname("hw.memsize", &memsize, &len, NULL, 0) != 0) {
        return false;
    }

    vm_size_t page = 0;
    if (host_page_size(mach_host_self(), &page) != KERN_SUCCESS) {
        page = (vm_size_t) getpagesize();
    }

    vm_statistics64_data_t vmstat;
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
    if (host_statistics64(mach_host_self(), HOST_VM_INFO64,
                          (host_info64_t) &vmstat, &count) != KERN_SUCCESS) {
        return false;
    }

    uint64_t avail_pages = (uint64_t) vmstat.free_count
                         + (uint64_t) vmstat.inactive_count
                         + (uint64_t) vmstat.speculative_count;
    uint64_t avail_now   = avail_pages * (uint64_t) page;

    /* GPU budget = the device's recommended working set, bounded by what is
     * actually reclaimable right now (the recommendation is static and knows
     * nothing about current memory pressure). When Metal is unavailable the
     * budget degrades to the availability estimate alone. */
    uint64_t recommended = metal_recommended_working_set();
    uint64_t budget      = avail_now;
    if (recommended > 0 && recommended < budget) {
        budget = recommended;
    }

    out->device_id   = device_id;
    out->total_bytes = (size_t) (recommended > 0 ? recommended : memsize);
    out->free_bytes  = (size_t) budget;
    out->is_gpu      = false;   /* unified memory: free-delta calibration is noisy */
    out->backend     = "metal";
    return true;
}

#endif /* __APPLE__ */

/* --------------------------------------------------------- CPU / fallback */

static bool query_cpu(int device_id, gpu_mem_info_t *out) {
    out->device_id = device_id;
    out->is_gpu    = false;
    out->backend   = "cpu";

#if defined(_SC_AVPHYS_PAGES) && defined(_SC_PAGESIZE)
    long avail = sysconf(_SC_AVPHYS_PAGES);
    long total = sysconf(_SC_PHYS_PAGES);
    long psz   = sysconf(_SC_PAGESIZE);
    if (avail > 0 && psz > 0) {
        out->free_bytes  = (size_t) avail * (size_t) psz;
        out->total_bytes = (total > 0) ? (size_t) total * (size_t) psz
                                       : out->free_bytes;
        return true;
    }
#endif

    /* Last resort: assume a modest budget so we still return a sane batch. */
    out->total_bytes = 0;
    out->free_bytes  = (size_t) 2 * 1024 * 1024 * 1024; /* 2 GiB */
    return true;
}

/* --------------------------------------------------------------- public API */

bool gpu_mem_query(int device_id, gpu_mem_info_t *out) {
    if (!out) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    out->compute_major = -1;
    out->compute_minor = -1;
    out->recovery_action = -1;

    if (device_id < 0) {
        return query_cpu(device_id, out);
    }

#if defined(__linux__)
    if (query_cuda(device_id, out)) {
        return true;
    }
#elif defined(__APPLE__)
    if (query_metal(device_id, out)) {
        return true;
    }
#endif
    return query_cpu(device_id, out);  /* never hard-fails */
}

// Resolve the shared working-memory budget from the current state of one device.
// Environment configuration is applied here so ONNX provider arenas and inference
// batch planning use the same fraction.
bool gpu_mem_budget(int device_id, double requested_fraction,
                    gpu_mem_budget_t *out) {
    if (!out) {
        return false;
    }

    memset(out, 0, sizeof(*out));
    if (!gpu_mem_query(device_id, &out->device)) {
        return false;
    }

    out->fraction = resolve_fraction(requested_fraction);
    out->usable_bytes =
        (size_t)((double)out->device.free_bytes * out->fraction);
    return true;
}

int gpu_plan_batch(const gpu_batch_spec_t *spec) {
    if (!spec) {
        return 1;
    }
    int         minb  = (spec->min_batch > 0) ? spec->min_batch : 1;
    int         maxb  = spec->max_batch;
    const char *label = spec->label ? spec->label : "gpu";

    /* 1. forced batch (caller's env override) short-circuits everything. */
    if (spec->force_batch > 0) {
        int b = clampi(spec->force_batch, minb, maxb);
        fprintf(stdout, "[gpu_batch:%s] forced batch=%d (min=%d max=%d)\n",
                label, b, minb, maxb);
        return b;
    }

    gpu_mem_budget_t memory;
    gpu_mem_budget(spec->device_id, spec->safety_fraction, &memory);
    gpu_mem_info_t info = memory.device;
    double frac = memory.fraction;

    size_t per_sample = (spec->bytes_per_sample > 0) ? spec->bytes_per_sample : 1;
    size_t overhead   = info.is_gpu ? (size_t)512 * 1024 * 1024 : 0;

    size_t budget = memory.usable_bytes;
    budget = (budget > overhead) ? (budget - overhead) : 0;

    long long batch = (per_sample > 0)
                    ? (long long) (budget / per_sample)
                    : (long long) minb;
    if (batch < minb) {
        batch = minb;
    }
    if (batch > 0x7fffffffLL) {
        batch = 0x7fffffffLL;
    }
    int b = clampi((int) batch, minb, maxb);

    fprintf(stdout,
            "[gpu_batch:%s] backend=%s free=%.1f MiB total=%.1f MiB frac=%.2f "
            "per_sample=%zu B overhead=%.0f MiB -> batch=%d (min=%d max=%d)\n",
            label, info.backend,
            info.free_bytes / 1048576.0, info.total_bytes / 1048576.0, frac,
            per_sample, overhead / 1048576.0,
            b, minb, maxb);
    return b;
}
