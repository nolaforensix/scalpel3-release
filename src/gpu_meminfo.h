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

/**
 * @author James Ghawaly
 */

/*
 * gpu_meminfo.h — central accelerator-memory query + batch-size planner.
 *
 * Purpose: give any GPU-based classifier/validator in Scalpel3 (MoDiCo today,
 * others later) one place to ask "how much device memory is available right
 * now?" and "given that, what batch size should I use?" — so each one doesn't
 * reinvent memory probing and OOM handling.
 *
 * Design:
 *   - gpu_mem_query()  reports hardware state (OUTPUT struct gpu_mem_info_t).
 *   - gpu_plan_batch() turns that + a per-classifier description
 *                      (INPUT struct gpu_batch_spec_t) into a batch size.
 *   The planner is the only place the two meet, which is what makes it
 *   reusable: each classifier supplies its own working-set estimate without
 *   exposing model details to the planner.
 *
 * Backends: NVIDIA via NVML (dlopen'd at runtime — no CUDA-toolkit build or
 * link dependency), Apple unified memory via Metal's
 * recommendedMaxWorkingSetSize (dlopen'd the same way; sysctl/mach
 * availability bounds it and serves as the fallback), and a CPU/sysconf
 * fallback. The query NEVER hard-fails: if no accelerator query works it
 * returns a conservative CPU estimate, mirroring MoDiCo's "model missing ->
 * run vanilla" philosophy. An accelerator is an optimization, never required.
 *
 * This header is intentionally dependency-free (only <stdbool.h>/<stddef.h>)
 * so including it never drags NVML/CUDA/ORT onto a translation unit — the same
 * coupling discipline scalpel.h follows.
 *
 * Threading: intended to be called from a single-threaded init/setup path
 * (e.g. MoDiCo's batched populate, which runs before the validation drain).
 * The NVML loader is lazily initialized and not guarded for concurrent first
 * use.
 */
#ifndef GPU_MEMINFO_H
#define GPU_MEMINFO_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* OUTPUT of gpu_mem_query(): the state of one device right now. */
typedef struct {
    int          device_id;    /* which device these numbers describe        */
    size_t       total_bytes;  /* total device memory                        */
    size_t       free_bytes;   /* currently-free memory (NVML: GPU-wide,      */
                               /* i.e. accounts for other processes)         */
    int          compute_major;/* CUDA compute capability, or -1 if unknown  */
    int          compute_minor;
    int          recovery_action; /* NVML recovery action, or -1 if unknown */
    char         uuid[96];     /* stable NVML GPU UUID, empty if unavailable */
    bool         is_gpu;       /* true only for a discrete GPU whose per-     */
                               /* device free figure is reliable              */
                               /* false for unified-memory (metal) or cpu.    */
    const char  *backend;      /* "cuda" | "metal" | "cpu" (static literal,   */
                               /* never freed)                               */
} gpu_mem_info_t;

/* A device-memory budget resolved from the current free memory and the shared
 * Scalpel3 safety policy. */
typedef struct {
    gpu_mem_info_t device;
    size_t         usable_bytes;
    double         fraction;
} gpu_mem_budget_t;

/* Query device memory. Fills *out and returns true. A negative device_id
 * explicitly selects host memory. Otherwise, device_id selects the GPU and a
 * backend failure falls back to a conservative CPU estimate. Returns false
 * only if out is NULL. */
bool gpu_mem_query(int device_id, gpu_mem_info_t *out);

/* Resolve the memory budget for one device. requested_fraction in (0,1]
 * overrides the default; SCALPEL3_GPU_MEM_FRACTION overrides both. */
bool gpu_mem_budget(int device_id, double requested_fraction,
                    gpu_mem_budget_t *out);


/* INPUT to gpu_plan_batch(): a classifier describing itself. Everything
 * model-specific lives here so the planner stays generic. */
typedef struct {
    int          device_id;        /* GPU this classifier's session runs on  */

    /* Classifier's own estimate of memory consumed per sample, including I/O,
     * activations, execution workspaces, and allocator headroom. Must be > 0
     * to plan. */
    size_t       bytes_per_sample;

    int          min_batch;        /* lower clamp (<=0 => 1)                  */
    int          max_batch;        /* upper clamp (<=0 => unbounded)          */

    /* >0 => use this batch verbatim (clamped), skip all planning. Callers wire
     * this to a per-classifier env override, e.g. SCALPEL3_MODICO_BATCH. */
    int          force_batch;

    /* Fraction of free memory to budget. <=0 => default 0.5, overridable by
     * env SCALPEL3_GPU_MEM_FRACTION. */
    double       safety_fraction;

    const char  *label;            /* for log lines, e.g. "modico" (may be    */
                                   /* NULL)                                   */
} gpu_batch_spec_t;

/* Plan a batch size for this classifier: query memory, reserve fixed overhead,
 * apply the safety fraction, divide by the classifier's working-set estimate,
 * and clamp. Logs the decision. Always returns a value in
 * [max(min_batch,1), max_batch]. */
int gpu_plan_batch(const gpu_batch_spec_t *spec);

#ifdef __cplusplus
}
#endif

#endif /* GPU_MEMINFO_H */
