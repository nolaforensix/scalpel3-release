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
 * modico_onnx_global.c — implementation of the process-global MoDiCo
 * ONNX session. See modico_onnx_global.h.
 *
 * Mirrors elf_onnx_global.c: a single mutex-guarded session. The
 * mutex only guards init/shutdown lifecycle; ORT Run() calls on the
 * shared session during the (single-threaded, batched) block-validation
 * populate loop do not need it.
 */
#include "modico_onnx_global.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static mc_session_t   *g_session = NULL;

/* Return true if 'path' names a readable regular file. */
static bool file_is_readable(const char *path)
{
    struct stat st;
    return (stat(path, &st) == 0) && S_ISREG(st.st_mode);
}

// Given a model base path (with or without a trailing ".onnx"), check that at
// least the FP32 model "<base>.onnx" exists and is readable. base_out receives
// the normalized base path for the subsequent automatic model selection.
static bool fp32_model_present(const char *model_base_path,
                               char *base_out, size_t base_cap)
{
    strncpy(base_out, model_base_path, base_cap - 1);
    base_out[base_cap - 1] = '\0';

    size_t blen = strlen(base_out);
    if (blen > 5 && strcmp(base_out + blen - 5, ".onnx") == 0) {
        base_out[blen - 5] = '\0';
    }

    char fp32_path[1024];
    snprintf(fp32_path, sizeof(fp32_path), "%s.onnx", base_out);
    return file_is_readable(fp32_path);
}

bool modico_onnx_global_init(const char *model_base_path,
                             int intra_op_threads,
                             const char *accelerator,
                             int device_id,
                             uint64_t expected_blocks)
{
    const char *accel = accelerator;

    if (!model_base_path || !model_base_path[0]) {
        return false;
    }

    if (!accel || !accel[0]) {
        accel = "cpu";
    }
    else if (strcmp(accel, "cuda") != 0
             && strcmp(accel, "coreml") != 0
             && strcmp(accel, "cpu") != 0) {
        accel = "cpu";
    }

    // A missing model disables MoDiCo without affecting the rest of the run.
    // Session creation reports a present but unusable model to the caller.
    char base[1024];
    if (!fp32_model_present(model_base_path, base, sizeof(base))) {
        return false;
    }

    pthread_mutex_lock(&g_lock);

    if (g_session) {
        /* Already initialized — idempotent. */
        pthread_mutex_unlock(&g_lock);
        return true;
    }

    /* Session creation picks FP32 vs INT8 based on CPU capability and which
     * files exist, then applies the requested provider and workload policy. */
    mc_session_info_t info;
    memset(&info, 0, sizeof(info));
    g_session = mc_create_session_auto_with_accelerator_device_for_workload(
        base, intra_op_threads, MC_KIND_AUTO, accel, device_id,
        expected_blocks, &info);

    pthread_mutex_unlock(&g_lock);
    return (g_session != NULL);
}

void modico_onnx_global_shutdown(void)
{
    pthread_mutex_lock(&g_lock);
    if (g_session) {
        mc_destroy_session(g_session);
        g_session = NULL;
    }
    pthread_mutex_unlock(&g_lock);
}

mc_session_t *modico_onnx_global_get(void)
{
    return g_session;
}

bool modico_onnx_global_enabled(void)
{
    return g_session != NULL;
}

int modico_onnx_global_num_classes(void)
{
    return g_session ? mc_get_num_classes(g_session) : 0;
}

const char *modico_onnx_global_provider(void)
{
    return g_session ? mc_execution_provider(g_session) : "none";
}

const char *modico_onnx_global_backend(void)
{
    return g_session ? mc_inference_backend(g_session) : "none";
}

const char *modico_onnx_global_model_path(void)
{
    return g_session ? mc_model_path(g_session) : NULL;
}

int modico_onnx_global_device_id(void)
{
    return g_session ? mc_cuda_device_id(g_session) : -1;
}

bool modico_onnx_global_uses_cuda(void)
{
    return g_session && mc_uses_cuda(g_session);
}

bool modico_onnx_global_uses_coreml(void)
{
    return g_session && mc_uses_coreml(g_session);
}

bool modico_onnx_global_uses_tensorrt(void)
{
    return g_session && mc_uses_tensorrt(g_session);
}

int modico_onnx_global_terminate_current_run(void)
{
    return g_session ? mc_terminate_current_run(g_session) : 1;
}
