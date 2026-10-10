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

#ifndef MODICO_CUDA_H
#define MODICO_CUDA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mc_cuda_preprocessor mc_cuda_preprocessor_t;

int mc_cuda_preprocessor_available(char *reason, size_t reason_size);

void *mc_cuda_stream_create(int device_id, char *reason, size_t reason_size);
void mc_cuda_stream_destroy(int device_id, void *stream);

mc_cuda_preprocessor_t *mc_cuda_preprocessor_create(
    int device_id, int run_batch, int block_size, int num_classes,
    void *shared_stream,
    char *reason, size_t reason_size);

void mc_cuda_preprocessor_destroy(mc_cuda_preprocessor_t *preprocessor);

int mc_cuda_preprocessor_prepare(mc_cuda_preprocessor_t *preprocessor,
                                 const uint8_t *bytes,
                                 int batch_size,
                                 char *reason,
                                 size_t reason_size);

int mc_cuda_preprocessor_copy_output(mc_cuda_preprocessor_t *preprocessor,
                                     float *logits,
                                     int batch_size,
                                     char *reason,
                                     size_t reason_size);

void *mc_cuda_preprocessor_input(const mc_cuda_preprocessor_t *preprocessor);
void *mc_cuda_preprocessor_global_histograms(
    const mc_cuda_preprocessor_t *preprocessor);
void *mc_cuda_preprocessor_local_histograms(
    const mc_cuda_preprocessor_t *preprocessor);
void *mc_cuda_preprocessor_output(const mc_cuda_preprocessor_t *preprocessor);
size_t mc_cuda_preprocessor_windows(
    const mc_cuda_preprocessor_t *preprocessor);

#ifdef __cplusplus
}
#endif

#endif
