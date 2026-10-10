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
 * modico.c — implementation of the MoDiCo C inference layer.
 * See modico.h for the public surface.
 */

#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#if defined(__APPLE__)
/* Expose BSD types (u_int, u_char, ...) used by <sys/sysctl.h>, which
 * _POSIX_C_SOURCE would otherwise hide under a strict -std=cNN. */
#  define _DARWIN_C_SOURCE 1
#endif

#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <math.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>

#if defined(__aarch64__) && defined(__linux__)
#  include <sys/auxv.h>
#  include <asm/hwcap.h>
#elif defined(__aarch64__) && defined(__APPLE__)
#  include <sys/sysctl.h>
#endif

#include "onnxruntime_c_api.h"
#include "gpu_meminfo.h"
#include "modico.h"
#include "scalpel_output.h"
#include "modico_cuda.h"
#include "onnx_cuda_options.h"
#include "onnx_providers.h"

/* ------------------------------------------------------------------------- */

static const OrtApi *g_ort = NULL;

static void mc_log_ort_status(OrtStatus *status, const char *context);
static int mc_ort_succeeded(OrtStatus *status, const char *context);
static int mc_message_contains(const char *message, const char *needle);
static mc_inference_status_t mc_classify_ort_failure(const char *message);
static int mc_init_api(void);
static int mc_cuda_requested(const char *accelerator);
static int mc_coreml_requested(const char *accelerator);
static int mc_coreml_static_batch(void);
static int mc_tensorrt_requested(mc_session_t *s, int device_id);
#if defined(__linux__)
static int mc_sanitize_path_component(const char *source,
                                      char *destination,
                                      size_t destination_size);
#endif
static int mc_prepare_tensorrt_cache(mc_session_t *s, int device_id);
static int mc_append_tensorrt_provider(mc_session_t *s, int device_id);
static int mc_append_cuda_provider(mc_session_t *s, int device_id);
static int mc_append_coreml_provider(mc_session_t *s, const char *model_path);
static int mc_prepare_session_options(mc_session_t *s, int intra_op_threads,
                                      OrtLoggingLevel log_level);
static int mc_ensure_scratch(mc_session_t *s, size_t n_elems);
static void mc_release_persistent_tensors(mc_session_t *s);
static int mc_prepare_persistent_tensors(mc_session_t *s,
                                         int run_batch,
                                         int block_size,
                                         size_t histogram_windows);
static void mc_release_cuda_fastpath(mc_session_t *s);
static int mc_prepare_cuda_fastpath(mc_session_t *s,
                                    int run_batch,
                                    int block_size,
                                    size_t histogram_windows);
static int mc_run_cuda_fastpath(mc_session_t *s,
                                const uint8_t *bytes,
                                int batch_size,
                                float *logits_out);
static void mc_record_run_timing(mc_session_t *s, double run_seconds);
static int mc_run_internal(mc_session_t *s, const uint8_t *bytes,
                           int batch_size, int block_size,
                           float *logits_out);
static int file_is_readable(const char *path);

#define MC_CACHE_DEFAULT_MAX_MIB 512ULL
#define MC_CACHE_DEFAULT_MAX_AGE_DAYS 30ULL
#define MC_CACHE_MIN_MAX_MIB 64ULL
#define MC_CACHE_MAX_MAX_MIB 65536ULL
#define MC_CACHE_MIN_GRACE_SECONDS 300
#define MC_TENSORRT_CACHE_PROFILE_VERSION 2
#define MC_TENSORRT_DEFAULT_MAX_BATCH 128
#define MC_TENSORRT_EMERGENCY_MAX_BATCH 8192

typedef struct {
    char root[PATH_MAX];
    char leaf[PATH_MAX];
    char marker[PATH_MAX];
    char max_mib_environment[96];
    char max_age_environment[96];
    uint64_t default_max_mib;
    uint64_t default_max_age_days;
    int marker_fd;
    int active;
} mc_cache_guard_t;

typedef struct {
    char *path;
    uint64_t bytes;
    time_t last_used;
    int directory;
    int protected_entry;
} mc_cache_entry_t;

typedef struct {
    mc_cache_entry_t *entries;
    size_t count;
    size_t capacity;
    uint64_t total_bytes;
    const char *current_leaf;
    int failed;
} mc_cache_inventory_t;


static void mc_log_ort_status(OrtStatus *status, const char *context)
{
    const char *msg = g_ort->GetErrorMessage(status);
    lock_fprintf(stderr, "MoDiCo: %s failed: %s\n",
            context ? context : "ORT operation",
            msg ? msg : "(null)");
    g_ort->ReleaseStatus(status);
}

static int mc_ort_succeeded(OrtStatus *status, const char *context)
{
    if (!status) {
        return 1;
    }
    mc_log_ort_status(status, context);
    return 0;
}

static int mc_message_contains(const char *message, const char *needle)
{
    size_t needle_len;

    if (!message || !needle || !*needle) {
        return 0;
    }
    needle_len = strlen(needle);
    for (const char *p = message; *p; p++) {
        if (strncasecmp(p, needle, needle_len) == 0) {
            return 1;
        }
    }
    return 0;
}

static mc_inference_status_t mc_classify_ort_failure(const char *message)
{
    if (mc_message_contains(message, "terminate flag")
        || mc_message_contains(message, "terminated")) {
        return MC_INFERENCE_TERMINATED;
    }
    if (mc_message_contains(message, "out of memory")
        || mc_message_contains(message, "memory allocation")
        || mc_message_contains(message, "cudaErrorMemoryAllocation")
        || mc_message_contains(message, "CUDNN_STATUS_ALLOC_FAILED")
        || mc_message_contains(message, "Available memory of")
        || mc_message_contains(message, "smaller than requested bytes")) {
        return MC_INFERENCE_RETRYABLE;
    }
    return MC_INFERENCE_FATAL;
}


struct mc_session {
    OrtEnv *env;
    OrtSession *session;
    OrtSessionOptions *opts;
    OrtRunOptions *run_options;
    OrtMemoryInfo *mem_info;
    char *input_name;
    char *global_histogram_input_name;
    char *local_histogram_input_name;
    char *output_name;
    size_t input_count;
    int   num_classes;
    int   device_id;
    int   static_batch_size;
    int   run_batch_size;
    int   tensorrt_enabled;
    int   tensorrt_cache_warm;
    void *cuda_user_stream;
    uint64_t expected_blocks;
    char  execution_provider[16];
    char  model_path[1024];
    char  tensorrt_cache_dir[PATH_MAX];
    mc_cache_guard_t tensorrt_cache_guard;
#if defined(__APPLE__)
    char  coreml_cache_dir[PATH_MAX];
    mc_cache_guard_t coreml_cache_guard;
#endif
    int   timing_enabled;
    int   profiling_enabled;
    mc_timing_t timing;

    /* Reusable scratch buffer for the uint8 -> int64 widening that
     * ORT's input tensor requires. Grows on demand; never shrinks. */
    int64_t *scratch_input;
    size_t   scratch_capacity_elems;

    /* Native histogram-input model scratch. */
    float  *scratch_global_histograms;
    float  *scratch_local_histograms;
    size_t  scratch_global_histogram_elems;
    size_t  scratch_local_histogram_elems;

    OrtValue *persistent_inputs[3];
    OrtValue *persistent_output;
    float *scratch_output;
    size_t scratch_output_elems;
    int persistent_batch_size;
    int persistent_block_size;
    size_t persistent_histogram_windows;

    mc_cuda_preprocessor_t *cuda_preprocessor;
    OrtMemoryInfo *cuda_mem_info;
    OrtIoBinding *cuda_binding;
    OrtValue *cuda_inputs[3];
    OrtValue *cuda_output;
    int cuda_fastpath_state;
    int cuda_fastpath_batch_size;
    int cuda_fastpath_block_size;
    size_t cuda_fastpath_histogram_windows;
};


static int mc_env_enabled(const char *name)
{
    const char *value = getenv(name);

    return value && *value
        && strcasecmp(value, "0") != 0
        && strcasecmp(value, "false") != 0
        && strcasecmp(value, "no") != 0
        && strcasecmp(value, "off") != 0;
}


static int mc_value_disabled(const char *value)
{
    return value && (!*value
        || strcasecmp(value, "0") == 0
        || strcasecmp(value, "false") == 0
        || strcasecmp(value, "no") == 0
        || strcasecmp(value, "off") == 0
        || strcasecmp(value, "none") == 0);
}


static double mc_elapsed_seconds(const struct timespec *start,
                                 const struct timespec *end)
{
    return (double)(end->tv_sec - start->tv_sec)
         + (double)(end->tv_nsec - start->tv_nsec) / 1e9;
}


static int mc_sha256_file_hex(const char *path, char hex[65])
{
    unsigned char buffer[64 * 1024];
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    EVP_MD_CTX *ctx = NULL;
    FILE *fp = NULL;
    int ok = 0;

    if (!path || !*path) {
        return 0;
    }
    fp = fopen(path, "rb");
    ctx = EVP_MD_CTX_new();
    if (!fp || !ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        goto done;
    }

    for (;;) {
        size_t count = fread(buffer, 1, sizeof(buffer), fp);

        if (count > 0 && EVP_DigestUpdate(ctx, buffer, count) != 1) {
            goto done;
        }
        if (count < sizeof(buffer)) {
            if (ferror(fp)) {
                goto done;
            }
            break;
        }
    }
    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1
        || digest_len != 32) {
        goto done;
    }

    for (unsigned int i = 0; i < digest_len; i++) {
        snprintf(hex + i * 2, 3, "%02x", digest[i]);
    }
    hex[64] = '\0';
    ok = 1;

done:
    if (fp) {
        fclose(fp);
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}


#if defined(__APPLE__)
static int mc_sha256_text_hex(const char *text, char hex[65])
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = 0;

    if (!ctx
        || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1
        || EVP_DigestUpdate(ctx, text, strlen(text)) != 1
        || EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1
        || digest_len != 32) {
        goto done;
    }
    for (unsigned int i = 0; i < digest_len; i++) {
        snprintf(hex + i * 2, 3, "%02x", digest[i]);
    }
    hex[64] = '\0';
    ok = 1;

done:
    EVP_MD_CTX_free(ctx);
    return ok;
}
#endif


static int mc_mkdir_one(const char *path)
{
    struct stat st;

    if (mkdir(path, 0700) == 0) {
        return 1;
    }
    return errno == EEXIST && stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}


static int mc_mkdir_p(const char *path)
{
    char current[PATH_MAX];
    size_t length = strlen(path);

    if (length == 0 || length >= sizeof(current)) {
        return 0;
    }
    memcpy(current, path, length + 1);

    for (char *p = current + 1; *p; p++) {
        if (*p != '/') {
            continue;
        }
        *p = '\0';
        if (!mc_mkdir_one(current)) {
            return 0;
        }
        *p = '/';
    }
    return mc_mkdir_one(current);
}


static int mc_directory_has_entries(const char *path)
{
    DIR *dir = opendir(path);
    struct dirent *entry;
    int found = 0;

    if (!dir) {
        return 0;
    }
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0
            && strcmp(entry->d_name, "..") != 0
            && strcmp(entry->d_name, ".last_used") != 0
            && strcmp(entry->d_name, ".scalpel3-cache.lock") != 0
            && strncmp(entry->d_name, ".active.", 8) != 0) {
            found = 1;
            break;
        }
    }
    closedir(dir);
    return found;
}


static int mc_cache_path_is_within(const char *root, const char *path)
{
    size_t root_length;

    if (!root || !path) {
        return 0;
    }
    root_length = strlen(root);
    return strncmp(root, path, root_length) == 0
        && (path[root_length] == '\0' || path[root_length] == '/');
}


static uint64_t mc_cache_policy_value(const char *environment,
                                      uint64_t default_value,
                                      uint64_t minimum,
                                      uint64_t maximum)
{
    const char *configured = getenv(environment);
    char *end = NULL;
    unsigned long long value;

    if (!configured || !*configured) {
        return default_value;
    }
    errno = 0;
    value = strtoull(configured, &end, 10);
    if (errno != 0 || end == configured || *end != '\0'
        || value < minimum || value > maximum) {
        lock_fprintf(stderr,
                "WARNING: MoDiCo is ignoring invalid %s=%s; using %llu.\n",
                environment, configured,
                (unsigned long long)default_value);
        return default_value;
    }
    return (uint64_t)value;
}


static int mc_cache_control_file(const char *name)
{
    return strcmp(name, ".scalpel3-cache.lock") == 0
        || strcmp(name, ".last_used") == 0
        || strncmp(name, ".active.", 8) == 0;
}


static int mc_cache_live_marker(const char *directory,
                                const char *name,
                                int remove_stale)
{
    const char *number;
    char *end = NULL;
    long pid;
    char path[PATH_MAX];
    char marker_kind[16] = {0};
    int fd = -1;
    int locked = 0;

    if (!directory || !name || strncmp(name, ".active.", 8) != 0) {
        return 0;
    }
    number = name + 8;
    errno = 0;
    pid = strtol(number, &end, 10);
    if (errno != 0 || end == number || pid <= 0
        || (*end != '\0' && *end != '.')) {
        return 0;
    }
    int written = snprintf(path, sizeof(path), "%s/%s", directory, name);
    if (written < 0 || (size_t)written >= sizeof(path)) {
        return 0;
    }
    fd = open(path, O_RDWR);
    if (fd >= 0) {
        if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
            locked = 1;
            ssize_t count = pread(fd, marker_kind,
                                  sizeof(marker_kind) - 1, 0);
            if (count < 0) {
                marker_kind[0] = '\0';
            }
        }
        else if (errno == EWOULDBLOCK || errno == EAGAIN) {
            close(fd);
            return 1;
        }
        else {
            close(fd);
            fd = -1;
        }
    }

    int new_marker = strncmp(marker_kind, "locked-v1", 9) == 0;
    int legacy_live = !new_marker
                   && (kill((pid_t)pid, 0) == 0 || errno == EPERM);
    if (locked) {
        flock(fd, LOCK_UN);
        close(fd);
    }
    if (legacy_live) {
        return 1;
    }
    if (remove_stale) {
        unlink(path);
    }
    return 0;
}


static int mc_cache_directory_metadata(const char *directory,
                                       int *has_last_used,
                                       time_t *last_used,
                                       int *has_live_marker)
{
    DIR *dir;
    struct dirent *entry;
    char path[PATH_MAX];
    struct stat st;

    *has_last_used = 0;
    *last_used = 0;
    *has_live_marker = 0;

    int written = snprintf(path, sizeof(path), "%s/.last_used", directory);
    if (written >= 0 && (size_t)written < sizeof(path)
        && lstat(path, &st) == 0 && S_ISREG(st.st_mode)) {
        *has_last_used = 1;
        *last_used = st.st_mtime;
    }

    dir = opendir(directory);
    if (!dir) {
        return 0;
    }
    while ((entry = readdir(dir)) != NULL) {
        if (mc_cache_live_marker(directory, entry->d_name, 1)) {
            *has_live_marker = 1;
        }
    }
    closedir(dir);
    return 1;
}


static int mc_cache_measure_tree(const char *path, uint64_t *bytes)
{
    struct stat st;
    DIR *dir;
    struct dirent *entry;
    char child[PATH_MAX];

    if (lstat(path, &st) != 0) {
        return errno == ENOENT;
    }
    if (!S_ISDIR(st.st_mode)) {
        if (st.st_size > 0) {
            *bytes += (uint64_t)st.st_size;
        }
        return 1;
    }

    dir = opendir(path);
    if (!dir) {
        return 0;
    }
    while ((entry = readdir(dir)) != NULL) {
        int written;

        if (strcmp(entry->d_name, ".") == 0
            || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        written = snprintf(child, sizeof(child), "%s/%s", path,
                           entry->d_name);
        if (written < 0 || (size_t)written >= sizeof(child)
            || !mc_cache_measure_tree(child, bytes)) {
            closedir(dir);
            return 0;
        }
    }
    closedir(dir);
    return 1;
}


static int mc_cache_inventory_add(mc_cache_inventory_t *inventory,
                                  const char *path,
                                  uint64_t bytes,
                                  time_t last_used,
                                  int directory,
                                  int protected_entry)
{
    if (inventory->count == inventory->capacity) {
        size_t new_capacity = inventory->capacity
                            ? inventory->capacity * 2 : 32;
        mc_cache_entry_t *resized = realloc(
            inventory->entries, new_capacity * sizeof(*resized));
        if (!resized) {
            return 0;
        }
        inventory->entries = resized;
        inventory->capacity = new_capacity;
    }

    mc_cache_entry_t *entry = &inventory->entries[inventory->count];
    memset(entry, 0, sizeof(*entry));
    entry->path = strdup(path);
    if (!entry->path) {
        return 0;
    }
    entry->bytes = bytes;
    entry->last_used = last_used;
    entry->directory = directory;
    entry->protected_entry = protected_entry;
    inventory->count++;
    inventory->total_bytes += bytes;
    return 1;
}


static int mc_cache_collect(const char *path,
                            int root,
                            mc_cache_inventory_t *inventory)
{
    struct stat st;
    DIR *dir;
    struct dirent *entry;
    int has_last_used = 0;
    int has_live_marker = 0;
    time_t last_used = 0;
    char child[PATH_MAX];

    if (lstat(path, &st) != 0) {
        return errno == ENOENT;
    }
    if (!S_ISDIR(st.st_mode)) {
        uint64_t bytes = st.st_size > 0 ? (uint64_t)st.st_size : 0;
        return mc_cache_inventory_add(inventory, path, bytes, st.st_mtime,
                                      0, 0);
    }

    if (!mc_cache_directory_metadata(path, &has_last_used, &last_used,
                                     &has_live_marker)) {
        return 0;
    }
    if (!root && (has_last_used || has_live_marker
                  || strcmp(path, inventory->current_leaf) == 0)) {
        uint64_t bytes = 0;
        int protected_entry = has_live_marker;

        if (!mc_cache_measure_tree(path, &bytes)) {
            return 0;
        }
        return mc_cache_inventory_add(inventory, path, bytes,
                                      has_last_used ? last_used : st.st_mtime,
                                      1, protected_entry);
    }

    dir = opendir(path);
    if (!dir) {
        return 0;
    }
    while ((entry = readdir(dir)) != NULL) {
        int written;

        if (strcmp(entry->d_name, ".") == 0
            || strcmp(entry->d_name, "..") == 0
            || mc_cache_control_file(entry->d_name)) {
            continue;
        }
        written = snprintf(child, sizeof(child), "%s/%s", path,
                           entry->d_name);
        if (written < 0 || (size_t)written >= sizeof(child)
            || !mc_cache_collect(child, 0, inventory)) {
            closedir(dir);
            return 0;
        }
    }
    closedir(dir);
    return 1;
}


static int mc_cache_remove_tree(const char *path)
{
    struct stat st;
    DIR *dir;
    struct dirent *entry;
    char child[PATH_MAX];
    int ok = 1;

    if (lstat(path, &st) != 0) {
        return errno == ENOENT;
    }
    if (!S_ISDIR(st.st_mode)) {
        return unlink(path) == 0 || errno == ENOENT;
    }

    dir = opendir(path);
    if (!dir) {
        return 0;
    }
    while ((entry = readdir(dir)) != NULL) {
        int written;

        if (strcmp(entry->d_name, ".") == 0
            || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        written = snprintf(child, sizeof(child), "%s/%s", path,
                           entry->d_name);
        if (written < 0 || (size_t)written >= sizeof(child)
            || !mc_cache_remove_tree(child)) {
            ok = 0;
        }
    }
    closedir(dir);
    if (ok && rmdir(path) != 0 && errno != ENOENT) {
        ok = 0;
    }
    return ok;
}


static void mc_cache_remove_empty_directories(const char *path,
                                               const char *root,
                                               const char *current_leaf)
{
    DIR *dir = opendir(path);
    struct dirent *entry;
    char child[PATH_MAX];

    if (!dir) {
        return;
    }
    while ((entry = readdir(dir)) != NULL) {
        struct stat st;
        int written;

        if (strcmp(entry->d_name, ".") == 0
            || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        written = snprintf(child, sizeof(child), "%s/%s", path,
                           entry->d_name);
        if (written >= 0 && (size_t)written < sizeof(child)
            && lstat(child, &st) == 0 && S_ISDIR(st.st_mode)) {
            mc_cache_remove_empty_directories(child, root, current_leaf);
        }
    }
    closedir(dir);
    if (strcmp(path, root) != 0 && strcmp(path, current_leaf) != 0) {
        rmdir(path);
    }
}


static int mc_cache_entry_compare(const void *left, const void *right)
{
    const mc_cache_entry_t *a = left;
    const mc_cache_entry_t *b = right;

    if (a->last_used < b->last_used) {
        return -1;
    }
    if (a->last_used > b->last_used) {
        return 1;
    }
    return strcmp(a->path, b->path);
}


static void mc_cache_inventory_free(mc_cache_inventory_t *inventory)
{
    for (size_t index = 0; index < inventory->count; index++) {
        free(inventory->entries[index].path);
    }
    free(inventory->entries);
    memset(inventory, 0, sizeof(*inventory));
}


static int mc_cache_prune_locked(const mc_cache_guard_t *guard,
                                 int respect_grace)
{
    mc_cache_inventory_t inventory;
    uint64_t max_mib;
    uint64_t max_age_days;
    uint64_t max_bytes;
    uint64_t removed_bytes = 0;
    size_t removed_entries = 0;
    time_t now = time(NULL);

    memset(&inventory, 0, sizeof(inventory));
    inventory.current_leaf = guard->leaf;
    if (!mc_cache_collect(guard->root, 1, &inventory)) {
        mc_cache_inventory_free(&inventory);
        return 0;
    }

    max_mib = mc_cache_policy_value(guard->max_mib_environment,
                                    guard->default_max_mib,
                                    MC_CACHE_MIN_MAX_MIB,
                                    MC_CACHE_MAX_MAX_MIB);
    max_age_days = mc_cache_policy_value(guard->max_age_environment,
                                         guard->default_max_age_days,
                                         1, 3650);
    max_bytes = max_mib * 1024ULL * 1024ULL;
    qsort(inventory.entries, inventory.count, sizeof(*inventory.entries),
          mc_cache_entry_compare);

    for (size_t index = 0; index < inventory.count; index++) {
        mc_cache_entry_t *entry = &inventory.entries[index];
        double age = difftime(now, entry->last_used);
        double max_age = (double)max_age_days * 24.0 * 60.0 * 60.0;

        if (!entry->protected_entry && age > max_age
            && mc_cache_remove_tree(entry->path)) {
            inventory.total_bytes -= entry->bytes;
            removed_bytes += entry->bytes;
            removed_entries++;
            entry->bytes = 0;
        }
    }

    for (size_t index = 0;
         index < inventory.count && inventory.total_bytes > max_bytes;
         index++) {
        mc_cache_entry_t *entry = &inventory.entries[index];
        double age = difftime(now, entry->last_used);

        if (entry->protected_entry || entry->bytes == 0
            || (respect_grace && age < MC_CACHE_MIN_GRACE_SECONDS)) {
            continue;
        }
        if (mc_cache_remove_tree(entry->path)) {
            inventory.total_bytes -= entry->bytes;
            removed_bytes += entry->bytes;
            removed_entries++;
            entry->bytes = 0;
        }
    }

    mc_cache_remove_empty_directories(guard->root, guard->root, guard->leaf);
    if (removed_entries > 0) {
        lock_fprintf(stdout,
                "MoDiCo cache pruning removed %zu inactive entr%s "
                "(%.1f MiB); %.1f MiB remain.\n",
                removed_entries, removed_entries == 1 ? "y" : "ies",
                (double)removed_bytes / 1048576.0,
                (double)inventory.total_bytes / 1048576.0);
    }
    if (inventory.total_bytes > max_bytes) {
        lock_fprintf(stdout,
                "MoDiCo cache temporarily exceeds its %llu MiB limit "
                "because all remaining entries are active or newly created.\n",
                (unsigned long long)max_mib);
    }
    mc_cache_inventory_free(&inventory);
    return 1;
}


static int mc_cache_touch(const char *path)
{
    int flags = O_WRONLY | O_CREAT;
#if defined(O_NOFOLLOW)
    flags |= O_NOFOLLOW;
#endif
    int fd = open(path, flags, 0600);
    int ok;

    if (fd < 0) {
        return 0;
    }
    ok = futimens(fd, NULL) == 0;
    if (close(fd) != 0) {
        ok = 0;
    }
    return ok;
}


static void mc_cache_remove_unused_leaf_locked(mc_cache_guard_t *guard)
{
    char last_used_path[PATH_MAX];
    int has_last_used = 0;
    int has_live_marker = 0;
    time_t last_used = 0;
    int written;

    if (!guard || mc_directory_has_entries(guard->leaf)
        || !mc_cache_directory_metadata(guard->leaf, &has_last_used,
                                        &last_used, &has_live_marker)
        || has_live_marker) {
        return;
    }
    written = snprintf(last_used_path, sizeof(last_used_path),
                       "%s/.last_used", guard->leaf);
    if (written >= 0 && (size_t)written < sizeof(last_used_path)) {
        unlink(last_used_path);
    }
    if (rmdir(guard->leaf) == 0 || errno == ENOENT) {
        mc_cache_remove_empty_directories(guard->root, guard->root,
                                          guard->leaf);
    }
}


static int mc_cache_guard_begin(mc_cache_guard_t *guard,
                                const char *root,
                                const char *leaf,
                                const char *max_mib_environment,
                                const char *max_age_environment)
{
    char root_real[PATH_MAX];
    char leaf_real[PATH_MAX];
    char lock_path[PATH_MAX];
    char last_used_path[PATH_MAX];
    struct timespec now;
    int lock_fd = -1;
    int marker_fd = -1;
    int written;
    int ok = 0;

    if (!guard || !root || !leaf || !max_mib_environment
        || !max_age_environment || !realpath(root, root_real)
        || !realpath(leaf, leaf_real)
        || !mc_cache_path_is_within(root_real, leaf_real)) {
        return 0;
    }
    memset(guard, 0, sizeof(*guard));
    guard->marker_fd = -1;
    snprintf(guard->root, sizeof(guard->root), "%s", root_real);
    snprintf(guard->leaf, sizeof(guard->leaf), "%s", leaf_real);
    snprintf(guard->max_mib_environment,
             sizeof(guard->max_mib_environment), "%s", max_mib_environment);
    snprintf(guard->max_age_environment,
             sizeof(guard->max_age_environment), "%s", max_age_environment);
    guard->default_max_mib = MC_CACHE_DEFAULT_MAX_MIB;
    guard->default_max_age_days = MC_CACHE_DEFAULT_MAX_AGE_DAYS;

    written = snprintf(lock_path, sizeof(lock_path),
                       "%s/.scalpel3-cache.lock", guard->root);
    if (written < 0 || (size_t)written >= sizeof(lock_path)) {
        goto done;
    }
    lock_fd = open(lock_path, O_RDWR | O_CREAT, 0600);
    if (lock_fd < 0 || flock(lock_fd, LOCK_EX) != 0) {
        goto done;
    }

    clock_gettime(CLOCK_MONOTONIC, &now);
    written = snprintf(guard->marker, sizeof(guard->marker),
                       "%s/.active.%ld.%llx", guard->leaf, (long)getpid(),
                       (unsigned long long)now.tv_nsec);
    if (written < 0 || (size_t)written >= sizeof(guard->marker)) {
        goto done;
    }
    marker_fd = open(guard->marker, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (marker_fd < 0 || flock(marker_fd, LOCK_EX | LOCK_NB) != 0) {
        goto done;
    }
    if (dprintf(marker_fd, "locked-v1 %ld\n", (long)getpid()) < 0) {
        goto done;
    }
    guard->marker_fd = marker_fd;
    marker_fd = -1;

    written = snprintf(last_used_path, sizeof(last_used_path),
                       "%s/.last_used", guard->leaf);
    if (written < 0 || (size_t)written >= sizeof(last_used_path)
        || !mc_cache_touch(last_used_path)
        || !mc_cache_prune_locked(guard, 1)) {
        goto done;
    }
    guard->active = 1;
    ok = 1;

done:
    if (!ok && guard->marker[0]) {
        unlink(guard->marker);
        guard->marker[0] = '\0';
    }
    if (!ok && guard->marker_fd >= 0) {
        flock(guard->marker_fd, LOCK_UN);
        close(guard->marker_fd);
        guard->marker_fd = -1;
    }
    if (marker_fd >= 0) {
        flock(marker_fd, LOCK_UN);
        close(marker_fd);
    }
    if (lock_fd >= 0) {
        flock(lock_fd, LOCK_UN);
        close(lock_fd);
    }
    return ok;
}


static void mc_cache_guard_finish(mc_cache_guard_t *guard)
{
    char lock_path[PATH_MAX];
    char last_used_path[PATH_MAX];
    int lock_fd = -1;
    int written;

    if (!guard || !guard->active) {
        return;
    }
    written = snprintf(lock_path, sizeof(lock_path),
                       "%s/.scalpel3-cache.lock", guard->root);
    if (written >= 0 && (size_t)written < sizeof(lock_path)) {
        lock_fd = open(lock_path, O_RDWR | O_CREAT, 0600);
    }
    if (lock_fd >= 0 && flock(lock_fd, LOCK_EX) == 0) {
        written = snprintf(last_used_path, sizeof(last_used_path),
                           "%s/.last_used", guard->leaf);
        if (written >= 0 && (size_t)written < sizeof(last_used_path)) {
            mc_cache_touch(last_used_path);
        }
        unlink(guard->marker);
        guard->marker[0] = '\0';
        if (guard->marker_fd >= 0) {
            flock(guard->marker_fd, LOCK_UN);
            close(guard->marker_fd);
            guard->marker_fd = -1;
        }
        mc_cache_remove_unused_leaf_locked(guard);
        mc_cache_prune_locked(guard, 0);
        flock(lock_fd, LOCK_UN);
    }
    else {
        unlink(guard->marker);
        guard->marker[0] = '\0';
    }
    if (guard->marker_fd >= 0) {
        flock(guard->marker_fd, LOCK_UN);
        close(guard->marker_fd);
        guard->marker_fd = -1;
    }
    if (lock_fd >= 0) {
        close(lock_fd);
    }
    guard->active = 0;
}


#if defined(__APPLE__)
static int mc_prepare_coreml_cache(mc_session_t *s, const char *model_path,
                                   const char *compute_units,
                                   const char *specialization,
                                   int low_precision)
{
    const char *configured = getenv("SCALPEL3_MODICO_COREML_CACHE_DIR");
    const char *home = getenv("HOME");
    char root[PATH_MAX];
    char model_hash[65];
    char options_hash[65];
    char options[512];
    int length;

    if (configured) {
        if (!*configured
            || strcasecmp(configured, "0") == 0
            || strcasecmp(configured, "false") == 0
            || strcasecmp(configured, "off") == 0
            || strcasecmp(configured, "none") == 0) {
            return 0;
        }
        length = snprintf(root, sizeof(root), "%s", configured);
    }
    else if (home && *home) {
        length = snprintf(root, sizeof(root),
                          "%s/Library/Caches/scalpel3/modico-coreml", home);
    }
    else {
        return 0;
    }
    if (length < 0 || (size_t)length >= sizeof(root)
        || !mc_sha256_file_hex(model_path, model_hash)) {
        lock_fprintf(stderr, "MoDiCo: CoreML cache disabled: could not hash %s.\n",
                model_path ? model_path : "(null)");
        return 0;
    }

    length = snprintf(options, sizeof(options),
                      "ort=%s;format=MLProgram;static=1;batch=%d;units=%s;"
                      "specialization=%s;low_precision=%d",
                      OrtGetApiBase()->GetVersionString(),
                      s->static_batch_size, compute_units, specialization,
                      low_precision);
    if (length < 0 || (size_t)length >= sizeof(options)
        || !mc_sha256_text_hex(options, options_hash)) {
        return 0;
    }

    length = snprintf(s->coreml_cache_dir, sizeof(s->coreml_cache_dir),
                      "%s/%s/%s", root, model_hash, options_hash);
    if (length < 0 || (size_t)length >= sizeof(s->coreml_cache_dir)
        || !mc_mkdir_p(s->coreml_cache_dir)) {
        lock_fprintf(stderr, "MoDiCo: CoreML cache disabled: cannot create %s.\n",
                length >= 0 && (size_t)length < sizeof(s->coreml_cache_dir)
                    ? s->coreml_cache_dir : root);
        s->coreml_cache_dir[0] = '\0';
        return 0;
    }

    int cache_warm = mc_directory_has_entries(s->coreml_cache_dir);
    if (!mc_cache_guard_begin(&s->coreml_cache_guard, root,
                              s->coreml_cache_dir,
                              "SCALPEL3_MODICO_COREML_CACHE_MAX_MIB",
                              "SCALPEL3_MODICO_COREML_CACHE_MAX_AGE_DAYS")) {
        lock_fprintf(stderr,
                "MoDiCo: CoreML cache disabled: lifecycle control failed.\n");
        s->coreml_cache_dir[0] = '\0';
        return 0;
    }
    lock_fprintf(stdout,
            "MoDiCo CoreML model cache:\n"
            "  State:                    %s\n"
            "  Model SHA256:             %s\n"
            "  Directory:                %s\n",
            cache_warm ? "warm" : "cold", model_hash, s->coreml_cache_dir);
    return 1;
}
#endif


#if defined(__linux__)
static int mc_sanitize_path_component(const char *source,
                                      char *destination,
                                      size_t destination_size)
{
    size_t used = 0;

    if (!source || !destination || destination_size == 0) {
        return 0;
    }
    for (const unsigned char *p = (const unsigned char *)source;
         *p && used + 1 < destination_size; p++) {
        destination[used++] = isalnum(*p) || *p == '.' || *p == '-'
                            ? (char)*p : '_';
    }
    destination[used] = '\0';
    return used > 0;
}
#endif


static int mc_prepare_tensorrt_cache(mc_session_t *s, int device_id)
{
#if defined(__linux__)
    const char *configured = getenv("SCALPEL3_MODICO_TENSORRT_CACHE");
    const char *xdg_cache = getenv("XDG_CACHE_HOME");
    const char *home = getenv("HOME");
    char root[PATH_MAX];
    char ort_version[64];
    char tensorrt_version[64];
    char gpu_identity[128];
    char inference_profile[96];
    char model_hash[65];
    gpu_mem_info_t gpu;
    int written;
    int configured_batch = 0;
    int configured_max_batch = MC_TENSORRT_DEFAULT_MAX_BATCH;

    if (!s || mc_value_disabled(configured)) {
        return 0;
    }
    if (configured && *configured) {
        written = snprintf(root, sizeof(root), "%s", configured);
    }
    else if (xdg_cache && *xdg_cache) {
        written = snprintf(root, sizeof(root),
                           "%s/scalpel3/modico-tensorrt", xdg_cache);
    }
    else if (home && *home) {
        written = snprintf(root, sizeof(root),
                           "%s/.cache/scalpel3/modico-tensorrt", home);
    }
    else {
        return 0;
    }
    if (written < 0 || (size_t)written >= sizeof(root)
        || !mc_sanitize_path_component(OrtGetApiBase()->GetVersionString(),
                                       ort_version, sizeof(ort_version))
        || !mc_sanitize_path_component(onnx_tensorrt_runtime_identity(),
                                       tensorrt_version,
                                       sizeof(tensorrt_version))
        || !mc_sha256_file_hex(s->model_path, model_hash)) {
        return 0;
    }

    memset(&gpu, 0, sizeof(gpu));
    if (gpu_mem_query(onnx_cuda_physical_device(device_id), &gpu)
        && gpu.uuid[0]) {
        if (!mc_sanitize_path_component(gpu.uuid, gpu_identity,
                                        sizeof(gpu_identity))) {
            return 0;
        }
    }
    else {
        snprintf(gpu_identity, sizeof(gpu_identity), "device-%d", device_id);
    }

    const char *max_batch_environment = getenv("SCALPEL3_MODICO_MAX_BATCH");
    const char *batch_environment = getenv("SCALPEL3_MODICO_BATCH");
    if (max_batch_environment && *max_batch_environment) {
        char *end = NULL;
        long parsed;

        errno = 0;
        parsed = strtol(max_batch_environment, &end, 10);
        if (errno == 0 && end != max_batch_environment && *end == '\0'
            && parsed > 0) {
            configured_max_batch = parsed > MC_TENSORRT_EMERGENCY_MAX_BATCH
                                 ? MC_TENSORRT_EMERGENCY_MAX_BATCH
                                 : (int)parsed;
        }
    }
    if (batch_environment && *batch_environment) {
        char *end = NULL;
        long parsed;

        errno = 0;
        parsed = strtol(batch_environment, &end, 10);
        if (errno == 0 && end != batch_environment && *end == '\0'
            && parsed > 0) {
            configured_batch = parsed > configured_max_batch
                             ? configured_max_batch : (int)parsed;
        }
    }
    written = snprintf(inference_profile, sizeof(inference_profile),
                       "profile-%d-batch-%s%d-max-%d",
                       MC_TENSORRT_CACHE_PROFILE_VERSION,
                       configured_batch > 0 ? "" : "auto-",
                       configured_batch, configured_max_batch);
    if (written < 0 || (size_t)written >= sizeof(inference_profile)) {
        return 0;
    }

    written = snprintf(s->tensorrt_cache_dir,
                       sizeof(s->tensorrt_cache_dir),
                       "%s/ort-%s/%s/%s/%s/model-%s", root, ort_version,
                       tensorrt_version, gpu_identity, inference_profile,
                       model_hash);
    if (written < 0
        || (size_t)written >= sizeof(s->tensorrt_cache_dir)
        || !mc_mkdir_p(s->tensorrt_cache_dir)) {
        s->tensorrt_cache_dir[0] = '\0';
        return 0;
    }

    s->tensorrt_cache_warm =
        mc_directory_has_entries(s->tensorrt_cache_dir);
    if (!mc_cache_guard_begin(&s->tensorrt_cache_guard, root,
                              s->tensorrt_cache_dir,
                              "SCALPEL3_MODICO_TENSORRT_CACHE_MAX_MIB",
                              "SCALPEL3_MODICO_TENSORRT_CACHE_MAX_AGE_DAYS")) {
        lock_fprintf(stderr,
                "MoDiCo: TensorRT cache disabled: lifecycle control failed.\n");
        s->tensorrt_cache_dir[0] = '\0';
        return 0;
    }

    lock_fprintf(stdout,
            "MoDiCo TensorRT cache:\n"
            "  State:                    %s\n"
            "  Directory:                %s\n",
            s->tensorrt_cache_warm ? "warm" : "cold", s->tensorrt_cache_dir);
    return 1;
#else
    (void)s;
    (void)device_id;
    return 0;
#endif
}


static int mc_init_api(void)
{
    if (g_ort == NULL) {
        g_ort = OrtGetApiBase()->GetApi(ORT_API_VERSION);
        if (g_ort == NULL) {
            lock_fprintf(stderr, "Failed to get ORT API (ORT_API_VERSION=%d). "
                            "Header/library version mismatch?\n", ORT_API_VERSION);
            return 0;
        }
    }
    return 1;
}

static int mc_cuda_requested(const char *accelerator)
{
    return accelerator && strcasecmp(accelerator, "cuda") == 0;
}

static int mc_coreml_requested(const char *accelerator)
{
#if defined(__APPLE__)
    return accelerator && strcasecmp(accelerator, "coreml") == 0;
#else
    (void)accelerator;
    return 0;
#endif
}

static int mc_coreml_static_batch(void)
{
    int max_batch = 8192;
    /* Batch 32 stays close to batch 64 throughput while using about half the
     * resident memory, and it outperforms larger tested batches. */
    int batch = 32;
    const char *e = getenv("SCALPEL3_MODICO_MAX_BATCH");

    if (e && *e) {
        int forced_max = atoi(e);
        if (forced_max > 0) {
            max_batch = forced_max;
        }
    }
    if (max_batch < 1) {
        max_batch = 1;
    }
    if (max_batch > 8192) {
        max_batch = 8192;
    }

    e = getenv("SCALPEL3_MODICO_BATCH");
    if (e && *e) {
        int forced = atoi(e);
        if (forced > 0) {
            batch = forced;
        }
    }
    if (batch < 1) {
        batch = 1;
    }
    if (batch > max_batch) {
        batch = max_batch;
    }

    return batch;
}


static int mc_tensorrt_requested(mc_session_t *s, int device_id)
{
    const char *configured = getenv("SCALPEL3_MODICO_TENSORRT");
    const char *threshold_environment =
        getenv("SCALPEL3_MODICO_TENSORRT_COLD_MIN_BLOCKS");
    const char *basename;
    unsigned int block_size = 0;
    int consumed = 0;
    uint64_t cold_minimum = UINT64_MAX;
    char reason[320] = {0};

    if (!s || mc_value_disabled(configured)) {
        return 0;
    }
    if (!configured
        && (!s->model_path[0]
            || strstr(s->model_path, "_coreml_graphcut.onnx") == NULL)) {
        return 0;
    }

    basename = strrchr(s->model_path, '/');
    basename = basename ? basename + 1 : s->model_path;
    if (sscanf(basename, "modico_%u_coreml_graphcut.onnx%n",
               &block_size, &consumed) == 1
        && basename[consumed] == '\0') {
        if (!configured && block_size < 4096) {
            return 0;
        }
        switch (block_size) {
        case 4096:
            cold_minimum = 65536;
            break;
        case 8192:
            cold_minimum = 32768;
            break;
        case 16384:
            cold_minimum = 24576;
            break;
        default:
            cold_minimum = 65536;
            break;
        }
    }
    else if (!configured) {
        return 0;
    }

    if (!onnx_tensorrt_available(reason, sizeof(reason))) {
        lock_fprintf(stdout, "MoDiCo TensorRT unavailable; using CUDA: %s\n",
                reason[0] ? reason : "no compatible runtime");
        return 0;
    }
    if (!mc_prepare_tensorrt_cache(s, device_id)) {
        lock_fprintf(stdout,
                "MoDiCo TensorRT cache is unavailable; using CUDA.\n");
        return 0;
    }
    if (configured || s->tensorrt_cache_warm
        || s->expected_blocks == UINT64_MAX) {
        return 1;
    }

    if (threshold_environment && *threshold_environment) {
        char *end = NULL;
        unsigned long long parsed;

        errno = 0;
        parsed = strtoull(threshold_environment, &end, 10);
        if (errno == 0 && end != threshold_environment && *end == '\0'
            && parsed > 0) {
            cold_minimum = (uint64_t)parsed;
        }
        else {
            lock_fprintf(stderr,
                    "WARNING: MoDiCo is ignoring invalid "
                    "SCALPEL3_MODICO_TENSORRT_COLD_MIN_BLOCKS=%s.\n",
                    threshold_environment);
        }
    }
    if (s->expected_blocks >= cold_minimum) {
        return 1;
    }

    lock_fprintf(stdout,
            "MoDiCo is using native CUDA for %llu expected blocks; the "
            "TensorRT cache is cold and its build threshold is %llu blocks.\n",
            (unsigned long long)s->expected_blocks,
            (unsigned long long)cold_minimum);
    mc_cache_guard_finish(&s->tensorrt_cache_guard);
    s->tensorrt_cache_dir[0] = '\0';
    return 0;
}

static int mc_append_cuda_provider(mc_session_t *s, int device_id)
{
    OrtCUDAProviderOptions cuda_opts;
    OnnxCudaProviderPolicy policy;

    if (!s || !s->opts
        || !onnx_cuda_provider_options(device_id, &cuda_opts, &policy)) {
        lock_fprintf(stderr,
                "MoDiCo: CUDA memory policy could not query device %d.\n",
                device_id);
        return 0;
    }

    lock_fprintf(stdout,
            "MoDiCo CUDA memory policy:\n"
            "  Device:                   %d (physical %d)\n"
            "  Available memory:         %.1f MiB\n"
            "  Arena limit:              %.1f MiB (%.0f%%)\n",
            device_id, policy.physical_device_id,
            policy.free_bytes / 1048576.0,
            policy.arena_limit / 1048576.0,
            policy.memory_fraction * 100.0);

    if (s->cuda_user_stream) {
        cuda_opts.has_user_compute_stream = 1;
        cuda_opts.user_compute_stream = s->cuda_user_stream;
    }

    OrtStatus *st =
        g_ort->SessionOptionsAppendExecutionProvider_CUDA(s->opts, &cuda_opts);
    if (st) {
        mc_log_ort_status(st, "CUDA execution provider setup");
        return 0;
    }
    return 1;
}


static int mc_append_tensorrt_provider(mc_session_t *s, int device_id)
{
    OrtTensorRTProviderOptionsV2 *trt_opts = NULL;
    char device[32];
    const char *keys[10];
    const char *values[10];
    size_t count = 0;

    if (!s || !s->opts) {
        return 0;
    }
    if (!s->tensorrt_cache_dir[0]) {
        return 0;
    }

    snprintf(device, sizeof(device), "%d", device_id);
    keys[count] = "device_id";
    values[count++] = device;
    keys[count] = "trt_fp16_enable";
    values[count++] = "0";
    keys[count] = "trt_bf16_enable";
    values[count++] = "0";
    keys[count] = "trt_engine_cache_enable";
    values[count++] = "1";
    keys[count] = "trt_engine_cache_path";
    values[count++] = s->tensorrt_cache_dir;
    keys[count] = "trt_engine_cache_prefix";
    values[count++] = "scalpel3_modico_fp32";
    keys[count] = "trt_timing_cache_enable";
    values[count++] = "1";
    keys[count] = "trt_timing_cache_path";
    values[count++] = s->tensorrt_cache_dir;

    OrtStatus *status = g_ort->CreateTensorRTProviderOptions(&trt_opts);
    if (!status) {
        status = g_ort->UpdateTensorRTProviderOptions(trt_opts, keys, values,
                                                      count);
    }
    if (!status && s->cuda_user_stream) {
        status = g_ort->UpdateTensorRTProviderOptionsWithValue(
            trt_opts, "user_compute_stream", s->cuda_user_stream);
    }
    if (!status) {
        status = g_ort->SessionOptionsAppendExecutionProvider_TensorRT_V2(
            s->opts, trt_opts);
    }
    if (trt_opts) {
        g_ort->ReleaseTensorRTProviderOptions(trt_opts);
    }
    if (status) {
        mc_log_ort_status(status, "TensorRT execution provider setup");
        lock_fprintf(stdout, "MoDiCo TensorRT setup failed; using CUDA.\n");
        return 0;
    }

    lock_fprintf(stdout, "MoDiCo TensorRT FP32 enabled on CUDA device %d.\n",
            device_id);
    return 1;
}

static int mc_append_coreml_provider(mc_session_t *s, const char *model_path)
{
#if defined(__APPLE__)
    /* MLProgram is essential for the wider operator coverage needed by
     * MoDiCo. Unsupported preprocessing operators still use CPU fallback. */
    const char *keys[8] = {"ModelFormat", "RequireStaticInputShapes"};
    const char *values[8] = {"MLProgram", "1"};
    const char *compute_units = "ALL";
    const char *specialization = "Default";
    const char *compute_env =
        getenv("SCALPEL3_MODICO_COREML_COMPUTE_UNITS");
    const char *specialization_env =
        getenv("SCALPEL3_MODICO_COREML_SPECIALIZATION");
    int low_precision =
        mc_env_enabled("SCALPEL3_MODICO_COREML_LOW_PRECISION");
    int profile_compute_plan =
        mc_env_enabled("SCALPEL3_MODICO_COREML_PROFILE_COMPUTE_PLAN");
    size_t count = 2;

    if (compute_env && *compute_env) {
        if (strcasecmp(compute_env, "ALL") == 0) {
            compute_units = "ALL";
        }
        else if (strcasecmp(compute_env, "CPUOnly") == 0) {
            compute_units = "CPUOnly";
        }
        else if (strcasecmp(compute_env, "CPUAndGPU") == 0) {
            compute_units = "CPUAndGPU";
        }
        else if (strcasecmp(compute_env, "CPUAndNeuralEngine") == 0) {
            compute_units = "CPUAndNeuralEngine";
        }
        else {
            lock_fprintf(stderr,
                    "WARNING: MoDiCo is ignoring invalid CoreML compute units: %s\n",
                    compute_env);
        }
        keys[count] = "MLComputeUnits";
        values[count++] = compute_units;
    }

    if (specialization_env && *specialization_env) {
        if (strcasecmp(specialization_env, "FastPrediction") == 0) {
            specialization = "FastPrediction";
        }
        else if (strcasecmp(specialization_env, "Default") != 0) {
            lock_fprintf(stderr,
                    "WARNING: MoDiCo is ignoring invalid CoreML specialization: %s\n",
                    specialization_env);
        }
        keys[count] = "SpecializationStrategy";
        values[count++] = specialization;
    }
    if (low_precision) {
        keys[count] = "AllowLowPrecisionAccumulationOnGPU";
        values[count++] = "1";
    }
    if (profile_compute_plan) {
        keys[count] = "ProfileComputePlan";
        values[count++] = "1";
    }
    if (mc_prepare_coreml_cache(s, model_path, compute_units,
                                specialization, low_precision)) {
        keys[count] = "ModelCacheDirectory";
        values[count++] = s->coreml_cache_dir;
    }

    lock_fprintf(stdout,
            "MoDiCo CoreML options:\n"
            "  Compute units:            %s\n"
            "  Specialization:           %s\n"
            "  Low precision:            %s\n"
            "  Compute plan profiling:   %s\n",
            compute_units, specialization, low_precision ? "yes" : "no",
            profile_compute_plan ? "yes" : "no");
    OrtStatus *st =
        g_ort->SessionOptionsAppendExecutionProvider(s->opts, "CoreML",
                                                     keys, values, count);
    if (st) {
        mc_log_ort_status(st, "CoreML execution provider setup");
        return 0;
    }
    return 1;
#else
    (void)s;
    (void)model_path;
    return 0;
#endif
}


static int mc_prepare_session_options(mc_session_t *s, int intra_op_threads,
                                      OrtLoggingLevel log_level)
{
    if (!s) {
        return 0;
    }
    if (s->opts) {
        g_ort->ReleaseSessionOptions(s->opts);
        s->opts = NULL;
    }
    if (!mc_ort_succeeded(g_ort->CreateSessionOptions(&s->opts),
                          "session-options creation")
        || !mc_ort_succeeded(g_ort->SetSessionLogSeverityLevel(s->opts,
                                                               log_level),
                             "session log configuration")) {
        return 0;
    }
    if (intra_op_threads >= 0
        && !mc_ort_succeeded(g_ort->SetIntraOpNumThreads(s->opts,
                                                         intra_op_threads),
                             "intra-op thread configuration")) {
        return 0;
    }
    if (!mc_ort_succeeded(g_ort->SetSessionGraphOptimizationLevel(
                              s->opts, ORT_ENABLE_ALL),
                          "graph optimization configuration")) {
        return 0;
    }

#if !defined(_WIN32)
    const char *profile_prefix = getenv("SCALPEL3_MODICO_ORT_PROFILE");
    if (profile_prefix && *profile_prefix) {
        OrtStatus *profile_status =
            g_ort->EnableProfiling(s->opts, profile_prefix);
        if (profile_status) {
            mc_log_ort_status(profile_status, "profiling configuration");
        }
        else {
            s->profiling_enabled = 1;
        }
    }
#endif
    return 1;
}

mc_session_t *mc_create_session(const char *model_path, int intra_op_threads)
{
    return mc_create_session_with_accelerator(model_path, intra_op_threads, "cpu");
}


mc_session_t *mc_create_session_with_accelerator(const char *model_path,
                                                 int intra_op_threads,
                                                 const char *accelerator)
{
    /* Convenience wrapper: device 0. Callers that target a specific GPU use
     * the _device variant. */
    return mc_create_session_with_accelerator_device(model_path,
                                                     intra_op_threads,
                                                     accelerator,
                                                     0);
}


mc_session_t *mc_create_session_with_accelerator_device(
                                                 const char *model_path,
                                                 int intra_op_threads,
                                                 const char *accelerator,
                                                 int device_id)
{
    return mc_create_session_with_accelerator_device_for_workload(
        model_path, intra_op_threads, accelerator, device_id, UINT64_MAX);
}


mc_session_t *mc_create_session_with_accelerator_device_for_workload(
                                                 const char *model_path,
                                                 int intra_op_threads,
                                                 const char *accelerator,
                                                 int device_id,
                                                 uint64_t expected_blocks)
{
    OrtTypeInfo *type_info = NULL;
    OrtAllocator *alloc = NULL;
    size_t ndims = 0;
    int64_t dims[8] = {0};

    if (!mc_init_api()) {
        return NULL;
    }

    mc_session_t *s = calloc(1, sizeof(*s));
    if (!s) {
        perror("calloc");
        return NULL;
    }
    s->device_id = -1;
    s->expected_blocks = expected_blocks;
    s->timing_enabled = mc_env_enabled("SCALPEL3_MODICO_TIMING");
    strncpy(s->execution_provider, "cpu", sizeof(s->execution_provider) - 1);
    if (model_path) {
        strncpy(s->model_path, model_path, sizeof(s->model_path) - 1);
        s->model_path[sizeof(s->model_path) - 1] = '\0';
    }

    OrtLoggingLevel log_level =
        mc_env_enabled("SCALPEL3_MODICO_COREML_PROFILE_COMPUTE_PLAN")
            ? ORT_LOGGING_LEVEL_VERBOSE : ORT_LOGGING_LEVEL_ERROR;
    if (!mc_ort_succeeded(g_ort->CreateEnv(log_level, "modico", &s->env),
                          "environment creation")) {
        goto fail;
    }
    if (!mc_prepare_session_options(s, intra_op_threads, log_level)) {
        goto fail;
    }
    if (!mc_ort_succeeded(g_ort->CreateRunOptions(&s->run_options),
                          "run-options creation")) {
        goto fail;
    }

    if (mc_cuda_requested(accelerator)) {
        s->device_id = device_id >= 0 ? device_id : 0;
        if (strstr(s->model_path, "_coreml_graphcut.onnx") != NULL
            && !mc_value_disabled(
                   getenv("SCALPEL3_MODICO_GPU_PREPROCESS"))) {
            char reason[320] = {0};
            s->cuda_user_stream = mc_cuda_stream_create(
                s->device_id, reason, sizeof(reason));
            if (!s->cuda_user_stream) {
                lock_fprintf(stdout,
                        "MoDiCo shared CUDA stream unavailable; "
                        "host preprocessing remains available: %s\n",
                        reason[0] ? reason : "initialization failed");
            }
        }
        if (mc_tensorrt_requested(s, s->device_id)) {
            s->tensorrt_enabled =
                mc_append_tensorrt_provider(s, s->device_id);
        }
        if (!mc_append_cuda_provider(s, s->device_id)) {
            mc_destroy_session(s);
            return NULL;
        }
        strncpy(s->execution_provider, "cuda", sizeof(s->execution_provider) - 1);
        lock_fprintf(stdout, "MoDiCo requested CUDA execution provider on device %d.\n",
                s->device_id);
    }
    else if (mc_coreml_requested(accelerator)) {
        s->static_batch_size = mc_coreml_static_batch();
        if (!mc_ort_succeeded(g_ort->AddFreeDimensionOverrideByName(
                                  s->opts, "batch", s->static_batch_size),
                              "CoreML static-batch configuration")) {
            goto fail;
        }
        if (!mc_append_coreml_provider(s, model_path)) {
            mc_destroy_session(s);
            return NULL;
        }
        strncpy(s->execution_provider, "coreml", sizeof(s->execution_provider) - 1);
        lock_fprintf(stdout,
                "MoDiCo requested CoreML execution provider "
                "(static batch size %d).\n",
                s->static_batch_size);
    }

    struct timespec session_start = {0, 0};
    struct timespec session_end = {0, 0};
    if (s->timing_enabled) {
        clock_gettime(CLOCK_MONOTONIC, &session_start);
    }
    OrtStatus *create_status =
        g_ort->CreateSession(s->env, model_path, s->opts, &s->session);
    if (create_status && s->tensorrt_enabled) {
        mc_log_ort_status(create_status, "TensorRT session creation");
        lock_fprintf(stdout,
                "MoDiCo TensorRT cannot compile this model; using CUDA.\n");
        s->tensorrt_enabled = 0;
        s->run_batch_size = 0;
        s->tensorrt_cache_dir[0] = '\0';
        s->profiling_enabled = 0;
        if (!mc_prepare_session_options(s, intra_op_threads, log_level)
            || !mc_append_cuda_provider(s, s->device_id)) {
            goto fail;
        }
        create_status =
            g_ort->CreateSession(s->env, model_path, s->opts, &s->session);
    }
    if (s->timing_enabled) {
        clock_gettime(CLOCK_MONOTONIC, &session_end);
        s->timing.session_create_seconds =
            mc_elapsed_seconds(&session_start, &session_end);
        lock_fprintf(stdout,
                "MoDiCo session timing: provider=%s session_create_secs=%.6f\n",
                s->execution_provider, s->timing.session_create_seconds);
    }
    if (create_status) {
        /* Provider resolution is already complete. A model that cannot be
         * created on the selected provider must not silently change devices. */
        if (mc_cuda_requested(accelerator)) {
            mc_log_ort_status(create_status, "CUDA session creation");
            mc_destroy_session(s);
            return NULL;
        }
        if (mc_coreml_requested(accelerator)) {
            mc_log_ort_status(create_status, "CoreML session creation");
            mc_destroy_session(s);
            return NULL;
        }
        mc_log_ort_status(create_status, "CPU session creation");
        goto fail;
    }
    if (!mc_ort_succeeded(g_ort->CreateCpuMemoryInfo(OrtArenaAllocator,
                                                     OrtMemTypeDefault,
                                                     &s->mem_info),
                          "CPU memory-info creation")) {
        goto fail;
    }

    if (!mc_ort_succeeded(g_ort->GetAllocatorWithDefaultOptions(&alloc),
                          "default allocator lookup")) {
        goto fail;
    }
    if (!mc_ort_succeeded(g_ort->SessionGetInputCount(s->session,
                                                       &s->input_count),
                          "input-count lookup")) {
        goto fail;
    }
    if (s->input_count != 1 && s->input_count != 3) {
        lock_fprintf(stderr, "MoDiCo: unexpected input count=%zu\n",
                s->input_count);
        goto fail;
    }
    if (!mc_ort_succeeded(g_ort->SessionGetInputName(s->session, 0, alloc,
                                                     &s->input_name),
                          "input-name lookup")) {
        goto fail;
    }
    if (s->input_count == 3) {
        if (!mc_ort_succeeded(g_ort->SessionGetInputName(
                                  s->session, 1, alloc,
                                  &s->global_histogram_input_name),
                              "global histogram input-name lookup")
            || !mc_ort_succeeded(g_ort->SessionGetInputName(
                                     s->session, 2, alloc,
                                     &s->local_histogram_input_name),
                                 "local histogram input-name lookup")) {
            goto fail;
        }
        if (strcmp(s->global_histogram_input_name,
                   "scalpel3_global_histogram_counts") != 0
            || strcmp(s->local_histogram_input_name,
                      "scalpel3_local_histogram_counts") != 0) {
            lock_fprintf(stderr,
                    "MoDiCo: unsupported three-input model: %s, %s\n",
                    s->global_histogram_input_name,
                    s->local_histogram_input_name);
            goto fail;
        }
        lock_fprintf(stdout, "MoDiCo native histogram inputs enabled.\n");
    }
    if (!mc_ort_succeeded(g_ort->SessionGetOutputName(s->session, 0, alloc,
                                                      &s->output_name),
                          "output-name lookup")) {
        goto fail;
    }

    /* Discover num_classes from the output type info. Output shape is
     * (batch, num_classes); we want the last dimension. */
    if (!mc_ort_succeeded(g_ort->SessionGetOutputTypeInfo(s->session, 0,
                                                          &type_info),
                          "output type lookup")) {
        goto fail;
    }
    const OrtTensorTypeAndShapeInfo *tensor_info;
    if (!mc_ort_succeeded(g_ort->CastTypeInfoToTensorInfo(type_info, &tensor_info),
                          "output tensor-type lookup")) {
        goto fail;
    }
    if (!mc_ort_succeeded(g_ort->GetDimensionsCount(tensor_info, &ndims),
                          "output dimension-count lookup")) {
        goto fail;
    }
    if (ndims == 0 || ndims > 8) {
        lock_fprintf(stderr, "MoDiCo: unexpected output ndims=%zu\n", ndims);
        goto fail;
    }
    if (!mc_ort_succeeded(g_ort->GetDimensions(tensor_info, dims, ndims),
                          "output dimension lookup")) {
        goto fail;
    }
    if (dims[ndims - 1] <= 0 || dims[ndims - 1] > INT_MAX) {
        lock_fprintf(stderr, "MoDiCo: invalid output class count=%lld\n",
                (long long)dims[ndims - 1]);
        goto fail;
    }
    s->num_classes = (int)dims[ndims - 1];
    g_ort->ReleaseTypeInfo(type_info);

    return s;

fail:
    if (type_info) {
        g_ort->ReleaseTypeInfo(type_info);
    }
    mc_destroy_session(s);
    return NULL;
}


void mc_destroy_session(mc_session_t *s)
{
    if (!s) {
        return;
    }
    OrtAllocator *alloc = NULL;
    OrtStatus *st = g_ort->GetAllocatorWithDefaultOptions(&alloc);
    if (st) {
        g_ort->ReleaseStatus(st);
    }
    if (alloc && s->session && s->profiling_enabled) {
        char *profile_path = NULL;
        st = g_ort->SessionEndProfiling(s->session, alloc, &profile_path);
        if (st) {
            mc_log_ort_status(st, "profiling finalization");
        }
        else if (profile_path) {
            lock_fprintf(stdout, "MoDiCo ONNX Runtime profile: %s\n",
                    profile_path);
            st = g_ort->AllocatorFree(alloc, profile_path);
            if (st) {
                g_ort->ReleaseStatus(st);
            }
        }
        s->profiling_enabled = 0;
    }
    mc_release_cuda_fastpath(s);
    mc_release_persistent_tensors(s);
    if (alloc) {
        if (s->input_name) {
            st = g_ort->AllocatorFree(alloc, s->input_name);
            if (st) {
                g_ort->ReleaseStatus(st);
            }
        }
        if (s->global_histogram_input_name) {
            st = g_ort->AllocatorFree(alloc,
                                      s->global_histogram_input_name);
            if (st) {
                g_ort->ReleaseStatus(st);
            }
        }
        if (s->local_histogram_input_name) {
            st = g_ort->AllocatorFree(alloc,
                                      s->local_histogram_input_name);
            if (st) {
                g_ort->ReleaseStatus(st);
            }
        }
        if (s->output_name) {
            st = g_ort->AllocatorFree(alloc, s->output_name);
            if (st) {
                g_ort->ReleaseStatus(st);
            }
        }
    }
    if (s->session) {
        g_ort->ReleaseSession(s->session);
    }
    if (s->run_options) {
        g_ort->ReleaseRunOptions(s->run_options);
    }
    if (s->opts) {
        g_ort->ReleaseSessionOptions(s->opts);
    }
    if (s->mem_info) {
        g_ort->ReleaseMemoryInfo(s->mem_info);
    }
    if (s->env) {
        g_ort->ReleaseEnv(s->env);
    }
    mc_cuda_stream_destroy(s->device_id, s->cuda_user_stream);
    s->cuda_user_stream = NULL;
    mc_cache_guard_finish(&s->tensorrt_cache_guard);
#if defined(__APPLE__)
    mc_cache_guard_finish(&s->coreml_cache_guard);
#endif
    free(s->scratch_input);
    free(s->scratch_global_histograms);
    free(s->scratch_local_histograms);
    free(s->scratch_output);
    free(s);
}


int mc_get_num_classes(const mc_session_t *s)
{
    return s ? s->num_classes : 0;
}

const char *mc_execution_provider(const mc_session_t *s)
{
    return s ? s->execution_provider : "none";
}

const char *mc_inference_backend(const mc_session_t *s)
{
    return s && s->tensorrt_enabled
         ? "tensorrt" : mc_execution_provider(s);
}

const char *mc_model_path(const mc_session_t *s)
{
    return s ? s->model_path : NULL;
}

int mc_cuda_device_id(const mc_session_t *s)
{
    return s ? s->device_id : -1;
}

int mc_uses_cuda(const mc_session_t *s)
{
    return s && strcmp(s->execution_provider, "cuda") == 0;
}

int mc_uses_coreml(const mc_session_t *s)
{
    return s && strcmp(s->execution_provider, "coreml") == 0;
}

int mc_uses_tensorrt(const mc_session_t *s)
{
    return s && s->tensorrt_enabled;
}

int mc_uses_native_histograms(const mc_session_t *s)
{
    return s && s->input_count == 3;
}

int mc_static_batch_size(const mc_session_t *s)
{
    return s ? s->static_batch_size : 0;
}

void mc_set_run_batch_size(mc_session_t *s, int batch_size)
{
    if (s && batch_size > 0
        && (s->tensorrt_enabled
            || strcmp(s->execution_provider, "cuda") == 0)) {
        s->run_batch_size = batch_size;
    }
}

int mc_timing_enabled(const mc_session_t *s)
{
    return s ? s->timing_enabled : 0;
}

void mc_get_timing(const mc_session_t *s, mc_timing_t *timing_out)
{
    if (!timing_out) {
        return;
    }
    if (s) {
        *timing_out = s->timing;
    }
    else {
        memset(timing_out, 0, sizeof(*timing_out));
    }
}

int mc_terminate_current_run(mc_session_t *s)
{
    if (!s || !s->run_options) {
        return 1;
    }
    OrtStatus *st = g_ort->RunOptionsSetTerminate(s->run_options);
    if (st) {
        const char *msg = g_ort->GetErrorMessage(st);
        lock_fprintf(stderr, "MoDiCo: failed to terminate active ORT run: %s\n",
                msg ? msg : "(null)");
        g_ort->ReleaseStatus(st);
        return 1;
    }
    return 0;
}


/* Ensure the per-session uint8->int64 scratch buffer can hold n_elems. */
static int mc_ensure_scratch(mc_session_t *s, size_t n_elems)
{
    if (s->scratch_capacity_elems >= n_elems) {
        return 0;
    }
    if (n_elems > SIZE_MAX / sizeof(int64_t)) {
        return 1;
    }
    int64_t *p = realloc(s->scratch_input, n_elems * sizeof(int64_t));
    if (!p) {
        perror("realloc");
        return 1;
    }
    s->scratch_input = p;
    s->scratch_capacity_elems = n_elems;
    return 0;
}


static int mc_resize_float_scratch(float **buffer, size_t *capacity,
                                   size_t n_elems)
{
    if (*capacity >= n_elems) {
        return 0;
    }
    if (n_elems > SIZE_MAX / sizeof(float)) {
        return 1;
    }
    float *resized = realloc(*buffer, n_elems * sizeof(float));
    if (!resized) {
        perror("realloc");
        return 1;
    }
    *buffer = resized;
    *capacity = n_elems;
    return 0;
}


static int mc_prepare_histogram_inputs(mc_session_t *s, const uint8_t *bytes,
                                       int batch_size, int run_batch,
                                       int block_size, size_t *windows_out)
{
    if (block_size < 32 || (block_size - 32) % 16 != 0) {
        lock_fprintf(stderr,
                "MoDiCo: unsupported histogram block size=%d\n",
                block_size);
        return 1;
    }

    size_t windows = (size_t)(block_size - 32) / 16u + 1u;
    size_t global_elems = (size_t)run_batch * 256u;
    if (windows > SIZE_MAX / 256u
        || (size_t)run_batch > SIZE_MAX / (windows * 256u)) {
        return 1;
    }
    size_t local_elems = (size_t)run_batch * windows * 256u;
    if (mc_resize_float_scratch(&s->scratch_global_histograms,
                                &s->scratch_global_histogram_elems,
                                global_elems) != 0
        || mc_resize_float_scratch(&s->scratch_local_histograms,
                                   &s->scratch_local_histogram_elems,
                                   local_elems) != 0) {
        return 1;
    }

    memset(s->scratch_global_histograms, 0,
           global_elems * sizeof(*s->scratch_global_histograms));
    memset(s->scratch_local_histograms, 0,
           local_elems * sizeof(*s->scratch_local_histograms));

    for (int batch = 0; batch < batch_size; batch++) {
        const uint8_t *block = bytes + (size_t)batch * (size_t)block_size;
        float *global = s->scratch_global_histograms + (size_t)batch * 256u;
        float *local = s->scratch_local_histograms
                     + (size_t)batch * windows * 256u;
        float counts[256] = {0};

        for (int offset = 0; offset < block_size; offset++) {
            global[block[offset]] += 1.0f;
        }
        for (int offset = 0; offset < 32; offset++) {
            counts[block[offset]] += 1.0f;
        }
        memcpy(local, counts, sizeof(counts));

        for (size_t window = 1; window < windows; window++) {
            size_t previous_start = (window - 1u) * 16u;
            for (size_t offset = 0; offset < 16u; offset++) {
                counts[block[previous_start + offset]] -= 1.0f;
                counts[block[previous_start + 32u + offset]] += 1.0f;
            }
            memcpy(local + window * 256u, counts, sizeof(counts));
        }
    }

    for (int batch = batch_size; batch < run_batch; batch++) {
        float *global = s->scratch_global_histograms + (size_t)batch * 256u;
        float *local = s->scratch_local_histograms
                     + (size_t)batch * windows * 256u;
        global[0] = (float)block_size;
        for (size_t window = 0; window < windows; window++) {
            local[window * 256u] = 32.0f;
        }
    }

    *windows_out = windows;
    return 0;
}


static void mc_release_values(OrtValue **values, size_t count)
{
    for (size_t index = 0; index < count; index++) {
        if (values[index]) {
            g_ort->ReleaseValue(values[index]);
            values[index] = NULL;
        }
    }
}


static void mc_release_persistent_tensors(mc_session_t *s)
{
    if (!s || !g_ort) {
        return;
    }
    mc_release_values(s->persistent_inputs, 3);
    if (s->persistent_output) {
        g_ort->ReleaseValue(s->persistent_output);
        s->persistent_output = NULL;
    }
    s->persistent_batch_size = 0;
    s->persistent_block_size = 0;
    s->persistent_histogram_windows = 0;
}


static void mc_release_cuda_fastpath(mc_session_t *s)
{
    if (!s || !g_ort) {
        return;
    }
    if (s->cuda_binding) {
        g_ort->ReleaseIoBinding(s->cuda_binding);
        s->cuda_binding = NULL;
    }
    mc_release_values(s->cuda_inputs, 3);
    if (s->cuda_output) {
        g_ort->ReleaseValue(s->cuda_output);
        s->cuda_output = NULL;
    }
    if (s->cuda_mem_info) {
        g_ort->ReleaseMemoryInfo(s->cuda_mem_info);
        s->cuda_mem_info = NULL;
    }
    mc_cuda_preprocessor_destroy(s->cuda_preprocessor);
    s->cuda_preprocessor = NULL;
    s->cuda_fastpath_state = 0;
    s->cuda_fastpath_batch_size = 0;
    s->cuda_fastpath_block_size = 0;
    s->cuda_fastpath_histogram_windows = 0;
}


static int mc_prepare_cuda_fastpath(mc_session_t *s,
                                    int run_batch,
                                    int block_size,
                                    size_t histogram_windows)
{
    const int64_t input_shape[2] = {
        (int64_t)run_batch, (int64_t)block_size
    };
    const int64_t global_shape[2] = {(int64_t)run_batch, 256};
    const int64_t local_shape[3] = {
        (int64_t)run_batch, (int64_t)histogram_windows, 256
    };
    const int64_t output_shape[2] = {
        (int64_t)run_batch, (int64_t)s->num_classes
    };
    const char *const input_names[3] = {
        s->input_name,
        s->global_histogram_input_name,
        s->local_histogram_input_name
    };
    size_t input_elems;
    size_t global_elems;
    size_t local_elems;
    size_t output_elems;
    char reason[1024] = {0};
    OrtStatus *status = NULL;

    if (!s || s->cuda_fastpath_state < 0
        || strcmp(s->execution_provider, "cuda") != 0
        || s->input_count != 3
        || mc_value_disabled(getenv("SCALPEL3_MODICO_GPU_PREPROCESS"))) {
        return 0;
    }
    if (s->cuda_fastpath_state > 0
        && s->cuda_fastpath_batch_size == run_batch
        && s->cuda_fastpath_block_size == block_size
        && s->cuda_fastpath_histogram_windows == histogram_windows) {
        return 1;
    }
    if (run_batch <= 0 || block_size <= 0 || histogram_windows == 0
        || (size_t)run_batch > SIZE_MAX / (size_t)block_size
        || (size_t)run_batch > SIZE_MAX / 256u
        || histogram_windows > SIZE_MAX / 256u
        || (size_t)run_batch > SIZE_MAX / (histogram_windows * 256u)
        || (size_t)run_batch > SIZE_MAX / (size_t)s->num_classes) {
        s->cuda_fastpath_state = -1;
        return 0;
    }

    mc_release_cuda_fastpath(s);
    input_elems = (size_t)run_batch * (size_t)block_size;
    global_elems = (size_t)run_batch * 256u;
    local_elems = (size_t)run_batch * histogram_windows * 256u;
    output_elems = (size_t)run_batch * (size_t)s->num_classes;
    s->cuda_preprocessor = mc_cuda_preprocessor_create(
        s->device_id, run_batch, block_size, s->num_classes,
        s->cuda_user_stream,
        reason, sizeof(reason));
    if (!s->cuda_preprocessor) {
        lock_fprintf(stdout,
                "MoDiCo CUDA device preprocessing unavailable; using "
                "host preprocessing: %s\n",
                reason[0] ? reason : "initialization failed");
        s->cuda_fastpath_state = -1;
        return 0;
    }

    status = g_ort->CreateMemoryInfo("Cuda", OrtDeviceAllocator,
                                     s->device_id, OrtMemTypeDefault,
                                     &s->cuda_mem_info);
    if (!status) {
        status = g_ort->CreateTensorWithDataAsOrtValue(
            s->cuda_mem_info, mc_cuda_preprocessor_input(s->cuda_preprocessor),
            input_elems * sizeof(int64_t), input_shape, 2,
            ONNX_TENSOR_ELEMENT_DATA_TYPE_INT64, &s->cuda_inputs[0]);
    }
    if (!status) {
        status = g_ort->CreateTensorWithDataAsOrtValue(
            s->cuda_mem_info,
            mc_cuda_preprocessor_global_histograms(s->cuda_preprocessor),
            global_elems * sizeof(float), global_shape, 2,
            ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT, &s->cuda_inputs[1]);
    }
    if (!status) {
        status = g_ort->CreateTensorWithDataAsOrtValue(
            s->cuda_mem_info,
            mc_cuda_preprocessor_local_histograms(s->cuda_preprocessor),
            local_elems * sizeof(float), local_shape, 3,
            ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT, &s->cuda_inputs[2]);
    }
    if (!status) {
        status = g_ort->CreateTensorWithDataAsOrtValue(
            s->cuda_mem_info,
            mc_cuda_preprocessor_output(s->cuda_preprocessor),
            output_elems * sizeof(float), output_shape, 2,
            ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT, &s->cuda_output);
    }
    if (!status) {
        status = g_ort->CreateIoBinding(s->session, &s->cuda_binding);
    }
    for (size_t index = 0; !status && index < 3; index++) {
        status = g_ort->BindInput(s->cuda_binding, input_names[index],
                                  s->cuda_inputs[index]);
    }
    if (!status) {
        status = g_ort->BindOutput(s->cuda_binding, s->output_name,
                                   s->cuda_output);
    }
    if (status) {
        mc_log_ort_status(status, "CUDA device tensor binding");
        mc_release_cuda_fastpath(s);
        s->cuda_fastpath_state = -1;
        lock_fprintf(stdout,
                "MoDiCo is using host preprocessing for this session.\n");
        return 0;
    }

    s->cuda_fastpath_state = 1;
    s->cuda_fastpath_batch_size = run_batch;
    s->cuda_fastpath_block_size = block_size;
    s->cuda_fastpath_histogram_windows = histogram_windows;
    lock_fprintf(stdout,
            "MoDiCo CUDA device preprocessing enabled "
            "(device %d, batch size %d).\n",
            s->device_id, run_batch);
    return 1;
}


static void mc_record_run_timing(mc_session_t *s, double run_seconds)
{
    if (s->timing.run_count == 0) {
        s->timing.first_run_seconds = run_seconds;
    }
    else {
        uint64_t previous_count = s->timing.run_count - 1;
        s->timing.subsequent_run_seconds += run_seconds;
        if (previous_count == 0
            || run_seconds < s->timing.subsequent_run_min_seconds) {
            s->timing.subsequent_run_min_seconds = run_seconds;
        }
        if (previous_count == 0
            || run_seconds > s->timing.subsequent_run_max_seconds) {
            s->timing.subsequent_run_max_seconds = run_seconds;
        }
    }
    s->timing.run_count++;
}


static int mc_run_cuda_fastpath(mc_session_t *s,
                                const uint8_t *bytes,
                                int batch_size,
                                float *logits_out)
{
    struct timespec conversion_start = {0, 0};
    struct timespec conversion_end = {0, 0};
    struct timespec run_start = {0, 0};
    struct timespec run_end = {0, 0};
    char reason[1024] = {0};

    if (s->timing_enabled) {
        clock_gettime(CLOCK_MONOTONIC, &conversion_start);
    }
    if (!mc_cuda_preprocessor_prepare(s->cuda_preprocessor, bytes,
                                      batch_size, reason,
                                      sizeof(reason))) {
        lock_fprintf(stderr,
                "MoDiCo: CUDA preprocessing failed: %s\n",
                reason[0] ? reason : "unknown CUDA error");
        return MC_INFERENCE_RETRYABLE;
    }
    if (s->timing_enabled) {
        clock_gettime(CLOCK_MONOTONIC, &conversion_end);
        s->timing.input_conversion_seconds +=
            mc_elapsed_seconds(&conversion_start, &conversion_end);
        clock_gettime(CLOCK_MONOTONIC, &run_start);
    }

    OrtStatus *run_status = g_ort->RunWithBinding(
        s->session, s->run_options, s->cuda_binding);
    if (run_status) {
        const char *message = g_ort->GetErrorMessage(run_status);
        mc_inference_status_t result = mc_classify_ort_failure(message);
        lock_fprintf(stderr, "MoDiCo: bound ORT Run failed: %s\n",
                message ? message : "(null)");
        g_ort->ReleaseStatus(run_status);
        return result;
    }
    if (!mc_cuda_preprocessor_copy_output(s->cuda_preprocessor, logits_out,
                                          batch_size, reason,
                                          sizeof(reason))) {
        lock_fprintf(stderr, "MoDiCo: CUDA output transfer failed: %s\n",
                reason[0] ? reason : "unknown CUDA error");
        return MC_INFERENCE_RETRYABLE;
    }
    if (s->timing_enabled) {
        clock_gettime(CLOCK_MONOTONIC, &run_end);
        mc_record_run_timing(
            s, mc_elapsed_seconds(&run_start, &run_end));
    }
    return MC_INFERENCE_OK;
}


static int mc_prepare_persistent_tensors(mc_session_t *s,
                                         int run_batch,
                                         int block_size,
                                         size_t histogram_windows)
{
    const int64_t input_shape[2] = {
        (int64_t)run_batch, (int64_t)block_size
    };
    const int64_t global_shape[2] = {(int64_t)run_batch, 256};
    const int64_t local_shape[3] = {
        (int64_t)run_batch, (int64_t)histogram_windows, 256
    };
    const int64_t output_shape[2] = {
        (int64_t)run_batch, (int64_t)s->num_classes
    };
    size_t input_elems;
    size_t output_elems;
    OrtStatus *status;

    if (run_batch <= 0 || block_size <= 0 || s->num_classes <= 0
        || (size_t)run_batch > SIZE_MAX / (size_t)block_size
        || (size_t)run_batch > SIZE_MAX / (size_t)s->num_classes) {
        return 1;
    }
    input_elems = (size_t)run_batch * (size_t)block_size;
    output_elems = (size_t)run_batch * (size_t)s->num_classes;
    if (input_elems > SIZE_MAX / sizeof(int64_t)
        || output_elems > SIZE_MAX / sizeof(float)) {
        return 1;
    }

    if (s->persistent_batch_size == run_batch
        && s->persistent_block_size == block_size
        && s->persistent_histogram_windows == histogram_windows
        && s->persistent_inputs[0] && s->persistent_output) {
        return 0;
    }
    mc_release_persistent_tensors(s);

    if (s->scratch_output_elems < output_elems) {
        float *resized = realloc(s->scratch_output,
                                 output_elems * sizeof(*resized));
        if (!resized) {
            perror("realloc");
            return 1;
        }
        s->scratch_output = resized;
        s->scratch_output_elems = output_elems;
    }

    status = g_ort->CreateTensorWithDataAsOrtValue(
        s->mem_info, s->scratch_input, input_elems * sizeof(int64_t),
        input_shape, 2, ONNX_TENSOR_ELEMENT_DATA_TYPE_INT64,
        &s->persistent_inputs[0]);
    if (status) {
        mc_log_ort_status(status, "persistent input tensor creation");
        mc_release_persistent_tensors(s);
        return 1;
    }

    if (s->input_count == 3) {
        size_t global_elems;
        size_t local_elems;

        if (histogram_windows == 0
            || (size_t)run_batch > SIZE_MAX / 256u
            || histogram_windows > SIZE_MAX / 256u
            || (size_t)run_batch > SIZE_MAX / (histogram_windows * 256u)) {
            mc_release_persistent_tensors(s);
            return 1;
        }
        global_elems = (size_t)run_batch * 256u;
        local_elems = (size_t)run_batch * histogram_windows * 256u;
        if (global_elems > SIZE_MAX / sizeof(float)
            || local_elems > SIZE_MAX / sizeof(float)) {
            mc_release_persistent_tensors(s);
            return 1;
        }

        status = g_ort->CreateTensorWithDataAsOrtValue(
            s->mem_info, s->scratch_global_histograms,
            global_elems * sizeof(float), global_shape, 2,
            ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT,
            &s->persistent_inputs[1]);
        if (!status) {
            status = g_ort->CreateTensorWithDataAsOrtValue(
                s->mem_info, s->scratch_local_histograms,
                local_elems * sizeof(float), local_shape, 3,
                ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT,
                &s->persistent_inputs[2]);
        }
        if (status) {
            mc_log_ort_status(status,
                              "persistent histogram tensor creation");
            mc_release_persistent_tensors(s);
            return 1;
        }
    }

    status = g_ort->CreateTensorWithDataAsOrtValue(
        s->mem_info, s->scratch_output, output_elems * sizeof(float),
        output_shape, 2, ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT,
        &s->persistent_output);
    if (status) {
        mc_log_ort_status(status, "persistent output tensor creation");
        mc_release_persistent_tensors(s);
        return 1;
    }

    s->persistent_batch_size = run_batch;
    s->persistent_block_size = block_size;
    s->persistent_histogram_windows = histogram_windows;
    return 0;
}


/* Internal: do a Run with shape (batch_size, block_size) and copy out the
 * (batch_size, num_classes) float logits. */
static int mc_run_internal(mc_session_t *s,
                           const uint8_t *bytes,
                           int batch_size, int block_size,
                           float *logits_out)
{
    if (!s || !bytes || !logits_out || block_size <= 0) {
        return MC_INFERENCE_FATAL;
    }
    int run_batch = s->static_batch_size > 0
                  ? s->static_batch_size
                  : (s->run_batch_size > 0
                         ? s->run_batch_size
                         : batch_size);
    if (batch_size > run_batch) {
        lock_fprintf(stderr,
                "MoDiCo: batch_size=%d exceeds configured session batch=%d\n",
                batch_size, run_batch);
        return MC_INFERENCE_FATAL;
    }

    const size_t actual_elems = (size_t)batch_size * (size_t)block_size;
    const size_t n_elems = (size_t)run_batch * (size_t)block_size;
    size_t histogram_windows = 0;
    if (s->input_count == 3) {
        if (block_size < 32 || (block_size - 32) % 16 != 0) {
            lock_fprintf(stderr,
                    "MoDiCo: unsupported histogram block size=%d\n",
                    block_size);
            return MC_INFERENCE_FATAL;
        }
        histogram_windows = (size_t)(block_size - 32) / 16u + 1u;
    }
    if (mc_prepare_cuda_fastpath(s, run_batch, block_size,
                                 histogram_windows)) {
        return mc_run_cuda_fastpath(s, bytes, batch_size, logits_out);
    }
    if (s->persistent_batch_size != 0
        && (s->persistent_batch_size != run_batch
            || s->persistent_block_size != block_size)) {
        mc_release_persistent_tensors(s);
    }
    if (mc_ensure_scratch(s, n_elems) != 0) {
        return MC_INFERENCE_RETRYABLE;
    }

    struct timespec conversion_start = {0, 0};
    struct timespec conversion_end = {0, 0};
    if (s->timing_enabled) {
        clock_gettime(CLOCK_MONOTONIC, &conversion_start);
    }

    /* Widen uint8 -> int64 into scratch. */
    int64_t *input_data = s->scratch_input;
    for (size_t i = 0; i < actual_elems; ++i) {
        input_data[i] = (int64_t)bytes[i];
    }
    if (actual_elems < n_elems) {
        memset(input_data + actual_elems, 0,
               (n_elems - actual_elems) * sizeof(*input_data));
    }
    if (s->input_count == 3
        && mc_prepare_histogram_inputs(s, bytes, batch_size, run_batch,
                                       block_size,
                                       &histogram_windows) != 0) {
        return MC_INFERENCE_RETRYABLE;
    }
    if (s->timing_enabled) {
        clock_gettime(CLOCK_MONOTONIC, &conversion_end);
        s->timing.input_conversion_seconds +=
            mc_elapsed_seconds(&conversion_start, &conversion_end);
    }

    if (mc_prepare_persistent_tensors(s, run_batch, block_size,
                                      histogram_windows) != 0) {
        return MC_INFERENCE_RETRYABLE;
    }

    const char *input_names[3] = {
        s->input_name,
        s->global_histogram_input_name,
        s->local_histogram_input_name,
    };
    const char *const output_names[] = {s->output_name};

    OrtValue *output_tensor = s->persistent_output;
    struct timespec run_start = {0, 0};
    struct timespec run_end = {0, 0};
    if (s->timing_enabled) {
        clock_gettime(CLOCK_MONOTONIC, &run_start);
    }
    OrtStatus *run_status = g_ort->Run(
        s->session, s->run_options,
        input_names, (const OrtValue *const *)s->persistent_inputs,
        s->input_count,
        output_names, 1, &output_tensor);
    if (s->timing_enabled) {
        double run_seconds;

        clock_gettime(CLOCK_MONOTONIC, &run_end);
        run_seconds = mc_elapsed_seconds(&run_start, &run_end);
        mc_record_run_timing(s, run_seconds);
    }
    if (run_status != NULL) {
        const char *msg = g_ort->GetErrorMessage(run_status);
        mc_inference_status_t result = mc_classify_ort_failure(msg);
        lock_fprintf(stderr, "MoDiCo: ORT Run failed: %s\n", msg ? msg : "(null)");
        g_ort->ReleaseStatus(run_status);
        if (output_tensor && output_tensor != s->persistent_output) {
            g_ort->ReleaseValue(output_tensor);
        }
        return result;
    }

    if (!output_tensor) {
        lock_fprintf(stderr, "MoDiCo: ORT Run returned no output tensor.\n");
        return MC_INFERENCE_FATAL;
    }

    float *raw = NULL;
    OrtStatus *data_status =
        g_ort->GetTensorMutableData(output_tensor, (void **)&raw);
    if (data_status) {
        const char *msg = g_ort->GetErrorMessage(data_status);
        int result = mc_classify_ort_failure(msg);
        lock_fprintf(stderr, "MoDiCo: output tensor access failed: %s\n",
                msg ? msg : "(null)");
        g_ort->ReleaseStatus(data_status);
        if (output_tensor != s->persistent_output) {
            g_ort->ReleaseValue(output_tensor);
        }
        return result;
    }
    memcpy(logits_out, raw,
           (size_t)batch_size * (size_t)s->num_classes * sizeof(float));

    if (output_tensor != s->persistent_output) {
        g_ort->ReleaseValue(output_tensor);
    }
    return MC_INFERENCE_OK;
}


int mc_classify(mc_session_t *s,
                const uint8_t *bytes, int block_size,
                float *logits_out)
{
    return mc_run_internal(s, bytes, 1, block_size, logits_out);
}


int mc_classify_batch(mc_session_t *s,
                      const uint8_t *bytes,
                      int batch_size, int block_size,
                      float *logits_out)
{
    if (batch_size <= 0) {
        return MC_INFERENCE_FATAL;
    }
    return mc_run_internal(s, bytes, batch_size, block_size, logits_out);
}


/* ------------------------------------------------------------------------- */
/* CPU capability detection + auto-select                                    */
/* ------------------------------------------------------------------------- */

int mc_cpu_supports_fast_int8(void)
{
#if defined(__x86_64__) || defined(__i386__)
    /* Probe via the compiler's built-in CPUID wrapper. AVX-VNNI (the
     * AVX2-extending one) is the more permissive of the two paths: it
     * landed in Tiger Lake (Intel, 2020) and Zen 4 (AMD EPYC 9xxx).
     * AVX-512 VNNI was earlier on server (Cascade Lake, 2019). */
    __builtin_cpu_init();
#  if (defined(__GNUC__) && __GNUC__ >= 11) || (defined(__clang_major__) && __clang_major__ >= 12)
    if (__builtin_cpu_supports("avxvnni")) {
        return 1;
    }
#  endif
    if (__builtin_cpu_supports("avx512vnni")) {
        return 1;
    }
    return 0;
#elif defined(__aarch64__) && defined(__linux__)
    /* Linux ARM: ASIMDDP (dot-product) is what onnxruntime uses for INT8
     * matmul on aarch64. I8MM is even better when present but optional.
     * getauxval / HWCAP_ASIMDDP are Linux glibc APIs. */
    unsigned long hwcap = getauxval(AT_HWCAP);
    return (hwcap & HWCAP_ASIMDDP) ? 1 : 0;
#elif defined(__aarch64__) && defined(__APPLE__)
    /* Apple Silicon: getauxval/HWCAP don't exist on macOS. Probe the
     * dot-product feature via sysctl. All shipping M-series parts have it,
     * but query rather than assume. (Note: on macOS the Core ML path is the
     * preferred MoDiCo backend anyway; this only matters for ORT-on-Mac.) */
    int has = 0;
    size_t sz = sizeof(has);
    if (sysctlbyname("hw.optional.arm.FEAT_DotProd", &has, &sz, NULL, 0) == 0) {
        return has ? 1 : 0;
    }
    return 0;
#else
    /* Other architectures: assume no fast INT8. Safer to use FP32. */
    return 0;
#endif
}


static int file_is_readable(const char *path)
{
    struct stat st;
    return (stat(path, &st) == 0) && S_ISREG(st.st_mode);
}


mc_session_t *mc_create_session_auto(const char *model_base_path,
                                     int intra_op_threads,
                                     mc_session_kind_t prefer,
                                     mc_session_info_t *info_out)
{
    return mc_create_session_auto_with_accelerator(model_base_path,
                                                  intra_op_threads,
                                                  prefer, "cpu",
                                                  info_out);
}


mc_session_t *mc_create_session_auto_with_accelerator(
                                     const char *model_base_path,
                                     int intra_op_threads,
                                     mc_session_kind_t prefer,
                                     const char *accelerator,
                                     mc_session_info_t *info_out)
{
    /* Convenience wrapper: device 0. Callers that target a specific GPU use
     * the _device variant. */
    return mc_create_session_auto_with_accelerator_device(model_base_path,
                                                         intra_op_threads,
                                                         prefer,
                                                         accelerator,
                                                         0,
                                                         info_out);
}


mc_session_t *mc_create_session_auto_with_accelerator_device(
                                     const char *model_base_path,
                                     int intra_op_threads,
                                     mc_session_kind_t prefer,
                                     const char *accelerator,
                                     int device_id,
                                     mc_session_info_t *info_out)
{
    return mc_create_session_auto_with_accelerator_device_for_workload(
        model_base_path, intra_op_threads, prefer, accelerator, device_id,
        UINT64_MAX, info_out);
}


mc_session_t *mc_create_session_auto_with_accelerator_device_for_workload(
                                     const char *model_base_path,
                                     int intra_op_threads,
                                     mc_session_kind_t prefer,
                                     const char *accelerator,
                                     int device_id,
                                     uint64_t expected_blocks,
                                     mc_session_info_t *info_out)
{
    /* Tolerate (and strip) a trailing ".onnx" on the input — Scalpel
     * users will sometimes pass the full FP32 path by habit. */
    char base[1024];
    strncpy(base, model_base_path, sizeof(base) - 1);
    base[sizeof(base) - 1] = '\0';
    size_t blen = strlen(base);
    if (blen > 5 && strcmp(base + blen - 5, ".onnx") == 0) {
        base[blen - 5] = '\0';
    }

    char fp32_path[1024];
    char int8_path[1024];
    snprintf(fp32_path, sizeof(fp32_path), "%s.onnx",      base);
    snprintf(int8_path, sizeof(int8_path), "%s_int8.onnx", base);

    int int8_supported = mc_cpu_supports_fast_int8();
    int int8_available = file_is_readable(int8_path);

    mc_session_kind_t kind;
    const char       *chosen;

    switch (prefer) {
    case MC_KIND_FP32:
        kind   = MC_KIND_FP32;
        chosen = fp32_path;
        break;

    case MC_KIND_INT8:
        if (!int8_available) {
            lock_fprintf(stdout,
                "MoDiCo INT8 model requested but %s does not exist; "
                "falling back to FP32.\n", int8_path);
            kind   = MC_KIND_FP32;
            chosen = fp32_path;
        } else {
            kind   = MC_KIND_INT8;
            chosen = int8_path;
        }
        break;

    case MC_KIND_AUTO:
    default:
        if (int8_supported && int8_available) {
            kind   = MC_KIND_INT8;
            chosen = int8_path;
        } else {
            kind   = MC_KIND_FP32;
            chosen = fp32_path;
        }
        break;
    }

    if (info_out) {
        info_out->kind_selected       = kind;
        info_out->int8_cpu_supported  = int8_supported;
        info_out->int8_file_available = int8_available;
        info_out->cuda_requested      = mc_cuda_requested(accelerator);
        info_out->cuda_enabled        = mc_cuda_requested(accelerator);
        info_out->coreml_requested    = mc_coreml_requested(accelerator);
        info_out->coreml_enabled      = mc_coreml_requested(accelerator);
        info_out->device_id           = info_out->cuda_enabled
                                      ? (device_id >= 0 ? device_id : 0)
                                      : -1;
        strncpy(info_out->execution_provider,
                info_out->cuda_enabled ? "cuda"
                    : (info_out->coreml_enabled ? "coreml" : "cpu"),
                sizeof(info_out->execution_provider) - 1);
        info_out->execution_provider[sizeof(info_out->execution_provider) - 1] = '\0';
        strncpy(info_out->selected_path, chosen, sizeof(info_out->selected_path) - 1);
        info_out->selected_path[sizeof(info_out->selected_path) - 1] = '\0';
    }

    lock_fprintf(stdout,
            "MoDiCo model selection:\n"
            "  Execution provider:       %s\n"
            "  CPU fast INT8 support:    %s\n"
            "  INT8 model available:     %s\n"
            "  Precision:                %s\n"
            "  Model:                    %s\n",
            mc_cuda_requested(accelerator) ? "cuda"
                : (mc_coreml_requested(accelerator) ? "coreml" : "cpu"),
            int8_supported ? "yes" : "no",
            int8_available ? "yes" : "no",
            kind == MC_KIND_INT8 ? "INT8" : "FP32", chosen);

    return mc_create_session_with_accelerator_device_for_workload(
        chosen, intra_op_threads, accelerator, device_id, expected_blocks);
}


/* ------------------------------------------------------------------------- */
/* Post-processing helpers                                                   */
/* ------------------------------------------------------------------------- */

void mc_topk_softmax(const float *logits, int n, int k,
                     int *out_idx, float *out_softmax)
{
    if (!logits || !out_idx || !out_softmax || n <= 0 || k <= 0) {
        return;
    }

    for (int j = 0; j < k; ++j) {
        out_idx[j] = -1;
        out_softmax[j] = -INFINITY;
    }

    float *top_logits = malloc((size_t)k * sizeof(float));
    if (!top_logits) {
        perror("malloc");
        return;
    }

    float max_logit = logits[0];
    for (int i = 1; i < n; ++i) {
        if (logits[i] > max_logit) {
            max_logit = logits[i];
        }
    }
    double sum_exp = 0.0;
    for (int i = 0; i < n; ++i) {
        sum_exp += exp((double)(logits[i] - max_logit));
    }

    for (int j = 0; j < k; ++j) {
        top_logits[j] = -INFINITY;
    }

    for (int i = 0; i < n; ++i) {
        float v = logits[i];
        for (int j = 0; j < k; ++j) {
            if (v > top_logits[j]) {
                for (int m = k - 1; m > j; --m) {
                    top_logits[m] = top_logits[m - 1];
                    out_idx[m]    = out_idx[m - 1];
                }
                top_logits[j] = v;
                out_idx[j]    = i;
                break;
            }
        }
    }

    for (int j = 0; j < k; ++j) {
        out_softmax[j] = (float)(exp((double)(top_logits[j] - max_logit)) / sum_exp);
    }

    free(top_logits);
}
