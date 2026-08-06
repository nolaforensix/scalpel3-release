/*
 * modico.c — implementation of the MoDiCo C inference layer.
 * See modico.h for the public surface.
 */

#define _POSIX_C_SOURCE 200809L
#if defined(__APPLE__)
/* Expose BSD types (u_int, u_char, ...) used by <sys/sysctl.h>, which
 * _POSIX_C_SOURCE would otherwise hide under a strict -std=cNN. */
#  define _DARWIN_C_SOURCE 1
#endif

#include <errno.h>
#include <math.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>

#if defined(__APPLE__)
#  include <dirent.h>
#  include <openssl/evp.h>
#endif

#if defined(__aarch64__) && defined(__linux__)
#  include <sys/auxv.h>
#  include <asm/hwcap.h>
#elif defined(__aarch64__) && defined(__APPLE__)
#  include <sys/sysctl.h>
#endif

#include "onnxruntime_c_api.h"
#include "modico.h"
#include "onnx_cuda_options.h"

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
static int mc_append_cuda_provider(OrtSessionOptions *opts, int device_id);
static int mc_append_coreml_provider(mc_session_t *s, const char *model_path);
static int mc_ensure_scratch(mc_session_t *s, size_t n_elems);
static int mc_run_internal(mc_session_t *s, const uint8_t *bytes,
                           int batch_size, int block_size,
                           float *logits_out);
static int file_is_readable(const char *path);


static void mc_log_ort_status(OrtStatus *status, const char *context)
{
    const char *msg = g_ort->GetErrorMessage(status);
    fprintf(stderr, "[modico] %s failed: %s\n",
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
    char  execution_provider[16];
    char  model_path[1024];
#if defined(__APPLE__)
    char  coreml_cache_dir[PATH_MAX];
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


static double mc_elapsed_seconds(const struct timespec *start,
                                 const struct timespec *end)
{
    return (double)(end->tv_sec - start->tv_sec)
         + (double)(end->tv_nsec - start->tv_nsec) / 1e9;
}


#if defined(__APPLE__)
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

    size_t count;
    while ((count = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        if (EVP_DigestUpdate(ctx, buffer, count) != 1) {
            goto done;
        }
    }
    if (ferror(fp)
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
    if (fp) {
        fclose(fp);
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}


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
            && strcmp(entry->d_name, "..") != 0) {
            found = 1;
            break;
        }
    }
    closedir(dir);
    return found;
}


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
        fprintf(stderr, "[modico] CoreML cache disabled: could not hash %s.\n",
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
        fprintf(stderr, "[modico] CoreML cache disabled: cannot create %s.\n",
                length >= 0 && (size_t)length < sizeof(s->coreml_cache_dir)
                    ? s->coreml_cache_dir : root);
        s->coreml_cache_dir[0] = '\0';
        return 0;
    }

    int cache_warm = mc_directory_has_entries(s->coreml_cache_dir);
    fprintf(stderr,
            "[modico] CoreML model cache: %s (state=%s, model_sha256=%s)\n",
            s->coreml_cache_dir, cache_warm ? "warm" : "cold",
            model_hash);
    return 1;
}
#endif


static int mc_init_api(void)
{
    if (g_ort == NULL) {
        g_ort = OrtGetApiBase()->GetApi(ORT_API_VERSION);
        if (g_ort == NULL) {
            fprintf(stderr, "Failed to get ORT API (ORT_API_VERSION=%d). "
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
    /* This model materializes large histogram intermediates outside CoreML.
     * Batch 32 is faster than 8/64/128 and uses far less memory than 128. */
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

static int mc_append_cuda_provider(OrtSessionOptions *opts, int device_id)
{
    OrtCUDAProviderOptions cuda_opts;
    OnnxCudaProviderPolicy policy;

    if (!onnx_cuda_provider_options(device_id, &cuda_opts, &policy)) {
        fprintf(stderr,
                "[modico] CUDA memory policy could not query device %d.\n",
                device_id);
        return 0;
    }

    fprintf(stderr,
            "[modico] CUDA device %d (physical %d): %.1f MiB free, "
            "%.1f MiB arena limit (%.0f%%).\n",
            device_id, policy.physical_device_id,
            policy.free_bytes / 1048576.0,
            policy.arena_limit / 1048576.0,
            policy.memory_fraction * 100.0);

    OrtStatus *st =
        g_ort->SessionOptionsAppendExecutionProvider_CUDA(opts, &cuda_opts);
    if (st) {
        mc_log_ort_status(st, "CUDA execution provider setup");
        return 0;
    }
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
            fprintf(stderr,
                    "[modico] ignoring invalid CoreML compute units: %s\n",
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
            fprintf(stderr,
                    "[modico] ignoring invalid CoreML specialization: %s\n",
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

    fprintf(stderr,
            "[modico] CoreML options: compute_units=%s specialization=%s "
            "low_precision=%d profile_compute_plan=%d\n",
            compute_units, specialization, low_precision,
            profile_compute_plan);
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
    if (!mc_ort_succeeded(g_ort->CreateSessionOptions(&s->opts),
                          "session-options creation")) {
        goto fail;
    }
    if (!mc_ort_succeeded(g_ort->SetSessionLogSeverityLevel(s->opts,
                                                            log_level),
                          "session log configuration")) {
        goto fail;
    }
    if (intra_op_threads >= 0) {
        if (!mc_ort_succeeded(g_ort->SetIntraOpNumThreads(s->opts, intra_op_threads),
                              "intra-op thread configuration")) {
            goto fail;
        }
    }
    if (!mc_ort_succeeded(g_ort->SetSessionGraphOptimizationLevel(s->opts,
                                                                  ORT_ENABLE_ALL),
                          "graph optimization configuration")) {
        goto fail;
    }
    if (!mc_ort_succeeded(g_ort->CreateRunOptions(&s->run_options),
                          "run-options creation")) {
        goto fail;
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

    if (mc_cuda_requested(accelerator)) {
        s->device_id = device_id >= 0 ? device_id : 0;
        if (!mc_append_cuda_provider(s->opts, s->device_id)) {
            mc_destroy_session(s);
            return NULL;
        }
        strncpy(s->execution_provider, "cuda", sizeof(s->execution_provider) - 1);
        fprintf(stderr, "[modico] requested CUDA execution provider (device=%d)\n",
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
        fprintf(stderr,
                "[modico] requested CoreML execution provider "
                "(static batch=%d)\n",
                s->static_batch_size);
    }

    struct timespec session_start = {0, 0};
    struct timespec session_end = {0, 0};
    if (s->timing_enabled) {
        clock_gettime(CLOCK_MONOTONIC, &session_start);
    }
    OrtStatus *create_status =
        g_ort->CreateSession(s->env, model_path, s->opts, &s->session);
    if (s->timing_enabled) {
        clock_gettime(CLOCK_MONOTONIC, &session_end);
        s->timing.session_create_seconds =
            mc_elapsed_seconds(&session_start, &session_end);
        fprintf(stderr,
                "[modico:timing] provider=%s session_create_secs=%.6f\n",
                s->execution_provider, s->timing.session_create_seconds);
    }
    if (create_status) {
        /* An accelerated session that cannot be created is recoverable: the
         * caller falls back to cpu. A cpu session that cannot be created is
         * not (bad model file), so that stays fatal. */
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
        fprintf(stderr, "[modico] unexpected input count=%zu\n",
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
            fprintf(stderr,
                    "[modico] unsupported three-input model: %s, %s\n",
                    s->global_histogram_input_name,
                    s->local_histogram_input_name);
            goto fail;
        }
        fprintf(stderr, "[modico] native histogram inputs enabled.\n");
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
        fprintf(stderr, "[modico] unexpected output ndims=%zu\n", ndims);
        goto fail;
    }
    if (!mc_ort_succeeded(g_ort->GetDimensions(tensor_info, dims, ndims),
                          "output dimension lookup")) {
        goto fail;
    }
    if (dims[ndims - 1] <= 0 || dims[ndims - 1] > INT_MAX) {
        fprintf(stderr, "[modico] invalid output class count=%lld\n",
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
            fprintf(stderr, "[modico] ONNX Runtime profile: %s\n",
                    profile_path);
            st = g_ort->AllocatorFree(alloc, profile_path);
            if (st) {
                g_ort->ReleaseStatus(st);
            }
        }
        s->profiling_enabled = 0;
    }
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
    free(s->scratch_input);
    free(s->scratch_global_histograms);
    free(s->scratch_local_histograms);
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

int mc_uses_native_histograms(const mc_session_t *s)
{
    return s && s->input_count == 3;
}

int mc_static_batch_size(const mc_session_t *s)
{
    return s ? s->static_batch_size : 0;
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
        fprintf(stderr, "[modico] failed to terminate active ORT run: %s\n",
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
        fprintf(stderr,
                "[modico] unsupported histogram block size=%d\n",
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
                  : batch_size;
    if (batch_size > run_batch) {
        fprintf(stderr,
                "[modico] batch_size=%d exceeds static session batch=%d\n",
                batch_size, run_batch);
        return MC_INFERENCE_FATAL;
    }

    const size_t actual_elems = (size_t)batch_size * (size_t)block_size;
    const size_t n_elems = (size_t)run_batch * (size_t)block_size;
    size_t histogram_windows = 0;
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

    const int64_t input_shape[2] = {(int64_t)run_batch, (int64_t)block_size};

    OrtValue *input_tensors[3] = {NULL, NULL, NULL};
    OrtStatus *tensor_status = g_ort->CreateTensorWithDataAsOrtValue(
        s->mem_info,
        input_data, n_elems * sizeof(int64_t),
        input_shape, 2,
        ONNX_TENSOR_ELEMENT_DATA_TYPE_INT64,
        &input_tensors[0]);
    if (tensor_status) {
        const char *msg = g_ort->GetErrorMessage(tensor_status);
        int result = mc_classify_ort_failure(msg);
        fprintf(stderr, "[modico] input tensor creation failed: %s\n",
                msg ? msg : "(null)");
        g_ort->ReleaseStatus(tensor_status);
        return result;
    }

    const char *input_names[3] = {
        s->input_name,
        s->global_histogram_input_name,
        s->local_histogram_input_name,
    };
    if (s->input_count == 3) {
        const int64_t global_shape[2] = {(int64_t)run_batch, 256};
        const int64_t local_shape[3] = {
            (int64_t)run_batch, (int64_t)histogram_windows, 256
        };
        size_t global_elems = (size_t)run_batch * 256u;
        size_t local_elems = (size_t)run_batch * histogram_windows * 256u;

        tensor_status = g_ort->CreateTensorWithDataAsOrtValue(
            s->mem_info,
            s->scratch_global_histograms,
            global_elems * sizeof(*s->scratch_global_histograms),
            global_shape, 2,
            ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT,
            &input_tensors[1]);
        if (!tensor_status) {
            tensor_status = g_ort->CreateTensorWithDataAsOrtValue(
                s->mem_info,
                s->scratch_local_histograms,
                local_elems * sizeof(*s->scratch_local_histograms),
                local_shape, 3,
                ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT,
                &input_tensors[2]);
        }
        if (tensor_status) {
            const char *msg = g_ort->GetErrorMessage(tensor_status);
            int result = mc_classify_ort_failure(msg);
            fprintf(stderr,
                    "[modico] histogram tensor creation failed: %s\n",
                    msg ? msg : "(null)");
            g_ort->ReleaseStatus(tensor_status);
            mc_release_values(input_tensors, s->input_count);
            return result;
        }
    }

    const char *const output_names[] = {s->output_name};

    OrtValue *output_tensor = NULL;
    struct timespec run_start = {0, 0};
    struct timespec run_end = {0, 0};
    if (s->timing_enabled) {
        clock_gettime(CLOCK_MONOTONIC, &run_start);
    }
    OrtStatus *run_status = g_ort->Run(
        s->session, s->run_options,
        input_names, (const OrtValue *const *)input_tensors, s->input_count,
        output_names, 1, &output_tensor);
    if (s->timing_enabled) {
        double run_seconds;

        clock_gettime(CLOCK_MONOTONIC, &run_end);
        run_seconds = mc_elapsed_seconds(&run_start, &run_end);
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
    if (run_status != NULL) {
        const char *msg = g_ort->GetErrorMessage(run_status);
        mc_inference_status_t result = mc_classify_ort_failure(msg);
        fprintf(stderr, "[modico] ORT Run failed: %s\n", msg ? msg : "(null)");
        g_ort->ReleaseStatus(run_status);
        if (output_tensor) {
            g_ort->ReleaseValue(output_tensor);
        }
        mc_release_values(input_tensors, s->input_count);
        return result;
    }

    if (!output_tensor) {
        fprintf(stderr, "[modico] ORT Run returned no output tensor.\n");
        mc_release_values(input_tensors, s->input_count);
        return MC_INFERENCE_FATAL;
    }

    float *raw = NULL;
    OrtStatus *data_status =
        g_ort->GetTensorMutableData(output_tensor, (void **)&raw);
    if (data_status) {
        const char *msg = g_ort->GetErrorMessage(data_status);
        int result = mc_classify_ort_failure(msg);
        fprintf(stderr, "[modico] output tensor access failed: %s\n",
                msg ? msg : "(null)");
        g_ort->ReleaseStatus(data_status);
        g_ort->ReleaseValue(output_tensor);
        mc_release_values(input_tensors, s->input_count);
        return result;
    }
    memcpy(logits_out, raw,
           (size_t)batch_size * (size_t)s->num_classes * sizeof(float));

    g_ort->ReleaseValue(output_tensor);
    mc_release_values(input_tensors, s->input_count);
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
            fprintf(stderr,
                "[modico] MC_KIND_INT8 requested but %s does not exist — "
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

    fprintf(stderr,
            "[modico] auto-select: ep=%s cpu_fast_int8=%s int8_file=%s -> loading %s (%s)\n",
            mc_cuda_requested(accelerator) ? "cuda"
                : (mc_coreml_requested(accelerator) ? "coreml" : "cpu"),
            int8_supported ? "yes" : "no",
            int8_available ? "yes" : "no",
            chosen,
            kind == MC_KIND_INT8 ? "INT8" : "FP32");

    return mc_create_session_with_accelerator_device(chosen, intra_op_threads,
                                                    accelerator, device_id);
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
