#include "elf_onnx.h"

#include <pthread.h>
#include <string.h>

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static elf_onnx_handle_t g_h = NULL;

static const char* sanitize_accel(const char* accelerator) {
    if (!accelerator || !accelerator[0]) return "cpu";
    if (strcmp(accelerator, "cuda") == 0) return "cuda";
    if (strcmp(accelerator, "coreml") == 0) return "coreml";
    if (strcmp(accelerator, "cpu") == 0) return "cpu";
    return "cpu";
}

bool elf_onnx_global_init_batch_device_threads(
    const char* model_path, const char* accelerator, int decode_mode,
    int max_batch, int device_id, int intra_op_threads) {

    if (!model_path || !model_path[0]) return false;

    pthread_mutex_lock(&g_lock);

    if (g_h) {
        int rc = elf_onnx_set_decode_mode(g_h, decode_mode);
        pthread_mutex_unlock(&g_lock);
        return rc == ELF_ONNX_OK;
    }

    g_h = elf_onnx_create_batch_device_threads(
        model_path, sanitize_accel(accelerator), max_batch, device_id,
        intra_op_threads);
    if (!g_h) {
        pthread_mutex_unlock(&g_lock);
        return false;
    }

    if (elf_onnx_set_decode_mode(g_h, decode_mode) != ELF_ONNX_OK) {
        elf_onnx_destroy(g_h);
        g_h = NULL;
        pthread_mutex_unlock(&g_lock);
        return false;
    }

    pthread_mutex_unlock(&g_lock);
    return true;
}

bool elf_onnx_global_init_batch_device(const char* model_path, const char* accelerator,
                                       int decode_mode, int max_batch, int device_id) {

    return elf_onnx_global_init_batch_device_threads(
        model_path, accelerator, decode_mode, max_batch, device_id, 0);
}

bool elf_onnx_global_init_batch(const char* model_path, const char* accelerator,
                                int decode_mode, int max_batch) {
    return elf_onnx_global_init_batch_device(model_path, accelerator, decode_mode,
                                             max_batch, 0);
}

bool elf_onnx_global_init(const char* model_path, const char* accelerator, int decode_mode) {
    return elf_onnx_global_init_batch(model_path, accelerator, decode_mode, 1);
}

void elf_onnx_global_shutdown(void) {
    pthread_mutex_lock(&g_lock);
    if (g_h) {
        elf_onnx_destroy(g_h);
        g_h = NULL;
    }
    pthread_mutex_unlock(&g_lock);
}

elf_onnx_handle_t elf_onnx_global_get(void) {
    return g_h;
}

int elf_onnx_global_set_decode_mode(int mode) {
    pthread_mutex_lock(&g_lock);
    elf_onnx_handle_t h = g_h;
    int rc = h ? elf_onnx_set_decode_mode(h, mode) : ELF_ONNX_BADARG;
    pthread_mutex_unlock(&g_lock);
    return rc;
}

int elf_onnx_global_terminate(void) {
    pthread_mutex_lock(&g_lock);
    elf_onnx_handle_t h = g_h;
    pthread_mutex_unlock(&g_lock);
    if (!h) return 1;
    return elf_onnx_terminate(h) == ELF_ONNX_OK ? 0 : 1;
}

void elf_onnx_global_reset_timing(void) {
    pthread_mutex_lock(&g_lock);
    elf_onnx_handle_t h = g_h;
    pthread_mutex_unlock(&g_lock);
    if (h) elf_onnx_reset_timing(h);
}

int elf_onnx_global_write_timing_report(const char* path) {
    if (!path || !path[0]) return ELF_ONNX_BADARG;
    pthread_mutex_lock(&g_lock);
    elf_onnx_handle_t h = g_h;
    pthread_mutex_unlock(&g_lock);
    if (!h) return ELF_ONNX_BADARG;
    return elf_onnx_write_timing_report(h, path);
}
