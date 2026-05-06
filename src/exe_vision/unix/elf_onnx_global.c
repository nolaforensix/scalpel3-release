#include "elf_onnx_global.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static elf_onnx_handle_t g_h = NULL;

bool elf_onnx_global_init(const char* model_path, const char* accelerator) {
    const char* accel = accelerator;

    if (!model_path || !model_path[0]) return false;

    if (!accel || !accel[0]) {
        accel = "cpu";
    } else if (strcmp(accel, "cuda") != 0 && strcmp(accel, "cpu") != 0) {
        accel = "cpu";
    }

    pthread_mutex_lock(&g_lock);

    if (g_h) {
        pthread_mutex_unlock(&g_lock);
        return true;
    }

    g_h = elf_onnx_create(model_path, accel);

    pthread_mutex_unlock(&g_lock);
    return (g_h != NULL);
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

void elf_onnx_global_write_timing_report(const char* path) {
    if (!path || !path[0]) return;

    pthread_mutex_lock(&g_lock);
    elf_onnx_handle_t h = g_h;
    pthread_mutex_unlock(&g_lock);

    if (!h) return;

    elf_onnx_write_timing_report(path);
}