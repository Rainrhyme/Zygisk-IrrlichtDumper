//
// Logging with file output
//

#ifndef ZYGISK_IRRLICHT_DUMPER_LOG_H
#define ZYGISK_IRRLICHT_DUMPER_LOG_H

#include <android/log.h>
#include <cstdio>
#include <ctime>
#include <cstring>

#define LOG_TAG "IrrlichtDumper"

// Global log file pointer
extern FILE *g_log_file;

// Initialize log file
inline void init_log_file(const char *game_data_dir) {
    if (g_log_file) return;
    
    char log_path[256];
    snprintf(log_path, sizeof(log_path), "%s/module_log.txt", game_data_dir);
    g_log_file = fopen(log_path, "w");
    
    if (g_log_file) {
        time_t now = time(nullptr);
        fprintf(g_log_file, "=== IrrlichtDumper Log ===\n");
        fprintf(g_log_file, "Time: %s\n", ctime(&now));
        fflush(g_log_file);
    }
}

// Close log file
inline void close_log_file() {
    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = nullptr;
    }
}

// Log to both logcat and file
#define LOGD(...) do { \
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__); \
    if (g_log_file) { fprintf(g_log_file, "[DEBUG] " __VA_ARGS__); fprintf(g_log_file, "\n"); fflush(g_log_file); } \
} while(0)

#define LOGW(...) do { \
    __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__); \
    if (g_log_file) { fprintf(g_log_file, "[WARN] " __VA_ARGS__); fprintf(g_log_file, "\n"); fflush(g_log_file); } \
} while(0)

#define LOGE(...) do { \
    __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__); \
    if (g_log_file) { fprintf(g_log_file, "[ERROR] " __VA_ARGS__); fprintf(g_log_file, "\n"); fflush(g_log_file); } \
} while(0)

#define LOGI(...) do { \
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__); \
    if (g_log_file) { fprintf(g_log_file, "[INFO] " __VA_ARGS__); fprintf(g_log_file, "\n"); fflush(g_log_file); } \
} while(0)

#endif //ZYGISK_IRRLICHT_DUMPER_LOG_H
