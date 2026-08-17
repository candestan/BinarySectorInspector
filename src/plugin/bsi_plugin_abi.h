#pragma once

// Host ABI v1. Plugins copy this into their tree (include/bsi_plugin.h) and
// must match BSI_PLUGIN_ABI_VERSION. Core does not special-case plugin ids.

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BSI_PLUGIN_ABI_VERSION 1

enum
{
    BsiSevTrace = 0,
    BsiSevDebug = 1,
    BsiSevInfo = 2,
    BsiSevSuccess = 3,
    BsiSevWarning = 4,
    BsiSevError = 5,
    BsiSevCritical = 6
};

enum
{
    BsiKindTool = 1,
    BsiKindView = 2
};

struct BsiPluginInfo
{
    const char* id;
    const char* name;
    const char* version;
    const char* author;
    const char* description;
    uint32_t    abi_version;
    uint32_t    kinds;
};

struct BsiToolInfo
{
    const char* id;
    const char* parent;
    const char* label;
};

struct BsiViewInfo
{
    const char* id;
    const char* label;
};

struct BsiHost
{
    uint32_t size;
    uint32_t abi_version;
    void*    ctx;
    void (*log)(void* ctx, int severity, const char* module, const char* message);
    int  (*job_ready)(void* ctx);
    const char* (*job_path)(void* ctx);
    const uint8_t* (*image)(void* ctx, size_t* n);
    int  (*has_product)(void* ctx, const char* product_key);
    int  (*has_media)(void* ctx, const char* media);
    int  (*has_rsrc_name)(void* ctx, const char* name);
    int  (*artifact_count)(void* ctx, const char* media);
    int  (*artifact_at)(void* ctx, const char* media, int index,
            uint32_t* file_off, uint32_t* size, uint32_t* extra, uint32_t* extra2,
            char* label, int label_cap, int* is_main);
    int  (*save_dialog)(void* ctx, const char* ext, const char* title, const char* suggest,
            char* out_path, int out_cap);
    int  (*write_file)(void* ctx, const char* path, const void* data, uint32_t n);
};

#ifdef __cplusplus
}
#endif
