#pragma once

// BinarySectorInspector Plugin SDK
// Copy this file into the plugin tree (for example include/bsi_plugin.h).
// Do not include host sources. Core never special-cases plugin ids.
//
// Drop-in: build a DLL that exports BsiPluginGetInfo, put it in
//   {exe}/plugins/           or  {exe}/plugins/<folder>/
// Restart (or Settings > Plugins rescan). No Core code change.
//
// Compatibility
//   BSI_PLUGIN_ABI_MIN .. BSI_PLUGIN_ABI_VERSION is the supported range.
//   Host and plugin structs grow only at the end. abi_version stays 2 until
//   a breaking change. Probe with BSI_HOST_HAS / BSI_UI_HAS before calling
//   a field the plugin did not compile against on an older host.
//   BsiHostCompatible() is the usual Init check (original v2 block present).
//
// Python and Lua runtimes are future plugins. They are not built into Core.

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BSI_PLUGIN_ABI_MIN     2
#define BSI_PLUGIN_ABI_VERSION 2

#if defined(_WIN32)
#define BSI_PLUGIN_EXPORT __declspec(dllexport)
#else
#define BSI_PLUGIN_EXPORT
#endif

#define BSI_FIELD_END(type, field) \
    (offsetof(type, field) + sizeof(((type*)0)->field))
#define BSI_HOST_HAS(h, field) \
    ((h) != 0 && (h)->size >= (uint32_t)BSI_FIELD_END(struct BsiHost, field))
#define BSI_UI_HAS(ui, field) \
    ((ui) != 0 && (ui)->size >= (uint32_t)BSI_FIELD_END(struct BsiUi, field))

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

// DetectCategory / DetectConfidence values from detection_at.
enum
{
    BsiDetectCatPacker = 0,
    BsiDetectCatProtector = 1,
    BsiDetectCatCompiler = 2,
    BsiDetectCatToolchain = 3,
    BsiDetectCatDotNetObfuscator = 4
};

enum
{
    BsiDetectConfLow = 0,
    BsiDetectConfMedium = 1,
    BsiDetectConfHigh = 2,
    BsiDetectConfExact = 3
};

enum
{
    BsiToastSuccess = 0,
    BsiToastInfo = 1,
    BsiToastWarning = 2,
    BsiToastError = 3
};

struct BsiPluginInfo
{
    const char* id;          // stable reverse-dns, e.g. com.example.myplugin
    const char* name;
    const char* version;
    const char* author;
    const char* description;
    uint32_t    abi_version; // set to BSI_PLUGIN_ABI_VERSION
    uint32_t    kinds;       // BsiKindTool | BsiKindView
};

struct BsiToolInfo
{
    const char* id;
    const char* parent; // Tools submenu title (usually plugin name)
    const char* label;
};

struct BsiViewInfo
{
    const char* id;
    const char* label;
};

// Optional card art. Paths are local (relative to the DLL directory, or absolute).
// http(s) is ignored. Omit the export, or leave fields null, if you have no art.
struct BsiVisuals
{
    uint32_t    size;
    const char* icon;  // square-ish; also used if cover is missing
    const char* cover; // wide card image
};

// Host-drawn widgets. Do not link ImGui in the plugin; call these during
// BsiPluginDrawSettings / BsiPluginViewDraw. id must be unique within the plugin.
struct BsiUi
{
    uint32_t size;
    void*    ctx;
    void (*label)(void* ctx, const char* text);
    void (*hint)(void* ctx, const char* text);
    int  (*button)(void* ctx, const char* id, const char* label);
    int  (*checkbox)(void* ctx, const char* id, const char* label, int* value);
    int  (*input_text)(void* ctx, const char* id, char* buf, int cap);
    void (*spacing)(void* ctx);
    void (*section)(void* ctx, const char* title);

    // Additive (probe with BSI_UI_HAS).
    void (*same_line)(void* ctx);
    void (*separator)(void* ctx);
    int  (*begin_child)(void* ctx, const char* id, float w, float h);
    void (*end_child)(void* ctx);
    int  (*combo)(void* ctx, const char* id, int* index, const char* const* items, int count);
    int  (*selectable)(void* ctx, const char* id, const char* label, int selected);
    int  (*input_int)(void* ctx, const char* id, int* value);
    void (*dummy)(void* ctx, float w, float h);
    void (*progress)(void* ctx, float frac);
    void (*begin_disabled)(void* ctx, int disabled);
    void (*end_disabled)(void* ctx);
    void (*tooltip)(void* ctx, const char* text);
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

    // Host paths. key: exe, plugins, themes, languages, settings, assets,
    // python2, python3, lua, self (this DLL), data (writable per-plugin dir).
    int  (*path)(void* ctx, const char* key, char* out, int cap);

    // Per-plugin settings.json keys (stored as plugin.cfg.<id>.<key>).
    int  (*setting_get)(void* ctx, const char* key, char* out, int cap, const char* def);
    int  (*setting_set)(void* ctx, const char* key, const char* val);
    int  (*setting_get_int)(void* ctx, const char* key, int def);
    void (*setting_set_int)(void* ctx, const char* key, int val);
    int  (*setting_get_bool)(void* ctx, const char* key, int def);
    void (*setting_set_bool)(void* ctx, const char* key, int val);

    // Host JSON. Handle 0 is invalid. Path is JSON pointer (/a/b/0)
    // or dotted (a.b.0). json_dump returns bytes needed including NUL; if cap
    // is too small nothing is written.
    uint32_t (*json_parse)(void* ctx, const char* text, char* err, int err_cap);
    uint32_t (*json_new)(void* ctx);
    uint32_t (*json_load_file)(void* ctx, const char* path, char* err, int err_cap);
    int  (*json_save_file)(void* ctx, uint32_t h, const char* path);
    void (*json_free)(void* ctx, uint32_t h);
    int  (*json_has)(void* ctx, uint32_t h, const char* path);
    int  (*json_size)(void* ctx, uint32_t h, const char* path);
    int  (*json_get_string)(void* ctx, uint32_t h, const char* path, char* out, int cap);
    int  (*json_get_int)(void* ctx, uint32_t h, const char* path, int* out);
    int  (*json_get_bool)(void* ctx, uint32_t h, const char* path, int* out);
    int  (*json_set_string)(void* ctx, uint32_t h, const char* path, const char* val);
    int  (*json_set_int)(void* ctx, uint32_t h, const char* path, int val);
    int  (*json_set_bool)(void* ctx, uint32_t h, const char* path, int val);
    int  (*json_dump)(void* ctx, uint32_t h, char* out, int cap);

    // Additive (probe with BSI_HOST_HAS). Original v2 ends at json_dump.
    const char* (*host_name)(void* ctx);
    const char* (*host_version)(void* ctx);
    int  (*read_file)(void* ctx, const char* path, void* buf, uint32_t cap, uint32_t* out_n);
    int  (*open_dialog)(void* ctx, const char* ext, const char* title,
            char* out_path, int out_cap);
    void* (*mem_alloc)(void* ctx, uint32_t n);
    void  (*mem_free)(void* ctx, void* p);
    const char* (*i18n_get)(void* ctx, const char* key);
    int  (*hex_goto)(void* ctx, uint32_t file_off);
    int  (*hex_select)(void* ctx, uint32_t file_off, uint32_t size);
    int  (*clipboard_set)(void* ctx, const char* text);
    uint64_t (*tick_ms)(void* ctx);
    int  (*open_job)(void* ctx, const char* path);
    int  (*detection_count)(void* ctx);
    int  (*detection_at)(void* ctx, int index,
            char* product_key, int key_cap,
            char* product, int product_cap,
            char* vendor, int vendor_cap,
            int* category, int* confidence, int* score);
    int  (*rsrc_count)(void* ctx);
    int  (*rsrc_at)(void* ctx, int index,
            char* type_name, int type_cap, char* name, int name_cap,
            uint32_t* file_off, uint32_t* size, uint16_t* lang);
    int  (*section_count)(void* ctx);
    int  (*section_at)(void* ctx, int index,
            char* name, int name_cap,
            uint32_t* vaddr, uint32_t* vsize, uint32_t* rawptr, uint32_t* rawsize,
            uint32_t* chars);
    void (*toast)(void* ctx, int type, const char* title, const char* body);
};

// Original v2 block is present (through json_dump). Prefer this in Init.
static inline int BsiHostCompatible(const struct BsiHost* h)
{
    if (!h)
        return 0;
    if (h->abi_version < BSI_PLUGIN_ABI_MIN)
        return 0;
    if (h->size < (uint32_t)BSI_FIELD_END(struct BsiHost, json_dump))
        return 0;
    return 1;
}

/*
Required exports (stdcall-free C, exported by name):

  const BsiPluginInfo* BsiPluginGetInfo(void);
  int  BsiPluginInit(const BsiHost* host);   // 0 = ok
  void BsiPluginShutdown(void);

Optional (GetProcAddress; omit if unused):

  int  BsiPluginToolCount(void);
  int  BsiPluginToolInfo(int index, BsiToolInfo* out);
  int  BsiPluginToolRun(int index);

  int  BsiPluginViewCount(void);
  int  BsiPluginViewInfo(int index, BsiViewInfo* out);
  int  BsiPluginViewDraw(int index, const BsiUi* ui);  // 1 = drew

  int  BsiPluginHasSettings(void);                     // 1 = Settings > Plugins block
  void BsiPluginDrawSettings(const BsiUi* ui);

  void BsiPluginOnJob(int ready);                      // 1 = PE ready, 0 = closed/failed

  const BsiVisuals* BsiPluginVisuals(void);            // card icon/cover; size = sizeof(BsiVisuals)
*/

#ifdef __cplusplus
}
#endif
