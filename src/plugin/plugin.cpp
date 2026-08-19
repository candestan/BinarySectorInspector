#include "plugin/plugin.h"
#include "plugin/bsi_plugin_abi.h"
#include "app/app.h"
#include "app/version.h"
#include "pe/pe.h"
#include "pe/patch.h"
#include "log/log.h"
#include "persist/paths.h"
#include "persist/settings.h"
#include "runtime/scripting.h"
#include "i18n/i18n.h"
#include "ui/widgets.h"
#include "ui/theme.h"
#include "ui/hex_view.h"
#include "ui/tex.h"

#include "imgui.h"
#include "imnodes.h"
#include <nlohmann/json.hpp>

#include <windows.h>
#include <d3d11.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <vector>
#include <string>

static const int kMaxPlugins = 32;

typedef const BsiPluginInfo* (*FnGetInfo)(void);
typedef int  (*FnInit)(const BsiHost*);
typedef void (*FnShutdown)(void);
typedef int  (*FnToolCount)(void);
typedef int  (*FnToolInfo)(int, BsiToolInfo*);
typedef int  (*FnToolRun)(int);
typedef int  (*FnViewCount)(void);
typedef int  (*FnViewInfo)(int, BsiViewInfo*);
typedef int  (*FnViewDraw)(int, const BsiUi*);
typedef int  (*FnHasSettings)(void);
typedef void (*FnDrawSettings)(const BsiUi*);
typedef void (*FnOnJob)(int);
typedef const BsiVisuals* (*FnVisuals)(void);

struct PluginRec
{
    HMODULE h;
    char    path[MAX_PATH];
    char    id[96];
    char    name[80];
    char    version[32];
    char    author[80];
    char    description[256];
    char    err[160];
    uint32_t kinds;
    bool    enabled;
    bool    inited;
    BsiHost host;
    FnGetInfo   get_info;
    FnInit      init;
    FnShutdown  shutdown;
    FnToolCount tool_count;
    FnToolInfo  tool_info;
    FnToolRun   tool_run;
    FnViewCount view_count;
    FnViewInfo  view_info;
    FnViewDraw  view_draw;
    FnHasSettings has_settings;
    FnDrawSettings draw_settings;
    FnOnJob     on_job;
    FnVisuals   visuals;
    char    icon_path[MAX_PATH];
    char    cover_path[MAX_PATH];
    ID3D11ShaderResourceView* icon_srv;
    ID3D11ShaderResourceView* cover_srv;
    int     icon_w;
    int     icon_h;
    int     cover_w;
    int     cover_h;
    bool    icon_tried;
    bool    cover_tried;
};

static std::vector<PluginRec> g_plugins;
static bool g_inited;

// Plugins are third-party code in our address space. A fault there must not take the
// host down. __try needs a frame that does not unwind C++ objects, so every call
// across the ABI goes through these two instead of being invoked directly.
template <typename R, typename... A, typename... V>
static bool PlugCall(R* out, R (*fn)(A...), V... args)
{
    __try
    {
        *out = fn(args...);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

template <typename... A, typename... V>
static bool PlugCallVoid(void (*fn)(A...), V... args)
{
    __try
    {
        fn(args...);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static void PlugFaulted(PluginRec* p, const char* what)
{
    if (!p)
        return;
    snprintf(p->err, sizeof(p->err), "faulted in %s", what);
    p->inited = false;
    p->enabled = false;
    LogFor(LogBuiltinCore).Module("Plugin").Error("Disabled %s after a fault in %s", p->name, what);
}

static void EnableKey(const char* id, char* out, int cap)
{
    snprintf(out, cap, "plugin.enabled.%s", id ? id : "");
}

static void RecLog(void* ctx, int severity, const char* module, const char* message)
{
    PluginRec* p = (PluginRec*)ctx;
    if (!p || !message)
        return;
    LogScope s = LogPlugin(p->id, p->name[0] ? p->name : p->id);
    if (module && module[0])
        s = s.Module(module);
    switch (severity)
    {
    case BsiSevTrace:    s.Trace("%s", message); break;
    case BsiSevDebug:    s.Debug("%s", message); break;
    case BsiSevSuccess:  s.Success("%s", message); break;
    case BsiSevWarning:  s.Warning("%s", message); break;
    case BsiSevError:    s.Error("%s", message); break;
    case BsiSevCritical: s.Critical("%s", message); break;
    default:             s.Info("%s", message); break;
    }
}

static int RecReady(void*)
{
    return PeJobResult() && !PeJobBusy() ? 1 : 0;
}

static const char* RecJobPath(void*)
{
    return PeJobPath();
}

static const uint8_t* RecImage(void*, size_t* n)
{
    return PeJobBytes(n);
}

static void WalkMedia(const AnalysisArtifact& a, const char* media, std::vector<const AnalysisArtifact*>* out)
{
    if (media && a.media[0] && _stricmp(a.media, media) == 0)
        out->push_back(&a);
    for (const AnalysisArtifact& ch : a.children)
        WalkMedia(ch, media, out);
}

static int RecHasProduct(void*, const char* key)
{
    const PeFile* pe = PeJobResult();
    if (!pe || !key || !key[0])
        return 0;
    for (const DetectionResult& r : pe->detections)
    {
        if (_stricmp(r.product_key.c_str(), key) == 0)
            return 1;
    }
    return 0;
}

static int RecHasMedia(void*, const char* media)
{
    const PeFile* pe = PeJobResult();
    if (!pe || !media)
        return 0;
    std::vector<const AnalysisArtifact*> hits;
    for (const AnalysisArtifact& a : pe->analysis)
        WalkMedia(a, media, &hits);
    return hits.empty() ? 0 : 1;
}

static int RecHasRsrcName(void*, const char* name)
{
    const PeFile* pe = PeJobResult();
    if (!pe || !name || !name[0])
        return 0;
    for (const PeRsrcLeaf& L : pe->rsrc)
    {
        if (_stricmp(L.name, name) == 0)
            return 1;
    }
    return 0;
}

static int RecArtCount(void*, const char* media)
{
    const PeFile* pe = PeJobResult();
    if (!pe)
        return 0;
    std::vector<const AnalysisArtifact*> hits;
    for (const AnalysisArtifact& a : pe->analysis)
        WalkMedia(a, media, &hits);
    return (int)hits.size();
}

static int RecArtAt(void*, const char* media, int index,
    uint32_t* file_off, uint32_t* size, uint32_t* extra, uint32_t* extra2,
    char* label, int label_cap, int* is_main)
{
    const PeFile* pe = PeJobResult();
    if (!pe)
        return 0;
    std::vector<const AnalysisArtifact*> hits;
    for (const AnalysisArtifact& a : pe->analysis)
        WalkMedia(a, media, &hits);
    if (index < 0 || index >= (int)hits.size())
        return 0;
    const AnalysisArtifact* a = hits[(size_t)index];
    if (file_off) *file_off = a->file_off;
    if (size) *size = a->size;
    if (extra) *extra = a->extra;
    if (extra2) *extra2 = a->extra2;
    if (label && label_cap > 0)
        snprintf(label, label_cap, "%s", a->label);
    if (is_main) *is_main = a->flag_main ? 1 : 0;
    return 1;
}

static void FilterFromExt(const char* ext, wchar_t* out, int cap)
{
    memset(out, 0, (size_t)cap * sizeof(wchar_t));
    if (cap < 24)
        return;
    const char* e = ext;
    if (e && e[0] == '.')
        e++;
    if (!e || !e[0] || _stricmp(e, "*") == 0 || _stricmp(e, "all") == 0)
    {
        static const wchar_t k[] = L"All\0*.*\0";
        memcpy(out, k, sizeof(k));
        return;
    }
    wchar_t we[32]{};
    if (!MultiByteToWideChar(CP_UTF8, 0, e, -1, we, 32) || !we[0])
    {
        static const wchar_t k[] = L"All\0*.*\0";
        memcpy(out, k, sizeof(k));
        return;
    }
    wchar_t* p = out;
    wchar_t* end = out + cap - 2;
    auto put = [&](const wchar_t* s) {
        while (s && *s && p < end)
            *p++ = *s++;
    };
    put(we);
    if (p < end)
        *p++ = 0;
    if (p < end)
        *p++ = L'*';
    if (p < end)
        *p++ = L'.';
    put(we);
    if (p < end)
        *p++ = 0;
    put(L"All");
    if (p < end)
        *p++ = 0;
    put(L"*.*");
    if (p < end)
        *p++ = 0;
}

static int RecSaveDialog(void*, const char* ext, const char* title, const char* suggest,
    char* out_path, int out_cap)
{
    if (!out_path || out_cap < 8)
        return 0;
    wchar_t filter[160]{};
    wchar_t wtitle[80];
    FilterFromExt(ext, filter, 160);
    const char* t = title && title[0] ? title : "Export";
    if (!MultiByteToWideChar(CP_UTF8, 0, t, -1, wtitle, 80))
        wcscpy_s(wtitle, L"Export");
    char path[MAX_PATH];
    if (!AppPickSaveFilter(path, MAX_PATH, filter, wtitle, suggest && suggest[0] ? suggest : "export.bin"))
        return 0;
    snprintf(out_path, out_cap, "%s", path);
    return 1;
}

static int RecWriteFile(void*, const char* path, const void* data, uint32_t n)
{
    if (!path || !data)
        return 0;
    wchar_t wpath[MAX_PATH];
    if (!MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, MAX_PATH))
        return 0;
    HANDLE h = CreateFileW(wpath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return 0;
    DWORD wr = 0;
    BOOL ok = WriteFile(h, data, n, &wr, nullptr);
    CloseHandle(h);
    return ok && wr == n ? 1 : 0;
}

static const int kMaxJson = 64;
static nlohmann::json g_json[kMaxJson];
static uint8_t g_json_live[kMaxJson];

static uint32_t JsonAlloc(nlohmann::json&& j)
{
    for (int i = 0; i < kMaxJson; i++)
    {
        if (!g_json_live[i])
        {
            g_json[i] = std::move(j);
            g_json_live[i] = 1;
            return (uint32_t)(i + 1);
        }
    }
    return 0;
}

static nlohmann::json* JsonAt(uint32_t h)
{
    if (!h || h > (uint32_t)kMaxJson || !g_json_live[h - 1])
        return nullptr;
    return &g_json[h - 1];
}

static std::string JsonPtr(const char* path)
{
    if (!path || !path[0])
        return "";
    if (path[0] == '/')
        return path;
    std::string s = "/";
    for (const char* c = path; *c; c++)
        s.push_back(*c == '.' ? '/' : *c);
    return s;
}

static nlohmann::json* JsonWalk(uint32_t h, const char* path, bool create)
{
    nlohmann::json* j = JsonAt(h);
    if (!j)
        return nullptr;
    std::string p = JsonPtr(path);
    if (p.empty())
        return j;
    try
    {
        auto ptr = nlohmann::json::json_pointer(p);
        if (create)
            return &((*j)[ptr]);
        return &(j->at(ptr));
    }
    catch (...)
    {
        return nullptr;
    }
}

static int RecHostPath(void* ctx, const char* key, char* out, int cap)
{
    if (!out || cap < 4)
        return 0;
    out[0] = 0;
    if (!key || !key[0])
        return 0;
    PluginRec* p = (PluginRec*)ctx;
    if (_stricmp(key, "exe") == 0)
        PathsExeDir(out, cap);
    else if (_stricmp(key, "plugins") == 0)
        PathsBesideExe(out, cap, "plugins");
    else if (_stricmp(key, "themes") == 0)
        PathsThemesDir(out, cap);
    else if (_stricmp(key, "languages") == 0)
        PathsLanguagesDir(out, cap);
    else if (_stricmp(key, "settings") == 0)
        PathsSettingsFile(out, cap);
    else if (_stricmp(key, "assets") == 0)
        PathsBesideExe(out, cap, "assets");
    else if (_stricmp(key, "python2") == 0)
        ScriptingPyGet(2, out, cap);
    else if (_stricmp(key, "python3") == 0)
        ScriptingPyGet(3, out, cap);
    else if (_stricmp(key, "lua") == 0)
        ScriptingLuaGet(out, cap);
    else if (_stricmp(key, "self") == 0 && p)
        snprintf(out, cap, "%s", p->path);
    else if (_stricmp(key, "data") == 0 && p && p->id[0])
    {
        int ok = 1;
        for (const char* c = p->id; *c; c++)
        {
            if (!isalnum((unsigned char)*c) && *c != '.' && *c != '_' && *c != '-')
            {
                ok = 0;
                break;
            }
        }
        if (!ok)
            return 0;
        char root[MAX_PATH];
        PathsBesideExe(root, MAX_PATH, "plugins\\data");
        CreateDirectoryA(root, nullptr);
        char rel[MAX_PATH];
        snprintf(rel, sizeof(rel), "plugins\\data\\%s", p->id);
        PathsBesideExe(out, cap, rel);
        CreateDirectoryA(out, nullptr);
        size_t n = strlen(out);
        if (n && out[n - 1] != '\\' && (int)n + 2 < cap)
        {
            out[n] = '\\';
            out[n + 1] = 0;
        }
    }
    else
        return 0;
    return out[0] ? 1 : 0;
}

static int CfgKey(PluginRec* p, const char* key, char* out, int cap)
{
    if (!p || !key || !key[0] || !out || cap < 8)
        return 0;
    if (strchr(key, '\\') || strstr(key, ".."))
        return 0;
    snprintf(out, cap, "plugin.cfg.%s.%s", p->id, key);
    return 1;
}

static int RecSettingGet(void* ctx, const char* key, char* out, int cap, const char* def)
{
    char full[192];
    if (!CfgKey((PluginRec*)ctx, key, full, (int)sizeof(full)))
        return 0;
    return SettingsGetString(full, out, cap, def ? def : "") ? 1 : 0;
}

static int RecSettingSet(void* ctx, const char* key, const char* val)
{
    char full[192];
    if (!CfgKey((PluginRec*)ctx, key, full, (int)sizeof(full)))
        return 0;
    SettingsSetString(full, val ? val : "");
    return 1;
}

static int RecSettingGetInt(void* ctx, const char* key, int def)
{
    char full[192];
    if (!CfgKey((PluginRec*)ctx, key, full, (int)sizeof(full)))
        return def;
    return SettingsGetInt(full, def);
}

static void RecSettingSetInt(void* ctx, const char* key, int val)
{
    char full[192];
    if (!CfgKey((PluginRec*)ctx, key, full, (int)sizeof(full)))
        return;
    SettingsSetInt(full, val);
}

static int RecSettingGetBool(void* ctx, const char* key, int def)
{
    char full[192];
    if (!CfgKey((PluginRec*)ctx, key, full, (int)sizeof(full)))
        return def;
    return SettingsGetBool(full, def != 0) ? 1 : 0;
}

static void RecSettingSetBool(void* ctx, const char* key, int val)
{
    char full[192];
    if (!CfgKey((PluginRec*)ctx, key, full, (int)sizeof(full)))
        return;
    SettingsSetBool(full, val != 0);
}

static uint32_t RecJsonParse(void*, const char* text, char* err, int err_cap)
{
    if (err && err_cap)
        err[0] = 0;
    if (!text)
    {
        if (err && err_cap)
            snprintf(err, err_cap, "empty");
        return 0;
    }
    try
    {
        return JsonAlloc(nlohmann::json::parse(text));
    }
    catch (const std::exception& e)
    {
        if (err && err_cap)
            snprintf(err, err_cap, "%s", e.what());
        return 0;
    }
}

static uint32_t RecJsonNew(void*)
{
    return JsonAlloc(nlohmann::json::object());
}

static uint32_t RecJsonLoadFile(void* ctx, const char* path, char* err, int err_cap)
{
    if (err && err_cap)
        err[0] = 0;
    char* text = nullptr;
    int n = 0;
    if (!PathsReadFile(path, &text, &n) || !text)
    {
        if (err && err_cap)
            snprintf(err, err_cap, "read failed");
        return 0;
    }
    uint32_t h = RecJsonParse(ctx, text, err, err_cap);
    free(text);
    return h;
}

static int RecJsonSaveFile(void*, uint32_t h, const char* path)
{
    nlohmann::json* j = JsonAt(h);
    if (!j || !path)
        return 0;
    std::string s = j->dump(2);
    return RecWriteFile(nullptr, path, s.c_str(), (uint32_t)s.size());
}

static void RecJsonFree(void*, uint32_t h)
{
    if (!h || h > (uint32_t)kMaxJson)
        return;
    g_json[h - 1] = nlohmann::json();
    g_json_live[h - 1] = 0;
}

static int RecJsonHas(void*, uint32_t h, const char* path)
{
    return JsonWalk(h, path, false) ? 1 : 0;
}

static int RecJsonSize(void*, uint32_t h, const char* path)
{
    nlohmann::json* n = JsonWalk(h, path, false);
    if (!n)
        return 0;
    if (n->is_array() || n->is_object())
        return (int)n->size();
    return 0;
}

static int RecJsonGetString(void*, uint32_t h, const char* path, char* out, int cap)
{
    if (!out || cap < 2)
        return 0;
    out[0] = 0;
    nlohmann::json* n = JsonWalk(h, path, false);
    if (!n)
        return 0;
    try
    {
        if (n->is_string())
            snprintf(out, cap, "%s", n->get<std::string>().c_str());
        else if (n->is_number_integer())
            snprintf(out, cap, "%d", n->get<int>());
        else if (n->is_boolean())
            snprintf(out, cap, "%s", n->get<bool>() ? "true" : "false");
        else
            snprintf(out, cap, "%s", n->dump().c_str());
        return 1;
    }
    catch (...)
    {
        return 0;
    }
}

static int RecJsonGetInt(void*, uint32_t h, const char* path, int* out)
{
    nlohmann::json* n = JsonWalk(h, path, false);
    if (!n || !out)
        return 0;
    try
    {
        if (n->is_number_integer())
            *out = n->get<int>();
        else if (n->is_number())
            *out = (int)n->get<double>();
        else if (n->is_boolean())
            *out = n->get<bool>() ? 1 : 0;
        else
            return 0;
        return 1;
    }
    catch (...)
    {
        return 0;
    }
}

static int RecJsonGetBool(void*, uint32_t h, const char* path, int* out)
{
    nlohmann::json* n = JsonWalk(h, path, false);
    if (!n || !out)
        return 0;
    try
    {
        if (n->is_boolean())
            *out = n->get<bool>() ? 1 : 0;
        else if (n->is_number())
            *out = n->get<int>() != 0 ? 1 : 0;
        else
            return 0;
        return 1;
    }
    catch (...)
    {
        return 0;
    }
}

static int RecJsonSetString(void*, uint32_t h, const char* path, const char* val)
{
    nlohmann::json* n = JsonWalk(h, path, true);
    if (!n)
        return 0;
    *n = val ? val : "";
    return 1;
}

static int RecJsonSetInt(void*, uint32_t h, const char* path, int val)
{
    nlohmann::json* n = JsonWalk(h, path, true);
    if (!n)
        return 0;
    *n = val;
    return 1;
}

static int RecJsonSetBool(void*, uint32_t h, const char* path, int val)
{
    nlohmann::json* n = JsonWalk(h, path, true);
    if (!n)
        return 0;
    *n = val != 0;
    return 1;
}

static int RecJsonDump(void*, uint32_t h, char* out, int cap)
{
    nlohmann::json* j = JsonAt(h);
    if (!j)
        return 0;
    std::string s = j->dump(2);
    int need = (int)s.size() + 1;
    if (!out || cap < need)
        return need;
    snprintf(out, cap, "%s", s.c_str());
    return need;
}

static const char* RecHostName(void*)
{
    return "BinarySectorInspector";
}

static const char* RecHostVersion(void*)
{
    return VersionString();
}

static int RecReadFile(void*, const char* path, void* buf, uint32_t cap, uint32_t* out_n)
{
    if (out_n)
        *out_n = 0;
    if (!path || !path[0])
        return 0;
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return 0;
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart < 0 || sz.QuadPart > 64 * 1024 * 1024)
    {
        CloseHandle(h);
        return 0;
    }
    uint32_t n = (uint32_t)sz.QuadPart;
    if (out_n)
        *out_n = n;
    if (!buf)
    {
        CloseHandle(h);
        return 1;
    }
    if (cap < n)
    {
        CloseHandle(h);
        return 0;
    }
    DWORD rd = 0;
    BOOL ok = ReadFile(h, buf, n, &rd, nullptr);
    CloseHandle(h);
    return ok && rd == n ? 1 : 0;
}

static int RecOpenDialog(void*, const char* ext, const char* title, char* out_path, int out_cap)
{
    if (!out_path || out_cap < 8)
        return 0;
    wchar_t filter[160]{};
    wchar_t wtitle[80];
    FilterFromExt(ext, filter, 160);
    const char* t = title && title[0] ? title : "Open";
    if (!MultiByteToWideChar(CP_UTF8, 0, t, -1, wtitle, 80))
        wcscpy_s(wtitle, L"Open");
    char path[MAX_PATH];
    if (!AppPickOpenFilter(path, MAX_PATH, filter, wtitle))
        return 0;
    snprintf(out_path, out_cap, "%s", path);
    return 1;
}

static void* RecMemAlloc(void*, uint32_t n)
{
    if (!n)
        return nullptr;
    return malloc(n);
}

static void RecMemFree(void*, void* p)
{
    free(p);
}

static const char* RecI18nGet(void*, const char* key)
{
    return I18nGet(key ? key : "");
}

static int RecHexGoto(void*, uint32_t file_off)
{
    HexViewGoto((size_t)file_off);
    return 1;
}

static int RecHexSelect(void*, uint32_t file_off, uint32_t size)
{
    HexViewSelect((size_t)file_off, (size_t)size);
    return 1;
}

static int RecClipboardSet(void*, const char* text)
{
    if (!text)
        return 0;
    ImGui::SetClipboardText(text);
    return 1;
}

static uint64_t RecTickMs(void*)
{
    return GetTickCount64();
}

static int RecOpenJob(void*, const char* path)
{
    if (!path || !path[0])
        return 0;
    AppOpenPath(path);
    return 1;
}

static int RecDetectCount(void*)
{
    const PeFile* pe = PeJobResult();
    return pe ? (int)pe->detections.size() : 0;
}

static int RecDetectAt(void*, int index,
    char* product_key, int key_cap,
    char* product, int product_cap,
    char* vendor, int vendor_cap,
    int* category, int* confidence, int* score)
{
    const PeFile* pe = PeJobResult();
    if (!pe || index < 0 || index >= (int)pe->detections.size())
        return 0;
    const DetectionResult& r = pe->detections[(size_t)index];
    if (product_key && key_cap > 0)
        snprintf(product_key, key_cap, "%s", r.product_key.c_str());
    if (product && product_cap > 0)
        snprintf(product, product_cap, "%s", r.product.c_str());
    if (vendor && vendor_cap > 0)
        snprintf(vendor, vendor_cap, "%s", r.vendor.c_str());
    if (category)
        *category = (int)r.category;
    if (confidence)
        *confidence = (int)r.confidence;
    if (score)
        *score = r.score;
    return 1;
}

static int RecRsrcCount(void*)
{
    const PeFile* pe = PeJobResult();
    return pe ? (int)pe->rsrc.size() : 0;
}

static int RecRsrcAt(void*, int index,
    char* type_name, int type_cap, char* name, int name_cap,
    uint32_t* file_off, uint32_t* size, uint16_t* lang)
{
    const PeFile* pe = PeJobResult();
    if (!pe || index < 0 || index >= (int)pe->rsrc.size())
        return 0;
    const PeRsrcLeaf& L = pe->rsrc[(size_t)index];
    if (type_name && type_cap > 0)
        snprintf(type_name, type_cap, "%s", L.type_name);
    if (name && name_cap > 0)
        snprintf(name, name_cap, "%s", L.name);
    if (file_off)
        *file_off = L.file_off;
    if (size)
        *size = L.size;
    if (lang)
        *lang = L.lang;
    return 1;
}

static int RecSectionCount(void*)
{
    const PeFile* pe = PeJobResult();
    return pe ? pe->section_n : 0;
}

static int RecSectionAt(void*, int index,
    char* name, int name_cap,
    uint32_t* vaddr, uint32_t* vsize, uint32_t* rawptr, uint32_t* rawsize,
    uint32_t* chars)
{
    const PeFile* pe = PeJobResult();
    if (!pe || index < 0 || index >= pe->section_n)
        return 0;
    const PeSection& s = pe->sections[index];
    if (name && name_cap > 0)
        snprintf(name, name_cap, "%s", s.name);
    if (vaddr)
        *vaddr = s.vaddr;
    if (vsize)
        *vsize = s.vsize;
    if (rawptr)
        *rawptr = s.rawptr;
    if (rawsize)
        *rawsize = s.rawsize;
    if (chars)
        *chars = s.chars;
    return 1;
}

static uint16_t RecPeMachine(void*)
{
    const PeFile* pe = PeJobResult();
    return pe ? pe->machine : 0;
}

static uint64_t RecImageBase(void*)
{
    const PeFile* pe = PeJobResult();
    return pe ? pe->image_base : 0;
}

static uint32_t RecEntryRva(void*)
{
    const PeFile* pe = PeJobResult();
    return pe ? pe->entry_rva : 0;
}

static int RecRvaToOff(void*, uint32_t rva, uint32_t* file_off)
{
    const PeFile* pe = PeJobResult();
    if (!pe || !file_off)
        return 0;
    uint32_t off = PeImageRvaToOff(pe, rva);
    if (!off && rva)
        return 0;
    *file_off = off;
    return 1;
}

static int RecOffToRva(void*, uint32_t file_off, uint32_t* rva)
{
    const PeFile* pe = PeJobResult();
    if (!pe || !rva)
        return 0;
    *rva = PeFileOffToRva(pe, file_off);
    return 1;
}

static int RecHexCursor(void*, uint32_t* file_off, uint32_t* size)
{
    size_t off = 0;
    size_t n = 0;
    if (!HexViewCursor(&off, &n))
    {
        if (file_off)
            *file_off = 0;
        if (size)
            *size = 0;
        return 0;
    }
    if (file_off)
        *file_off = (uint32_t)off;
    if (size)
        *size = (uint32_t)n;
    return 1;
}

static void RecToast(void*, int type, const char* title, const char* body)
{
    UiToastType t = UiToastInfo;
    if (type == BsiToastSuccess)
        t = UiToastSuccess;
    else if (type == BsiToastWarning)
        t = UiToastWarning;
    else if (type == BsiToastError)
        t = UiToastError;
    UiToastPush(t, title, body);
}

static void* RecThemeFontMono(void*)
{
    return ThemeFontMono();
}

static uint32_t RecThemeCodeColor(void*, uint32_t token_kind)
{
    switch (token_kind)
    {
    case BsiTokKeyword: return ThemeColAccent();
    case BsiTokMnemonic: return ThemeColFg();
    case BsiTokBytes: return ThemeColMuted();
    case BsiTokType: return ThemeColInfo();
    case BsiTokFunction: return ThemeColAccent();
    case BsiTokImport: return ThemeColAccent();
    case BsiTokVariable: return ThemeColMuted();
    case BsiTokParameter: return ThemeColMuted();
    case BsiTokRegister: return ThemeColFg();
    case BsiTokImmediate:
    case BsiTokNumber:
        return ThemeColInfo();
    case BsiTokAddress:
        return ThemeColMuted();
    case BsiTokString:
        return ThemeColSuccess();
    case BsiTokComment:
        return ThemeColMuted();
    case BsiTokOperator:
        return ThemeColFg();
    case BsiTokLabel:
    case BsiTokBranch:
        return ThemeColWarning();
    case BsiTokField:
        return ThemeColMuted();
    case BsiTokNamespace:
        return ThemeColInfo();
    case BsiTokSymbol:
        return ThemeColAccent();
    default:
        return ThemeColFg();
    }
}

static char g_prog_id[80];
static char g_prog_title[96];
static char g_prog_stage[160];
static float g_prog_frac;
static int g_prog_cancel;

static void RecProgressSet(void*, const char* task_id, const char* title, const char* stage, float frac)
{
    snprintf(g_prog_id, sizeof(g_prog_id), "%s", task_id ? task_id : "");
    snprintf(g_prog_title, sizeof(g_prog_title), "%s", title ? title : "");
    snprintf(g_prog_stage, sizeof(g_prog_stage), "%s", stage ? stage : "");
    g_prog_frac = frac;
}

static void RecProgressClear(void*, const char* task_id)
{
    if (task_id && g_prog_id[0] && strcmp(g_prog_id, task_id) != 0)
        return;
    g_prog_id[0] = 0;
    g_prog_title[0] = 0;
    g_prog_stage[0] = 0;
    g_prog_frac = 0.f;
    g_prog_cancel = 0;
}

static int RecProgressWantCancel(void*, const char* task_id)
{
    if (task_id && g_prog_id[0] && strcmp(g_prog_id, task_id) != 0)
        return 0;
    return g_prog_cancel;
}

static uint64_t RecImageEpoch(void*)
{
    return PatchStateEpoch();
}

static int RecImageDirty(void*)
{
    return PeJobDirty() ? 1 : 0;
}

static void* RecImguiContext(void*)
{
    return ImGui::GetCurrentContext();
}

static void RecImguiAllocators(void*, void** alloc_fn, void** free_fn, void** user_data)
{
    ImGuiMemAllocFunc a = nullptr;
    ImGuiMemFreeFunc fr = nullptr;
    void* user = nullptr;
    ImGui::GetAllocatorFunctions(&a, &fr, &user);
    if (alloc_fn)
        *alloc_fn = (void*)a;
    if (free_fn)
        *free_fn = (void*)fr;
    if (user_data)
        *user_data = user;
}

static const char* RecImguiVersion(void*)
{
    return ImGui::GetVersion();
}

static const char* RecImguiCompileFlags(void*)
{
    return "IMGUI_USE_WCHAR32;IMGUI_ENABLE_FREETYPE";
}

static void* RecImnodesContext(void*)
{
    return ImNodes::GetCurrentContext();
}

static void UiLabel(void*, const char* text)
{
    if (text)
        ImGui::TextUnformatted(text);
}

static void UiHint(void*, const char* text)
{
    if (!text)
        return;
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    ImGui::TextWrapped("%s", text);
    ImGui::PopStyleColor();
}

static int UiBtn(void*, const char* id, const char* label)
{
    ImGui::PushID(id ? id : "btn");
    int hit = UiButton(label ? label : "", ImVec2(0, 0)) ? 1 : 0;
    ImGui::PopID();
    return hit;
}

static int UiCheck(void*, const char* id, const char* label, int* value)
{
    if (!value)
        return 0;
    bool v = *value != 0;
    int ch = UiCheckbox(id ? id : "chk", label ? label : "", &v) ? 1 : 0;
    int nv = v ? 1 : 0;
    int changed = (*value != nv) ? 1 : 0;
    *value = nv;
    return ch && changed ? 1 : 0;
}

static int UiInput(void*, const char* id, char* buf, int cap)
{
    if (!buf || cap < 2)
        return 0;
    ImGui::SetNextItemWidth(-1.f);
    return ImGui::InputText(id ? id : "##in", buf, (size_t)cap) ? 1 : 0;
}

static void UiSpc(void*)
{
    ImGui::Spacing();
}

static void UiSec(void*, const char* title)
{
    UiSection(title ? title : "");
}

static void UiSameLine(void*)
{
    ImGui::SameLine();
}

static void UiSep(void*)
{
    ImGui::Separator();
}

static int UiBeginChild(void*, const char* id, float w, float h)
{
    return ImGui::BeginChild(id ? id : "##ch", ImVec2(w, h), ImGuiChildFlags_Borders) ? 1 : 0;
}

static void UiEndChild(void*)
{
    ImGui::EndChild();
}

static int UiCombo(void*, const char* id, int* index, const char* const* items, int count)
{
    if (!index || !items || count <= 0)
        return 0;
    if (*index < 0 || *index >= count)
        *index = 0;
    int prev = *index;
    const char* preview = items[*index] ? items[*index] : "";
    if (ImGui::BeginCombo(id ? id : "##combo", preview))
    {
        for (int i = 0; i < count; i++)
        {
            bool sel = (i == *index);
            if (ImGui::Selectable(items[i] ? items[i] : "", sel))
                *index = i;
            if (sel)
                ImGui::SetItemDefaultFocus();
        }
        ImGui::EndCombo();
    }
    return *index != prev ? 1 : 0;
}

static int UiSelectable(void*, const char* id, const char* label, int selected)
{
    ImGui::PushID(id ? id : "sel");
    int hit = ImGui::Selectable(label ? label : "", selected != 0) ? 1 : 0;
    ImGui::PopID();
    return hit;
}

static int UiInputInt(void*, const char* id, int* value)
{
    if (!value)
        return 0;
    ImGui::SetNextItemWidth(-1.f);
    return ImGui::InputInt(id ? id : "##i", value) ? 1 : 0;
}

static void UiDummy(void*, float w, float h)
{
    ImGui::Dummy(ImVec2(w, h));
}

static void UiProgress(void*, float frac)
{
    ImGui::ProgressBar(frac, ImVec2(-1.f, 0.f));
}

static void UiBeginDisabled(void*, int disabled)
{
    ImGui::BeginDisabled(disabled != 0);
}

static void UiEndDisabled(void*)
{
    ImGui::EndDisabled();
}

static void UiTip(void*, const char* text)
{
    if (text && text[0])
        UiTooltip(text);
}

static void FillUi(BsiUi* ui)
{
    memset(ui, 0, sizeof(*ui));
    ui->size = (uint32_t)sizeof(BsiUi);
    ui->label = UiLabel;
    ui->hint = UiHint;
    ui->button = UiBtn;
    ui->checkbox = UiCheck;
    ui->input_text = UiInput;
    ui->spacing = UiSpc;
    ui->section = UiSec;
    ui->same_line = UiSameLine;
    ui->separator = UiSep;
    ui->begin_child = UiBeginChild;
    ui->end_child = UiEndChild;
    ui->combo = UiCombo;
    ui->selectable = UiSelectable;
    ui->input_int = UiInputInt;
    ui->dummy = UiDummy;
    ui->progress = UiProgress;
    ui->begin_disabled = UiBeginDisabled;
    ui->end_disabled = UiEndDisabled;
    ui->tooltip = UiTip;
    ui->imgui = ImGui::GetCurrentContext();
    ui->imnodes = ImNodes::GetCurrentContext();
}

static void FillHost(PluginRec* p)
{
    memset(&p->host, 0, sizeof(p->host));
    p->host.size = (uint32_t)sizeof(BsiHost);
    p->host.abi_version = BSI_PLUGIN_ABI_VERSION;
    p->host.ctx = p;
    p->host.log = RecLog;
    p->host.job_ready = RecReady;
    p->host.job_path = RecJobPath;
    p->host.image = RecImage;
    p->host.has_product = RecHasProduct;
    p->host.has_media = RecHasMedia;
    p->host.has_rsrc_name = RecHasRsrcName;
    p->host.artifact_count = RecArtCount;
    p->host.artifact_at = RecArtAt;
    p->host.save_dialog = RecSaveDialog;
    p->host.write_file = RecWriteFile;
    p->host.path = RecHostPath;
    p->host.setting_get = RecSettingGet;
    p->host.setting_set = RecSettingSet;
    p->host.setting_get_int = RecSettingGetInt;
    p->host.setting_set_int = RecSettingSetInt;
    p->host.setting_get_bool = RecSettingGetBool;
    p->host.setting_set_bool = RecSettingSetBool;
    p->host.json_parse = RecJsonParse;
    p->host.json_new = RecJsonNew;
    p->host.json_load_file = RecJsonLoadFile;
    p->host.json_save_file = RecJsonSaveFile;
    p->host.json_free = RecJsonFree;
    p->host.json_has = RecJsonHas;
    p->host.json_size = RecJsonSize;
    p->host.json_get_string = RecJsonGetString;
    p->host.json_get_int = RecJsonGetInt;
    p->host.json_get_bool = RecJsonGetBool;
    p->host.json_set_string = RecJsonSetString;
    p->host.json_set_int = RecJsonSetInt;
    p->host.json_set_bool = RecJsonSetBool;
    p->host.json_dump = RecJsonDump;
    p->host.host_name = RecHostName;
    p->host.host_version = RecHostVersion;
    p->host.read_file = RecReadFile;
    p->host.open_dialog = RecOpenDialog;
    p->host.mem_alloc = RecMemAlloc;
    p->host.mem_free = RecMemFree;
    p->host.i18n_get = RecI18nGet;
    p->host.hex_goto = RecHexGoto;
    p->host.hex_select = RecHexSelect;
    p->host.clipboard_set = RecClipboardSet;
    p->host.tick_ms = RecTickMs;
    p->host.open_job = RecOpenJob;
    p->host.detection_count = RecDetectCount;
    p->host.detection_at = RecDetectAt;
    p->host.rsrc_count = RecRsrcCount;
    p->host.rsrc_at = RecRsrcAt;
    p->host.section_count = RecSectionCount;
    p->host.section_at = RecSectionAt;
    p->host.pe_machine = RecPeMachine;
    p->host.image_base = RecImageBase;
    p->host.entry_rva = RecEntryRva;
    p->host.rva_to_off = RecRvaToOff;
    p->host.off_to_rva = RecOffToRva;
    p->host.hex_cursor = RecHexCursor;
    p->host.toast = RecToast;
    p->host.imgui_context = RecImguiContext;
    p->host.imgui_get_allocators = RecImguiAllocators;
    p->host.imgui_version = RecImguiVersion;
    p->host.imgui_compile_flags = RecImguiCompileFlags;
    p->host.imnodes_context = RecImnodesContext;

    // Additive: semantic code rendering + patch/byte invalidation helpers.
    p->host.theme_font_mono = RecThemeFontMono;
    p->host.theme_code_color = RecThemeCodeColor;
    p->host.image_epoch = RecImageEpoch;
    p->host.image_dirty = RecImageDirty;
    p->host.progress_set = RecProgressSet;
    p->host.progress_clear = RecProgressClear;
    p->host.progress_want_cancel = RecProgressWantCancel;
}

static void ReleaseSrv(ID3D11ShaderResourceView** srv)
{
    if (srv && *srv)
    {
        (*srv)->Release();
        *srv = nullptr;
    }
}

static void DllDir(const char* dll, char* out, int cap)
{
    if (!out || cap < 4)
        return;
    out[0] = 0;
    if (!dll || !dll[0])
        return;
    snprintf(out, cap, "%s", dll);
    char* slash = strrchr(out, '\\');
    if (!slash)
        slash = strrchr(out, '/');
    if (slash)
        slash[1] = 0;
    else
        out[0] = 0;
}

static int PathIsUrl(const char* p)
{
    return p && (_strnicmp(p, "http://", 7) == 0 || _strnicmp(p, "https://", 8) == 0);
}

static int PathOkSpec(const char* p)
{
    if (!p || !p[0] || PathIsUrl(p) || strstr(p, ".."))
        return 0;
    return 1;
}

static int PathIsAbs(const char* p)
{
    if (!p || !p[0])
        return 0;
    if (p[0] == '\\' || p[0] == '/')
        return 1;
    if (p[1] == ':')
        return 1;
    return 0;
}

static int ResolveLocal(const char* dll, const char* spec, char* out, int cap)
{
    if (!out || cap < 8 || !PathOkSpec(spec))
        return 0;
    out[0] = 0;
    if (PathIsAbs(spec))
        snprintf(out, cap, "%s", spec);
    else
    {
        char dir[MAX_PATH];
        DllDir(dll, dir, MAX_PATH);
        snprintf(out, cap, "%s%s", dir, spec);
    }
    DWORD attr = GetFileAttributesA(out);
    return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0;
}

static int TryDefaultVisual(const char* dll, const char* stem, char* out, int cap)
{
    static const char* kExt[] = { ".png", ".jpg", ".jpeg", ".webp", ".bmp", nullptr };
    char dir[MAX_PATH];
    DllDir(dll, dir, MAX_PATH);
    for (int i = 0; kExt[i]; i++)
    {
        char rel[96];
        snprintf(rel, sizeof(rel), "%s%s", stem, kExt[i]);
        if (ResolveLocal(dll, rel, out, cap))
            return 1;
    }
    return 0;
}

static void TakeSpec(PluginRec* p, const char* spec, char* dest, int cap, int cover)
{
    (void)cover;
    if (!p || dest[0] || !spec || !spec[0])
        return;
    char abs[MAX_PATH];
    if (ResolveLocal(p->path, spec, abs, MAX_PATH))
        snprintf(dest, cap, "%s", abs);
}

static void AttachVisuals(PluginRec* p)
{
    if (!p)
        return;
    p->icon_path[0] = 0;
    p->cover_path[0] = 0;
    if (p->visuals)
    {
        const BsiVisuals* v = nullptr;
        if (!PlugCall(&v, p->visuals))
            v = nullptr;
        if (v && v->size >= (uint32_t)BSI_FIELD_END(struct BsiVisuals, icon))
            TakeSpec(p, v->icon, p->icon_path, (int)sizeof(p->icon_path), 0);
        if (v && v->size >= (uint32_t)BSI_FIELD_END(struct BsiVisuals, cover))
            TakeSpec(p, v->cover, p->cover_path, (int)sizeof(p->cover_path), 1);
    }
    char dir[MAX_PATH];
    DllDir(p->path, dir, MAX_PATH);
    const char* json_names[] = { "plugin.json", "tool.json", nullptr };
    for (int i = 0; json_names[i]; i++)
    {
        char f[MAX_PATH];
        snprintf(f, sizeof(f), "%s%s", dir, json_names[i]);
        char* text = nullptr;
        int n = 0;
        if (!PathsReadFile(f, &text, &n) || !text)
            continue;
        try
        {
            nlohmann::json j = nlohmann::json::parse(text);
            if (!p->icon_path[0] && j.contains("icon") && j["icon"].is_string())
                TakeSpec(p, j["icon"].get<std::string>().c_str(), p->icon_path, (int)sizeof(p->icon_path), 0);
            if (!p->cover_path[0] && j.contains("cover") && j["cover"].is_string())
                TakeSpec(p, j["cover"].get<std::string>().c_str(), p->cover_path, (int)sizeof(p->cover_path), 1);
        }
        catch (...)
        {
        }
        free(text);
    }
    if (!p->icon_path[0])
        TryDefaultVisual(p->path, "icon", p->icon_path, (int)sizeof(p->icon_path));
    if (!p->cover_path[0])
        TryDefaultVisual(p->path, "cover", p->cover_path, (int)sizeof(p->cover_path));
}

static void* LazyTex(PluginRec* p, int cover, int* w, int* h)
{
    if (!p)
        return nullptr;
    char* path = cover ? p->cover_path : p->icon_path;
    bool* tried = cover ? &p->cover_tried : &p->icon_tried;
    ID3D11ShaderResourceView** srv = cover ? &p->cover_srv : &p->icon_srv;
    int* ow = cover ? &p->cover_w : &p->icon_w;
    int* oh = cover ? &p->cover_h : &p->icon_h;
    if (!path[0])
        return nullptr;
    if (!*tried)
    {
        *tried = true;
        TexLoadFile(path, srv, ow, oh);
    }
    if (w)
        *w = *ow;
    if (h)
        *h = *oh;
    return *srv;
}

static void UnloadOne(PluginRec& p)
{
    if (p.inited && p.shutdown && !PlugCallVoid(p.shutdown))
        PlugFaulted(&p, "shutdown");
    p.inited = false;
    ReleaseSrv(&p.icon_srv);
    ReleaseSrv(&p.cover_srv);
    if (p.h)
        FreeLibrary(p.h);
    p.h = nullptr;
}

static bool LoadDll(const char* path)
{
    if (!path || !path[0] || (int)g_plugins.size() >= kMaxPlugins)
        return false;
    for (const PluginRec& have : g_plugins)
    {
        if (_stricmp(have.path, path) == 0)
            return false;
    }
    // Pin where the plugin's own dependencies may come from: its own folder, the exe
    // folder (bsi_imgui.dll), and System32. Never the cwd or PATH.
    HMODULE h = LoadLibraryExA(path, nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!h)
    {
        auto log = LogFor(LogBuiltinCore).Module("Plugin");
        log.Warning("LoadLibrary failed %s (%u)", path, GetLastError());
        return false;
    }
    auto get_info = (FnGetInfo)GetProcAddress(h, "BsiPluginGetInfo");
    if (!get_info)
    {
        auto log = LogFor(LogBuiltinCore).Module("Plugin");
        log.Warning("Skipped %s (no BsiPluginGetInfo)", path);
        FreeLibrary(h);
        return false;
    }
    const BsiPluginInfo* info = nullptr;
    if (!PlugCall(&info, get_info))
    {
        auto log = LogFor(LogBuiltinCore).Module("Plugin");
        log.Warning("Skipped %s (fault in BsiPluginGetInfo)", path);
        FreeLibrary(h);
        return false;
    }
    if (!info || !info->id || !info->id[0] ||
        info->abi_version < BSI_PLUGIN_ABI_MIN ||
        info->abi_version > BSI_PLUGIN_ABI_VERSION)
    {
        auto log = LogFor(LogBuiltinCore).Module("Plugin");
        log.Warning("Skipped %s (missing info or ABI %u not in %u..%u)",
            path, info ? info->abi_version : 0, BSI_PLUGIN_ABI_MIN, BSI_PLUGIN_ABI_VERSION);
        FreeLibrary(h);
        return false;
    }
    PluginRec p{};
    p.h = h;
    snprintf(p.path, sizeof(p.path), "%s", path);
    snprintf(p.id, sizeof(p.id), "%s", info->id);
    snprintf(p.name, sizeof(p.name), "%s", info->name ? info->name : info->id);
    snprintf(p.version, sizeof(p.version), "%s", info->version ? info->version : "");
    snprintf(p.author, sizeof(p.author), "%s", info->author ? info->author : "");
    snprintf(p.description, sizeof(p.description), "%s", info->description ? info->description : "");
    p.kinds = info->kinds;
    p.get_info = get_info;
    p.init = (FnInit)GetProcAddress(h, "BsiPluginInit");
    p.shutdown = (FnShutdown)GetProcAddress(h, "BsiPluginShutdown");
    p.tool_count = (FnToolCount)GetProcAddress(h, "BsiPluginToolCount");
    p.tool_info = (FnToolInfo)GetProcAddress(h, "BsiPluginToolInfo");
    p.tool_run = (FnToolRun)GetProcAddress(h, "BsiPluginToolRun");
    p.view_count = (FnViewCount)GetProcAddress(h, "BsiPluginViewCount");
    p.view_info = (FnViewInfo)GetProcAddress(h, "BsiPluginViewInfo");
    p.view_draw = (FnViewDraw)GetProcAddress(h, "BsiPluginViewDraw");
    p.has_settings = (FnHasSettings)GetProcAddress(h, "BsiPluginHasSettings");
    p.draw_settings = (FnDrawSettings)GetProcAddress(h, "BsiPluginDrawSettings");
    p.on_job = (FnOnJob)GetProcAddress(h, "BsiPluginOnJob");
    p.visuals = (FnVisuals)GetProcAddress(h, "BsiPluginVisuals");
    AttachVisuals(&p);
    char key[160];
    EnableKey(p.id, key, (int)sizeof(key));
    p.enabled = SettingsGetBool(key, true);
    g_plugins.push_back(p);
    PluginRec& slot = g_plugins.back();
    FillHost(&slot);
    auto log = LogFor(LogBuiltinCore).Module("Plugin");
    log.Info("Found %s %s (%s)", slot.name, slot.version, slot.id);
    if (slot.enabled && slot.init)
    {
        int rc = -1;
        if (!PlugCall(&rc, slot.init, &slot.host))
            PlugFaulted(&slot, "init");
        else if (rc == 0)
        {
            slot.inited = true;
            log.Success("Enabled %s", slot.name);
        }
        else
        {
            snprintf(slot.err, sizeof(slot.err), "init failed");
            slot.enabled = false;
            log.Error("Init failed: %s", slot.name);
        }
    }
    return true;
}

static void ScanDir(const char* dir, int depth)
{
    if (!dir || depth > 1)
        return;
    char spec[MAX_PATH];
    snprintf(spec, sizeof(spec), "%s\\*", dir);
    WIN32_FIND_DATAA fd{};
    HANDLE h = FindFirstFileA(spec, &fd);
    if (h == INVALID_HANDLE_VALUE)
        return;
    do
    {
        if (fd.cFileName[0] == '.')
            continue;
        char full[MAX_PATH];
        snprintf(full, sizeof(full), "%s\\%s", dir, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            ScanDir(full, depth + 1);
            continue;
        }
        size_t n = strlen(fd.cFileName);
        if (n > 4 && _stricmp(fd.cFileName + n - 4, ".dll") == 0)
            LoadDll(full);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

void PluginShutdown()
{
    for (PluginRec& p : g_plugins)
        UnloadOne(p);
    g_plugins.clear();
    g_inited = false;
}

void PluginRescan()
{
    PluginShutdown();
    g_plugins.reserve(kMaxPlugins);
    char dir[MAX_PATH];
    PathsBesideExe(dir, MAX_PATH, "plugins");
    CreateDirectoryA(dir, nullptr);
    auto log = LogFor(LogBuiltinCore).Module("Plugin");
    log.Info("Scanning %s", dir);
    ScanDir(dir, 0);
    g_inited = true;
    log.Info("%d plugin(s)", (int)g_plugins.size());
}

void PluginInit()
{
    if (g_inited)
        return;
    PluginRescan();
}

void PluginNotifyJob(int ready)
{
    for (PluginRec& p : g_plugins)
    {
        if (p.enabled && p.inited && p.on_job && !PlugCallVoid(p.on_job, ready))
            PlugFaulted(&p, "on_job");
    }
}

int PluginCount() { return (int)g_plugins.size(); }

static PluginRec* At(int i)
{
    if (i < 0 || i >= (int)g_plugins.size())
        return nullptr;
    return &g_plugins[(size_t)i];
}

const char* PluginId(int i) { PluginRec* p = At(i); return p ? p->id : ""; }
const char* PluginName(int i) { PluginRec* p = At(i); return p ? p->name : ""; }
const char* PluginVersion(int i) { PluginRec* p = At(i); return p ? p->version : ""; }
const char* PluginAuthor(int i) { PluginRec* p = At(i); return p ? p->author : ""; }
const char* PluginDescription(int i) { PluginRec* p = At(i); return p ? p->description : ""; }
const char* PluginPath(int i) { PluginRec* p = At(i); return p ? p->path : ""; }
const char* PluginError(int i) { PluginRec* p = At(i); return p && p->err[0] ? p->err : ""; }

void* PluginIconSrv(int i, int* w, int* h)
{
    return LazyTex(At(i), 0, w, h);
}

void* PluginCoverSrv(int i, int* w, int* h)
{
    void* cover = LazyTex(At(i), 1, w, h);
    if (cover)
        return cover;
    return PluginIconSrv(i, w, h);
}
bool PluginEnabled(int i) { PluginRec* p = At(i); return p && p->enabled; }
bool PluginInited(int i) { PluginRec* p = At(i); return p && p->inited; }

void PluginSetEnabled(int i, bool on)
{
    PluginRec* p = At(i);
    if (!p)
        return;
    char key[160];
    EnableKey(p->id, key, (int)sizeof(key));
    SettingsSetBool(key, on);
    auto log = LogFor(LogBuiltinCore).Module("Plugin");
    if (on)
    {
        p->enabled = true;
        if (!p->inited && p->init)
        {
            int rc = -1;
            if (!PlugCall(&rc, p->init, &p->host))
            {
                PlugFaulted(p, "init");
                SettingsSetBool(key, false);
            }
            else if (rc == 0)
            {
                p->inited = true;
                p->err[0] = 0;
                log.Success("Enabled %s", p->name);
            }
            else
            {
                p->enabled = false;
                snprintf(p->err, sizeof(p->err), "init failed");
                SettingsSetBool(key, false);
                log.Error("Init failed: %s", p->name);
            }
        }
    }
    else
    {
        if (p->inited && p->shutdown && !PlugCallVoid(p->shutdown))
            PlugFaulted(p, "shutdown");
        p->inited = false;
        p->enabled = false;
        log.Info("Disabled %s", p->name);
    }
}

bool PluginHasSettings(int i)
{
    PluginRec* p = At(i);
    if (!p || !p->enabled || !p->inited || !p->has_settings || !p->draw_settings)
        return false;
    int has = 0;
    if (!PlugCall(&has, p->has_settings))
    {
        PlugFaulted(p, "has_settings");
        return false;
    }
    return has != 0;
}

void PluginDrawSettings(int i)
{
    PluginRec* p = At(i);
    if (!PluginHasSettings(i) || !p)
        return;
    BsiUi ui{};
    FillUi(&ui);
    ImGui::PushID(p->id);
    bool ok = PlugCallVoid(p->draw_settings, &ui);
    ImGui::PopID();
    if (!ok)
        PlugFaulted(p, "draw_settings");
}

void PluginDrawToolsMenu(bool, bool)
{
    int shown = 0;
    for (int pi = 0; pi < (int)g_plugins.size(); pi++)
    {
        PluginRec& p = g_plugins[(size_t)pi];
        if (!p.enabled || !p.inited || !p.tool_count || !p.tool_info || !p.tool_run)
            continue;
        int n = 0;
        if (!PlugCall(&n, p.tool_count))
        {
            PlugFaulted(&p, "tool_count");
            continue;
        }
        if (n <= 0)
            continue;
        ImGui::PushID(pi);
        if (ImGui::BeginMenu(p.name))
        {
            for (int t = 0; t < n; t++)
            {
                BsiToolInfo info{};
                int got = 0;
                if (!PlugCall(&got, p.tool_info, t, &info))
                {
                    PlugFaulted(&p, "tool_info");
                    break;
                }
                if (!got || !info.label)
                    continue;
                if (ImGui::MenuItem(info.label))
                {
                    int rc = 0;
                    if (!PlugCall(&rc, p.tool_run, t))
                    {
                        PlugFaulted(&p, "tool_run");
                        break;
                    }
                }
            }
            ImGui::EndMenu();
        }
        ImGui::PopID();
        shown++;
    }
    if (!shown)
    {
        ImGui::MenuItem(I18nGet("plugin.none"), nullptr, false, false);
        UiTipWhenDisabled(I18nGet("plugin.none_hint"));
    }
}

int PluginViewCount()
{
    int n = 0;
    for (PluginRec& p : g_plugins)
    {
        if (!p.enabled || !p.inited || !p.view_count)
            continue;
        int mine = 0;
        if (!PlugCall(&mine, p.view_count))
        {
            PlugFaulted(&p, "view_count");
            continue;
        }
        n += mine;
    }
    return n;
}

static bool ViewAt(int want, PluginRec** rec, int* local)
{
    int cur = 0;
    for (PluginRec& p : g_plugins)
    {
        if (!p.enabled || !p.inited || !p.view_count)
            continue;
        int n = 0;
        if (!PlugCall(&n, p.view_count))
        {
            PlugFaulted(&p, "view_count");
            continue;
        }
        if (want < cur + n)
        {
            *rec = &p;
            *local = want - cur;
            return true;
        }
        cur += n;
    }
    return false;
}

bool PluginViewSelId(int i, char* out, int cap)
{
    if (!out)
        return false;
    snprintf(out, cap, "pview:%d", i);
    return true;
}

const char* PluginViewLabel(int i)
{
    static char lab[80];
    PluginRec* p = nullptr;
    int local = 0;
    if (!ViewAt(i, &p, &local) || !p->view_info)
        return "";
    BsiViewInfo info{};
    int got = 0;
    if (!PlugCall(&got, p->view_info, local, &info))
    {
        PlugFaulted(p, "view_info");
        return "";
    }
    if (!got || !info.label)
        return p->name;
    snprintf(lab, sizeof(lab), "%s", info.label);
    return lab;
}

static bool ViewMetaAt(int i, BsiViewInfo* out)
{
    if (!out)
        return false;
    PluginRec* p = nullptr;
    int local = 0;
    if (!ViewAt(i, &p, &local) || !p->view_info)
        return false;
    memset(out, 0, sizeof(*out));
    int got = 0;
    if (!PlugCall(&got, p->view_info, local, out))
    {
        PlugFaulted(p, "view_info");
        return false;
    }
    return got != 0;
}

static BsiViewInfo ViewMetaLegacyDefaults()
{
    BsiViewInfo out{};
    // Keep existing host behavior for legacy plugins.
    out.region = 4;        // WsCenter
    out.default_open = 0;
    out.utility = 0;
    out.menu_group = 2;   // WsMenuView
    out.min_w = 280.f;
    out.min_h = 0.f;
    out.meta_version = 0;
    return out;
}

uint32_t PluginViewRegion(int i)
{
    BsiViewInfo meta = ViewMetaLegacyDefaults();
    BsiViewInfo out{};
    if (ViewMetaAt(i, &out) && out.meta_version >= 1)
        meta = out;
    return meta.region;
}

int PluginViewDefaultOpen(int i)
{
    BsiViewInfo meta = ViewMetaLegacyDefaults();
    BsiViewInfo out{};
    if (ViewMetaAt(i, &out) && out.meta_version >= 1)
        meta = out;
    return meta.default_open ? 1 : 0;
}

int PluginViewUtility(int i)
{
    BsiViewInfo meta = ViewMetaLegacyDefaults();
    BsiViewInfo out{};
    if (ViewMetaAt(i, &out) && out.meta_version >= 1)
        meta = out;
    return meta.utility ? 1 : 0;
}

uint32_t PluginViewMenuGroup(int i)
{
    BsiViewInfo meta = ViewMetaLegacyDefaults();
    BsiViewInfo out{};
    if (ViewMetaAt(i, &out) && out.meta_version >= 1)
        meta = out;
    return meta.menu_group;
}

float PluginViewMinW(int i)
{
    BsiViewInfo meta = ViewMetaLegacyDefaults();
    BsiViewInfo out{};
    if (ViewMetaAt(i, &out) && out.meta_version >= 1)
        meta = out;
    return meta.min_w > 0.f ? meta.min_w : 280.f;
}

float PluginViewMinH(int i)
{
    BsiViewInfo meta = ViewMetaLegacyDefaults();
    BsiViewInfo out{};
    if (ViewMetaAt(i, &out) && out.meta_version >= 1)
        meta = out;
    return meta.min_h;
}

bool PluginSelIsView(const char* sel)
{
    return sel && strncmp(sel, "pview:", 6) == 0;
}

void PluginDrawView(const char* sel)
{
    if (!PluginSelIsView(sel))
        return;
    int i = atoi(sel + 6);
    PluginRec* p = nullptr;
    int local = 0;
    if (!ViewAt(i, &p, &local))
    {
        ImGui::TextUnformatted(I18nGet("plugin.view_missing"));
        return;
    }
    if (p->view_draw)
    {
        BsiUi ui{};
        FillUi(&ui);
        int drawn = 0;
        if (!PlugCall(&drawn, p->view_draw, local, &ui))
        {
            PlugFaulted(p, "view_draw");
            ImGui::TextUnformatted(p->err);
            return;
        }
        if (drawn)
            return;
    }
    ImGui::TextWrapped("%s", I18nGet("plugin.view_stub"));
}
