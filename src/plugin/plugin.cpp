#include "plugin/plugin.h"
#include "plugin/bsi_plugin_abi.h"
#include "app/app.h"
#include "pe/pe.h"
#include "log/log.h"
#include "persist/paths.h"
#include "persist/settings.h"
#include "i18n/i18n.h"
#include "ui/widgets.h"

#include "imgui.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
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
typedef int  (*FnViewDraw)(int);

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
};

static std::vector<PluginRec> g_plugins;
static bool g_inited;

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

static const char* RecPath(void*)
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

static int RecSaveDialog(void*, const char* ext, const char* title, const char* suggest,
    char* out_path, int out_cap)
{
    if (!out_path || out_cap < 8)
        return 0;
    wchar_t filter[128]{};
    wchar_t wtitle[80];
    if (ext && _stricmp(ext, "py") == 0)
    {
        static const wchar_t k[] = L"Python\0*.py\0All\0*.*\0";
        memcpy(filter, k, sizeof(k));
    }
    else if (ext && _stricmp(ext, "pyc") == 0)
    {
        static const wchar_t k[] = L"Python bytecode\0*.pyc\0All\0*.*\0";
        memcpy(filter, k, sizeof(k));
    }
    else
    {
        static const wchar_t k[] = L"All\0*.*\0";
        memcpy(filter, k, sizeof(k));
    }
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

static void FillHost(PluginRec* p)
{
    memset(&p->host, 0, sizeof(p->host));
    p->host.size = (uint32_t)sizeof(BsiHost);
    p->host.abi_version = BSI_PLUGIN_ABI_VERSION;
    p->host.ctx = p;
    p->host.log = RecLog;
    p->host.job_ready = RecReady;
    p->host.job_path = RecPath;
    p->host.image = RecImage;
    p->host.has_product = RecHasProduct;
    p->host.has_media = RecHasMedia;
    p->host.has_rsrc_name = RecHasRsrcName;
    p->host.artifact_count = RecArtCount;
    p->host.artifact_at = RecArtAt;
    p->host.save_dialog = RecSaveDialog;
    p->host.write_file = RecWriteFile;
}

static void UnloadOne(PluginRec& p)
{
    if (p.inited && p.shutdown)
        p.shutdown();
    p.inited = false;
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
    HMODULE h = LoadLibraryA(path);
    if (!h)
        return false;
    auto get_info = (FnGetInfo)GetProcAddress(h, "BsiPluginGetInfo");
    if (!get_info)
    {
        FreeLibrary(h);
        return false;
    }
    const BsiPluginInfo* info = get_info();
    if (!info || !info->id || !info->id[0] || info->abi_version != BSI_PLUGIN_ABI_VERSION)
    {
        auto log = LogFor(LogBuiltinCore).Module("Plugin");
        log.Warning("Skipped %s (missing info or ABI %u != %u)",
            path, info ? info->abi_version : 0, BSI_PLUGIN_ABI_VERSION);
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
        if (slot.init(&slot.host) == 0)
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
            if (p->init(&p->host) == 0)
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
        if (p->inited && p->shutdown)
            p->shutdown();
        p->inited = false;
        p->enabled = false;
        log.Info("Disabled %s", p->name);
    }
}

void PluginDrawToolsMenu(bool, bool)
{
    int shown = 0;
    for (int pi = 0; pi < (int)g_plugins.size(); pi++)
    {
        PluginRec& p = g_plugins[(size_t)pi];
        if (!p.enabled || !p.inited || !p.tool_count || !p.tool_info || !p.tool_run)
            continue;
        int n = p.tool_count();
        if (n <= 0)
            continue;
        ImGui::PushID(pi);
        if (ImGui::BeginMenu(p.name))
        {
            for (int t = 0; t < n; t++)
            {
                BsiToolInfo info{};
                if (!p.tool_info(t, &info) || !info.label)
                    continue;
                if (ImGui::MenuItem(info.label))
                    p.tool_run(t);
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
    for (const PluginRec& p : g_plugins)
    {
        if (!p.enabled || !p.inited || !p.view_count)
            continue;
        n += p.view_count();
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
        int n = p.view_count();
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
    if (!p->view_info(local, &info) || !info.label)
        return p->name;
    snprintf(lab, sizeof(lab), "%s", info.label);
    return lab;
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
    if (p->view_draw && p->view_draw(local))
        return;
    ImGui::TextWrapped("%s", I18nGet("plugin.view_stub"));
}
