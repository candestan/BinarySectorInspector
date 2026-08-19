#include "persist/settings.h"
#include "persist/paths.h"

#include <windows.h>
#include <fstream>
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>
#include <math.h>

// credit: https://github.com/nlohmann/json (MIT, third_party/nlohmann_json)

static nlohmann::json g_doc = nlohmann::json::object();
static char           g_path[MAX_PATH];
static bool           g_dirty;
static DWORD          g_dirty_at;
static int            g_layout_epoch;

static const int kLayoutSchema = 1;
static const DWORD kSaveDebounceMs = 450;

static void SettingsPath()
{
    PathsSettingsFile(g_path, MAX_PATH);
}

nlohmann::json& SettingsRoot()
{
    return g_doc;
}

bool SettingsLoad()
{
    SettingsPath();
    g_doc = nlohmann::json::object();
    std::ifstream in(g_path);
    if (!in)
        return false;
    try
    {
        in >> g_doc;
        if (!g_doc.is_object())
            g_doc = nlohmann::json::object();
    }
    catch (...)
    {
        g_doc = nlohmann::json::object();
        return false;
    }
    return true;
}

bool SettingsSave()
{
    SettingsPath();
    char tmp[MAX_PATH];
    snprintf(tmp, MAX_PATH, "%s.tmp", g_path);
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out)
            return false;
        out << g_doc.dump(2);
        if (!out)
            return false;
    }
    if (!MoveFileExA(tmp, g_path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    {
        DeleteFileA(tmp);
        std::ofstream out(g_path, std::ios::trunc);
        if (!out)
            return false;
        out << g_doc.dump(2);
        return (bool)out;
    }
    g_dirty = false;
    return true;
}

void SettingsMarkDirty()
{
    g_dirty = true;
    g_dirty_at = GetTickCount();
}

void SettingsFlush()
{
    if (g_dirty)
        SettingsSave();
}

void SettingsTick()
{
    if (!g_dirty)
        return;
    DWORD now = GetTickCount();
    if (now - g_dirty_at < kSaveDebounceMs)
        return;
    SettingsSave();
}

bool SettingsGetWindow(const char* name, WindowLayout* out)
{
    if (!name || !out || !g_doc.contains("windows") || !g_doc["windows"].is_object())
        return false;
    auto& wins = g_doc["windows"];
    if (!wins.contains(name) || !wins[name].is_object())
        return false;
    auto& w = wins[name];
    out->x = w.value("x", 80);
    out->y = w.value("y", 80);
    out->w = w.value("w", 360);
    out->h = w.value("h", 240);
    out->maximized = w.value("maximized", false);
    return true;
}

void SettingsPutWindow(const char* name, const WindowLayout& w)
{
    if (!name || w.w < 1 || w.h < 1)
        return;
    if (!g_doc.contains("windows") || !g_doc["windows"].is_object())
        g_doc["windows"] = nlohmann::json::object();
    auto& node = g_doc["windows"][name]; // merge this window node; don't clobber the rest of the doc.
    if (!node.is_object())
        node = nlohmann::json::object();
    node["x"] = w.x;
    node["y"] = w.y;
    node["w"] = w.w;
    node["h"] = w.h;
    node["maximized"] = w.maximized;
    SettingsSave();
}

static const int kRecentsMax = 5;

void SettingsRecentsAdd(const char* path)
{
    if (!path || !path[0])
        return;
    if (!g_doc.contains("recents") || !g_doc["recents"].is_array())
        g_doc["recents"] = nlohmann::json::array();
    nlohmann::json next = nlohmann::json::array();
    next.push_back(path);
    for (auto& item : g_doc["recents"])
    {
        if (!item.is_string())
            continue;
        if (item.get<std::string>() == path)
            continue;
        next.push_back(item);
        if ((int)next.size() >= kRecentsMax)
            break;
    }
    g_doc["recents"] = next;
    SettingsSave();
}

int SettingsRecentsCount()
{
    if (!g_doc.contains("recents") || !g_doc["recents"].is_array())
        return 0;
    return (int)g_doc["recents"].size();
}

bool SettingsRecentsGet(int index, char* out, int cap)
{
    if (!out || cap < 2)
        return false;
    out[0] = 0;
    if (index < 0 || index >= SettingsRecentsCount())
        return false;
    auto& item = g_doc["recents"][index];
    if (!item.is_string())
        return false;
    std::string s = item.get<std::string>();
    snprintf(out, cap, "%s", s.c_str());
    return true;
}

void SettingsSetString(const char* key, const char* val)
{
    if (!key || !key[0] || !val)
        return;
    g_doc[key] = val;
    SettingsSave();
}

bool SettingsGetString(const char* key, char* out, int cap, const char* def)
{
    if (!out || cap < 2)
        return false;
    const char* src = def ? def : "";
    std::string owned;
    if (key && g_doc.contains(key) && g_doc[key].is_string())
    {
        owned = g_doc[key].get<std::string>();
        src = owned.c_str();
    }
    snprintf(out, cap, "%s", src);
    return true;
}

void SettingsSetBool(const char* key, bool val)
{
    if (!key || !key[0])
        return;
    g_doc[key] = val;
    SettingsSave();
}

bool SettingsGetBool(const char* key, bool def)
{
    if (!key || !g_doc.contains(key))
        return def;
    if (g_doc[key].is_boolean())
        return g_doc[key].get<bool>();
    return def;
}

void SettingsSetInt(const char* key, int val)
{
    if (!key || !key[0])
        return;
    g_doc[key] = val;
    SettingsSave();
}

int SettingsGetInt(const char* key, int def)
{
    if (!key || !g_doc.contains(key))
        return def;
    if (g_doc[key].is_number_integer())
        return g_doc[key].get<int>();
    if (g_doc[key].is_number())
        return (int)g_doc[key].get<double>();
    return def;
}

void SettingsSetFloat(const char* key, float val)
{
    if (!key || !key[0])
        return;
    g_doc[key] = val;
    SettingsSave();
}

float SettingsGetFloat(const char* key, float def)
{
    if (!key || !g_doc.contains(key))
        return def;
    if (g_doc[key].is_number())
        return (float)g_doc[key].get<double>();
    return def;
}

int SettingsLayoutEpoch()
{
    return g_layout_epoch;
}

static nlohmann::json& LayoutRoot()
{
    if (!g_doc.contains("layout") || !g_doc["layout"].is_object())
        g_doc["layout"] = nlohmann::json::object();
    auto& L = g_doc["layout"];
    if (!L.contains("schema_version") || !L["schema_version"].is_number())
        L["schema_version"] = kLayoutSchema;
    return L;
}

static nlohmann::json* LayoutFind(const char* key)
{
    if (!key || !key[0] || !g_doc.contains("layout") || !g_doc["layout"].is_object())
        return nullptr;
    auto& L = g_doc["layout"];
    if (!L.contains(key))
        return nullptr;
    return &L[key];
}

bool SettingsLayoutHas(const char* key)
{
    return LayoutFind(key) != nullptr;
}

float SettingsLayoutGet(const char* key, float def)
{
    nlohmann::json* n = LayoutFind(key);
    if (!n)
        return def;
    if (n->is_number())
        return (float)n->get<double>();
    return def;
}

void SettingsLayoutSet(const char* key, float val)
{
    if (!key || !key[0])
        return;
    if (val < 0.f)
        val = 0.f;
    nlohmann::json* n = LayoutFind(key);
    if (n && n->is_number() && fabs((float)n->get<double>() - val) < 0.05f)
        return;
    LayoutRoot()[key] = val;
    SettingsMarkDirty();
}

int SettingsLayoutGetInt(const char* key, int def)
{
    nlohmann::json* n = LayoutFind(key);
    if (!n)
        return def;
    if (n->is_number_integer())
        return n->get<int>();
    if (n->is_number())
        return (int)n->get<double>();
    return def;
}

void SettingsLayoutSetInt(const char* key, int val)
{
    if (!key || !key[0])
        return;
    nlohmann::json* n = LayoutFind(key);
    if (n && n->is_number_integer() && n->get<int>() == val)
        return;
    if (n && n->is_number() && (int)n->get<double>() == val)
        return;
    LayoutRoot()[key] = val;
    SettingsMarkDirty();
}

bool SettingsLayoutGetBool(const char* key, bool def)
{
    nlohmann::json* n = LayoutFind(key);
    if (!n)
        return def;
    if (n->is_boolean())
        return n->get<bool>();
    return def;
}

void SettingsLayoutSetBool(const char* key, bool val)
{
    if (!key || !key[0])
        return;
    nlohmann::json* n = LayoutFind(key);
    if (n && n->is_boolean() && n->get<bool>() == val)
        return;
    LayoutRoot()[key] = val;
    SettingsMarkDirty();
}

int SettingsLayoutGetString(const char* key, char* out, int cap, const char* def)
{
    const char* src = def ? def : "";
    nlohmann::json* n = LayoutFind(key);
    if (n && n->is_string())
        src = n->get_ref<const std::string&>().c_str();
    int need = (int)strlen(src) + 1;
    if (!out || cap <= 0)
        return need;
    snprintf(out, cap, "%s", src);
    return need;
}

void SettingsLayoutSetString(const char* key, const char* val)
{
    if (!key || !key[0])
        return;
    const char* v = val ? val : "";
    nlohmann::json* n = LayoutFind(key);
    if (n && n->is_string() && n->get_ref<const std::string&>() == v)
        return;
    LayoutRoot()[key] = v;
    SettingsMarkDirty();
}

static nlohmann::json* TableCols(const char* table, bool create)
{
    if (!table || !table[0])
        return nullptr;
    if (!create && (!g_doc.contains("layout") || !g_doc["layout"].is_object()))
        return nullptr;
    auto& L = create ? LayoutRoot() : g_doc["layout"];
    if (!L.contains("tables") || !L["tables"].is_object())
    {
        if (!create)
            return nullptr;
        L["tables"] = nlohmann::json::object();
    }
    auto& tables = L["tables"];
    if (!tables.contains(table) || !tables[table].is_object())
    {
        if (!create)
            return nullptr;
        tables[table] = nlohmann::json::object();
    }
    return &tables[table];
}

bool SettingsLayoutHasCol(const char* table, const char* col)
{
    nlohmann::json* t = TableCols(table, false);
    if (!t || !col || !col[0] || !t->contains(col))
        return false;
    return (*t)[col].is_number();
}

float SettingsLayoutColW(const char* table, const char* col, float def)
{
    nlohmann::json* t = TableCols(table, false);
    if (!t || !col || !col[0] || !t->contains(col) || !(*t)[col].is_number())
        return def;
    float w = (float)(*t)[col].get<double>();
    if (w < 16.f)
        w = 16.f;
    if (w > 2400.f)
        w = 2400.f;
    return w;
}

void SettingsLayoutSetColW(const char* table, const char* col, float logical)
{
    nlohmann::json* t = TableCols(table, true);
    if (!t || !col || !col[0])
        return;
    if (logical < 16.f)
        logical = 16.f;
    if (logical > 2400.f)
        logical = 2400.f;
    if (t->contains(col) && (*t)[col].is_number())
    {
        float prev = (float)(*t)[col].get<double>();
        if (fabs(prev - logical) < 0.25f)
            return;
    }
    (*t)[col] = logical;
    SettingsMarkDirty();
}

void SettingsLayoutClearTable(const char* table)
{
    if (!table || !table[0])
        return;
    if (!g_doc.contains("layout") || !g_doc["layout"].is_object())
        return;
    auto& L = g_doc["layout"];
    if (!L.contains("tables") || !L["tables"].is_object())
        return;
    L["tables"].erase(table);
    g_layout_epoch++;
    SettingsMarkDirty();
}

void SettingsLayoutResetWorkspace()
{
    if (g_doc.contains("layout") && g_doc["layout"].is_object())
    {
        g_doc["layout"].erase("imgui");
        auto& L = g_doc["layout"];
        std::vector<std::string> drop;
        for (auto it = L.begin(); it != L.end(); ++it)
        {
            if (it.key().compare(0, 11, "ws.visible.") == 0)
                drop.push_back(it.key());
        }
        for (const std::string& k : drop)
            L.erase(k);
        L.erase("panel.tree");
        L.erase("panel.console");
        L.erase("split.dock_pair");
    }
    g_doc.erase("view.tree_w");
    g_doc.erase("view.console_h");
    g_doc.erase("view.tree_dock");
    g_doc.erase("view.console_dock");
    g_layout_epoch++;
    SettingsSave();
}
