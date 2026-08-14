#include "persist/settings.h"
#include "persist/paths.h"

#include <windows.h>
#include <fstream>
#include <stdio.h>
#include <string.h>
#include <string>

// credit: https://github.com/nlohmann/json (MIT, third_party/nlohmann_json)

static nlohmann::json g_doc = nlohmann::json::object();
static char           g_path[MAX_PATH];

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
    std::ofstream out(g_path, std::ios::trunc);
    if (!out)
        return false;
    out << g_doc.dump(2);
    return (bool)out;
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
