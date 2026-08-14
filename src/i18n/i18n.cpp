#include "i18n/i18n.h"
#include "persist/paths.h"
#include "persist/settings.h"

#include <nlohmann/json.hpp>
// credit: https://github.com/nlohmann/json (MIT, third_party/nlohmann_json)
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <map>
#include <string>

static const int kMaxLang = 32;

struct LangEntry
{
    char file[64];
    char name[80];
};

static nlohmann::json g_strings = nlohmann::json::object();
static std::map<std::string, std::string> g_map;
static LangEntry      g_list[kMaxLang];
static int            g_list_n;
static char           g_file[64] = "en.json";
static char           g_name[80] = "English";

static void LangDir(char* out, int cap)
{
    char exe[MAX_PATH];
    PathsExeDir(exe, MAX_PATH);
    PathsJoin(out, cap, exe, "languages\\");
}

void I18nRescan()
{
    g_list_n = 0;
    char dir[MAX_PATH];
    LangDir(dir, MAX_PATH);
    char spec[MAX_PATH];
    PathsJoin(spec, MAX_PATH, dir, "*.json");
    WIN32_FIND_DATAA fd{};
    HANDLE h = FindFirstFileA(spec, &fd);
    if (h == INVALID_HANDLE_VALUE)
        return;
    do
    {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;
        if (g_list_n >= kMaxLang)
            break;
        LangEntry& e = g_list[g_list_n];
        snprintf(e.file, sizeof(e.file), "%s", fd.cFileName);
        snprintf(e.name, sizeof(e.name), "%s", fd.cFileName);
        char path[MAX_PATH];
        PathsJoin(path, MAX_PATH, dir, fd.cFileName);
        char* text = nullptr;
        if (PathsReadFile(path, &text, nullptr) && text)
        {
            try
            {
                auto j = nlohmann::json::parse(text);
                if (j.contains("name") && j["name"].is_string())
                    snprintf(e.name, sizeof(e.name), "%s", j["name"].get<std::string>().c_str());
            }
            catch (...)
            {
            }
            free(text);
        }
        g_list_n++;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

void I18nLoadFile(const char* file)
{
    if (!file || !file[0])
        file = "en.json";
    char dir[MAX_PATH];
    LangDir(dir, MAX_PATH);
    char path[MAX_PATH];
    PathsJoin(path, MAX_PATH, dir, file);
    char* text = nullptr;
    g_strings = nlohmann::json::object();
    snprintf(g_file, sizeof(g_file), "%s", file);
    snprintf(g_name, sizeof(g_name), "%s", file);
    if (PathsReadFile(path, &text, nullptr) && text)
    {
        try
        {
            auto j = nlohmann::json::parse(text);
            if (j.contains("name") && j["name"].is_string())
                snprintf(g_name, sizeof(g_name), "%s", j["name"].get<std::string>().c_str());
            if (j.contains("strings") && j["strings"].is_object())
                g_strings = j["strings"];
            else
            {
                g_strings = j;
                g_strings.erase("name");
            }
            g_map.clear();
            for (auto it = g_strings.begin(); it != g_strings.end(); ++it)
            {
                if (it.value().is_string())
                    g_map[it.key()] = it.value().get<std::string>(); // copy out; nlohmann value is destroyed with the parse tree.
            }
            SettingsSetString("language", g_file);
        }
        catch (...)
        {
        }
        free(text);
    }
}

void I18nInit()
{
    char chosen[64];
    SettingsGetString("language", chosen, 64, "en.json");
    I18nRescan();
    I18nLoadFile(chosen);
}

const char* I18nGet(const char* key)
{
    if (!key)
        return "";
    auto it = g_map.find(key);
    if (it != g_map.end())
        return it->second.c_str();
    return key;
}

const char* I18nName() { return g_name; }
const char* I18nFile() { return g_file; }
int         I18nCount() { return g_list_n; }
const char* I18nEntryName(int i) { return (i >= 0 && i < g_list_n) ? g_list[i].name : ""; }
const char* I18nEntryFile(int i) { return (i >= 0 && i < g_list_n) ? g_list[i].file : ""; }
