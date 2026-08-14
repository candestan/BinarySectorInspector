#include "ui/theme_pack.h"
#include "ui/theme.h"
#include "persist/paths.h"
#include "persist/settings.h"
#include "i18n/i18n.h"

#include <nlohmann/json.hpp>
// credit: https://github.com/nlohmann/json (MIT, third_party/nlohmann_json)
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string>

static const int kMaxThemes = 48;
static ThemeInfo g_list[kMaxThemes];
static int       g_list_n;
static char      g_file[64] = "bold-typography.json";

static void ThemesDir(char* out, int cap)
{
    char exe[MAX_PATH];
    PathsExeDir(exe, MAX_PATH);
    PathsJoin(out, cap, exe, "themes\\");
}

static int ParseHex(const nlohmann::json& j, const char* key, int fallback)
{
    if (!j.contains(key) || !j[key].is_string())
        return fallback;
    std::string s = j[key].get<std::string>();
    const char* p = s.c_str();
    if (p[0] == '#')
        p++;
    unsigned int v = (unsigned int)strtoul(p, nullptr, 16);
    return (int)(v & 0xffffff);
}

static ThemeKind ParseKind(const nlohmann::json& j)
{
    if (!j.contains("kind") || !j["kind"].is_string())
        return ThemeKindDark;
    std::string k = j["kind"].get<std::string>();
    if (k == "light")
        return ThemeKindLight;
    if (k == "both")
        return ThemeKindBoth;
    return ThemeKindDark;
}

static bool ReadInfo(const char* path, const char* file, ThemeInfo* out)
{
    char* text = nullptr;
    if (!PathsReadFile(path, &text, nullptr) || !text)
        return false;
    bool ok = false;
    try
    {
        auto j = nlohmann::json::parse(text);
        memset(out, 0, sizeof(*out));
        snprintf(out->file, sizeof(out->file), "%s", file);
        std::string nm = j.value("name", std::string(file));
        std::string au = j.value("author", std::string());
        std::string ds = j.value("description", std::string());
        std::string im = j.value("image", std::string());
        snprintf(out->name, sizeof(out->name), "%s", nm.c_str());
        snprintf(out->author, sizeof(out->author), "%s", au.c_str());
        snprintf(out->description, sizeof(out->description), "%s", ds.c_str());
        snprintf(out->image, sizeof(out->image), "%s", im.c_str());
        out->kind = ParseKind(j);
        auto colors = j.contains("colors") && j["colors"].is_object() ? j["colors"] : j;
        out->preview_bg = ParseHex(colors, "bg", 0x0A0A0A);
        out->preview_card = ParseHex(colors, "card", 0x0F0F0F);
        out->preview_accent = ParseHex(colors, "accent", 0xFF3D00);
        ok = true;
    }
    catch (...)
    {
    }
    free(text);
    return ok;
}

void ThemePackRescan()
{
    g_list_n = 0;
    char dir[MAX_PATH];
    ThemesDir(dir, MAX_PATH);
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
        if (g_list_n >= kMaxThemes)
            break;
        char path[MAX_PATH];
        PathsJoin(path, MAX_PATH, dir, fd.cFileName);
        if (ReadInfo(path, fd.cFileName, &g_list[g_list_n]))
            g_list_n++;
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

bool ThemePackApplyFile(const char* file)
{
    if (!file || !file[0])
        file = "bold-typography.json";
    char dir[MAX_PATH];
    ThemesDir(dir, MAX_PATH);
    char path[MAX_PATH];
    PathsJoin(path, MAX_PATH, dir, file);
    char* text = nullptr;
    if (!PathsReadFile(path, &text, nullptr) || !text)
        return false;
    bool ok = false;
    try
    {
        auto j = nlohmann::json::parse(text);
        auto colors = j.contains("colors") && j["colors"].is_object() ? j["colors"] : j;
        int bg = ParseHex(colors, "bg", 0x0A0A0A);
        int fg = ParseHex(colors, "fg", 0xFAFAFA);
        int muted = ParseHex(colors, "muted", 0x1A1A1A);
        int muted_fg = ParseHex(colors, "muted_fg", 0x737373);
        int accent = ParseHex(colors, "accent", 0xFF3D00);
        int border = ParseHex(colors, "border", 0x262626);
        int input = ParseHex(colors, "input", 0x1A1A1A);
        int card = ParseHex(colors, "card", 0x0F0F0F);
        float rounding = j.value("rounding", 0.f);
        ThemeSetPalette(bg, fg, muted, muted_fg, accent, border, input, card, rounding);
        snprintf(g_file, sizeof(g_file), "%s", file);
        SettingsSetString("theme", g_file);
        ok = true;
    }
    catch (...)
    {
    }
    free(text);
    return ok;
}

void ThemePackInit()
{
    char chosen[64];
    SettingsGetString("theme", chosen, 64, "bold-typography.json");
    ThemePackRescan();
    if (!ThemePackApplyFile(chosen) && g_list_n > 0)
        ThemePackApplyFile(g_list[0].file);
}

const char* ThemePackFile() { return g_file; }
int ThemePackCount() { return g_list_n; }
const ThemeInfo* ThemePackGet(int index)
{
    if (index < 0 || index >= g_list_n)
        return nullptr;
    return &g_list[index];
}

const char* ThemeKindLabel(ThemeKind k)
{
    if (k == ThemeKindLight)
        return I18nGet("theme.kind.light");
    if (k == ThemeKindBoth)
        return I18nGet("theme.kind.both");
    return I18nGet("theme.kind.dark");
}
