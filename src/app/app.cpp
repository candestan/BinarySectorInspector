#include "app/app.h"
#include "app/welcome.h"
#include "app/settings_page.h"
#include "app/inspector.h"
#include "i18n/i18n.h"
#include "ui/theme.h"
#include "ui/theme_pack.h"
#include "ui/widgets.h"
#include "engine/engine.h"
#include "persist/settings.h"
#include "pe/pe.h"

#include <windows.h>
#include <commdlg.h>
#include <stdio.h>
#include <string.h>

static AppPage g_page = AppPageWelcome;
static AppPage g_settings_from = AppPageWelcome;
static char    g_open_path[MAX_PATH];
static float   g_page_sweep = 1.f;

void AppInit()
{
    I18nInit();
    ThemePackInit();
}

void AppShutdown()
{
    PeJobShutdown();
}

void AppSetPage(AppPage page)
{
    if (g_page == page)
        return;
    g_page = page;
    g_page_sweep = 0.f;
}

void AppOpenSettings()
{
    if (g_page != AppPageSettings)
        g_settings_from = g_page;
    AppSetPage(AppPageSettings);
}

AppPage AppSettingsReturn()
{
    return g_settings_from;
}

AppPage AppGetPage()
{
    return g_page;
}

void AppOpenPath(const char* path)
{
    // drop / argv / dialog land here. kick the PE job, then the inspector.
    if (!path || !path[0])
        return;
    wchar_t wpath[MAX_PATH];
    if (!MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, MAX_PATH))
        return;
    DWORD attr = GetFileAttributesW(wpath);
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY))
        return;
    snprintf(g_open_path, MAX_PATH, "%s", path);
    SettingsRecentsAdd(path);
    PeJobStart(path);
    AppSetPage(AppPageInspector);
}

bool AppPickOpenFilter(char* out, int cap, const wchar_t* filter, const wchar_t* title)
{
    wchar_t wpath[MAX_PATH];
    wpath[0] = 0;
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = GetActiveWindow();
    ofn.lpstrFile = wpath;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = title ? title : L"Open";
    ofn.lpstrFilter = filter ? filter : L"All files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (!GetOpenFileNameW(&ofn))
        return false;
    if (!WideCharToMultiByte(CP_UTF8, 0, wpath, -1, out, cap, nullptr, nullptr))
        return false;
    return out[0] != 0;
}

bool AppPickSaveFilter(char* out, int cap, const wchar_t* filter, const wchar_t* title, const char* suggest)
{
    wchar_t wpath[MAX_PATH];
    wpath[0] = 0;
    if (suggest && suggest[0])
        MultiByteToWideChar(CP_UTF8, 0, suggest, -1, wpath, MAX_PATH);
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = GetActiveWindow();
    ofn.lpstrFile = wpath;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = title ? title : L"Save";
    ofn.lpstrFilter = filter ? filter : L"All files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (!GetSaveFileNameW(&ofn))
        return false;
    if (!WideCharToMultiByte(CP_UTF8, 0, wpath, -1, out, cap, nullptr, nullptr))
        return false;
    return out[0] != 0;
}

bool AppPickOpenPe(char* out, int cap)
{
    wchar_t wpath[MAX_PATH];
    wpath[0] = 0;
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = GetActiveWindow();
    ofn.lpstrFile = wpath;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = L"Open PE";
    ofn.lpstrFilter = L"Windows PE\0*.exe;*.dll;*.sys;*.ocx;*.cpl;*.scr;*.drv\0All files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (!GetOpenFileNameW(&ofn))
        return false;
    if (!WideCharToMultiByte(CP_UTF8, 0, wpath, -1, out, cap, nullptr, nullptr))
        return false;
    return out[0] != 0;
}

bool AppPickSavePe(char* out, int cap)
{
    wchar_t wpath[MAX_PATH];
    wpath[0] = 0;
    const char* cur = PeJobPath();
    if (cur && cur[0])
        MultiByteToWideChar(CP_UTF8, 0, cur, -1, wpath, MAX_PATH);
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = GetActiveWindow();
    ofn.lpstrFile = wpath;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = L"Save PE";
    ofn.lpstrFilter = L"Windows PE\0*.exe;*.dll;*.sys;*.ocx\0All files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (!GetSaveFileNameW(&ofn))
        return false;
    if (!WideCharToMultiByte(CP_UTF8, 0, wpath, -1, out, cap, nullptr, nullptr))
        return false;
    return out[0] != 0;
}

void AppPrepareFrame()
{
    ThemeSetCaption(I18nGet("app.title"));
    char dropped[MAX_PATH];
    while (EngineTakeDrop(dropped, MAX_PATH))
        AppOpenPath(dropped);
}

void AppDraw()
{
    switch (g_page)
    {
    case AppPageSettings:
        SettingsPageDraw();
        break;
    case AppPageInspector:
        InspectorDraw();
        break;
    case AppPageWelcome:
    default:
        WelcomeDraw();
        break;
    }

    if (!UiAnimEnabled())
    {
        g_page_sweep = 1.f;
        return;
    }
    if (g_page_sweep >= 1.f)
        return;
    g_page_sweep += ImGui::GetIO().DeltaTime * 1.05f; // ~1s wipe. used to snap too fast.
    if (g_page_sweep > 1.f)
        g_page_sweep = 1.f;
    float grow = g_page_sweep * 1.15f;
    if (grow > 1.f)
        grow = 1.f;
    float fade = 1.f - g_page_sweep;
    ImVec2 a = ImGui::GetWindowPos();
    ImVec2 b = ImVec2(a.x + ImGui::GetWindowSize().x, a.y + ImGui::GetWindowSize().y);
    ImDrawList* fg = ImGui::GetForegroundDrawList();
    UiHoverSweep(a, b, grow, fade, fg);
}
