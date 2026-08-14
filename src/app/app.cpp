#include "app/app.h"
#include "app/welcome.h"
#include "app/settings_page.h"
#include "i18n/i18n.h"
#include "ui/theme.h"
#include "ui/theme_pack.h"
#include "ui/widgets.h"
#include "engine/engine.h"
#include "persist/settings.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>

static AppPage g_page = AppPageWelcome;
static char    g_open_path[MAX_PATH];
static float   g_page_sweep = 1.f;

void AppInit()
{
    I18nInit();
    ThemePackInit();
}

void AppSetPage(AppPage page)
{
    if (g_page == page)
        return;
    g_page = page;
    g_page_sweep = 0.f;
}

AppPage AppGetPage()
{
    return g_page;
}

void AppOpenPath(const char* path)
{
    // drop / argv / dialog land here. PE parse comes later; recents only for now.
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
    g_page_sweep += ImGui::GetIO().DeltaTime * 2.6f;
    if (g_page_sweep > 1.f)
        g_page_sweep = 1.f;
    float grow = g_page_sweep * 1.35f;
    if (grow > 1.f)
        grow = 1.f;
    float fade = 1.f - g_page_sweep;
    ImVec2 a = ImGui::GetWindowPos();
    ImVec2 b = ImVec2(a.x + ImGui::GetWindowSize().x, a.y + ImGui::GetWindowSize().y);
    UiHoverSweep(a, b, grow, fade);
}
