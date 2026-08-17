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
#include "detect/detect.h"
#include "log/log.h"
#include "platform/window_process.h"
#include "imgui.h"

#include <windows.h>
#include <commdlg.h>
#include <stdio.h>
#include <string.h>

static AppPage g_page = AppPageWelcome;
static AppPage g_settings_from = AppPageWelcome;
static char    g_open_path[MAX_PATH];
static float   g_page_sweep = 1.f;

static const int kWindowPickCap = 256;
static bool g_win_pick;
static PlatformWindowEntry g_win_rows[kWindowPickCap];
static int g_win_n;
static int g_win_sel = -1;
static char g_win_filter[128];

void AppInit()
{
    I18nInit();
    ThemePackInit();
    LogInit();
    DetectInit();
}

void AppShutdown()
{
    PeJobShutdown();
    DetectShutdown();
    LogShutdown();
}

void AppSetPage(AppPage page)
{
    if (g_page == page)
        return;
    g_page = page;
    g_page_sweep = 0.f;
    UiAnimPageEnter();
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
    LogInfo(LogBuiltinFile, "Opening %s", path);
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

void AppOpenWindowPicker()
{
    g_win_pick = true;
    g_win_sel = -1;
    g_win_filter[0] = 0;
    g_win_n = PlatformSnapshotWindows(g_win_rows, kWindowPickCap);
}

static bool RowMatchesFilter(const PlatformWindowEntry& e)
{
    if (!g_win_filter[0])
        return true;
    char pid[16];
    snprintf(pid, sizeof(pid), "%lu", (unsigned long)e.pid);
    return strstr(e.title, g_win_filter) || strstr(e.image_path, g_win_filter) || strstr(pid, g_win_filter);
}

static void DrawWindowPicker()
{
    if (!g_win_pick)
        return;
    ImGui::OpenPopup("winpick");
    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(ThemePx(720.f), ThemePx(480.f)), ImGuiCond_Appearing);
    char title[160];
    snprintf(title, sizeof(title), "%s###winpick", I18nGet("welcome.from_window"));
    if (!ImGui::BeginPopupModal(title, &g_win_pick, ImGuiWindowFlags_None))
        return;

    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    ImGui::TextWrapped("%s", I18nGet("welcome.window_hint"));
    ImGui::PopStyleColor();
    ImGui::Dummy(ImVec2(1.f, ThemeSpaceXs()));

    if (UiButton(I18nGet("welcome.refresh_windows")))
        g_win_n = PlatformSnapshotWindows(g_win_rows, kWindowPickCap);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(-1.f);
    ImGui::InputTextWithHint("##winf", I18nGet("welcome.window_filter"), g_win_filter, (int)sizeof(g_win_filter));

    int vis[256];
    int nv = 0;
    for (int i = 0; i < g_win_n && nv < 256; i++)
    {
        if (RowMatchesFilter(g_win_rows[i]))
            vis[nv++] = i;
    }
    float foot = ImGui::GetFrameHeight() + ThemeSpaceMd();
    if (nv == 0)
    {
        ImGui::BeginChild("win_empty", ImVec2(-1.f, -foot), ImGuiChildFlags_Borders);
        UiEmpty(I18nGet("pe.none"));
        ImGui::EndChild();
    }
    else if (ImGui::BeginTable("wins", 3,
        ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable |
        ImGuiTableFlags_SizingStretchProp, ImVec2(-1.f, -foot)))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn(I18nGet("welcome.window_title"), ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, ThemePx(72.f));
        ImGui::TableSetupColumn(I18nGet("welcome.window_image"), ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        ImGuiListClipper clip;
        clip.Begin(nv);
        while (clip.Step())
        {
            for (int k = clip.DisplayStart; k < clip.DisplayEnd; k++)
            {
                int i = vis[k];
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::PushID(i);
                bool sel = (g_win_sel == i);
                if (ImGui::Selectable(g_win_rows[i].title[0] ? g_win_rows[i].title : "(untitled)", sel,
                    ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick))
                {
                    g_win_sel = i;
                    if (ImGui::IsMouseDoubleClicked(0) && g_win_rows[i].image_path[0])
                    {
                        AppOpenPath(g_win_rows[i].image_path);
                        g_win_pick = false;
                        ImGui::CloseCurrentPopup();
                    }
                }
                ImGui::TableNextColumn();
                ImGui::Text("%lu", (unsigned long)g_win_rows[i].pid);
                ImGui::TableNextColumn();
                const char* img = strrchr(g_win_rows[i].image_path, '\\');
                ImGui::TextUnformatted(img ? img + 1 : (g_win_rows[i].image_path[0] ? g_win_rows[i].image_path : "(access denied)"));
                ImGui::PopID();
            }
        }
        ImGui::EndTable();
    }

    bool can = g_win_sel >= 0 && g_win_sel < g_win_n && g_win_rows[g_win_sel].image_path[0];
    ImGui::BeginDisabled(!can);
    bool go = UiButton(I18nGet("welcome.analyze"), ImVec2(0.f, 0.f), 1);
    ImGui::EndDisabled();
    if (!can)
        UiTipWhenDisabled(I18nGet("welcome.window_no_image"));
    if (go && can)
    {
        AppOpenPath(g_win_rows[g_win_sel].image_path);
        g_win_pick = false;
        ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    if (UiButton(I18nGet("settings.back")))
    {
        g_win_pick = false;
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
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
    if (ThemeConsumeSettingsClick() && g_page != AppPageSettings)
        AppOpenSettings();

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

    DrawWindowPicker();

    if (!UiAnimEnabled())
    {
        g_page_sweep = 1.f;
        return;
    }
    if (g_page_sweep >= 1.f)
        return;
    g_page_sweep += ImGui::GetIO().DeltaTime * 3.4f;
    if (g_page_sweep > 1.f)
        g_page_sweep = 1.f;
    float e = UiEaseOut(g_page_sweep);
    float fade = 1.f - e;
    ImVec2 a = ImGui::GetWindowPos();
    ImVec2 b = ImVec2(a.x + ImGui::GetWindowSize().x, a.y + ImGui::GetWindowSize().y);
    ImDrawList* fg = ImGui::GetForegroundDrawList();
    fg->AddRectFilled(a, b, ThemeColBgA(fade * 0.55f));
    float y = a.y + ThemeTitleBarH();
    float x1 = a.x + (b.x - a.x) * e;
    fg->AddLine(ImVec2(a.x, y), ImVec2(x1, y), ThemeWithAlpha(ThemeColAccent(), fade), 2.f);
    UiHoverSweep(a, b, e, fade * 0.65f, fg);
}
