#include "app/welcome.h"
#include "app/quotes.h"
#include "app/app.h"
#include "ui/theme.h"
#include "ui/icons.h"
#include "persist/settings.h"
#include "i18n/i18n.h"

#include "imgui.h"
#include "imgui_internal.h"

#include <windows.h>
#include <commdlg.h>
#include <stdio.h>
#include <string.h>

static const char* kGithubUrl = "https://github.com/candestan/BinarySectorInspector";
static const char* kAuthorUrl = "https://github.com/candestan";

static void OpenUrl(const char* url)
{
    if (url && url[0])
        ShellExecuteA(nullptr, "open", url, nullptr, nullptr, SW_SHOWNORMAL);
}

static bool Link(const char* label)
{
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColAccent()));
    ImGui::TextUnformatted(label);
    ImGui::PopStyleColor();
    bool hit = ImGui::IsItemClicked();
    if (ImGui::IsItemHovered())
        ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
    return hit;
}

static bool PickFile(char* out, int cap)
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

static const char* FileNameOf(const char* path)
{
    const char* slash = strrchr(path, '\\');
    const char* fwd = strrchr(path, '/');
    if (fwd && (!slash || fwd > slash))
        slash = fwd;
    return slash ? slash + 1 : path;
}

void WelcomeDraw()
{
    ImVec2 wp = ImGui::GetWindowPos();
    ImVec2 ws = ImGui::GetWindowSize();
    const float bar = ThemeTitleBarH();
    const float footer_h = 78.f;
    const float pad = 24.f;
    float top = wp.y + bar + 8.f;
    float bot = wp.y + ws.y - footer_h;
    float mid_x = wp.x + ws.x * 0.5f;
    float body_h = bot - top;
    if (body_h < 80.f)
        body_h = 80.f;

    float logo_s = 36.f;
    if (logo_s > body_h * 0.12f)
        logo_s = body_h * 0.12f;
    if (logo_s < 22.f)
        logo_s = 22.f;
    float logo_y = top + body_h * 0.22f;
    ThemeDrawLogo(ImVec2(mid_x, logo_y), logo_s);

    if (ImFont* title = ThemeFontTitle())
        ImGui::PushFont(title);
    const char* name = I18nGet("app.title");
    ImVec2 ts = ImGui::CalcTextSize(name);
    ImGui::SetCursorScreenPos(ImVec2(mid_x - ts.x * 0.5f, logo_y + logo_s + 16.f));
    ImGui::TextUnformatted(name);
    if (ThemeFontTitle())
        ImGui::PopFont();

    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    const char* tag = I18nGet("welcome.tagline");
    ImVec2 ds = ImGui::CalcTextSize(tag);
    ImGui::SetCursorScreenPos(ImVec2(mid_x - ds.x * 0.5f, logo_y + logo_s + 16.f + ts.y + 4.f));
    ImGui::TextUnformatted(tag);
    ImGui::PopStyleColor();

    float recents_y = logo_y + logo_s + 16.f + ts.y + ds.y + 28.f;
    float recents_w = ws.x - pad * 2.f;
    if (recents_w > 560.f)
        recents_w = 560.f;
    float recents_x = mid_x - recents_w * 0.5f;

    ImGui::SetCursorScreenPos(ImVec2(recents_x, recents_y));
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    ImGui::TextUnformatted(I18nGet("welcome.recents"));
    ImGui::PopStyleColor();

    ImGui::SetCursorScreenPos(ImVec2(recents_x, recents_y + 26.f));
    const float row_h = ImGui::GetTextLineHeightWithSpacing();
    const float recents_box_h = row_h * 5.f + ImGui::GetFrameHeight() + 20.f;
    ImGui::BeginChild("recents", ImVec2(recents_w, recents_box_h), ImGuiChildFlags_Borders);
    int n = SettingsRecentsCount();
    if (n > 5)
        n = 5;
    if (n == 0)
    {
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
        ImGui::TextUnformatted(I18nGet("welcome.empty"));
        ImGui::TextUnformatted(I18nGet("welcome.drop"));
        ImGui::PopStyleColor();
    }
    else
    {
        for (int i = 0; i < n; i++)
        {
            char path[MAX_PATH];
            if (!SettingsRecentsGet(i, path, MAX_PATH))
                continue;
            ImGui::PushID(i);
            ImVec2 row = ImGui::GetCursorScreenPos();
            IconDraw(IconFile, ImVec2(row.x + 8.f, row.y + row_h * 0.5f), 6.f, ThemeColMuted());
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 18.f);
            if (ImGui::Selectable(FileNameOf(path)))
                AppOpenPath(path);
            if (ImGui::IsItemHovered())
            {
                ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
                ImGui::SetTooltip("%s", path);
            }
            ImGui::PopID();
        }
    }
    if (IconButton("open", IconFolder, I18nGet("welcome.open")))
    {
        char path[MAX_PATH];
        if (PickFile(path, MAX_PATH))
            AppOpenPath(path);
    }
    ImGui::EndChild();

    float fy = wp.y + ws.y - footer_h + 8.f;
    if (ImFont* font_sm = ThemeFontSmall())
        ImGui::PushFont(font_sm);

    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    ImGui::SetCursorScreenPos(ImVec2(wp.x + pad, fy));
    ImGui::TextUnformatted(I18nGet("welcome.about"));
    ImGui::SetCursorScreenPos(ImVec2(wp.x + pad, fy + 18.f));
    ImGui::PopStyleColor();
    if (Link(I18nGet("welcome.github")))
        OpenUrl(kGithubUrl);
    ImGui::SameLine();
    ImGui::TextDisabled("·");
    ImGui::SameLine();
    if (Link(I18nGet("welcome.author")))
        OpenUrl(kAuthorUrl);
    ImGui::SameLine();
    ImGui::Dummy(ImVec2(16.f, 1.f));
    ImGui::SameLine();
    if (IconButton("settings", IconGear, I18nGet("welcome.settings")))
        AppOpenSettings();

    if (kWelcomeQuoteCount > 0)
    {
        static int q = -1;
        if (q < 0)
            q = (int)(GetTickCount() % (DWORD)kWelcomeQuoteCount);
        const WelcomeQuote& line = kWelcomeQuotes[q];
        char buf[256];
        if (line.by && line.by[0])
            snprintf(buf, sizeof(buf), "\"%s\"  ~%s", line.text ? line.text : "", line.by);
        else
            snprintf(buf, sizeof(buf), "\"%s\"", line.text ? line.text : "");
        ImVec2 qs = ImGui::CalcTextSize(buf);
        float qy = wp.y + ws.y - qs.y - 10.f;
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
        ImGui::SetCursorScreenPos(ImVec2(mid_x - qs.x * 0.5f, qy));
        ImGui::TextUnformatted(buf);
        ImGui::PopStyleColor();
    }

    if (ThemeFontSmall())
        ImGui::PopFont();

    ImGuiWindow* win = ImGui::GetCurrentWindow();
    win->DC.CursorMaxPos = ImVec2(wp.x + ws.x, wp.y + ws.y);
    win->DC.IdealMaxPos = win->DC.CursorMaxPos;
}
