#include "app/welcome.h"
#include "app/quotes.h"
#include "app/app.h"
#include "ui/theme.h"
#include "ui/icons.h"
#include "ui/widgets.h"
#include "persist/settings.h"
#include "i18n/i18n.h"

#include "imgui.h"
#include "imgui_internal.h"

#include <windows.h>
#include <commdlg.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

static const float kWelcomePad = 24.f;
static const float kWelcomeFooterH = 78.f;
static const float kWelcomeQuotePad = 10.f;
static const float kWelcomeFooterLeft = 280.f;
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
    const float footer_h = kWelcomeFooterH;
    const float pad = kWelcomePad;
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
    float e0 = UiEnter(0.00f, 0.38f);
    float e1 = UiEnter(0.06f, 0.40f);
    float e2 = UiEnter(0.12f, 0.42f);
    float e3 = UiEnter(0.18f, 0.40f);
    float breathe = UiAnimEnabled() ? 1.f + 0.025f * sinf((float)ImGui::GetTime() * 1.7f) : 1.f;
    float logo_y = top + body_h * 0.22f - (1.f - e0) * 10.f;
    ThemeDrawLogo(ImVec2(mid_x, logo_y), logo_s * (0.82f + 0.18f * e0) * breathe);

    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, e1);

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
    ImGui::PopStyleVar();

    float recents_y = logo_y + logo_s + 16.f + ts.y + ds.y + 28.f + (1.f - e2) * 8.f;
    float recents_w = ws.x - pad * 2.f;
    if (recents_w > 560.f)
        recents_w = 560.f;
    float recents_x = mid_x - recents_w * 0.5f;

    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, e2);
    ImGui::SetCursorScreenPos(ImVec2(recents_x, recents_y));
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    ImGui::TextUnformatted(I18nGet("welcome.recents"));
    ImGui::PopStyleColor();

    ImGui::SetCursorScreenPos(ImVec2(recents_x, recents_y + 26.f));
    const float row_h = ImGui::GetTextLineHeightWithSpacing();
    float recents_box_h = row_h * 5.f + ImGui::GetFrameHeight() + 20.f;
    float recents_max_h = bot - 8.f - (recents_y + 26.f);
    if (recents_max_h < recents_box_h)
        recents_box_h = recents_max_h;
    if (recents_box_h < row_h * 2.f + ImGui::GetFrameHeight())
        recents_box_h = row_h * 2.f + ImGui::GetFrameHeight();
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
            float s = IconSize(IconRoleSm);
            IconDraw(IconFile, ImVec2(row.x + ThemeSpaceXs() + s, row.y + row_h * 0.5f), s, ThemeColMuted());
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + IconSlotW(IconRoleSm));
            if (ImGui::Selectable(FileNameOf(path)))
                AppOpenPath(path);
            UiDecorateLastButton();
            if (ImGui::IsItemHovered())
            {
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
    ImGui::SameLine();
    if (IconButton("fromwin", IconBox, I18nGet("welcome.from_window")))
        AppOpenWindowPicker();
    ImGui::EndChild();
    ImGui::PopStyleVar();

    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, e3);
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
        float qy = wp.y + ws.y - qs.y - kWelcomeQuotePad;
        float qx = wp.x + ws.x - pad - qs.x;
        if (qx >= wp.x + pad + kWelcomeFooterLeft)
        {
            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
            ImGui::SetCursorScreenPos(ImVec2(qx, qy));
            ImGui::TextUnformatted(buf);
            ImGui::PopStyleColor();
        }
    }

    if (ThemeFontSmall())
        ImGui::PopFont();
    ImGui::PopStyleVar();

    ImGuiWindow* win = ImGui::GetCurrentWindow();
    win->DC.CursorMaxPos = ImVec2(wp.x + ws.x, wp.y + ws.y);
    win->DC.IdealMaxPos = win->DC.CursorMaxPos;
}
