#include "ui/theme.h"
#include "ui/widgets.h"
#include "imgui.h"
#include "imgui_internal.h"

#include <windows.h>
#include <stdio.h>

static ImVec4 T(int hex, float a = 1.f)
{
    return ImVec4(
        (float)((hex >> 16) & 255) / 255.f,
        (float)((hex >> 8) & 255) / 255.f,
        (float)(hex & 255) / 255.f,
        a);
}

static int kBg      = 0x0A0A0A;
static int kFg      = 0xFAFAFA;
static int kMuted   = 0x1A1A1A;
static int kMutedFg = 0x737373;
static int kAccent  = 0xFF3D00;
static int kBorder  = 0x262626;
static int kInput   = 0x1A1A1A;
static int kCard    = 0x0F0F0F;
static float kRound = 0.f;
static char g_caption[128];

static ImFont* g_font_title;
static ImFont* g_font_small;

ImU32 ThemeCol(int hex, float a)
{
    return ImGui::ColorConvertFloat4ToU32(T(hex, a));
}

ImU32 ThemeColFg() { return ThemeCol(kFg); }
ImU32 ThemeColMuted() { return ThemeCol(kMutedFg); }
ImU32 ThemeColAccent() { return ThemeCol(kAccent); }
ImU32 ThemeColBg() { return ThemeCol(kBg); }
ImU32 ThemeColCard() { return ThemeCol(kCard); }
ImU32 ThemeColBorder() { return ThemeCol(kBorder); }

void ThemeSetCaption(const char* caption)
{
    snprintf(g_caption, sizeof(g_caption), "%s", caption ? caption : "");
}

const char* ThemeCaptionOr(const char* fallback)
{
    return g_caption[0] ? g_caption : fallback;
}

void ThemeSetPalette(int bg, int fg, int muted, int muted_fg, int accent, int border, int input, int card, float rounding)
{
    kBg = bg;
    kFg = fg;
    kMuted = muted;
    kMutedFg = muted_fg;
    kAccent = accent;
    kBorder = border;
    kInput = input;
    kCard = card;
    kRound = rounding;
    if (ImGui::GetCurrentContext())
        ThemeApply();
}

ImFont* ThemeFontTitle() { return g_font_title; }
ImFont* ThemeFontSmall() { return g_font_small; }

void ThemeLoadFonts()
{
    ImGuiIO& io = ImGui::GetIO();
    ImFontConfig fc{};
    fc.OversampleH = 2;
    fc.OversampleV = 1;
    fc.PixelSnapH = false;
    fc.RasterizerDensity = 1.0f; // 2.0 was crunchy. this is not MSAA.
    const char* path = "C:\\Windows\\Fonts\\segoeui.ttf";
    const char* title_path = "C:\\Windows\\Fonts\\seguisb.ttf";
    if (GetFileAttributesA(title_path) == INVALID_FILE_ATTRIBUTES)
        title_path = path;
    if (ImFont* body = io.Fonts->AddFontFromFileTTF(path, ThemeFontSize(), &fc))
        io.FontDefault = body;
    g_font_title = io.Fonts->AddFontFromFileTTF(title_path, 28.0f, &fc);
    g_font_small = io.Fonts->AddFontFromFileTTF(path, 16.0f, &fc);
}

void ThemeDrawLogo(ImVec2 c, float s)
{
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImU32 fg = ThemeColFg();
    ImU32 acc = ThemeColAccent();
    ImVec2 a(c.x - s, c.y - s);
    ImVec2 b(c.x + s, c.y + s);
    dl->AddRect(a, b, fg, 0.f, 0, 2.f);
    dl->AddRectFilled(ImVec2(c.x - s * 0.52f, c.y - s * 0.52f), ImVec2(c.x - s * 0.08f, c.y + s * 0.52f), acc);
    dl->AddRectFilled(ImVec2(c.x - s * 0.52f, c.y + s * 0.14f), ImVec2(c.x + s * 0.52f, c.y + s * 0.52f), acc);
    dl->AddLine(ImVec2(c.x + s * 0.08f, c.y - s * 0.52f), ImVec2(c.x + s * 0.52f, c.y + s * 0.08f), fg, 2.f);
}

void ThemeApply()
{
    ImGuiStyle& s = ImGui::GetStyle();
    s.WindowRounding = kRound;
    s.ChildRounding = kRound;
    s.PopupRounding = kRound;
    s.FrameRounding = kRound;
    s.GrabRounding = kRound;
    s.TabRounding = kRound;
    s.ScrollbarRounding = kRound;
    s.WindowBorderSize = 0.f;
    s.ChildBorderSize = 1.f;
    s.PopupBorderSize = 1.f;
    s.FrameBorderSize = 1.f;
    s.WindowPadding = ImVec2(14.f, 12.f);
    s.FramePadding = ImVec2(10.f, 6.f);
    s.ItemSpacing = ImVec2(10.f, 8.f);
    s.ItemInnerSpacing = ImVec2(6.f, 4.f);
    s.IndentSpacing = 14.f;
    s.ScrollbarSize = 10.f;
    s.GrabMinSize = 10.f;
    s.AntiAliasedLines = true;
    s.AntiAliasedLinesUseTex = true;
    s.AntiAliasedFill = true;

    ImVec4* c = s.Colors;
    c[ImGuiCol_Text]                  = T(kFg);
    c[ImGuiCol_TextDisabled]          = T(kMutedFg);
    c[ImGuiCol_WindowBg]              = T(kCard, 0.f);
    c[ImGuiCol_ChildBg]               = T(kCard);
    c[ImGuiCol_PopupBg]               = T(kMuted);
    c[ImGuiCol_Border]                = T(kBorder);
    c[ImGuiCol_BorderShadow]          = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_FrameBg]               = T(kInput);
    c[ImGuiCol_FrameBgHovered]        = T(kMuted);
    c[ImGuiCol_FrameBgActive]         = T(kMuted);
    c[ImGuiCol_TitleBg]               = T(kBg);
    c[ImGuiCol_TitleBgActive]         = T(kBg);
    c[ImGuiCol_TitleBgCollapsed]      = T(kBg);
    c[ImGuiCol_MenuBarBg]             = T(kBg);
    c[ImGuiCol_ScrollbarBg]           = T(kBg);
    c[ImGuiCol_ScrollbarGrab]         = T(kBorder);
    c[ImGuiCol_ScrollbarGrabHovered]  = T(kFg, 0.35f);
    c[ImGuiCol_ScrollbarGrabActive]   = T(kFg, 0.55f);
    c[ImGuiCol_CheckMark]             = T(kAccent);
    c[ImGuiCol_SliderGrab]            = T(kAccent);
    c[ImGuiCol_SliderGrabActive]      = T(kFg);
    c[ImGuiCol_Button]                = T(kCard, 0.f);
    c[ImGuiCol_ButtonHovered]         = T(kMuted);
    c[ImGuiCol_ButtonActive]          = T(kFg, 0.12f);
    c[ImGuiCol_Header]                = T(kMuted);
    c[ImGuiCol_HeaderHovered]         = T(kMuted);
    c[ImGuiCol_HeaderActive]          = T(kBorder);
    c[ImGuiCol_Separator]             = T(kBorder);
    c[ImGuiCol_SeparatorHovered]      = T(kFg, 0.35f);
    c[ImGuiCol_SeparatorActive]       = T(kAccent);
    c[ImGuiCol_ResizeGrip]            = T(kBorder);
    c[ImGuiCol_ResizeGripHovered]     = T(kAccent, 0.70f);
    c[ImGuiCol_ResizeGripActive]      = T(kAccent);
    c[ImGuiCol_Tab]                   = T(kMuted);
    c[ImGuiCol_TabHovered]            = T(kBorder);
    c[ImGuiCol_TabSelected]           = T(kCard);
    c[ImGuiCol_PlotLines]             = T(kAccent);
    c[ImGuiCol_PlotHistogram]         = T(kAccent);
    c[ImGuiCol_TableHeaderBg]         = T(kMuted);
    c[ImGuiCol_TableBorderStrong]     = T(kBorder);
    c[ImGuiCol_TableBorderLight]      = T(kBorder);
    c[ImGuiCol_TextSelectedBg]        = T(kAccent, 0.28f);
    c[ImGuiCol_NavHighlight]          = T(kAccent);
    c[ImGuiCol_NavWindowingHighlight] = T(kAccent, 0.40f);
    c[ImGuiCol_ModalWindowDimBg]      = T(kBg, 0.70f);
}

static bool ChromeBtn(const char* id, ImVec2 a, float w, float h)
{
    ImGui::SetCursorScreenPos(a);
    bool hit = ImGui::InvisibleButton(id, ImVec2(w, h));
    UiHandIfHovered();
    UiHoverSweep(a, ImVec2(a.x + w, a.y + h), UiHoverT(ImGui::GetItemID(), ImGui::IsItemHovered()));
    return hit;
}

int ThemeDecorateWindow(const char* title, bool maximized)
{
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 p = ImGui::GetWindowPos();
    ImVec2 s = ImGui::GetWindowSize();
    const float bar_h = ThemeTitleBarH();
    const float btn_w = ThemeChromeBtnW();

    dl->AddRectFilled(p, ImVec2(p.x + s.x, p.y + s.y), ImGui::ColorConvertFloat4ToU32(T(kCard)));
    dl->AddRect(p, ImVec2(p.x + s.x, p.y + s.y), ImGui::ColorConvertFloat4ToU32(T(kBorder)));
    dl->AddRectFilled(p, ImVec2(p.x + s.x, p.y + bar_h), ImGui::ColorConvertFloat4ToU32(T(kBg)));

    ImVec2 tp = ImVec2(p.x + 10.f, p.y + (bar_h - ImGui::GetFontSize()) * 0.5f);
    dl->AddText(tp, ImGui::ColorConvertFloat4ToU32(T(kFg)), title);

    float bx = p.x + s.x - btn_w * 3.f;
    ImVec2 min_a(bx, p.y);
    ImVec2 max_a(bx + btn_w, p.y);
    ImVec2 cls_a(bx + btn_w * 2.f, p.y);
    ImU32 fg = ImGui::ColorConvertFloat4ToU32(T(kFg));
    int hit = 0;

    ImGuiWindow* win = ImGui::GetCurrentWindow();
    ImVec2 bak_cursor = win->DC.CursorPos;
    ImVec2 bak_max = win->DC.CursorMaxPos; // chrome InvisibleButtons inflate CursorMaxPos; restore or HWND grows.
    ImVec2 bak_ideal = win->DC.IdealMaxPos;

    if (ChromeBtn("min", min_a, btn_w, bar_h))
        hit |= ThemeClickMin;
    {
        float y = (float)(int)(min_a.y + bar_h * 0.5f);
        dl->AddLine(ImVec2(min_a.x + 12.f, y), ImVec2(min_a.x + btn_w - 12.f, y), fg, 1.f);
    }

    if (ChromeBtn("max", max_a, btn_w, bar_h))
        hit |= ThemeClickMax;
    {
        float x0 = max_a.x + 12.f, y0 = max_a.y + 10.f, x1 = max_a.x + btn_w - 12.f, y1 = max_a.y + bar_h - 10.f;
        if (maximized)
        {
            dl->AddRect(ImVec2(x0 + 3.f, y0 - 2.f), ImVec2(x1 + 3.f, y1 - 2.f), fg);
            dl->AddRectFilled(ImVec2(x0, y0 + 2.f), ImVec2(x1, y1 + 2.f), ImGui::ColorConvertFloat4ToU32(T(kBg)));
            dl->AddRect(ImVec2(x0, y0 + 2.f), ImVec2(x1, y1 + 2.f), fg);
        }
        else
            dl->AddRect(ImVec2(x0, y0), ImVec2(x1, y1), fg);
    }

    if (ChromeBtn("close", cls_a, btn_w, bar_h))
        hit |= ThemeClickClose;
    dl->AddLine(ImVec2(cls_a.x + 13.f, cls_a.y + 10.f), ImVec2(cls_a.x + btn_w - 13.f, cls_a.y + bar_h - 10.f), fg, 1.f);
    dl->AddLine(ImVec2(cls_a.x + btn_w - 13.f, cls_a.y + 10.f), ImVec2(cls_a.x + 13.f, cls_a.y + bar_h - 10.f), fg, 1.f);

    win->DC.CursorPos = bak_cursor;
    win->DC.CursorMaxPos = bak_max;
    win->DC.IdealMaxPos = bak_ideal;

    ImGui::Dummy(ImVec2(1.f, bar_h - ImGui::GetStyle().WindowPadding.y));
    return hit;
}
