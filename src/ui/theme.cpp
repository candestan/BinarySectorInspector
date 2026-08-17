#include "ui/theme.h"
#include "ui/widgets.h"
#include "persist/paths.h"
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
static float g_dpi = 1.f;

float ThemeDpi()
{
    return g_dpi < 1.f ? 1.f : g_dpi;
}

float ThemePx(float logical)
{
    return logical * ThemeDpi();
}

float ThemeSpaceXs() { return ThemePx(4.f); }
float ThemeSpaceSm() { return ThemePx(8.f); }
float ThemeSpaceMd() { return ThemePx(12.f); }
float ThemeSpaceLg() { return ThemePx(16.f); }
float ThemeSpaceXl() { return ThemePx(24.f); }
float ThemeFontSize() { return ThemePx(16.f); }
float ThemeTitleBarH() { return ThemePx(32.f); }
float ThemeChromeBtnW() { return ThemePx(40.f); }
float ThemeLabelW() { return ThemePx(200.f); }
float ThemeTreeMinW() { return ThemePx(168.f); }
float ThemeIconSm() { return ThemePx(6.f); }
float ThemeSplitHit() { return ThemePx(5.f); }

static void RefreshDpi()
{
    UINT d = 96;
    if (ImGui::GetCurrentContext())
    {
        ImGuiViewport* vp = ImGui::GetMainViewport();
        if (vp && vp->PlatformHandleRaw)
            d = GetDpiForWindow((HWND)vp->PlatformHandleRaw);
        else
            d = GetDpiForSystem();
    }
    else
        d = GetDpiForSystem();
    g_dpi = (float)d / 96.f;
    if (g_dpi < 1.f)
        g_dpi = 1.f;
    if (g_dpi > 3.f)
        g_dpi = 3.f;
}

static ImFont* g_font_title;
static ImFont* g_font_small;
static ImFont* g_font_mono;

static ImU32 Col(int hex, float a)
{
    return ImGui::ColorConvertFloat4ToU32(T(hex, a));
}

ImU32 ThemeWithAlpha(ImU32 c, float a)
{
    if (a < 0.f)
        a = 0.f;
    if (a > 1.f)
        a = 1.f;
    return (c & 0x00ffffff) | ((ImU32)(a * 255.f + 0.5f) << 24);
}

ImU32 ThemeColRgb(int rgb, float a)
{
    return Col(rgb, a);
}

ImU32 ThemeColFg() { return Col(kFg, 1.f); }
ImU32 ThemeColFgA(float a) { return Col(kFg, a); }
ImU32 ThemeColMuted() { return Col(kMutedFg, 1.f); }
ImU32 ThemeColMutedA(float a) { return Col(kMutedFg, a); }
ImU32 ThemeColAccent() { return Col(kAccent, 1.f); }
ImU32 ThemeColAccentA(float a) { return Col(kAccent, a); }
ImU32 ThemeColBg() { return Col(kBg, 1.f); }
ImU32 ThemeColBgA(float a) { return Col(kBg, a); }
ImU32 ThemeColCard() { return Col(kCard, 1.f); }
ImU32 ThemeColCardA(float a) { return Col(kCard, a); }
ImU32 ThemeColBorder() { return Col(kBorder, 1.f); }
ImU32 ThemeColBorderA(float a) { return Col(kBorder, a); }
ImU32 ThemeColHover() { return Col(kMuted, 1.f); }
ImU32 ThemeColHoverA(float a) { return Col(kMuted, a); }
ImU32 ThemeColInput() { return Col(kInput, 1.f); }
ImVec4 ThemeVec4Transparent() { return T(kBg, 0.f); }

int ThemeHexBg() { return kBg; }
int ThemeHexFg() { return kFg; }
int ThemeHexMuted() { return kMuted; }
int ThemeHexMutedFg() { return kMutedFg; }
int ThemeHexAccent() { return kAccent; }
int ThemeHexBorder() { return kBorder; }
int ThemeHexInput() { return kInput; }
int ThemeHexCard() { return kCard; }

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
ImFont* ThemeFontMono() { return g_font_mono; }

void ThemeLoadFonts()
{
    RefreshDpi();
    ImGuiIO& io = ImGui::GetIO();
    ImFontConfig fc{};
    fc.OversampleH = 2;
    fc.OversampleV = 1;
    fc.PixelSnapH = false;
    fc.RasterizerDensity = 1.0f;
    char body[MAX_PATH];
    char title[MAX_PATH];
    char mono[MAX_PATH];
    bool have_body = PathsWindowsFont(body, MAX_PATH, "segoeui.ttf");
    bool have_title = PathsWindowsFont(title, MAX_PATH, "seguisb.ttf");
    bool have_mono = PathsWindowsFont(mono, MAX_PATH, "consola.ttf");
    float body_px = ThemePx(16.f);
    float title_px = ThemePx(22.f);
    float small_px = ThemePx(13.f);
    float mono_px = ThemePx(13.f);
    if (have_body)
    {
        if (ImFont* f = io.Fonts->AddFontFromFileTTF(body, body_px, &fc))
            io.FontDefault = f;
        g_font_small = io.Fonts->AddFontFromFileTTF(body, small_px, &fc);
    }
    else
        io.FontDefault = io.Fonts->AddFontDefault();
    if (have_title)
        g_font_title = io.Fonts->AddFontFromFileTTF(title, title_px, &fc);
    else if (have_body)
        g_font_title = io.Fonts->AddFontFromFileTTF(body, title_px, &fc);
    if (have_mono)
        g_font_mono = io.Fonts->AddFontFromFileTTF(mono, mono_px, &fc);
    else if (have_body)
        g_font_mono = io.Fonts->AddFontFromFileTTF(body, mono_px, &fc);
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
    s.WindowPadding = ImVec2(ThemeSpaceMd(), ThemeSpaceSm());
    s.FramePadding = ImVec2(ThemeSpaceSm(), ThemePx(5.f));
    s.ItemSpacing = ImVec2(ThemeSpaceSm(), ThemeSpaceXs() + 2.f);
    s.ItemInnerSpacing = ImVec2(ThemeSpaceXs() + 2.f, ThemeSpaceXs());
    s.CellPadding = ImVec2(ThemeSpaceSm(), ThemePx(5.f));
    s.IndentSpacing = ThemeSpaceMd();
    s.ScrollbarSize = ThemePx(10.f);
    s.GrabMinSize = ThemePx(10.f);
    s.HoverStationaryDelay = 0.35f;
    s.HoverDelayShort = 0.15f;
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
    c[ImGuiCol_BorderShadow]          = T(kBg, 0.f);
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

    ImVec2 tp = ImVec2(p.x + ThemeSpaceSm(), p.y + (bar_h - ImGui::GetFontSize()) * 0.5f);
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
        dl->AddLine(ImVec2(min_a.x + ThemePx(12.f), y), ImVec2(min_a.x + btn_w - ThemePx(12.f), y), fg, 1.f);
    }

    if (ChromeBtn("max", max_a, btn_w, bar_h))
        hit |= ThemeClickMax;
    {
        float pad = ThemePx(12.f);
        float vpad = ThemePx(10.f);
        float x0 = max_a.x + pad, y0 = max_a.y + vpad, x1 = max_a.x + btn_w - pad, y1 = max_a.y + bar_h - vpad;
        if (maximized)
        {
            dl->AddRect(ImVec2(x0 + ThemePx(3.f), y0 - ThemePx(2.f)), ImVec2(x1 + ThemePx(3.f), y1 - ThemePx(2.f)), fg);
            dl->AddRectFilled(ImVec2(x0, y0 + ThemePx(2.f)), ImVec2(x1, y1 + ThemePx(2.f)), ImGui::ColorConvertFloat4ToU32(T(kBg)));
            dl->AddRect(ImVec2(x0, y0 + ThemePx(2.f)), ImVec2(x1, y1 + ThemePx(2.f)), fg);
        }
        else
            dl->AddRect(ImVec2(x0, y0), ImVec2(x1, y1), fg);
    }

    if (ChromeBtn("close", cls_a, btn_w, bar_h))
        hit |= ThemeClickClose;
    float cpad = ThemePx(13.f);
    float cvpad = ThemePx(10.f);
    dl->AddLine(ImVec2(cls_a.x + cpad, cls_a.y + cvpad), ImVec2(cls_a.x + btn_w - cpad, cls_a.y + bar_h - cvpad), fg, 1.f);
    dl->AddLine(ImVec2(cls_a.x + btn_w - cpad, cls_a.y + cvpad), ImVec2(cls_a.x + cpad, cls_a.y + bar_h - cvpad), fg, 1.f);

    win->DC.CursorPos = bak_cursor;
    win->DC.CursorMaxPos = bak_max;
    win->DC.IdealMaxPos = bak_ideal;

    ImGui::Dummy(ImVec2(1.f, bar_h - ImGui::GetStyle().WindowPadding.y));
    return hit;
}
