#include "ui/hex_view.h"
#include "app/inspector.h"
#include "pe/pe.h"
#include "pe/patch.h"
#include "i18n/i18n.h"
#include "ui/theme.h"
#include "ui/widgets.h"
#include "persist/settings.h"

#include "imgui.h"
// credit: https://github.com/ocornut/imgui_club
#include "imgui_memory_editor.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <regex>
#include <algorithm>

enum HexSearchMode
{
    HexModeAob = 0,
    HexModeAscii,
    HexModeRegex
};

struct PatByte
{
    uint8_t v;
    uint8_t mask; // 0xFF exact, 0 wildcard
};

static MemoryEditor g_ed;
static bool g_primed;
static int g_hex_epoch = -1;
static size_t g_goto = (size_t)-1;
static size_t g_anchor = (size_t)-1;
static size_t g_sel_end = (size_t)-1;
static bool g_drag;

static char g_query[512];
static int g_mode = HexModeAob;
static char g_status[192];
static bool g_focus_search;
static std::vector<size_t> g_hits;
static int g_hit_i = -1;
static size_t g_hit_len;

static void SetStatus(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_status, (int)sizeof(g_status), fmt, ap);
    va_end(ap);
}

static bool HexNib(char c, int* o)
{
    if (c >= '0' && c <= '9') { *o = c - '0'; return true; }
    if (c >= 'a' && c <= 'f') { *o = 10 + (c - 'a'); return true; }
    if (c >= 'A' && c <= 'F') { *o = 10 + (c - 'A'); return true; }
    return false;
}

static bool IsJunk(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ',' ||
        c == '{' || c == '}' || c == '[' || c == ']' || c == '"' || c == '\'' ||
        c == ';' || c == '|' || c == '(' || c == ')';
}

static bool ParseAob(const char* s, std::vector<PatByte>* out, char* err, int errcap)
{
    out->clear();
    if (!s || !s[0])
    {
        snprintf(err, errcap, "%s", I18nGet("pe.hex_bad_pat"));
        return false;
    }
    const char* p = s;
    while (*p)
    {
        while (*p && IsJunk(*p))
            p++;
        if (!*p)
            break;
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
        {
            p += 2;
            continue;
        }
        if (p[0] == '\\' && (p[1] == 'x' || p[1] == 'X'))
        {
            p += 2;
            continue;
        }
        if (p[0] == '?' || p[0] == '*')
        {
            if (p[1] == '?' || p[1] == '*')
                p += 2;
            else
                p += 1;
            PatByte b{ 0, 0 };
            out->push_back(b);
            continue;
        }
        int hi = 0, lo = 0;
        bool hi_ok = HexNib(p[0], &hi);
        if (!hi_ok)
        {
            snprintf(err, errcap, "%s", I18nGet("pe.hex_bad_pat"));
            return false;
        }
        p++;
        PatByte b{};
        if (*p == '?' || *p == '*')
        {
            b.v = (uint8_t)(hi << 4);
            b.mask = 0xF0;
            p++;
        }
        else if (HexNib(*p, &lo))
        {
            b.v = (uint8_t)((hi << 4) | lo);
            b.mask = 0xFF;
            p++;
        }
        else
        {
            // single nibble as a full byte is too ambiguous; require pairs except ??
            snprintf(err, errcap, "%s", I18nGet("pe.hex_bad_pat"));
            return false;
        }
        out->push_back(b);
    }
    if (out->empty())
    {
        snprintf(err, errcap, "%s", I18nGet("pe.hex_bad_pat"));
        return false;
    }
    if (out->size() > 4096)
    {
        snprintf(err, errcap, "%s", I18nGet("pe.hex_bad_pat"));
        return false;
    }
    return true;
}

static bool MatchAob(const uint8_t* data, size_t n, size_t off, const std::vector<PatByte>& pat)
{
    if (off + pat.size() > n)
        return false;
    for (size_t i = 0; i < pat.size(); i++)
    {
        if ((data[off + i] & pat[i].mask) != (pat[i].v & pat[i].mask))
            return false;
    }
    return true;
}

static void CollectAob(const uint8_t* data, size_t n, const std::vector<PatByte>& pat)
{
    g_hits.clear();
    if (pat.empty() || n < pat.size())
        return;
    size_t last = n - pat.size();
    for (size_t i = 0; i <= last; i++)
    {
        if (MatchAob(data, n, i, pat))
        {
            g_hits.push_back(i);
            if (g_hits.size() >= 8192)
                break;
        }
    }
    g_hit_len = pat.size();
}

static void CollectAscii(const uint8_t* data, size_t n, const char* q)
{
    g_hits.clear();
    g_hit_len = 0;
    if (!q || !q[0])
        return;
    size_t qn = strlen(q);
    if (qn > n)
        return;
    g_hit_len = qn;
    size_t last = n - qn;
    for (size_t i = 0; i <= last; i++)
    {
        if (memcmp(data + i, q, qn) == 0)
        {
            g_hits.push_back(i);
            if (g_hits.size() >= 8192)
                break;
        }
    }
}

static void CollectRegex(const uint8_t* data, size_t n, const char* q, char* err, int errcap)
{
    g_hits.clear();
    g_hit_len = 0;
    err[0] = 0;
    if (!q || !q[0])
        return;
    std::regex re;
    try
    {
        re = std::regex(q, std::regex::ECMAScript);
    }
    catch (const std::regex_error&)
    {
        snprintf(err, errcap, "%s", I18nGet("pe.hex_bad_regex"));
        return;
    }
    const char* begin = (const char*)data;
    const char* end = begin + n;
    const char* cur = begin;
    std::cmatch m;
    while (cur < end && std::regex_search(cur, end, m, re))
    {
        if (m.length() == 0)
        {
            cur += 1;
            continue;
        }
        size_t off = (size_t)(m[0].first - begin);
        g_hits.push_back(off);
        if (g_hit_len == 0)
            g_hit_len = (size_t)m.length();
        cur = m[0].second;
        if (g_hits.size() >= 8192)
            break;
    }
}

static void ApplyHit(int i)
{
    if (i < 0 || i >= (int)g_hits.size())
        return;
    g_hit_i = i;
    size_t off = g_hits[(size_t)i];
    size_t len = g_hit_len ? g_hit_len : 1;
    g_anchor = off;
    g_sel_end = off + len - 1;
    g_ed.GotoAddrAndHighlight(off, off + len);
    SetStatus("%s  %d / %d  @ 0x%X", I18nGet("pe.hex_hits"), i + 1, (int)g_hits.size(), (unsigned)off);
}

static void RunSearch(const uint8_t* data, size_t n, bool next)
{
    g_status[0] = 0;
    if (g_mode == HexModeAob)
    {
        std::vector<PatByte> pat;
        char err[96];
        if (!ParseAob(g_query, &pat, err, (int)sizeof(err)))
        {
            snprintf(g_status, sizeof(g_status), "%s", err);
            return;
        }
        CollectAob(data, n, pat);
    }
    else if (g_mode == HexModeAscii)
        CollectAscii(data, n, g_query);
    else
    {
        char err[96] = {};
        CollectRegex(data, n, g_query, err, (int)sizeof(err));
        if (err[0])
        {
            snprintf(g_status, sizeof(g_status), "%s", err);
            return;
        }
    }
    if (g_hits.empty())
    {
        snprintf(g_status, sizeof(g_status), "%s", I18nGet("pe.hex_no_hit"));
        g_hit_i = -1;
        return;
    }
    size_t from = 0;
    if (g_sel_end != (size_t)-1)
        from = g_sel_end + 1;
    else if (g_ed.DataPreviewAddr != (size_t)-1)
        from = g_ed.DataPreviewAddr + 1;
    int pick = 0;
    if (next)
    {
        pick = 0;
        for (int i = 0; i < (int)g_hits.size(); i++)
        {
            if (g_hits[(size_t)i] >= from)
            {
                pick = i;
                break;
            }
        }
    }
    else
    {
        pick = (int)g_hits.size() - 1;
        size_t before = (g_anchor != (size_t)-1) ? g_anchor : from;
        for (int i = (int)g_hits.size() - 1; i >= 0; i--)
        {
            if (g_hits[(size_t)i] < before)
            {
                pick = i;
                break;
            }
        }
    }
    ApplyHit(pick);
}

static void CopySel(const uint8_t* data, size_t n, bool ascii)
{
    if (g_anchor == (size_t)-1 || g_sel_end == (size_t)-1)
        return;
    size_t a = g_anchor < g_sel_end ? g_anchor : g_sel_end;
    size_t b = g_anchor < g_sel_end ? g_sel_end : g_anchor;
    if (a >= n)
        return;
    if (b >= n)
        b = n - 1;
    size_t len = b - a + 1;
    if (len > 256u * 1024u)
        len = 256u * 1024u;
    std::string s;
    if (ascii)
    {
        s.reserve(len);
        for (size_t i = 0; i < len; i++)
        {
            unsigned char c = data[a + i];
            s.push_back((c >= 32 && c < 127) ? (char)c : '.');
        }
    }
    else
    {
        s.reserve(len * 3);
        for (size_t i = 0; i < len; i++)
        {
            char buf[4];
            snprintf(buf, sizeof(buf), "%s%02X", i ? " " : "", data[a + i]);
            s.append(buf);
        }
    }
    ImGui::SetClipboardText(s.c_str());
}

static void OnWrite(ImU8*, size_t off, ImU8 d, void*)
{
    uint8_t after = d;
    if (PatchApply((uint32_t)off, &after, 1, PatchSrcHex))
        InspectorNoteHexWrite();
}

static ImU32 OnBg(const ImU8* mem, size_t off, void*)
{
    PatchByteState st = PatchColor((uint32_t)off, mem[off]);
    if (st == PatchByteUnsaved)
        return ThemeColHexUnsaved();
    if (st == PatchByteSaved)
        return ThemeColHexSaved();
    return 0;
}

static void UpdateSelFromMouse()
{
    ImGuiIO& io = ImGui::GetIO();
    if (g_ed.MouseHovered && g_ed.MouseHoveredAddr != (size_t)-1)
    {
        if (ImGui::IsMouseClicked(ImGuiMouseButton_Left))
        {
            if (io.KeyShift && g_anchor != (size_t)-1)
                g_sel_end = g_ed.MouseHoveredAddr;
            else
            {
                g_anchor = g_ed.MouseHoveredAddr;
                g_sel_end = g_anchor;
            }
            g_drag = true;
        }
        if (g_drag && ImGui::IsMouseDown(ImGuiMouseButton_Left))
        {
            g_sel_end = g_ed.MouseHoveredAddr;
            if (g_sel_end != g_anchor)
                g_ed.DataEditingAddr = (size_t)-1;
        }
    }
    if (ImGui::IsMouseReleased(ImGuiMouseButton_Left))
        g_drag = false;

    if (g_anchor != (size_t)-1 && g_sel_end != (size_t)-1)
    {
        size_t a = g_anchor < g_sel_end ? g_anchor : g_sel_end;
        size_t b = g_anchor < g_sel_end ? g_sel_end : g_anchor;
        g_ed.HighlightMin = a;
        g_ed.HighlightMax = b + 1;
    }
}

void HexViewReset()
{
    g_anchor = g_sel_end = (size_t)-1;
    g_goto = (size_t)-1;
    g_drag = false;
    g_hits.clear();
    g_hit_i = -1;
    g_hit_len = 0;
    g_status[0] = 0;
    g_ed.HighlightMin = g_ed.HighlightMax = (size_t)-1;
    g_ed.DataEditingAddr = g_ed.DataPreviewAddr = (size_t)-1;
}

void HexViewOpen(const uint8_t*, size_t)
{
    HexViewReset();
}

void HexViewOnSaved()
{
}

void HexViewGoto(size_t off)
{
    g_goto = off;
    g_anchor = off;
    g_sel_end = off;
}

void HexViewSelect(size_t off, size_t n)
{
    if (!n)
        n = 1;
    g_goto = off;
    g_anchor = off;
    g_sel_end = off + n - 1;
}

void HexViewDraw()
{
    size_t n = 0;
    uint8_t* b = PeJobBytes(&n);
    if (!b || !n)
    {
        ImGui::TextUnformatted(I18nGet("pe.none"));
        return;
    }

    if (g_hex_epoch != SettingsLayoutEpoch())
    {
        g_primed = false;
        g_hex_epoch = SettingsLayoutEpoch();
    }
    if (!g_primed)
    {
        g_ed.ReadOnly = false;
        g_ed.OptShowDataPreview = SettingsLayoutGetBool("hex.preview", true);
        g_ed.Cols = SettingsLayoutGetInt("hex.cols", 16);
        if (g_ed.Cols < 4)
            g_ed.Cols = 4;
        if (g_ed.Cols > 32)
            g_ed.Cols = 32;
        g_ed.OptShowAscii = SettingsLayoutGetBool("hex.ascii", true);
        g_ed.OptShowHexII = SettingsLayoutGetBool("hex.hexii", false);
        g_ed.OptGreyOutZeroes = SettingsLayoutGetBool("hex.grey_zeroes", true);
        g_ed.OptUpperCaseHex = SettingsLayoutGetBool("hex.uppercase", true);
        g_ed.WriteFn = OnWrite;
        g_ed.BgColorFn = OnBg;
        g_primed = true;
    }
    ImVec4 hl = ImGui::ColorConvertU32ToFloat4(ThemeColAccent());
    hl.w = 0.38f;
    g_ed.HighlightColor = ImGui::ColorConvertFloat4ToU32(hl);

    if (g_goto != (size_t)-1)
    {
        size_t a = g_goto;
        size_t b = a + 1;
        if (g_sel_end != (size_t)-1 && g_sel_end >= a)
            b = g_sel_end + 1;
        g_ed.GotoAddrAndHighlight(a, b);
        if (g_anchor == (size_t)-1)
        {
            g_anchor = a;
            g_sel_end = a;
        }
        g_goto = (size_t)-1;
    }

    ImGuiIO& io = ImGui::GetIO();
    bool hex_win = ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows);
    bool cell = g_ed.DataEditingAddr != (size_t)-1;
    bool search_text = io.WantTextInput && !cell;
    if (hex_win && !search_text)
    {
        ImGuiInputFlags zflags = ImGuiInputFlags_RouteFocused;
        if (cell)
            zflags = ImGuiInputFlags_RouteGlobal | ImGuiInputFlags_RouteOverActive;
        if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_Z, zflags))
        {
            if (PatchUndo())
                InspectorNoteHexWrite();
        }
        if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_Y, zflags))
        {
            if (PatchRedo())
                InspectorNoteHexWrite();
        }
    }
    if (hex_win && io.KeyCtrl &&
        ImGui::IsKeyPressed(ImGuiKey_F, false) && !io.WantTextInput)
        g_focus_search = true;

    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    ImGui::TextWrapped("%s", I18nGet("pe.hex_hint"));
    ImGui::PopStyleColor();
    ImGui::Spacing();

    if (g_focus_search)
    {
        ImGui::SetKeyboardFocusHere();
        g_focus_search = false;
    }
    float qw = ImGui::GetContentRegionAvail().x - ThemePx(360.f);
    if (qw < ThemePx(140.f))
        qw = ThemePx(140.f);
    ImGui::SetNextItemWidth(qw);
    bool enter = ImGui::InputTextWithHint("##hexq", I18nGet("pe.hex_search"), g_query,
        IM_ARRAYSIZE(g_query), ImGuiInputTextFlags_EnterReturnsTrue);
    if (ImGui::IsItemHovered())
        UiTooltip(I18nGet("help.hex_search"));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ThemePx(140.f));
    const char* modes[3] = {
        I18nGet("pe.hex_mode_aob"),
        I18nGet("pe.hex_mode_ascii"),
        I18nGet("pe.hex_mode_regex")
    };
    if (ImGui::BeginCombo("##hexmode", modes[g_mode]))
    {
        for (int i = 0; i < 3; i++)
        {
            bool sel = (g_mode == i);
            if (ImGui::Selectable(modes[i], sel))
                g_mode = i;
            if (sel)
                ImGui::SetItemDefaultFocus();
        }
        ImGui::EndCombo();
    }
    ImGui::SameLine();
    if (UiButton(I18nGet("pe.hex_find_next")) || enter)
        RunSearch(b, n, true);
    ImGui::SameLine();
    if (UiButton(I18nGet("pe.hex_find_prev")))
        RunSearch(b, n, false);

    if (g_anchor != (size_t)-1 && g_sel_end != (size_t)-1)
    {
        size_t a = g_anchor < g_sel_end ? g_anchor : g_sel_end;
        size_t e = g_anchor < g_sel_end ? g_sel_end : g_anchor;
        if (e >= n)
            e = n - 1;
        size_t len = e - a + 1;
        ImGui::Text("%s  0x%X-0x%X  (%zu)", I18nGet("pe.hex_sel"), (unsigned)a, (unsigned)e, len);
        ImGui::SameLine();
        if (UiButton(I18nGet("pe.hex_copy_hex")))
            CopySel(b, n, false);
        ImGui::SameLine();
        if (UiButton(I18nGet("pe.hex_copy_ascii")))
            CopySel(b, n, true);
        if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && io.KeyCtrl &&
            ImGui::IsKeyPressed(ImGuiKey_C, false) && !io.WantTextInput)
            CopySel(b, n, false);
    }
    if (g_status[0])
    {
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
        ImGui::TextUnformatted(g_status);
        ImGui::PopStyleColor();
    }

    UpdateSelFromMouse();

    if (ImFont* mono = ThemeFontMono())
        ImGui::PushFont(mono);
    g_ed.DrawContents(b, n);
    if (ThemeFontMono())
        ImGui::PopFont();

    UpdateSelFromMouse();

    SettingsLayoutSetInt("hex.cols", g_ed.Cols);
    SettingsLayoutSetBool("hex.ascii", g_ed.OptShowAscii);
    SettingsLayoutSetBool("hex.hexii", g_ed.OptShowHexII);
    SettingsLayoutSetBool("hex.grey_zeroes", g_ed.OptGreyOutZeroes);
    SettingsLayoutSetBool("hex.uppercase", g_ed.OptUpperCaseHex);
    SettingsLayoutSetBool("hex.preview", g_ed.OptShowDataPreview);
}
