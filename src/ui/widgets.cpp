#include "ui/widgets.h"
#include "ui/theme.h"
#include "persist/settings.h"
#include "i18n/i18n.h"
#include "ui/icons.h"
#include "imgui.h"
#include "imgui_internal.h"

#include <math.h>
#include <float.h>
#include <string.h>
#include <stdio.h>

#include <windows.h>

bool UiAnimEnabled()
{
    return SettingsGetBool("animations", true);
}

float UiEaseOut(float t)
{
    if (t <= 0.f)
        return 0.f;
    if (t >= 1.f)
        return 1.f;
    float u = 1.f - t;
    return 1.f - u * u * u;
}

static float Saturate(float t)
{
    if (t < 0.f)
        return 0.f;
    if (t > 1.f)
        return 1.f;
    return t;
}

ImU32 UiLerpCol(ImU32 a, ImU32 b, float t)
{
    t = Saturate(t);
    int ar = (int)(a & 255), ag = (int)((a >> 8) & 255), ab = (int)((a >> 16) & 255), aa = (int)((a >> 24) & 255);
    int br = (int)(b & 255), bg = (int)((b >> 8) & 255), bb = (int)((b >> 16) & 255), ba = (int)((b >> 24) & 255);
    int r = (int)(ar + (br - ar) * t);
    int g = (int)(ag + (bg - ag) * t);
    int bl = (int)(ab + (bb - ab) * t);
    int al = (int)(aa + (ba - aa) * t);
    return (ImU32)(r | (g << 8) | (bl << 16) | (al << 24));
}

float UiHoverT(unsigned int id, bool hovered)
{
    float target = hovered ? 1.f : 0.f;
    if (!UiAnimEnabled())
        return target;
    ImGuiStorage* st = ImGui::GetStateStorage();
    ImGuiID key = (ImGuiID)id;
    float t = st->GetFloat(key, 0.f);
    float dt = ImGui::GetIO().DeltaTime;
    float k = 1.f - expf(-UiAnimSpeedMs(UiAnimFastMs) * dt);
    t += (target - t) * k;
    st->SetFloat(key, t);
    return UiEaseOut(t);
}

float UiAnimToward(unsigned int id, float target, float speed)
{
    if (!UiAnimEnabled())
        return target;
    ImGuiStorage* st = ImGui::GetStateStorage();
    ImGuiID key = (ImGuiID)id;
    float t = st->GetFloat(key, target);
    float dt = ImGui::GetIO().DeltaTime;
    if (speed < 1.f)
        speed = 1.f;
    float k = 1.f - expf(-speed * dt);
    t += (target - t) * k;
    st->SetFloat(key, t);
    return t;
}

float UiReveal(unsigned int id, bool active, float speed)
{
    if (!active)
    {
        ImGui::GetStateStorage()->SetFloat((ImGuiID)id, 0.f);
        return 0.f;
    }
    if (!UiAnimEnabled())
        return 1.f;
    ImGuiStorage* st = ImGui::GetStateStorage();
    ImGuiID key = (ImGuiID)id;
    float t = st->GetFloat(key, 0.f);
    t += ImGui::GetIO().DeltaTime * speed;
    t = Saturate(t);
    st->SetFloat(key, t);
    return UiEaseOut(t);
}

static double g_enter_at;
static bool   g_enter_set;

void UiAnimPageEnter()
{
    g_enter_at = ImGui::GetTime();
    g_enter_set = true;
}

float UiEnter(float delay, float dur)
{
    if (!UiAnimEnabled())
        return 1.f;
    if (!g_enter_set)
    {
        g_enter_at = ImGui::GetTime();
        g_enter_set = true;
    }
    if (dur < 0.02f)
        dur = 0.02f;
    float t = (float)(ImGui::GetTime() - g_enter_at - (double)delay) / dur;
    return UiEaseOut(Saturate(t));
}

void UiHoverSweep(ImVec2 a, ImVec2 b, float t, float alpha_scale, ImDrawList* dl)
{
    if (t <= 0.001f || alpha_scale <= 0.001f)
        return;
    if (!dl)
        dl = ImGui::GetWindowDrawList();
    float tf = t * alpha_scale;
    if (tf > 1.f)
        tf = 1.f;
    unsigned fill_a = (unsigned)(32.f * tf);
    unsigned line_a = (unsigned)(220.f * tf);
    dl->AddRectFilled(a, b, ThemeColAccentA((float)fill_a / 255.f));
    float mid = (a.x + b.x) * 0.5f;
    float hw = (b.x - a.x) * 0.5f * t;
    dl->AddLine(ImVec2(mid - hw, b.y - 1.f), ImVec2(mid + hw, b.y - 1.f),
        ThemeColAccentA((float)line_a / 255.f), 1.6f);
    dl->PushClipRect(a, b, true);
    float reach = t * ((b.x - a.x) * 0.55f + 6.f);
    unsigned alpha = (unsigned)(48.f * tf);
    ImU32 col = ThemeColAccentA((float)alpha / 255.f);
    ImVec2 bl(a.x, b.y);
    dl->AddTriangleFilled(bl, ImVec2(a.x + reach * 2.f, b.y), ImVec2(a.x, b.y - reach * 2.f), col);
    dl->PopClipRect();
}

void UiAccentBar(ImVec2 a, ImVec2 b, float t, ImDrawList* dl)
{
    if (t <= 0.001f)
        return;
    if (!dl)
        dl = ImGui::GetWindowDrawList();
    float h = (b.y - a.y) * t;
    float y0 = a.y + ((b.y - a.y) - h) * 0.5f;
    dl->AddRectFilled(ImVec2(a.x, y0), ImVec2(a.x + 3.f, y0 + h), ThemeColAccent());
}

void UiHandIfHovered()
{
    if (ImGui::IsItemHovered())
        ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
}

void UiDecorateLastButton()
{
    UiHandIfHovered();
    ImVec2 a = ImGui::GetItemRectMin();
    ImVec2 b = ImGui::GetItemRectMax();
    float t = UiHoverT(ImGui::GetItemID(), ImGui::IsItemHovered());
    UiHoverSweep(a, b, t);
}

bool UiButton(const char* label, ImVec2 size, int kind)
{
    ImVec2 ts = ImGui::CalcTextSize(label);
    ImVec2 pad = ImGui::GetStyle().FramePadding;
    if (size.x <= 0.f)
        size.x = ts.x + pad.x * 2.f;
    if (size.y <= 0.f)
        size.y = ImGui::GetFrameHeight();
    if (size.y < ThemeHitMin())
        size.y = ThemeHitMin();
    ImVec2 p = ImGui::GetCursorScreenPos();
    bool hit = ImGui::InvisibleButton(label, size);
    ImVec2 q = ImGui::GetItemRectMax();
    bool hovered = ImGui::IsItemHovered();
    bool active = ImGui::IsItemActive();
    bool focused = ImGui::IsItemFocused();
    float t = UiHoverT(ImGui::GetItemID(), hovered || active);
    if (active)
        t = 1.f;
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImU32 fill;
    ImU32 border;
    ImU32 text;
    if (kind == 1)
    {
        fill = UiLerpCol(ThemeColAccent(), ThemeColFg(), active ? 0.22f : t * 0.12f);
        border = ThemeColAccent();
        text = ThemeColBg();
    }
    else
    {
        fill = UiLerpCol(ThemeColCard(), ThemeColHover(), t);
        if (active)
            fill = UiLerpCol(fill, ThemeColAccent(), 0.18f);
        border = UiLerpCol(ThemeColBorder(), ThemeColAccent(), t);
        text = UiLerpCol(ThemeColFg(), ThemeColAccent(), t * 0.55f);
    }
    dl->AddRectFilled(p, q, fill);
    dl->AddRect(p, q, focused ? ThemeColAccent() : border);
    UiHandIfHovered();
    if (kind != 1)
        UiHoverSweep(p, q, t);
    float lift = 0.f;
    if (UiAnimEnabled())
        lift = active ? 1.f : t * -1.f;
    dl->AddText(ImVec2(p.x + (size.x - ts.x) * 0.5f, p.y + (size.y - ts.y) * 0.5f + lift), text, label);
    return hit;
}

void UiEmpty(const char* title, const char* detail)
{
    ImGui::Dummy(ImVec2(1.f, ThemeSpaceMd()));
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    if (title && title[0])
        ImGui::TextWrapped("%s", title);
    if (detail && detail[0])
        ImGui::TextWrapped("%s", detail);
    ImGui::PopStyleColor();
}

void UiSection(const char* title)
{
    if (!title || !title[0])
        return;
    ImGui::Dummy(ImVec2(1.f, ThemeSpaceXs()));
    ImGui::TextUnformatted(title);
    ImVec2 a = ImGui::GetItemRectMin();
    ImVec2 b = ImGui::GetItemRectMax();
    ImGui::GetWindowDrawList()->AddLine(
        ImVec2(b.x + ThemeSpaceSm(), (a.y + b.y) * 0.5f),
        ImVec2(a.x + ImGui::GetContentRegionAvail().x, (a.y + b.y) * 0.5f),
        ThemeColBorder());
    ImGui::Dummy(ImVec2(1.f, ThemeSpaceXs()));
}

void UiTooltip(const char* text)
{
    if (!text || !text[0])
        return;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(ThemeTooltipPad(), ThemeTooltipPad()));
    ImGui::BeginTooltip();
    ImGui::PushTextWrapPos(ImGui::GetFontSize() * 36.f);
    ImGui::TextUnformatted(text);
    ImGui::PopTextWrapPos();
    ImGui::EndTooltip();
    ImGui::PopStyleVar();
}

void UiTipWhenDisabled(const char* text)
{
    if (!text || !text[0])
        return;
    if (!ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled | ImGuiHoveredFlags_DelayShort))
        return;
    UiTooltip(text);
}

struct BadgeGeom
{
    ImVec2 ts;
    ImVec2 sz;
    float  pad_x;
    float  pad_y;
    float  icon_slot;
};

static BadgeGeom BadgeCalc(const char* label, float min_w, int icon)
{
    BadgeGeom g;
    g.pad_x = ThemeBadgePadX();
    g.pad_y = ThemeBadgePadY();
    g.icon_slot = 0.f;
    if (icon >= 0)
        g.icon_slot = IconSize(IconRoleXs) * 2.f + ThemeBadgeIconGap();
    ImFont* font = ImGui::GetFont();
    float fs = ImGui::GetFontSize();
    if (label && label[0] && font)
        g.ts = font->CalcTextSizeA(fs, FLT_MAX, 0.f, label);
    else
        g.ts = ImVec2(0.f, fs);
    float w = g.ts.x + g.pad_x * 2.f + g.icon_slot;
    float h = g.ts.y + g.pad_y * 2.f;
    float min_h = ThemeBadgeMinH();
    if (h < min_h)
        h = min_h;
    if (min_w > 0.f && w < min_w)
        w = min_w;
    g.sz = ImVec2(ceilf(w), ceilf(h));
    return g;
}

float UiBadgeWidth(const char* label, float min_w, int icon)
{
    return BadgeCalc(label, min_w, icon).sz.x;
}

float UiBadgeHeight()
{
    return BadgeCalc("", 0.f, -1).sz.y;
}

static void BadgeAlignInline(float h)
{
    ImGuiWindow* w = ImGui::GetCurrentWindow();
    if (!w || w->SkipItems || !w->DC.IsSameLine)
        return;
    float prev_h = w->DC.PrevLineSize.y;
    if (prev_h <= 1.f || h >= prev_h)
        return;
    w->DC.CursorPos.y += floorf((prev_h - h) * 0.5f);
}

void UiBadge(const char* id, const char* label, ImU32 col, const char* tip, float min_w, int icon)
{
    if (!label || !label[0])
        return;
    BadgeGeom g = BadgeCalc(label, min_w, icon);
    float avail = ImGui::GetContentRegionAvail().x;
    bool clipped = false;
    if (avail > ThemePx(24.f) && g.sz.x > avail)
    {
        g.sz.x = floorf(avail);
        clipped = true;
    }
    BadgeAlignInline(g.sz.y);
    ImGui::PushID(id ? id : "badge");
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImGui::Dummy(g.sz);
    ImVec2 q = ImVec2(p.x + g.sz.x, p.y + g.sz.y);
    float alpha = ImGui::GetStyle().Alpha;
    if (alpha < 0.f)
        alpha = 0.f;
    if (alpha > 1.f)
        alpha = 1.f;
    ImU32 bg = ThemeWithAlpha(col, 0.14f * alpha);
    ImU32 border = ThemeWithAlpha(col, 0.50f * alpha);
    ImU32 fg = ThemeWithAlpha(col, alpha);
    float r = ThemeBadgeRadius(g.sz.y);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(p, q, bg, r);
    dl->AddRect(p, q, border, r, 0, ThemeBadgeBorderW());
    dl->PushClipRect(p, q, true);
    float ix = p.x + g.pad_x;
    if (icon >= 0)
    {
        float is = IconSize(IconRoleXs);
        IconDraw(icon, ImVec2(ix + is, p.y + g.sz.y * 0.5f), is, fg, dl);
        ix += g.icon_slot;
    }
    float inner_w = q.x - g.pad_x - ix;
    float tx = ix;
    if (inner_w > g.ts.x)
        tx += floorf((inner_w - g.ts.x) * 0.5f);
    float ty = p.y + floorf((g.sz.y - g.ts.y) * 0.5f + 0.5f) + ThemePx(0.75f);
    dl->AddText(ImGui::GetFont(), ImGui::GetFontSize(), ImVec2(tx, ty), fg, label);
    dl->PopClipRect();
    const char* hover_tip = tip;
    if ((!hover_tip || !hover_tip[0]) && clipped)
        hover_tip = label;
    if (hover_tip && hover_tip[0] && ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort))
        UiTooltip(hover_tip);
    ImGui::PopID();
}

bool UiCopyButton(const char* id, const char* text)
{
    ImGui::PushID(id ? id : "copy");
    float h = ImGui::GetFrameHeight();
    if (h < ThemePx(28.f))
        h = ThemePx(28.f);
    float w = h;
    ImVec2 p = ImGui::GetCursorScreenPos();
    bool disabled = !text || !text[0];
    if (disabled)
        ImGui::BeginDisabled();
    bool hit = ImGui::InvisibleButton("cpy", ImVec2(w, h));
    ImVec2 q = ImGui::GetItemRectMax();
    bool hovered = ImGui::IsItemHovered();
    bool active = ImGui::IsItemActive();
    float ht = UiHoverT(ImGui::GetItemID(), hovered || active);
    if (active)
        ht = 1.f;
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImU32 fill = UiLerpCol(ThemeColCard(), ThemeColHover(), ht);
    if (active)
        fill = UiLerpCol(fill, ThemeColAccent(), 0.16f);
    dl->AddRectFilled(p, q, fill);
    UiHandIfHovered();
    ImU32 col = UiLerpCol(ThemeColFg(), ThemeColAccent(), ht);
    float s = IconSize(IconRoleMd);
    IconDraw(IconCopy, ImVec2(p.x + w * 0.5f, p.y + h * 0.5f), s, col, dl);
    if (disabled)
        ImGui::EndDisabled();
    else if (hit)
    {
        ImGui::SetClipboardText(text);
        UiToastPush(UiToastSuccess, I18nGet("toast.copy.title"), nullptr);
    }
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort))
        UiTooltip(I18nGet("ui.copy"));
    ImGui::PopID();
    return hit && !disabled;
}

void UiFieldText(const char* id, char* buf, int buf_cap, float width)
{
    if (!id || !buf || buf_cap < 2)
        return;
    ImGui::PushID(id);
    ImGui::AlignTextToFramePadding();
    ImGui::SetNextItemWidth(width);
    ImVec4 frame = ImGui::ColorConvertU32ToFloat4(ThemeColCardA(0.45f));
    ImVec4 border = ImGui::ColorConvertU32ToFloat4(ThemeColBorderA(0.35f));
    ImGui::PushStyleColor(ImGuiCol_FrameBg, frame);
    ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, frame);
    ImGui::PushStyleColor(ImGuiCol_FrameBgActive, frame);
    ImGui::PushStyleColor(ImGuiCol_Border, border);
    ImGui::InputText("##field", buf, (size_t)buf_cap, ImGuiInputTextFlags_ReadOnly);
    ImGui::PopStyleColor(4);
    ImGui::PopID();
}

enum { kPersistStackMax = 4 };

struct PersistTableFrame
{
    char  id[48];
    char  col[UiTableColMax][48];
    float def_w[UiTableColMax];
    int   n;
};

static PersistTableFrame g_persist_stack[kPersistStackMax];
static int g_persist_n;

struct PersistApply
{
    char id[48];
    int  epoch;
};

static PersistApply g_persist_applied[32];

static int PersistAppliedEpoch(const char* id)
{
    for (int i = 0; i < 32; i++)
    {
        if (g_persist_applied[i].id[0] && strcmp(g_persist_applied[i].id, id) == 0)
            return g_persist_applied[i].epoch;
    }
    return -1;
}

static void PersistMarkApplied(const char* id, int epoch)
{
    int slot = -1;
    for (int i = 0; i < 32; i++)
    {
        if (g_persist_applied[i].id[0] && strcmp(g_persist_applied[i].id, id) == 0)
        {
            slot = i;
            break;
        }
        if (slot < 0 && !g_persist_applied[i].id[0])
            slot = i;
    }
    if (slot < 0)
        slot = 0;
    snprintf(g_persist_applied[slot].id, sizeof(g_persist_applied[slot].id), "%s", id);
    g_persist_applied[slot].epoch = epoch;
}

bool UiBeginPersistTable(const char* table_id, const UiTableColDef* cols, int n,
    ImGuiTableFlags flags, ImVec2 outer_size)
{
    if (!table_id || !table_id[0] || !cols || n < 1)
        return false;
    if (n > UiTableColMax)
        n = UiTableColMax;
    flags |= ImGuiTableFlags_NoSavedSettings;
    if (!ImGui::BeginTable(table_id, n, flags, outer_size))
        return false;
    if (g_persist_n >= kPersistStackMax)
    {
        ImGui::EndTable();
        return false;
    }
    PersistTableFrame& f = g_persist_stack[g_persist_n++];
    snprintf(f.id, sizeof(f.id), "%s", table_id);
    f.n = n;
    float dpi = ThemeDpi();
    if (dpi < 0.5f)
        dpi = 1.f;
    for (int i = 0; i < n; i++)
    {
        snprintf(f.col[i], sizeof(f.col[i]), "%s", cols[i].id ? cols[i].id : "col");
        f.def_w[i] = cols[i].def_w;
        ImGuiTableColumnFlags cf = cols[i].flags;
        float init = 0.f;
        bool skip_saved = (cf & ImGuiTableColumnFlags_WidthFixed) != 0 && cols[i].def_w <= 0.f;
        if (skip_saved)
            init = 0.f;
        else if (SettingsLayoutHasCol(table_id, f.col[i]))
        {
            init = SettingsLayoutColW(table_id, f.col[i], cols[i].def_w) * dpi;
            cf = (cf & ~ImGuiTableColumnFlags_WidthMask_) | ImGuiTableColumnFlags_WidthFixed;
        }
        else if (cols[i].def_w > 0.f)
        {
            init = ThemePx(cols[i].def_w);
            if ((cf & ImGuiTableColumnFlags_WidthMask_) == 0)
                cf |= ImGuiTableColumnFlags_WidthFixed;
        }
        ImGui::TableSetupColumn(cols[i].label ? cols[i].label : f.col[i], cf, init);
    }
    int epoch = SettingsLayoutEpoch();
    ImGuiTable* cur = ImGui::GetCurrentTable();
    if (cur && cur->MinColumnWidth > 0.f && PersistAppliedEpoch(table_id) != epoch)
    {
        for (int i = 0; i < n; i++)
        {
            bool skip_saved = (cols[i].flags & ImGuiTableColumnFlags_WidthFixed) != 0 && f.def_w[i] <= 0.f;
            if (skip_saved)
                continue;
            ImGuiTableColumnFlags cf = cur->Columns[i].Flags;
            if ((cf & ImGuiTableColumnFlags_WidthFixed) == 0)
                continue;
            float px = 0.f;
            if (SettingsLayoutHasCol(table_id, f.col[i]))
                px = SettingsLayoutColW(table_id, f.col[i], f.def_w[i]) * dpi;
            else if (f.def_w[i] > 0.f)
                px = ThemePx(f.def_w[i]);
            if (px > 0.f)
                ImGui::TableSetColumnWidth(i, px);
        }
        PersistMarkApplied(table_id, epoch);
    }
    return true;
}

void UiEndPersistTable()
{
    if (g_persist_n <= 0)
    {
        ImGui::EndTable();
        return;
    }
    PersistTableFrame f = g_persist_stack[--g_persist_n];
    ImGuiTable* t = ImGui::GetCurrentTable();
    if (t && t->ResizedColumn != -1)
    {
        float dpi = ThemeDpi();
        if (dpi < 0.5f)
            dpi = 1.f;
        int nc = t->ColumnsCount;
        if (nc > f.n)
            nc = f.n;
        for (int i = 0; i < nc; i++)
        {
            float w = t->Columns[i].WidthGiven;
            if (w < 8.f)
                continue;
            SettingsLayoutSetColW(f.id, f.col[i], w / dpi);
        }
    }
    ImGui::EndTable();
}

float UiPersistSplitW(const char* id, float* sz, float def_frac, float min_a, float min_b)
{
    (void)id;
    float avail = ImGui::GetContentRegionAvail().x;
    if (!sz)
        return avail * (def_frac > 0.f ? def_frac : 0.36f);
    if (*sz < 1.f)
        *sz = avail * (def_frac > 0.f ? def_frac : 0.36f);
    if (*sz < min_a)
        *sz = min_a;
    if (*sz + min_b > avail)
        *sz = avail - min_b;
    if (*sz < min_a)
        *sz = min_a;
    if (*sz < ThemePx(48.f))
        *sz = ThemePx(48.f);
    return *sz;
}

void UiPushPopupMetrics()
{
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(ThemePopupPad(), ThemePopupPad()));
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(ThemeMenuItemPadX(), ThemeMenuItemPadY()));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(ThemePx(8.f), ThemeMenuItemPadY()));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemInnerSpacing, ImVec2(ThemePx(8.f), ThemePx(4.f)));
}

void UiPopPopupMetrics()
{
    ImGui::PopStyleVar(4);
}

bool UiBeginPopup(const char* str_id)
{
    UiPushPopupMetrics();
    ImGui::SetNextWindowSizeConstraints(ImVec2(ThemePx(196.f), 0.f), ImVec2(FLT_MAX, FLT_MAX));
    bool open = ImGui::BeginPopup(str_id);
    if (!open)
    {
        UiPopPopupMetrics();
        return false;
    }
    UiPopupFadePush();
    return true;
}

bool UiBeginPopupContextItem(const char* str_id)
{
    UiPushPopupMetrics();
    ImGui::SetNextWindowSizeConstraints(ImVec2(ThemePx(196.f), 0.f), ImVec2(FLT_MAX, FLT_MAX));
    bool open = ImGui::BeginPopupContextItem(str_id);
    if (!open)
    {
        UiPopPopupMetrics();
        return false;
    }
    UiPopupFadePush();
    return true;
}

void UiEndPopup()
{
    UiPopupFadePop();
    ImGui::EndPopup();
    UiPopPopupMetrics();
}

bool UiCheckbox(const char* id, const char* label, bool* value)
{
    if (!value)
        return false;
    ImGui::PushID(id ? id : "chk");
    float h = ImGui::GetFrameHeight();
    float box = h - ThemeSpaceXs() * 2.f;
    ImVec2 ts = ImGui::CalcTextSize(label ? label : "");
    ImVec2 p = ImGui::GetCursorScreenPos();
    float w = box + ThemeSpaceSm() + ts.x + ThemeSpaceXs();
    bool hit = ImGui::InvisibleButton("hit", ImVec2(w, h));
    if (hit)
        *value = !*value;
    UiHandIfHovered();
    ImVec2 q = ImGui::GetItemRectMax();
    float ht = UiHoverT(ImGui::GetItemID(), ImGui::IsItemHovered());
    UiHoverSweep(p, q, ht);

    float bx = p.x + 2.f;
    float by = p.y + (h - box) * 0.5f;
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(ImVec2(bx, by), ImVec2(bx + box, by + box), ThemeColCard());
    dl->AddRect(ImVec2(bx, by), ImVec2(bx + box, by + box), UiLerpCol(ThemeColBorder(), ThemeColAccent(), ht));
    float ct = UiAnimToward(ImGui::GetItemID() ^ 0xC11u, *value ? 1.f : 0.f, 18.f);
    if (ct > 0.01f)
    {
        ImU32 acc = ThemeWithAlpha(ThemeColAccent(), ct);
        float m = 0.35f + 0.65f * ct;
        dl->AddLine(ImVec2(bx + 3.f, by + box * 0.55f), ImVec2(bx + box * 0.42f, by + box - 3.f), acc, 2.f * m);
        dl->AddLine(ImVec2(bx + box * 0.42f, by + box - 3.f), ImVec2(bx + box - 3.f, by + 3.f), acc, 2.f * m);
    }
    dl->AddText(ImVec2(bx + box + ThemeSpaceSm(), p.y + (h - ts.y) * 0.5f), ThemeColFg(), label ? label : "");
    ImGui::PopID();
    return hit;
}

void UiSpinner(ImVec2 center, float radius, float progress)
{
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const float pi = 3.14159265f;
    float pulse = 1.f;
    if (UiAnimEnabled() && !(progress >= 0.f && progress <= 1.f))
        pulse = 1.f + 0.04f * sinf((float)ImGui::GetTime() * 5.f);
    float r = radius * pulse;
    dl->AddCircle(center, r, ThemeColBorder(), 48, 3.f);
    float t = (float)ImGui::GetTime();
    float a0;
    float a1;
    if (progress >= 0.f && progress <= 1.f)
    {
        a0 = -pi * 0.5f;
        a1 = a0 + progress * pi * 2.f;
    }
    else
    {
        a0 = t * 4.2f;
        a1 = a0 + pi * 1.35f;
    }
    dl->PathArcTo(center, r, a0, a1, 32);
    dl->PathStroke(ThemeColAccent(), 0, 3.f);
}

void UiHelpMark(const char* text)
{
    if (!text || !text[0])
        return;
    ImVec2 p = ImGui::GetCursorScreenPos();
    float h = ImGui::GetTextLineHeight();
    float s = h * 0.92f;
    ImGui::InvisibleButton("helpq", ImVec2(s, s));
    float t = UiHoverT(ImGui::GetItemID(), ImGui::IsItemHovered());
    ImVec2 c(p.x + s * 0.5f, p.y + s * 0.5f);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    float rad = s * (0.42f + 0.08f * t);
    ImU32 col = UiLerpCol(ThemeColMuted(), ThemeColAccent(), t);
    dl->AddCircle(c, rad, col, 16, 1.3f);
    const char* q = "?";
    ImVec2 ts = ImGui::CalcTextSize(q);
    dl->AddText(ImVec2(c.x - ts.x * 0.5f, c.y - ts.y * 0.52f), col, q);
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNone))
        UiTooltip(text);
}

void UiPopupFadePush()
{
    float t = UiReveal(ImGui::GetID("##popfade"), true, 12.f);
    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, 0.45f + 0.55f * t);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 a = ImGui::GetWindowPos();
    ImVec2 b = ImVec2(a.x + ImGui::GetWindowSize().x, a.y + ImGui::GetWindowSize().y);
    float mid = (a.x + b.x) * 0.5f;
    float hw = (b.x - a.x) * 0.5f * t;
    dl->AddLine(ImVec2(mid - hw, a.y + 1.f), ImVec2(mid + hw, a.y + 1.f), ThemeColAccent(), 1.5f);
}

void UiPopupFadePop()
{
    ImGui::PopStyleVar();
}

static const int kToastMax = 5;
static const float kToastDur[4] = { 3.2f, 4.0f, 5.0f, 6.5f };

struct UiToastSlot
{
    bool     active;
    UiToastType type;
    char     title[96];
    char     body[192];
    double   born;
    float    close_t;
    bool     closing;
    unsigned dedup;
};

static UiToastSlot g_toasts[kToastMax];

static double ToastNowSec()
{
    return (double)GetTickCount64() * 0.001;
}

static unsigned ToastDedupHash(UiToastType type, const char* title, const char* body)
{
    unsigned h = (unsigned)type * 1315423911u;
    if (title)
        for (const char* p = title; *p; p++)
            h = h * 33u + (unsigned char)*p;
    if (body)
        for (const char* p = body; *p; p++)
            h = h * 33u + (unsigned char)*p;
    return h;
}

static ImU32 ToastAccentCol(UiToastType type)
{
    switch (type)
    {
    case UiToastSuccess: return ThemeColSuccess();
    case UiToastInfo:    return ThemeColInfo();
    case UiToastWarning: return ThemeColWarning();
    case UiToastError:   return ThemeColDanger();
    default:             return ThemeColAccent();
    }
}

void UiToastPush(UiToastType type, const char* title, const char* body)
{
    if (!title || !title[0])
        return;
    unsigned dedup = ToastDedupHash(type, title, body);
    double now = ToastNowSec();
    for (int i = 0; i < kToastMax; i++)
    {
        if (g_toasts[i].active && g_toasts[i].dedup == dedup)
        {
            g_toasts[i].born = now;
            g_toasts[i].closing = false;
            g_toasts[i].close_t = 0.f;
            return;
        }
    }
    int slot = -1;
    for (int i = 0; i < kToastMax; i++)
    {
        if (!g_toasts[i].active)
        {
            slot = i;
            break;
        }
    }
    if (slot < 0)
    {
        slot = 0;
        for (int i = 1; i < kToastMax; i++)
            if (g_toasts[i].born < g_toasts[slot].born)
                slot = i;
    }
    UiToastSlot& t = g_toasts[slot];
    t.active = true;
    t.type = type;
    snprintf(t.title, sizeof(t.title), "%s", title);
    if (body && body[0])
        snprintf(t.body, sizeof(t.body), "%s", body);
    else
        t.body[0] = 0;
    t.born = now;
    t.close_t = 0.f;
    t.closing = false;
    t.dedup = dedup;
}

static float ToastLife(const UiToastSlot& t)
{
    if ((int)t.type >= 0 && (int)t.type < 4)
        return kToastDur[(int)t.type];
    return 4.f;
}

static int ToastIcon(UiToastType type)
{
    switch (type)
    {
    case UiToastSuccess: return IconCheck;
    case UiToastInfo:    return IconInfo;
    case UiToastWarning: return IconWarn;
    case UiToastError:   return IconClose;
    default:             return IconInfo;
    }
}

void UiToastDraw()
{
    if (!ImGui::GetCurrentContext())
        return;
    ImGuiViewport* vp = ImGui::GetMainViewport();
    if (!vp)
        return;
    ImDrawList* dl = ImGui::GetForegroundDrawList();
    float dt = ImGui::GetIO().DeltaTime;
    double now = ToastNowSec();
    float margin = ThemeSpaceMd();
    float tw = ThemeToastWidth();
    float gap = ThemeToastGap();
    float accent_w = ThemeToastAccentW();
    float pad = ThemePopupPad();
    float y = vp->Pos.y + ThemeTitleBarH() + ThemeSpaceSm();

    float stack_y = y;
    for (int pass = 0; pass < 2; pass++)
    {
        for (int i = 0; i < kToastMax; i++)
        {
            UiToastSlot& t = g_toasts[i];
            if (!t.active)
                continue;
            float life = ToastLife(t);
            float age = (float)(now - t.born);
            if (!t.closing && age > life)
                t.closing = true;
            if (t.closing)
            {
                t.close_t += dt * (UiAnimEnabled() ? 3.5f : 8.f);
                if (t.close_t >= 1.f)
                {
                    t.active = false;
                    continue;
                }
            }
            if (pass == 0)
                continue;

            ImFont* font = ImGui::GetFont();
            float fs = ImGui::GetFontSize();
            float icon_slot = ThemePx(22.f);
            float text_w = tw - pad * 2.f - accent_w - icon_slot - ThemeSpaceSm() - ThemePx(22.f);
            if (text_w < ThemePx(80.f))
                text_w = ThemePx(80.f);
            ImVec2 title_sz = font->CalcTextSizeA(fs, text_w, text_w, t.title);
            float body_h = 0.f;
            if (t.body[0])
            {
                ImVec2 body_sz = font->CalcTextSizeA(fs * 0.92f, text_w, text_w, t.body);
                body_h = body_sz.y + ThemePx(4.f);
            }
            float close_sz = ThemePx(18.f);
            float h = pad * 2.f + title_sz.y + body_h;
            if (h < icon_slot + pad * 2.f)
                h = icon_slot + pad * 2.f;
            if (h < close_sz + pad)
                h = close_sz + pad;
            float x = vp->WorkPos.x + vp->WorkSize.x - margin - tw;
            float slide = 0.f;
            float alpha = 1.f;
            if (UiAnimEnabled())
            {
                if (!t.closing && age < 0.22f)
                    slide = (1.f - UiEaseOut(age / 0.22f)) * ThemePx(18.f);
                if (t.closing)
                    alpha = 1.f - UiEaseOut(t.close_t);
            }
            else if (t.closing)
                alpha = 1.f - t.close_t;
            x += slide;
            ImVec2 a(x, stack_y);
            ImVec2 b(x + tw, stack_y + h);
            ImU32 acc = ToastAccentCol(t.type);
            ImU32 bg = ThemeWithAlpha(ThemeColCard(), 0.96f * alpha);
            ImU32 border = ThemeWithAlpha(ThemeColBorder(), 0.85f * alpha);
            dl->AddRectFilled(a, b, bg, ThemePx(2.f));
            dl->AddRect(a, b, border, ThemePx(2.f));
            dl->AddRectFilled(a, ImVec2(a.x + accent_w, b.y), ThemeWithAlpha(acc, alpha));
            float icon_x = a.x + accent_w + pad + icon_slot * 0.5f;
            float icon_y = a.y + h * 0.5f;
            dl->AddCircleFilled(ImVec2(icon_x, icon_y), icon_slot * 0.48f, ThemeWithAlpha(acc, 0.20f * alpha));
            IconDraw(ToastIcon(t.type), ImVec2(icon_x, icon_y), IconSize(IconRoleMd),
                ThemeWithAlpha(acc, alpha), dl);
            float tx = a.x + accent_w + pad + icon_slot + ThemeSpaceXs();
            float ty = a.y + pad;
            dl->AddText(font, fs, ImVec2(tx, ty), ThemeWithAlpha(ThemeColFg(), alpha), t.title, nullptr, text_w);
            if (t.body[0])
            {
                ty += title_sz.y + ThemePx(2.f);
                dl->AddText(font, fs * 0.92f, ImVec2(tx, ty), ThemeWithAlpha(ThemeColMuted(), alpha), t.body, nullptr, text_w);
            }
            ImVec2 close_min(b.x - pad - close_sz, a.y + pad * 0.5f);
            ImVec2 close_max(close_min.x + close_sz, close_min.y + close_sz);
            bool close_hov = ImGui::IsMouseHoveringRect(close_min, close_max);
            if (close_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
                t.closing = true;
            IconDraw(IconClose, ImVec2((close_min.x + close_max.x) * 0.5f, (close_min.y + close_max.y) * 0.5f),
                IconSize(IconRoleXs), ThemeWithAlpha(close_hov ? ThemeColFg() : ThemeColMuted(), alpha), dl);
            stack_y += h + gap;
        }
    }
}
