#include "ui/widgets.h"
#include "ui/theme.h"
#include "persist/settings.h"
#include "imgui.h"

#include <math.h>
#include <float.h>
#include <string.h>
#include <stdio.h>

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
    float k = 1.f - expf(-14.f * dt);
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
    double now = ImGui::GetCurrentContext() ? ImGui::GetTime() : 0.0;
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

void UiToastDraw()
{
    if (!ImGui::GetCurrentContext())
        return;
    ImGuiViewport* vp = ImGui::GetMainViewport();
    if (!vp)
        return;
    ImDrawList* dl = ImGui::GetForegroundDrawList();
    float dt = ImGui::GetIO().DeltaTime;
    double now = ImGui::GetTime();
    float margin = ThemeSpaceMd();
    float tw = ThemeToastWidth();
    float gap = ThemeToastGap();
    float accent_w = ThemeToastAccentW();
    float pad = ThemePopupPad();
    float y = vp->WorkPos.y + margin;

    int visible = 0;
    for (int i = 0; i < kToastMax; i++)
        if (g_toasts[i].active)
            visible++;

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
            ImVec2 title_sz = font->CalcTextSizeA(fs, tw - pad * 2.f - accent_w - ThemeSpaceSm(), 0.f, t.title);
            float body_h = 0.f;
            if (t.body[0])
            {
                ImVec2 body_sz = font->CalcTextSizeA(fs * 0.92f, tw - pad * 2.f - accent_w - ThemeSpaceSm(), 0.f, t.body);
                body_h = body_sz.y + ThemePx(4.f);
            }
            float close_sz = ThemePx(18.f);
            float h = pad * 2.f + title_sz.y + body_h;
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
            ImU32 bg = ThemeWithAlpha(ThemeColCard(), 0.96f * alpha);
            ImU32 border = ThemeWithAlpha(ThemeColBorder(), 0.85f * alpha);
            dl->AddRectFilled(a, b, bg, ThemePx(2.f));
            dl->AddRect(a, b, border, ThemePx(2.f));
            dl->AddRectFilled(a, ImVec2(a.x + accent_w, b.y), ThemeWithAlpha(ToastAccentCol(t.type), alpha));
            float tx = a.x + accent_w + pad;
            float ty = a.y + pad;
            dl->AddText(font, fs, ImVec2(tx, ty), ThemeWithAlpha(ThemeColFg(), alpha), t.title);
            if (t.body[0])
            {
                ty += title_sz.y + ThemePx(2.f);
                dl->AddText(font, fs * 0.92f, ImVec2(tx, ty), ThemeWithAlpha(ThemeColMuted(), alpha), t.body);
            }
            ImVec2 close_min(b.x - pad - close_sz, a.y + pad * 0.5f);
            ImVec2 close_max(close_min.x + close_sz, close_min.y + close_sz);
            bool close_hov = ImGui::IsMouseHoveringRect(close_min, close_max);
            if (close_hov && ImGui::IsMouseClicked(ImGuiMouseButton_Left))
                t.closing = true;
            const char* xlabel = "x";
            ImVec2 xs = font->CalcTextSizeA(fs * 0.85f, FLT_MAX, 0.f, xlabel);
            ImVec2 cx((close_min.x + close_max.x) * 0.5f, (close_min.y + close_max.y) * 0.5f);
            dl->AddText(font, fs * 0.85f,
                ImVec2(cx.x - xs.x * 0.5f, cx.y - xs.y * 0.5f),
                ThemeWithAlpha(close_hov ? ThemeColFg() : ThemeColMuted(), alpha), xlabel);
            stack_y += h + gap;
        }
    }
}
