#include "ui/widgets.h"
#include "ui/theme.h"
#include "persist/settings.h"
#include "imgui.h"

#include <math.h>

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
    ImVec2 p = ImGui::GetCursorScreenPos();
    bool hit = ImGui::InvisibleButton(label, size);
    ImVec2 q = ImGui::GetItemRectMax();
    float t = UiHoverT(ImGui::GetItemID(), ImGui::IsItemHovered());
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImU32 fill;
    ImU32 border;
    ImU32 text;
    if (kind == 1)
    {
        fill = UiLerpCol(ThemeColAccent(), ThemeColFg(), t * 0.12f);
        border = ThemeColAccent();
        text = ThemeColBg();
    }
    else
    {
        fill = UiLerpCol(ThemeColCard(), ThemeColHover(), t);
        border = UiLerpCol(ThemeColBorder(), ThemeColAccent(), t);
        text = UiLerpCol(ThemeColFg(), ThemeColAccent(), t * 0.55f);
    }
    dl->AddRectFilled(p, q, fill);
    dl->AddRect(p, q, border);
    UiHandIfHovered();
    if (kind != 1)
        UiHoverSweep(p, q, t);
    float lift = UiAnimEnabled() ? t * -1.f : 0.f;
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

void UiTipWhenDisabled(const char* text)
{
    if (!text || !text[0])
        return;
    if (!ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled | ImGuiHoveredFlags_DelayShort))
        return;
    ImGui::BeginTooltip();
    ImGui::PushTextWrapPos(ImGui::GetFontSize() * 28.f);
    ImGui::TextUnformatted(text);
    ImGui::PopTextWrapPos();
    ImGui::EndTooltip();
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
    {
        ImGui::BeginTooltip();
        ImGui::PushTextWrapPos(ImGui::GetFontSize() * 36.f);
        ImGui::TextUnformatted(text);
        ImGui::PopTextWrapPos();
        ImGui::EndTooltip();
    }
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
