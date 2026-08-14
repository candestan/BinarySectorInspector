#include "ui/widgets.h"
#include "ui/theme.h"
#include "persist/settings.h"
#include "imgui.h"

bool UiAnimEnabled()
{
    return SettingsGetBool("animations", true);
}

float UiHoverT(unsigned int id, bool hovered)
{
    if (!UiAnimEnabled())
        return 0.f;
    ImGuiStorage* st = ImGui::GetStateStorage();
    ImGuiID key = (ImGuiID)id;
    float t = st->GetFloat(key, 0.f);
    float dt = ImGui::GetIO().DeltaTime;
    t += (hovered ? 1.f : -1.f) * dt * 9.f;
    if (t < 0.f) t = 0.f;
    if (t > 1.f) t = 1.f;
    st->SetFloat(key, t);
    return t;
}

void UiHoverSweep(ImVec2 a, ImVec2 b, float t, float alpha_scale, ImDrawList* dl)
{
    if (t <= 0.001f || alpha_scale <= 0.001f)
        return;
    if (!dl)
        dl = ImGui::GetWindowDrawList();
    dl->PushClipRect(a, b, true);
    float reach = t * ((b.x - a.x) + (b.y - a.y) + 8.f); // BL->TR fill, clipped to item.
    ImU32 col = ThemeColAccent();
    unsigned alpha = (unsigned)((70.f + 90.f * t) * alpha_scale);
    if (alpha > 255)
        alpha = 255;
    col = (col & 0x00ffffff) | (alpha << 24);
    ImVec2 bl(a.x, b.y);
    dl->AddTriangleFilled(bl, ImVec2(a.x + reach * 2.f, b.y), ImVec2(a.x, b.y - reach * 2.f), col);
    dl->PopClipRect();
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

bool UiButton(const char* label, ImVec2 size)
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
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(p, q, ThemeColCard());
    dl->AddRect(p, q, ThemeColBorder());
    UiHandIfHovered();
    UiHoverSweep(p, q, UiHoverT(ImGui::GetItemID(), ImGui::IsItemHovered()));
    dl->AddText(ImVec2(p.x + (size.x - ts.x) * 0.5f, p.y + (size.y - ts.y) * 0.5f), ThemeColFg(), label);
    return hit;
}

bool UiCheckbox(const char* id, const char* label, bool* value)
{
    if (!value)
        return false;
    ImGui::PushID(id ? id : "chk");
    float h = ImGui::GetFrameHeight();
    float box = h - 8.f;
    ImVec2 ts = ImGui::CalcTextSize(label ? label : "");
    ImVec2 p = ImGui::GetCursorScreenPos();
    float w = box + 10.f + ts.x + 4.f;
    bool hit = ImGui::InvisibleButton("hit", ImVec2(w, h));
    if (hit)
        *value = !*value;
    UiHandIfHovered();
    ImVec2 q = ImGui::GetItemRectMax();
    UiHoverSweep(p, q, UiHoverT(ImGui::GetItemID(), ImGui::IsItemHovered()));

    float bx = p.x + 2.f;
    float by = p.y + (h - box) * 0.5f;
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(ImVec2(bx, by), ImVec2(bx + box, by + box), ThemeColCard());
    dl->AddRect(ImVec2(bx, by), ImVec2(bx + box, by + box), ThemeColBorder());
    if (*value)
    {
        ImU32 acc = ThemeColAccent();
        dl->AddLine(ImVec2(bx + 3.f, by + box * 0.55f), ImVec2(bx + box * 0.42f, by + box - 3.f), acc, 2.f);
        dl->AddLine(ImVec2(bx + box * 0.42f, by + box - 3.f), ImVec2(bx + box - 3.f, by + 3.f), acc, 2.f);
    }
    dl->AddText(ImVec2(bx + box + 8.f, p.y + (h - ts.y) * 0.5f), ThemeColFg(), label ? label : "");
    ImGui::PopID();
    return hit;
}

void UiSpinner(ImVec2 center, float radius, float progress)
{
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const float pi = 3.14159265f;
    dl->AddCircle(center, radius, ThemeColBorder(), 48, 3.f);
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
    dl->PathArcTo(center, radius, a0, a1, 32);
    dl->PathStroke(ThemeColAccent(), 0, 3.f);
}
