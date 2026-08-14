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

void UiHoverSweep(ImVec2 a, ImVec2 b, float t, float alpha_scale)
{
    if (t <= 0.001f || alpha_scale <= 0.001f)
        return;
    ImDrawList* dl = ImGui::GetWindowDrawList();
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
