#include "ui/icons.h"
#include "ui/theme.h"
#include "ui/widgets.h"
#include "imgui.h"

void IconDraw(int icon, ImVec2 c, float s, unsigned int col)
{
    ImDrawList* dl = ImGui::GetWindowDrawList();
    float x0 = c.x - s, y0 = c.y - s, x1 = c.x + s, y1 = c.y + s;
    switch (icon)
    {
    case IconBack:
        dl->AddLine(ImVec2(c.x + s * 0.35f, y0 + s * 0.35f), ImVec2(x0 + s * 0.25f, c.y), col, 2.f);
        dl->AddLine(ImVec2(x0 + s * 0.25f, c.y), ImVec2(c.x + s * 0.35f, y1 - s * 0.35f), col, 2.f);
        break;
    case IconGear:
        dl->AddCircle(c, s * 0.72f, col, 10, 1.6f);
        dl->AddCircle(c, s * 0.28f, col, 8, 1.6f);
        break;
    case IconFolder:
        dl->AddRect(ImVec2(x0 + 1.f, y0 + s * 0.35f), ImVec2(x1 - 1.f, y1 - 1.f), col, 0.f, 0, 1.6f);
        dl->AddRectFilled(ImVec2(x0 + 1.f, y0 + 1.f), ImVec2(c.x, y0 + s * 0.45f), col);
        break;
    case IconFile:
        dl->AddRect(ImVec2(x0 + 2.f, y0 + 1.f), ImVec2(x1 - 2.f, y1 - 1.f), col, 0.f, 0, 1.6f);
        dl->AddLine(ImVec2(x0 + 5.f, c.y - 2.f), ImVec2(x1 - 5.f, c.y - 2.f), col, 1.f);
        dl->AddLine(ImVec2(x0 + 5.f, c.y + 3.f), ImVec2(x1 - 5.f, c.y + 3.f), col, 1.f);
        break;
    case IconChevron:
        dl->AddLine(ImVec2(c.x - s * 0.3f, c.y - s * 0.15f), ImVec2(c.x, c.y + s * 0.35f), col, 1.8f);
        dl->AddLine(ImVec2(c.x, c.y + s * 0.35f), ImVec2(c.x + s * 0.3f, c.y - s * 0.15f), col, 1.8f);
        break;
    }
}

bool IconButton(const char* id, int icon, const char* label)
{
    ImVec2 ts = label ? ImGui::CalcTextSize(label) : ImVec2(0, 0);
    float h = ImGui::GetFrameHeight();
    float w = h + (label ? ts.x + 10.f : 0.f);
    ImVec2 p = ImGui::GetCursorScreenPos();
    bool hit = ImGui::InvisibleButton(id, ImVec2(w, h));
    ImVec2 q = ImGui::GetItemRectMax();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(p, q, ThemeColCard());
    UiHandIfHovered();
    UiHoverSweep(p, q, UiHoverT(ImGui::GetItemID(), ImGui::IsItemHovered()));
    ImU32 col = ImGui::IsItemHovered() ? ThemeColAccent() : ThemeColFg();
    IconDraw(icon, ImVec2(p.x + h * 0.5f, p.y + h * 0.5f), h * 0.28f, col);
    if (label)
    {
        ImGui::GetWindowDrawList()->AddText(ImVec2(p.x + h, p.y + (h - ts.y) * 0.5f), col, label);
    }
    return hit;
}
