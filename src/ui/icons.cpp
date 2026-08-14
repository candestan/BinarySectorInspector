#include "ui/icons.h"
#include "ui/theme.h"
#include "ui/widgets.h"
#include "imgui.h"

#include <stdio.h>

void IconDraw(int icon, ImVec2 c, float s, unsigned int col, ImDrawList* dl)
{
    if (!dl)
        dl = ImGui::GetWindowDrawList();
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
    case IconSave:
        dl->AddRect(ImVec2(x0 + 2.f, y0 + 1.f), ImVec2(x1 - 2.f, y1 - 1.f), col, 0.f, 0, 1.6f);
        dl->AddRectFilled(ImVec2(x0 + 5.f, y0 + 1.f), ImVec2(x1 - 5.f, c.y - 1.f), col);
        dl->AddRect(ImVec2(c.x - s * 0.22f, c.y), ImVec2(c.x + s * 0.22f, y1 - 2.f), col, 0.f, 0, 1.4f);
        break;
    case IconHex:
        dl->AddLine(ImVec2(x0 + 2.f, y0 + 3.f), ImVec2(x1 - 2.f, y0 + 3.f), col, 1.3f);
        dl->AddLine(ImVec2(x0 + 2.f, c.y), ImVec2(x1 - 2.f, c.y), col, 1.3f);
        dl->AddLine(ImVec2(x0 + 2.f, y1 - 3.f), ImVec2(c.x, y1 - 3.f), col, 1.3f);
        break;
    case IconBox:
        dl->AddRect(ImVec2(x0 + 2.f, y0 + 2.f), ImVec2(x1 - 2.f, y1 - 2.f), col, 0.f, 0, 1.6f);
        dl->AddLine(ImVec2(x0 + 2.f, c.y), ImVec2(x1 - 2.f, c.y), col, 1.f);
        dl->AddLine(ImVec2(c.x, y0 + 2.f), ImVec2(c.x, y1 - 2.f), col, 1.f);
        break;
    case IconCpu:
        dl->AddRect(ImVec2(x0 + 3.f, y0 + 3.f), ImVec2(x1 - 3.f, y1 - 3.f), col, 0.f, 0, 1.6f);
        dl->AddLine(ImVec2(c.x, y0), ImVec2(c.x, y0 + 3.f), col, 1.4f);
        dl->AddLine(ImVec2(c.x, y1 - 3.f), ImVec2(c.x, y1), col, 1.4f);
        dl->AddLine(ImVec2(x0, c.y), ImVec2(x0 + 3.f, c.y), col, 1.4f);
        dl->AddLine(ImVec2(x1 - 3.f, c.y), ImVec2(x1, c.y), col, 1.4f);
        break;
    case IconShield:
        dl->AddTriangle(ImVec2(c.x, y0), ImVec2(x0 + 1.f, y0 + s * 0.35f), ImVec2(x1 - 1.f, y0 + s * 0.35f), col, 1.5f);
        dl->AddLine(ImVec2(x0 + 1.f, y0 + s * 0.35f), ImVec2(c.x, y1), col, 1.5f);
        dl->AddLine(ImVec2(x1 - 1.f, y0 + s * 0.35f), ImVec2(c.x, y1), col, 1.5f);
        break;
    case IconClose:
        dl->AddLine(ImVec2(x0 + 3.f, y0 + 3.f), ImVec2(x1 - 3.f, y1 - 3.f), col, 1.8f);
        dl->AddLine(ImVec2(x1 - 3.f, y0 + 3.f), ImVec2(x0 + 3.f, y1 - 3.f), col, 1.8f);
        break;
    case IconTree:
        dl->AddCircleFilled(ImVec2(c.x, y0 + 3.f), 2.f, col);
        dl->AddLine(ImVec2(c.x, y0 + 5.f), ImVec2(c.x, y1 - 2.f), col, 1.4f);
        dl->AddLine(ImVec2(c.x, c.y), ImVec2(x1 - 2.f, c.y), col, 1.4f);
        dl->AddLine(ImVec2(c.x, y1 - 2.f), ImVec2(x1 - 2.f, y1 - 2.f), col, 1.4f);
        break;
    case IconCom:
        dl->AddCircle(c, s * 0.7f, col, 12, 1.6f);
        dl->AddLine(ImVec2(c.x - s * 0.35f, c.y), ImVec2(c.x + s * 0.35f, c.y), col, 1.5f);
        dl->AddLine(ImVec2(c.x, c.y - s * 0.35f), ImVec2(c.x, c.y + s * 0.35f), col, 1.5f);
        break;
    case IconImport:
        dl->AddLine(ImVec2(c.x, y0 + 2.f), ImVec2(c.x, y1 - 2.f), col, 1.6f);
        dl->AddLine(ImVec2(c.x, y1 - 2.f), ImVec2(c.x - s * 0.4f, c.y + 1.f), col, 1.6f);
        dl->AddLine(ImVec2(c.x, y1 - 2.f), ImVec2(c.x + s * 0.4f, c.y + 1.f), col, 1.6f);
        break;
    case IconExport:
        dl->AddLine(ImVec2(c.x, y1 - 2.f), ImVec2(c.x, y0 + 2.f), col, 1.6f);
        dl->AddLine(ImVec2(c.x, y0 + 2.f), ImVec2(c.x - s * 0.4f, c.y - 1.f), col, 1.6f);
        dl->AddLine(ImVec2(c.x, y0 + 2.f), ImVec2(c.x + s * 0.4f, c.y - 1.f), col, 1.6f);
        break;
    case IconPlay:
        dl->AddTriangle(ImVec2(x0 + 3.f, y0 + 2.f), ImVec2(x0 + 3.f, y1 - 2.f), ImVec2(x1 - 1.f, c.y), col, 1.6f);
        break;
    case IconSearch:
        dl->AddCircle(ImVec2(c.x - s * 0.15f, c.y - s * 0.15f), s * 0.55f, col, 12, 1.6f);
        dl->AddLine(ImVec2(c.x + s * 0.2f, c.y + s * 0.2f), ImVec2(x1 - 1.f, y1 - 1.f), col, 1.8f);
        break;
    case IconImage:
        dl->AddRect(ImVec2(x0 + 1.f, y0 + 2.f), ImVec2(x1 - 1.f, y1 - 2.f), col, 0.f, 0, 1.5f);
        dl->AddCircle(ImVec2(c.x - s * 0.3f, c.y - s * 0.2f), 1.6f, col, 8, 1.4f);
        dl->AddLine(ImVec2(x0 + 3.f, y1 - 4.f), ImVec2(c.x, c.y), col, 1.4f);
        dl->AddLine(ImVec2(c.x, c.y), ImVec2(x1 - 3.f, y1 - 5.f), col, 1.4f);
        break;
    case IconEye:
        dl->AddCircle(c, s * 0.35f, col, 10, 1.5f);
        dl->AddBezierCubic(ImVec2(x0 + 1.f, c.y), ImVec2(c.x - s * 0.4f, y0 + 2.f), ImVec2(c.x + s * 0.4f, y0 + 2.f), ImVec2(x1 - 1.f, c.y), col, 1.5f);
        break;
    case IconGo:
        dl->AddLine(ImVec2(x0 + 1.f, c.y), ImVec2(x1 - 2.f, c.y), col, 1.6f);
        dl->AddLine(ImVec2(x1 - 2.f, c.y), ImVec2(c.x + s * 0.15f, c.y - s * 0.45f), col, 1.6f);
        dl->AddLine(ImVec2(x1 - 2.f, c.y), ImVec2(c.x + s * 0.15f, c.y + s * 0.45f), col, 1.6f);
        break;
    case IconEdit:
        dl->AddLine(ImVec2(x0 + 2.f, y1 - 2.f), ImVec2(c.x + s * 0.15f, y0 + 4.f), col, 1.5f);
        dl->AddLine(ImVec2(c.x + s * 0.15f, y0 + 4.f), ImVec2(x1 - 2.f, y0 + 2.f), col, 1.5f);
        break;
    case IconReplace:
        dl->AddLine(ImVec2(x0 + 2.f, y0 + 4.f), ImVec2(x1 - 2.f, y0 + 4.f), col, 1.4f);
        dl->AddLine(ImVec2(x1 - 2.f, y0 + 4.f), ImVec2(c.x + s * 0.2f, y0 + 1.f), col, 1.4f);
        dl->AddLine(ImVec2(x0 + 2.f, y1 - 4.f), ImVec2(x1 - 2.f, y1 - 4.f), col, 1.4f);
        dl->AddLine(ImVec2(x0 + 2.f, y1 - 4.f), ImVec2(c.x - s * 0.2f, y1 - 1.f), col, 1.4f);
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

bool IconTool(const char* id, int icon, const char* label)
{
    ImVec2 ts = label ? ImGui::CalcTextSize(label) : ImVec2(0, 0);
    float h = ImGui::GetFrameHeight();
    float w = h + (label ? ts.x + 8.f : 0.f);
    ImVec2 p = ImGui::GetCursorScreenPos();
    bool hit = ImGui::InvisibleButton(id, ImVec2(w, h));
    ImVec2 q = ImGui::GetItemRectMax();
    UiHandIfHovered();
    UiHoverSweep(p, q, UiHoverT(ImGui::GetItemID(), ImGui::IsItemHovered()));
    ImU32 col = ImGui::IsItemHovered() ? ThemeColAccent() : ThemeColFg();
    IconDraw(icon, ImVec2(p.x + h * 0.42f, p.y + h * 0.5f), h * 0.26f, col);
    if (label)
        ImGui::GetWindowDrawList()->AddText(ImVec2(p.x + h * 0.78f, p.y + (h - ts.y) * 0.5f), col, label);
    return hit;
}

bool IconMenuItem(int icon, const char* label, const char* shortcut, bool enabled)
{
    char buf[96];
    snprintf(buf, sizeof(buf), "    %s", label ? label : "");
    bool hit = ImGui::MenuItem(buf, shortcut, false, enabled);
    ImVec2 a = ImGui::GetItemRectMin();
    float h = ImGui::GetItemRectSize().y;
    IconDraw(icon, ImVec2(a.x + 12.f, a.y + h * 0.5f), 5.5f, enabled ? ThemeColFg() : ThemeColMuted());
    return hit;
}

bool IconBeginMenu(int icon, const char* label)
{
    char buf[80];
    snprintf(buf, sizeof(buf), "    %s", label ? label : "");
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    bool open = ImGui::BeginMenu(buf);
    float h = ImGui::GetFrameHeight();
    IconDraw(icon, ImVec2(p.x + 10.f, p.y + h * 0.5f), 5.5f, ThemeColFg(), dl);
    return open;
}
