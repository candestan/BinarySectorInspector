#include "ui/icons.h"
#include "ui/theme.h"
#include "ui/widgets.h"
#include "persist/settings.h"
#include "imgui.h"

#include <stdio.h>

float IconSize(int role)
{
    float fs = 0.f;
    if (ImGui::GetCurrentContext())
        fs = ImGui::GetFontSize();
    if (fs < 8.f)
        fs = ThemeFontSize();
    float k = 0.50f;
    switch (role)
    {
    case IconRoleXs: k = 0.40f; break;
    case IconRoleSm: k = 0.50f; break;
    case IconRoleMd: k = 0.56f; break;
    case IconRoleLg: k = 0.62f; break;
    case IconRoleXl: k = 0.92f; break;
    default: break;
    }
    return fs * k;
}

float IconTextGap()
{
    return ThemePx(6.f);
}

float IconSlotW(int role)
{
    return IconSize(role) * 2.f + IconTextGap();
}

void IconPrefixLabel(char* dst, int cap, int role, const char* label)
{
    if (!dst || cap < 2)
        return;
    float need = IconSlotW(role);
    float spw = ImGui::CalcTextSize(" ").x;
    if (spw < 1.f)
        spw = 4.f;
    int n = (int)(need / spw + 0.99f);
    if (n < 2)
        n = 2;
    if (n > 8)
        n = 8;
    int i = 0;
    while (i < n && i < cap - 1)
        dst[i++] = ' ';
    if (label)
    {
        while (*label && i < cap - 1)
            dst[i++] = *label++;
    }
    dst[i] = 0;
}

static float Stroke(float s)
{
    float sw = s * 0.18f;
    if (sw < 1.05f)
        sw = 1.05f;
    if (sw > 2.15f)
        sw = 2.15f;
    return sw;
}

static float GlyphOptical(int icon)
{
    switch (icon)
    {
    case IconChevron: return 1.22f;
    case IconHex:     return 1.14f;
    case IconEye:     return 1.10f;
    case IconEdit:    return 1.10f;
    case IconBack:    return 1.08f;
    case IconSearch:  return 1.08f;
    case IconGo:      return 1.06f;
    case IconReplace: return 1.06f;
    case IconPlay:    return 1.04f;
    case IconTree:    return 1.04f;
    case IconGear:    return 0.92f;
    case IconCom:     return 0.92f;
    case IconClose:   return 0.90f;
    default:          return 1.0f;
    }
}

static float GlyphY(int icon)
{
    switch (icon)
    {
    case IconFolder:  return  0.06f;
    case IconChevron: return  0.10f;
    case IconSearch:  return  0.06f;
    case IconExport:  return  0.04f;
    case IconImport:  return -0.04f;
    case IconShield:  return -0.03f;
    default:          return  0.f;
    }
}

static const char* IconEmojiGlyph(int icon)
{
    switch (icon)
    {
    case IconBack:     return "\xF0\x9F\x94\x99";   // 🔙
    case IconGear:     return "\xE2\x9A\x99";       // ⚙
    case IconFolder:   return "\xF0\x9F\x93\x81";   // 📁
    case IconFile:     return "\xF0\x9F\x93\x84";   // 📄
    case IconChevron:  return "\xE2\x96\xBE";       // ▾
    case IconSave:     return "\xF0\x9F\x92\xBE";   // 💾
    case IconHex:      return "\xF0\x9F\x94\xA2";   // 🔢
    case IconBox:      return "\xF0\x9F\x93\xA6";   // 📦
    case IconCpu:      return "\xF0\x9F\x92\xBB";   // 💻
    case IconShield:   return "\xF0\x9F\x9B\xA1";   // 🛡
    case IconClose:    return "\xE2\x9D\x8C";       // ❌
    case IconCom:      return "\xF0\x9F\x94\x8C";   // 🔌
    case IconImport:   return "\xF0\x9F\x93\xA5";   // 📥
    case IconExport:   return "\xF0\x9F\x93\xA4";   // 📤
    case IconPlay:     return "\xE2\x96\xB6";       // ▶
    case IconSearch:   return "\xF0\x9F\x94\x8D";   // 🔍
    case IconImage:    return "\xF0\x9F\x96\xBC";   // 🖼
    case IconEye:      return "\xF0\x9F\x91\x81";   // 👁
    case IconGo:       return "\xE2\x9E\xA1";       // ➡
    case IconEdit:     return "\xE2\x9C\x8F";       // ✏
    case IconReplace:  return "\xF0\x9F\x94\x84";   // 🔄
    default:           return nullptr;
    }
}

static unsigned int Utf8Code(const char* s)
{
    if (!s || !s[0])
        return 0;
    unsigned char c = (unsigned char)s[0];
    if (c < 0x80)
        return c;
    if ((c & 0xE0) == 0xC0 && s[1])
        return ((unsigned int)(c & 0x1F) << 6) | (unsigned char)(s[1] & 0x3F);
    if ((c & 0xF0) == 0xE0 && s[1] && s[2])
        return ((unsigned int)(c & 0x0F) << 12) |
            ((unsigned int)((unsigned char)s[1] & 0x3F) << 6) |
            (unsigned char)(s[2] & 0x3F);
    if ((c & 0xF8) == 0xF0 && s[1] && s[2] && s[3])
        return ((unsigned int)(c & 0x07) << 18) |
            ((unsigned int)((unsigned char)s[1] & 0x3F) << 12) |
            ((unsigned int)((unsigned char)s[2] & 0x3F) << 6) |
            (unsigned char)(s[3] & 0x3F);
    return 0;
}

static bool IconDrawEmoji(int icon, ImVec2 c, float s, unsigned int col, ImDrawList* dl)
{
    if (!SettingsGetBool("ui.use_emojis", false))
        return false;
    const char* em = IconEmojiGlyph(icon);
    if (!em)
        return false;
    ImFont* font = ImGui::GetIO().FontDefault;
    if (!font)
        font = ImGui::GetFont();
    if (!font)
        return false;
    unsigned int cp = Utf8Code(em);
    if (!cp)
        return false;
    float fs = s * 1.85f;
    ImVec2 ts = font->CalcTextSizeA(fs, 1e10f, 0.f, em);
    dl->AddText(font, fs, ImVec2(c.x - ts.x * 0.5f, c.y - ts.y * 0.5f), col, em);
    return true;
}

void IconDraw(int icon, ImVec2 c, float s, unsigned int col, ImDrawList* dl)
{
    if (!dl)
        dl = ImGui::GetWindowDrawList();
    if (IconDrawEmoji(icon, c, s, col, dl))
        return;
    s *= GlyphOptical(icon);
    c.y += GlyphY(icon) * s;
    float sw = Stroke(s);
    float x0 = c.x - s, y0 = c.y - s, x1 = c.x + s, y1 = c.y + s;
    switch (icon)
    {
    case IconBack:
        dl->AddLine(ImVec2(c.x + s * 0.32f, c.y - s * 0.52f), ImVec2(c.x - s * 0.42f, c.y), col, sw);
        dl->AddLine(ImVec2(c.x - s * 0.42f, c.y), ImVec2(c.x + s * 0.32f, c.y + s * 0.52f), col, sw);
        break;
    case IconGear:
        dl->AddCircle(c, s * 0.70f, col, 12, sw);
        dl->AddCircle(c, s * 0.28f, col, 8, sw);
        break;
    case IconFolder:
        dl->AddRect(ImVec2(x0 + s * 0.08f, c.y - s * 0.28f), ImVec2(x1 - s * 0.08f, y1 - s * 0.08f), col, 0.f, 0, sw);
        dl->AddRectFilled(ImVec2(x0 + s * 0.08f, y0 + s * 0.10f), ImVec2(c.x + s * 0.06f, c.y - s * 0.16f), col);
        break;
    case IconFile:
        dl->AddRect(ImVec2(x0 + s * 0.22f, y0 + s * 0.08f), ImVec2(x1 - s * 0.22f, y1 - s * 0.08f), col, 0.f, 0, sw);
        dl->AddLine(ImVec2(x0 + s * 0.38f, c.y - s * 0.18f), ImVec2(x1 - s * 0.38f, c.y - s * 0.18f), col, sw);
        dl->AddLine(ImVec2(x0 + s * 0.38f, c.y + s * 0.18f), ImVec2(x1 - s * 0.38f, c.y + s * 0.18f), col, sw);
        break;
    case IconChevron:
        dl->AddLine(ImVec2(c.x - s * 0.42f, c.y - s * 0.18f), ImVec2(c.x, c.y + s * 0.32f), col, sw);
        dl->AddLine(ImVec2(c.x, c.y + s * 0.32f), ImVec2(c.x + s * 0.42f, c.y - s * 0.18f), col, sw);
        break;
    case IconSave:
        dl->AddRect(ImVec2(x0 + s * 0.18f, y0 + s * 0.10f), ImVec2(x1 - s * 0.18f, y1 - s * 0.10f), col, 0.f, 0, sw);
        dl->AddRectFilled(ImVec2(x0 + s * 0.36f, y0 + s * 0.10f), ImVec2(x1 - s * 0.36f, c.y - s * 0.12f), col);
        dl->AddRect(ImVec2(c.x - s * 0.22f, c.y), ImVec2(c.x + s * 0.22f, y1 - s * 0.16f), col, 0.f, 0, sw);
        break;
    case IconHex:
        dl->AddLine(ImVec2(x0 + s * 0.12f, y0 + s * 0.28f), ImVec2(x1 - s * 0.12f, y0 + s * 0.28f), col, sw);
        dl->AddLine(ImVec2(x0 + s * 0.12f, c.y), ImVec2(x1 - s * 0.12f, c.y), col, sw);
        dl->AddLine(ImVec2(x0 + s * 0.12f, y1 - s * 0.28f), ImVec2(c.x, y1 - s * 0.28f), col, sw);
        break;
    case IconBox:
        dl->AddRect(ImVec2(x0 + s * 0.16f, y0 + s * 0.16f), ImVec2(x1 - s * 0.16f, y1 - s * 0.16f), col, 0.f, 0, sw);
        dl->AddLine(ImVec2(x0 + s * 0.16f, c.y), ImVec2(x1 - s * 0.16f, c.y), col, sw);
        dl->AddLine(ImVec2(c.x, y0 + s * 0.16f), ImVec2(c.x, y1 - s * 0.16f), col, sw);
        break;
    case IconCpu:
        dl->AddRect(ImVec2(x0 + s * 0.28f, y0 + s * 0.28f), ImVec2(x1 - s * 0.28f, y1 - s * 0.28f), col, 0.f, 0, sw);
        dl->AddLine(ImVec2(c.x, y0 + s * 0.04f), ImVec2(c.x, y0 + s * 0.28f), col, sw);
        dl->AddLine(ImVec2(c.x, y1 - s * 0.28f), ImVec2(c.x, y1 - s * 0.04f), col, sw);
        dl->AddLine(ImVec2(x0 + s * 0.04f, c.y), ImVec2(x0 + s * 0.28f, c.y), col, sw);
        dl->AddLine(ImVec2(x1 - s * 0.28f, c.y), ImVec2(x1 - s * 0.04f, c.y), col, sw);
        break;
    case IconShield:
        dl->AddTriangle(ImVec2(c.x, y0 + s * 0.06f), ImVec2(x0 + s * 0.12f, y0 + s * 0.38f), ImVec2(x1 - s * 0.12f, y0 + s * 0.38f), col, sw);
        dl->AddLine(ImVec2(x0 + s * 0.12f, y0 + s * 0.38f), ImVec2(c.x, y1 - s * 0.08f), col, sw);
        dl->AddLine(ImVec2(x1 - s * 0.12f, y0 + s * 0.38f), ImVec2(c.x, y1 - s * 0.08f), col, sw);
        break;
    case IconClose:
        dl->AddLine(ImVec2(x0 + s * 0.28f, y0 + s * 0.28f), ImVec2(x1 - s * 0.28f, y1 - s * 0.28f), col, sw);
        dl->AddLine(ImVec2(x1 - s * 0.28f, y0 + s * 0.28f), ImVec2(x0 + s * 0.28f, y1 - s * 0.28f), col, sw);
        break;
    case IconTree:
        dl->AddCircleFilled(ImVec2(c.x, y0 + s * 0.22f), s * 0.16f, col);
        dl->AddLine(ImVec2(c.x, y0 + s * 0.38f), ImVec2(c.x, y1 - s * 0.12f), col, sw);
        dl->AddLine(ImVec2(c.x, c.y), ImVec2(x1 - s * 0.12f, c.y), col, sw);
        dl->AddLine(ImVec2(c.x, y1 - s * 0.12f), ImVec2(x1 - s * 0.12f, y1 - s * 0.12f), col, sw);
        break;
    case IconCom:
        dl->AddCircle(c, s * 0.70f, col, 12, sw);
        dl->AddLine(ImVec2(c.x - s * 0.34f, c.y), ImVec2(c.x + s * 0.34f, c.y), col, sw);
        dl->AddLine(ImVec2(c.x, c.y - s * 0.34f), ImVec2(c.x, c.y + s * 0.34f), col, sw);
        break;
    case IconImport:
        dl->AddLine(ImVec2(c.x, y0 + s * 0.16f), ImVec2(c.x, y1 - s * 0.16f), col, sw);
        dl->AddLine(ImVec2(c.x, y1 - s * 0.16f), ImVec2(c.x - s * 0.40f, c.y + s * 0.12f), col, sw);
        dl->AddLine(ImVec2(c.x, y1 - s * 0.16f), ImVec2(c.x + s * 0.40f, c.y + s * 0.12f), col, sw);
        break;
    case IconExport:
        dl->AddLine(ImVec2(c.x, y1 - s * 0.16f), ImVec2(c.x, y0 + s * 0.16f), col, sw);
        dl->AddLine(ImVec2(c.x, y0 + s * 0.16f), ImVec2(c.x - s * 0.40f, c.y - s * 0.12f), col, sw);
        dl->AddLine(ImVec2(c.x, y0 + s * 0.16f), ImVec2(c.x + s * 0.40f, c.y - s * 0.12f), col, sw);
        break;
    case IconPlay:
        dl->AddTriangle(ImVec2(x0 + s * 0.22f, y0 + s * 0.18f), ImVec2(x0 + s * 0.22f, y1 - s * 0.18f), ImVec2(x1 - s * 0.12f, c.y), col, sw);
        break;
    case IconSearch:
        dl->AddCircle(ImVec2(c.x - s * 0.14f, c.y - s * 0.14f), s * 0.52f, col, 12, sw);
        dl->AddLine(ImVec2(c.x + s * 0.22f, c.y + s * 0.22f), ImVec2(x1 - s * 0.08f, y1 - s * 0.08f), col, sw);
        break;
    case IconImage:
        dl->AddRect(ImVec2(x0 + s * 0.10f, y0 + s * 0.16f), ImVec2(x1 - s * 0.10f, y1 - s * 0.16f), col, 0.f, 0, sw);
        dl->AddCircle(ImVec2(c.x - s * 0.28f, c.y - s * 0.18f), s * 0.14f, col, 8, sw);
        dl->AddLine(ImVec2(x0 + s * 0.22f, y1 - s * 0.28f), ImVec2(c.x, c.y + s * 0.04f), col, sw);
        dl->AddLine(ImVec2(c.x, c.y + s * 0.04f), ImVec2(x1 - s * 0.22f, y1 - s * 0.32f), col, sw);
        break;
    case IconEye:
        dl->AddCircle(c, s * 0.32f, col, 10, sw);
        dl->AddBezierCubic(ImVec2(x0 + s * 0.08f, c.y), ImVec2(c.x - s * 0.40f, y0 + s * 0.18f),
            ImVec2(c.x + s * 0.40f, y0 + s * 0.18f), ImVec2(x1 - s * 0.08f, c.y), col, sw);
        break;
    case IconGo:
        dl->AddLine(ImVec2(x0 + s * 0.10f, c.y), ImVec2(x1 - s * 0.16f, c.y), col, sw);
        dl->AddLine(ImVec2(x1 - s * 0.16f, c.y), ImVec2(c.x + s * 0.12f, c.y - s * 0.42f), col, sw);
        dl->AddLine(ImVec2(x1 - s * 0.16f, c.y), ImVec2(c.x + s * 0.12f, c.y + s * 0.42f), col, sw);
        break;
    case IconEdit:
        dl->AddLine(ImVec2(x0 + s * 0.16f, y1 - s * 0.16f), ImVec2(c.x + s * 0.12f, y0 + s * 0.28f), col, sw);
        dl->AddLine(ImVec2(c.x + s * 0.12f, y0 + s * 0.28f), ImVec2(x1 - s * 0.16f, y0 + s * 0.16f), col, sw);
        break;
    case IconReplace:
        dl->AddLine(ImVec2(x0 + s * 0.16f, y0 + s * 0.28f), ImVec2(x1 - s * 0.16f, y0 + s * 0.28f), col, sw);
        dl->AddLine(ImVec2(x1 - s * 0.16f, y0 + s * 0.28f), ImVec2(c.x + s * 0.18f, y0 + s * 0.08f), col, sw);
        dl->AddLine(ImVec2(x0 + s * 0.16f, y1 - s * 0.28f), ImVec2(x1 - s * 0.16f, y1 - s * 0.28f), col, sw);
        dl->AddLine(ImVec2(x0 + s * 0.16f, y1 - s * 0.28f), ImVec2(c.x - s * 0.18f, y1 - s * 0.08f), col, sw);
        break;
    }
}

void IconDrawRole(int icon, ImVec2 center, int role, unsigned int col, ImDrawList* dl)
{
    IconDraw(icon, center, IconSize(role), col, dl);
}

static ImVec2 IconCenterInSlot(ImVec2 p, float h, float pad, float s)
{
    return ImVec2(p.x + pad + s, p.y + h * 0.5f);
}

bool IconButton(const char* id, int icon, const char* label)
{
    ImVec2 ts = label ? ImGui::CalcTextSize(label) : ImVec2(0, 0);
    float h = ImGui::GetFrameHeight();
    if (h < ThemePx(28.f))
        h = ThemePx(28.f);
    float s = IconSize(IconRoleMd);
    float gap = IconTextGap();
    float pad = ThemeSpaceXs();
    float slot = s * 2.f;
    float w;
    if (label && label[0])
        w = pad + slot + gap + ts.x + pad;
    else
        w = h;
    ImVec2 p = ImGui::GetCursorScreenPos();
    bool hit = ImGui::InvisibleButton(id, ImVec2(w, h));
    ImVec2 q = ImGui::GetItemRectMax();
    bool hovered = ImGui::IsItemHovered();
    bool active = ImGui::IsItemActive();
    bool focused = ImGui::IsItemFocused();
    float ht = UiHoverT(ImGui::GetItemID(), hovered || active);
    if (active)
        ht = 1.f;
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImU32 fill = UiLerpCol(ThemeColCard(), ThemeColHover(), ht);
    if (active)
        fill = UiLerpCol(fill, ThemeColAccent(), 0.16f);
    dl->AddRectFilled(p, q, fill);
    if (focused)
        dl->AddRect(p, q, ThemeColAccent());
    UiHandIfHovered();
    UiHoverSweep(p, q, ht);
    ImU32 col = UiLerpCol(ThemeColFg(), ThemeColAccent(), ht);
    if (label && label[0])
        IconDraw(icon, IconCenterInSlot(p, h, pad, s), s, col, dl);
    else
        IconDraw(icon, ImVec2(p.x + w * 0.5f, p.y + h * 0.5f), s, col, dl);
    if (label && label[0])
        dl->AddText(ImVec2(p.x + pad + slot + gap, p.y + (h - ts.y) * 0.5f), col, label);
    else if (hovered && ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort))
        UiTooltip(id);
    return hit;
}

bool IconTool(const char* id, int icon, const char* label)
{
    ImVec2 ts = label ? ImGui::CalcTextSize(label) : ImVec2(0, 0);
    float h = ImGui::GetFrameHeight();
    if (h < ThemePx(28.f))
        h = ThemePx(28.f);
    float s = IconSize(IconRoleLg);
    float gap = IconTextGap();
    float pad = ThemeSpaceXs();
    float slot = s * 2.f;
    float w = label && label[0] ? pad + slot + gap + ts.x + pad : h;
    ImVec2 p = ImGui::GetCursorScreenPos();
    bool hit = ImGui::InvisibleButton(id, ImVec2(w, h));
    UiHandIfHovered();
    float ht = UiHoverT(ImGui::GetItemID(), ImGui::IsItemHovered());
    UiHoverSweep(p, ImGui::GetItemRectMax(), ht);
    ImU32 col = UiLerpCol(ThemeColFg(), ThemeColAccent(), ht);
    IconDraw(icon, IconCenterInSlot(p, h, pad, s), s, col);
    if (label && label[0])
        ImGui::GetWindowDrawList()->AddText(ImVec2(p.x + pad + slot + gap, p.y + (h - ts.y) * 0.5f), col, label);
    return hit;
}

bool IconMenuItem(int icon, const char* label, const char* shortcut, bool enabled)
{
    char buf[96];
    IconPrefixLabel(buf, (int)sizeof(buf), IconRoleSm, label);
    bool hit = ImGui::MenuItem(buf, shortcut, false, enabled);
    ImVec2 a = ImGui::GetItemRectMin();
    float h = ImGui::GetItemRectSize().y;
    float s = IconSize(IconRoleSm);
    IconDraw(icon, ImVec2(a.x + ThemeSpaceSm() + s, a.y + h * 0.5f), s,
        enabled ? ThemeColFg() : ThemeColMuted());
    return hit;
}

bool IconBeginMenu(int icon, const char* label)
{
    char buf[80];
    IconPrefixLabel(buf, (int)sizeof(buf), IconRoleSm, label);
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    bool open = ImGui::BeginMenu(buf);
    float h = ImGui::GetFrameHeight();
    float s = IconSize(IconRoleSm);
    IconDraw(icon, ImVec2(p.x + ThemeSpaceSm() + s, p.y + h * 0.5f), s, ThemeColFg(), dl);
    return open;
}
