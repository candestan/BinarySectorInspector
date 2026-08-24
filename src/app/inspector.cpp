#include "app/inspector.h"
#include "app/inspector_internal.h"
#include "app/app.h"
#include "pe/pe.h"
#include "detect/detect.h"
#include "log/log.h"
#include "ui/theme.h"
#include "ui/icons.h"
#include "ui/widgets.h"
#include "ui/console_view.h"
#include "ui/workspace.h"
#include "ui/selection.h"
#include "ui/tex.h"
#include "i18n/i18n.h"
#include "persist/settings.h"

#include "ui/hex_view.h"
#include "pe/patch.h"
#include "plugin/plugin.h"
#include "tool/tool.h"
#include "findings/findings.h"
#include "imgui.h"

#include <windows.h>
#include <d3d11.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <math.h>
#include <vector>
#include <string>
#include <algorithm>
#include <ctype.h>

#ifndef IMAGE_DLLCHARACTERISTICS_GUARD_CF
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF 0x4000
#endif

static char g_sel[96] = "overview";
static const char* SelCaption();
static int g_icon_sel = 0;
static unsigned g_dirt;
static int g_rsrc_kind; // 0 all, 1 version, 2 icons, 3 com
static int g_rsrc_row;
int g_an_root;
int g_an_child = -1; // -1 = selected root artifact
int g_an_grand = -1; // -1 = no grandchild under children[g_an_child]
int g_find_sel = -1;
static int g_reloc_sel;
static int g_sec_sel;
static int g_imp_sel;
static int g_exp_sel;
static char g_str_filter[128];
static char g_imp_filter[128];
static char g_exp_filter[128];
static int g_save_phase; // 0 idle, 1 spinning, 2 summary, 3 backup-fail confirm
static float g_save_t;
static bool g_save_wrote;
static bool g_save_ok;
static bool g_save_skip_backup;
static int g_patch_row = -1;
static char g_save_dst[MAX_PATH];
static char g_con[14][192];
static int g_con_n;

static const float kSplitListFrac = 0.36f;
static float g_split_sec;
static float g_split_imp;
float g_split_an;
static float g_split_rsrc;
float g_split_find;
float g_split_start_here;
static float g_pair_frac = 0.5f;

static float g_sel_bar_y = -1.f;
static float g_sel_bar_h;
static float g_sel_bar_x0;
static float g_sel_bar_x1;

static bool g_layout_loaded;
static int  g_layout_seen_epoch = -1;

static float LayoutPx(const char* key, float fallback_logical)
{
    float dpi = ThemeDpi();
    if (dpi < 0.5f)
        dpi = 1.f;
    if (SettingsLayoutHas(key))
    {
        float logical = SettingsLayoutGet(key, fallback_logical);
        if (logical < 8.f)
            logical = 8.f;
        return logical * dpi;
    }
    return ThemePx(fallback_logical);
}

static void LayoutSavePx(const char* key, float physical)
{
    float dpi = ThemeDpi();
    if (dpi < 0.5f)
        dpi = 1.f;
    SettingsLayoutSet(key, physical / dpi);
}

static void LoadViewLayout()
{
    int epoch = SettingsLayoutEpoch();
    if (g_layout_loaded && g_layout_seen_epoch == epoch)
        return;
    g_layout_loaded = true;
    g_layout_seen_epoch = epoch;
    g_split_sec = SettingsLayoutHas("split.sections") ? LayoutPx("split.sections", 220.f) : 0.f;
    g_split_imp = SettingsLayoutHas("split.imports") ? LayoutPx("split.imports", 220.f) : 0.f;
    g_split_an = SettingsLayoutHas("split.analysis") ? LayoutPx("split.analysis", 220.f) : 0.f;
    g_split_rsrc = SettingsLayoutHas("split.resources") ? LayoutPx("split.resources", 220.f) : 0.f;
    g_split_find = SettingsLayoutHas("split.findings") ? LayoutPx("split.findings", 280.f) : 0.f;
    g_split_start_here = SettingsLayoutHas("split.start_here") ? LayoutPx("split.start_here", 0.f) : 0.f;
    g_pair_frac = SettingsLayoutGet("split.dock_pair", 0.5f);
    if (g_pair_frac < 0.2f)
        g_pair_frac = 0.2f;
    if (g_pair_frac > 0.8f)
        g_pair_frac = 0.8f;
}

void InspectorReloadLayout()
{
    g_layout_loaded = false;
    LoadViewLayout();
}

enum
{
    DirtHex = 1,
    DirtVer = 2,
    DirtIco = 4,
    DirtCom = 8,
};

static void MarkDirt(unsigned bit)
{
    g_dirt |= bit;
    PeJobTouch();
}

void InspectorNoteHexWrite()
{
    MarkDirt(DirtHex);
}

static void ConClear()
{
    g_con_n = 0;
    for (int i = 0; i < 14; i++)
        g_con[i][0] = 0;
}

static void ConLog(const char* s)
{
    if (g_con_n >= 14 || !s)
        return;
    snprintf(g_con[g_con_n++], 192, "%s", s);
    LogInfo(LogBuiltinFile, "%s", s);
}

struct IconTex
{
    uint32_t off;
    ID3D11ShaderResourceView* srv;
    int w, h;
};
static std::vector<IconTex> g_icon_tex;

static void NukeIconTex()
{
    for (IconTex& t : g_icon_tex)
    {
        if (t.srv)
            t.srv->Release();
    }
    g_icon_tex.clear();
}

static ID3D11ShaderResourceView* BytesPreview(uint32_t off, uint32_t size, int* w, int* h)
{
    for (IconTex& t : g_icon_tex)
    {
        if (t.off == off)
        {
            if (w) *w = t.w;
            if (h) *h = t.h;
            return t.srv;
        }
    }
    size_t n = 0;
    uint8_t* b = PeJobBytes(&n);
    if (!b || size == 0 || (uint64_t)off + size > n)
        return nullptr;
    IconTex t{};
    t.off = off;
    if (TexLoadPeIcon(b + off, size, &t.srv, &t.w, &t.h) ||
        TexLoadMemory(b + off, size, &t.srv, &t.w, &t.h))
    {
        if (w) *w = t.w;
        if (h) *h = t.h;
        g_icon_tex.push_back(t);
        return t.srv;
    }
    return nullptr;
}

static ID3D11ShaderResourceView* IconPreview(const PeIconImg& ic, int* w, int* h)
{
    return BytesPreview(ic.file_off, ic.size, w, h);
}

static void DoSave(bool save_as)
{
    if (g_save_phase)
        return;
    char path[MAX_PATH];
    if (save_as || !PeJobPath()[0])
    {
        if (!AppPickSavePe(path, MAX_PATH))
            return;
    }
    else
        snprintf(path, MAX_PATH, "%s", PeJobPath());
    snprintf(g_save_dst, MAX_PATH, "%s", path);
    g_save_phase = 1;
    g_save_t = 0.f;
    g_save_wrote = false;
    g_save_ok = false;
    g_save_skip_backup = false;
    ConClear();
    ConLog(I18nGet("save.log_hold"));
}

void GoHex(uint32_t off)
{
    NavOpenInHex(off);
}

static const char* ViewForSel(const char* id)
{
    if (!id || !id[0])
        return "view.overview";
    if (strcmp(id, "overview") == 0)
        return "view.overview";
    if (strcmp(id, "hex") == 0)
        return "view.hex";
    if (strcmp(id, "findings") == 0)
        return "view.findings";
    if (strcmp(id, "detection") == 0)
        return "view.detection";
    if (strcmp(id, "headers") == 0)
        return "view.headers";
    if (strcmp(id, "sections") == 0 || strncmp(id, "sec:", 4) == 0)
        return "view.sections";
    if (strcmp(id, "imports") == 0 || strncmp(id, "imp:", 4) == 0)
        return "view.imports";
    if (strcmp(id, "exports") == 0)
        return "view.exports";
    if (strcmp(id, "relocs") == 0)
        return "view.relocs";
    if (strcmp(id, "tls") == 0)
        return "view.tls";
    if (strcmp(id, "debug") == 0)
        return "view.debug";
    if (strcmp(id, "entropy") == 0)
        return "view.entropy";
    if (strcmp(id, "strings") == 0)
        return "view.strings";
    if (strcmp(id, "analysis") == 0)
        return "view.analysis";
    if (strcmp(id, "rsrc") == 0 || strcmp(id, "ver") == 0 ||
        strcmp(id, "icons") == 0 || strcmp(id, "com") == 0)
        return "view.resources";
    if (strcmp(id, "overlay") == 0)
        return "view.overlay";
    if (strcmp(id, "changes") == 0)
        return "panel.patch_history";
    if (PluginSelIsView(id))
        return id;
    return "view.overview";
}

void InspectorSelect(const char* id)
{
    if (!id || !id[0])
        return;
    if (strcmp(g_sel, id) != 0)
        LogDebug(LogBuiltinUI, "Selection: %s", id);
    snprintf(g_sel, sizeof(g_sel), "%s", id);

    const char* kind = "file";
    uint32_t off = 0;
    uint32_t size = 0;
    const PeFile* pe = PeJobResult();
    if (strncmp(id, "sec:", 4) == 0)
    {
        kind = "section";
        int i = atoi(id + 4);
        if (pe && i >= 0 && i < pe->section_n)
        {
            off = pe->sections[i].rawptr;
            size = pe->sections[i].rawsize;
        }
    }
    else if (strncmp(id, "imp:", 4) == 0)
        kind = "import";
    else if (strcmp(id, "sections") == 0)
        kind = "section";
    else if (strcmp(id, "imports") == 0)
        kind = "import";
    else if (strcmp(id, "exports") == 0)
        kind = "export";
    else if (strcmp(id, "rsrc") == 0 || strcmp(id, "ver") == 0 ||
        strcmp(id, "icons") == 0 || strcmp(id, "com") == 0)
        kind = "resource";
    else if (strcmp(id, "findings") == 0)
        kind = "finding";
    else if (strcmp(id, "detection") == 0)
        kind = "detection";
    else if (strcmp(id, "analysis") == 0)
        kind = "artifact";
    else if (strcmp(id, "hex") == 0)
        kind = "range";
    else if (strcmp(id, "overlay") == 0 && pe)
    {
        kind = "range";
        off = pe->overlay_off;
        size = (uint32_t)pe->overlay_size;
    }
    SelectionSet(kind, id, SelCaption(), nullptr, off, size);
    NavOpenView(ViewForSel(id));
}

static const char* FileNameOf(const char* path)
{
    const char* slash = strrchr(path, '\\');
    const char* fwd = strrchr(path, '/');
    if (fwd && (!slash || fwd > slash))
        slash = fwd;
    return slash ? slash + 1 : path;
}

static const char* DetectConfKey(DetectConfidence conf)
{
    switch (conf)
    {
    case DetectConfLow: return "detect.conf.low";
    case DetectConfMedium: return "detect.conf.medium";
    case DetectConfHigh: return "detect.conf.high";
    case DetectConfExact: return "detect.conf.exact";
    default: return "detect.conf.low";
    }
}

static const char* DetectConfTipKey(DetectConfidence conf)
{
    switch (conf)
    {
    case DetectConfLow: return "detect.conf.tip.low";
    case DetectConfMedium: return "detect.conf.tip.medium";
    case DetectConfHigh: return "detect.conf.tip.high";
    case DetectConfExact: return "detect.conf.tip.exact";
    default: return "detect.conf.tip.low";
    }
}

static ImU32 DetectConfCol(DetectConfidence conf)
{
    if (conf == DetectConfExact || conf == DetectConfHigh)
        return ThemeColInfo();
    if (conf == DetectConfMedium)
        return ThemeColFg();
    return ThemeColMuted();
}

void ConfBadge(const char* id, DetectConfidence conf)
{
    float min_w = 0.f;
    const char* keys[] = {
        "detect.conf.low", "detect.conf.medium", "detect.conf.high", "detect.conf.exact"
    };
    for (int i = 0; i < 4; i++)
    {
        float w = UiBadgeWidth(I18nGet(keys[i]));
        if (w > min_w)
            min_w = w;
    }
    UiBadge(id, I18nGet(DetectConfKey(conf)), DetectConfCol(conf), I18nGet(DetectConfTipKey(conf)), min_w);
}

float FieldLabelCol()
{
    float content_w = ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x;
    float col = ThemeLabelW();
    if (col > content_w - ThemePx(80.f))
        col = content_w * 0.42f;
    if (col < ThemePx(72.f))
        col = ThemePx(72.f);
    return col;
}

void FieldLabel(const char* k, const char* help)
{
    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(ThemeColMuted()), "%s", k);
    if (help && help[0])
    {
        ImGui::SameLine(0.f, ThemeSpaceXs());
        ImGui::PushID(k);
        UiHelpMark(help);
        ImGui::PopID();
    }
}

void EmptyHint(const char* key)
{
    UiEmpty(I18nGet(key));
}

void Field(const char* k, const char* v, const char* help)
{
    FieldLabel(k, help);
    float col = FieldLabelCol();
    float label_right = ImGui::GetItemRectMax().x - ImGui::GetWindowPos().x + ImGui::GetScrollX();
    if (label_right + ThemeSpaceSm() > col)
        ImGui::SameLine(0.f, ThemeSpaceSm());
    else
        ImGui::SameLine(col);
    ImGui::AlignTextToFramePadding();
    ImGui::PushTextWrapPos(0.f);
    ImGui::TextUnformatted(v ? v : "");
    ImGui::PopTextWrapPos();
}

static void FieldCopy(const char* k, const char* v, const char* help)
{
    ImGui::PushID(k);
    FieldLabel(k, help);
    ImGui::SameLine(FieldLabelCol());
    if (!v || !v[0])
    {
        ImGui::AlignTextToFramePadding();
        ImGui::TextDisabled("%s", I18nGet("pe.none"));
        ImGui::PopID();
        return;
    }
    char buf[512];
    snprintf(buf, sizeof(buf), "%s", v);
    float row_h = ImGui::GetFrameHeight();
    float btn_w = row_h;
    float val_w = ImGui::GetContentRegionAvail().x - btn_w - ThemeSpaceXs();
    if (val_w < ThemePx(80.f))
        val_w = ThemePx(80.f);
    UiFieldText("val", buf, (int)sizeof(buf), val_w);
    ImGui::SameLine(0.f, ThemeSpaceXs());
    UiCopyButton("cpy", v);
    ImGui::PopID();
}

static void FieldIdent(const char* k, const char* v, bool detected, DetectConfidence conf, const char* help)
{
    FieldLabel(k, help);
    ImGui::SameLine(FieldLabelCol());
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted(v ? v : "");
    if (detected)
    {
        ImGui::SameLine(0.f, ThemeBadgeGap());
        ConfBadge(k, conf);
    }
}

static void FieldYesNo(const char* k, bool yes, const char* help, const char* tip)
{
    FieldLabel(k, help);
    ImGui::SameLine(FieldLabelCol());
    ImGui::AlignTextToFramePadding();
    const char* lab = yes ? I18nGet("pe.yes") : I18nGet("pe.no");
    ImGui::TextUnformatted(lab);
    ImGui::SameLine(0.f, ThemeBadgeGap());
    UiBadge("yn", lab, yes ? ThemeColSuccess() : ThemeColMuted(), tip);
}

void FieldU(const char* k, uint64_t v, bool hex, const char* help)
{
    char buf[48];
    if (hex)
        snprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)v);
    else
        snprintf(buf, sizeof(buf), "%llu", (unsigned long long)v);
    Field(k, buf, help);
}

static bool Node(const char* id, const char* label, int icon, bool leaf, bool dirty)
{
    bool sel = strcmp(g_sel, id) == 0;
    if (strcmp(id, "rsrc") == 0 && (strcmp(g_sel, "ver") == 0 || strcmp(g_sel, "icons") == 0 || strcmp(g_sel, "com") == 0))
        sel = true;
    ImGui::PushID(id);
    float h = ImGui::GetTextLineHeight() + ThemePx(12.f);
    float w = ImGui::GetContentRegionAvail().x;
    if (ImGui::Selectable("##n", sel, 0, ImVec2(w, h)))
        InspectorSelect(id);
    UiHandIfHovered();
    ImVec2 a = ImGui::GetItemRectMin();
    ImVec2 b = ImGui::GetItemRectMax();
    float row_h = b.y - a.y;
    float ht = UiHoverT(ImGui::GetItemID(), ImGui::IsItemHovered() || sel);
    UiHoverSweep(a, b, ht);
    if (sel)
    {
        g_sel_bar_x0 = a.x;
        g_sel_bar_x1 = b.x;
        if (g_sel_bar_y < 0.f || !UiAnimEnabled())
        {
            g_sel_bar_y = a.y;
            g_sel_bar_h = row_h;
        }
        else
        {
            float k = 1.f - expf(-18.f * ImGui::GetIO().DeltaTime);
            g_sel_bar_y += (a.y - g_sel_bar_y) * k;
            g_sel_bar_h += (row_h - g_sel_bar_h) * k;
        }
    }
    float s = IconSize(IconRoleSm);
    float gap = IconTextGap();
    float left = ThemeSpaceSm();
    ImVec2 ts = ImGui::CalcTextSize(label);
    float text_y = a.y + (row_h - ts.y) * 0.5f;
    float icon_y = a.y + row_h * 0.5f;
    IconDraw(icon, ImVec2(a.x + left + s, icon_y), s,
        sel ? ThemeColAccent() : UiLerpCol(ThemeColMuted(), ThemeColAccent(), ht));
    ImGui::GetWindowDrawList()->AddText(ImVec2(a.x + left + s * 2.f + gap, text_y),
        ThemeColFg(), label);
    if (dirty)
    {
        float pulse = UiAnimEnabled() ? 0.55f + 0.45f * (0.5f + 0.5f * sinf((float)ImGui::GetTime() * 5.f)) : 1.f;
        ImU32 dc = ThemeWithAlpha(ThemeColAccent(), pulse);
        ImGui::GetWindowDrawList()->AddText(ImVec2(b.x - 18.f, a.y + (row_h - ImGui::GetFontSize()) * 0.5f),
            dc, "!");
    }
    ImGui::PopID();
    (void)leaf;
    return false;
}

static bool RsrcBtn(const char* id, const char* label, int kind, bool dirty, float width)
{
    bool sel = strcmp(g_sel, "rsrc") == 0 && g_rsrc_kind == kind;
    if (strcmp(g_sel, id) == 0)
        sel = true;
    ImGui::PushID(id);
    ImVec2 p = ImGui::GetCursorScreenPos();
    float w = width > 0.f ? width : ImGui::GetContentRegionAvail().x;
    float h = ImGui::GetFrameHeight();
    bool hit = ImGui::InvisibleButton("hit", ImVec2(w, h));
    ImVec2 q = ImGui::GetItemRectMax();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    bool hovered = ImGui::IsItemHovered();
    bool active = ImGui::IsItemActive();
    float ht = UiHoverT(ImGui::GetItemID(), hovered || sel || active);
    if (active)
        ht = 1.f;
    ImU32 fill = UiLerpCol(ThemeColCard(), ThemeColHover(), sel ? 1.f : ht);
    if (active)
        fill = UiLerpCol(fill, ThemeColAccent(), 0.16f);
    dl->AddRectFilled(p, q, fill);
    dl->AddRect(p, q, UiLerpCol(ThemeColBorder(), ThemeColAccent(), sel || active ? 1.f : ht));
    UiHandIfHovered();
    UiHoverSweep(p, q, ht);
    UiAccentBar(p, q, sel ? 1.f : ht * 0.35f, dl);
    dl->AddText(ImVec2(p.x + 10.f, p.y + (h - ImGui::GetFontSize()) * 0.5f),
        sel ? ThemeColAccent() : ThemeColFg(), label);
    if (dirty)
        dl->AddText(ImVec2(q.x - 18.f, p.y + (h - ImGui::GetFontSize()) * 0.5f), ThemeColAccent(), "!");
    ImGui::PopID();
    if (hit)
    {
        InspectorSelect("rsrc");
        g_rsrc_kind = kind;
        g_rsrc_row = 0;
        LogDebug(LogBuiltinUI, "Resource filter: %s", label);
    }
    return hit;
}

static bool TopMenu(const char* id, const char* label)
{
    ImGui::PushID(id);
    bool popup_open = ImGui::IsPopupOpen("##drop");
    ImGui::PushStyleColor(ImGuiCol_Button, popup_open
        ? ImGui::ColorConvertU32ToFloat4(ThemeColHover())
        : ThemeVec4Transparent());
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImGui::ColorConvertU32ToFloat4(ThemeColHover()));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImGui::ColorConvertU32ToFloat4(ThemeColAccentA(0.22f)));
    ImVec2 ts = ImGui::CalcTextSize(label);
    float bar_h = ThemeMenuBarH();
    ImVec2 btn_sz(ts.x + ThemeMenuBarPadX() * 2.f, bar_h - ThemePx(2.f));
    bool press = ImGui::Button(label, btn_sz);
    ImGui::PopStyleColor(3);
    float ht = UiHoverT(ImGui::GetItemID(), ImGui::IsItemHovered() || popup_open);
    UiHoverSweep(ImGui::GetItemRectMin(), ImGui::GetItemRectMax(), ht);
    if (press)
        ImGui::OpenPopup("##drop", ImGuiPopupFlags_NoReopen);
    bool open = UiBeginPopup("##drop");
    if (!open)
        ImGui::PopID();
    return open;
}

static void TopMenuEnd()
{
    UiEndPopup();
    ImGui::PopID();
}

static void DrawMenubar()
{
    ImVec2 p0 = ImGui::GetCursorScreenPos();
    float w = ImGui::GetContentRegionAvail().x;
    float h = ThemeMenuBarH();
    ImGui::GetWindowDrawList()->AddRectFilled(p0, ImVec2(p0.x + w, p0.y + h), ThemeColBg());
    ImGui::GetWindowDrawList()->AddLine(ImVec2(p0.x, p0.y + h), ImVec2(p0.x + w, p0.y + h), ThemeColBorder());
    ImGui::BeginChild("menubar", ImVec2(w, h), ImGuiChildFlags_None,
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

    bool busy = PeJobBusy();
    bool ready = PeJobResult() != nullptr && !busy;
    bool locked = g_save_phase != 0;

    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(ThemeMenuBarPadX(), ThemeMenuBarPadY()));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(ThemePx(1.f), 0.f));

    if (TopMenu("file", I18nGet("menu.file")))
    {
        if (ImGui::MenuItem(I18nGet("welcome.open"), "Ctrl+O", false, !locked))
        {
            char path[MAX_PATH];
            if (AppPickOpenPe(path, MAX_PATH))
                AppOpenPath(path);
        }
        if (ImGui::MenuItem(I18nGet("welcome.from_window"), nullptr, false, !locked))
            AppOpenWindowPicker();
        if (ImGui::BeginMenu(I18nGet("menu.open_recent"), SettingsRecentsCount() > 0 && !locked))
        {
            char rec[MAX_PATH];
            int n = SettingsRecentsCount();
            for (int i = 0; i < n; i++)
            {
                if (!SettingsRecentsGet(i, rec, MAX_PATH))
                    continue;
                ImGui::PushID(i);
                if (ImGui::MenuItem(FileNameOf(rec)))
                    AppOpenPath(rec);
                ImGui::PopID();
            }
            ImGui::EndMenu();
        }
        ImGui::Separator();
        if (ImGui::MenuItem(I18nGet("pe.save"), "Ctrl+S", false, ready && !locked))
            DoSave(false);
        if (ImGui::MenuItem(I18nGet("menu.save_as"), "Ctrl+Shift+S", false, ready && !locked))
            DoSave(true);
        ImGui::Separator();
        if (ImGui::MenuItem(I18nGet("pe.close"), nullptr, false, (ready || busy) && !locked))
            AppSetPage(AppPageWelcome);
        ImGui::Separator();
        if (ImGui::MenuItem(I18nGet("navigation.settings"), nullptr, false, !locked))
            AppOpenSettings();
        TopMenuEnd();
    }
    ImGui::SameLine(0.f, 0.f);
    if (TopMenu("edit", I18nGet("menu.edit")))
    {
        if (ImGui::MenuItem(I18nGet("pe.hex"), nullptr, false, ready && !locked))
            InspectorSelect("hex");
        if (ImGui::MenuItem(I18nGet("patch.title"), nullptr, false, ready && !locked))
            InspectorSelect("changes");
        ImGui::Separator();
        if (ImGui::MenuItem(I18nGet("patch.undo"), "Ctrl+Z", false, ready && !locked && PatchCanUndo()))
        {
            PatchUndo();
            MarkDirt(DirtHex);
        }
        if (ImGui::MenuItem(I18nGet("patch.redo"), "Ctrl+Y", false, ready && !locked && PatchCanRedo()))
        {
            PatchRedo();
            MarkDirt(DirtHex);
        }
        TopMenuEnd();
    }
    ImGui::SameLine(0.f, 0.f);
    if (TopMenu("sel", I18nGet("menu.selection")))
    {
        if (ImGui::MenuItem(I18nGet("pe.overview"), nullptr, false, ready && !locked))
            InspectorSelect("overview");
        if (ImGui::MenuItem(I18nGet("pe.headers"), nullptr, false, ready && !locked))
            InspectorSelect("headers");
        if (ImGui::MenuItem(I18nGet("pe.resources"), nullptr, false, ready && !locked))
        {
            InspectorSelect("rsrc");
            g_rsrc_kind = 0;
        }
        if (ImGui::MenuItem(I18nGet("pe.hex"), nullptr, false, ready && !locked))
            InspectorSelect("hex");
        TopMenuEnd();
    }
    ImGui::SameLine(0.f, 0.f);
    if (TopMenu("view", I18nGet("menu.view")))
    {
        WorkspaceDrawViewMenu(ready, locked);
        TopMenuEnd();
    }
    ImGui::SameLine(0.f, 0.f);
    if (TopMenu("go", I18nGet("menu.go")))
    {
        const PeFile* pe = PeJobResult();
        uint32_t ep = pe ? PeRvaToFileOff(pe->entry_rva) : 0;
        if (ImGui::MenuItem(I18nGet("menu.go_entry"), nullptr, false, ready && ep && !locked))
            GoHex(ep);
        if (ImGui::MenuItem(I18nGet("menu.go_overlay"), nullptr, false, ready && pe && pe->overlay_size && !locked))
            GoHex(pe->overlay_off);
        if (ImGui::MenuItem(I18nGet("pe.resources"), nullptr, false, ready && !locked))
        {
            InspectorSelect("rsrc");
            g_rsrc_kind = 0;
        }
        TopMenuEnd();
    }
    ImGui::SameLine(0.f, 0.f);
    if (TopMenu("tools", I18nGet("menu.tools")))
    {
        PluginDrawToolsMenu(ready, locked);
        TopMenuEnd();
    }
    ImGui::SameLine(0.f, 0.f);
    if (TopMenu("run", I18nGet("menu.run")))
    {
        ImGui::MenuItem(I18nGet("menu.run_none"), nullptr, false, false);
        UiTipWhenDisabled(I18nGet("menu.run_none"));
        TopMenuEnd();
    }

    ImGui::PopStyleVar(2);

    const char* path = PeJobPath();
    if (path[0])
    {
        char cap[280];
        if (PeJobDirty())
            snprintf(cap, sizeof(cap), "* %s", FileNameOf(path));
        else
            snprintf(cap, sizeof(cap), "%s", FileNameOf(path));
        ImVec2 ts = ImGui::CalcTextSize(cap);
        ImVec2 wp = ImGui::GetWindowPos();
        float ww = ImGui::GetWindowSize().x;
        ImGui::GetWindowDrawList()->AddText(
            ImVec2(wp.x + ww - ts.x - ThemeSpaceSm(), wp.y + (h - ts.y) * 0.5f),
            ThemeColMuted(), cap);
    }
    ImGui::EndChild();
}

static void DrawOverview(const PeFile* pe)
{
    Field(I18nGet("pe.file"), pe->path, I18nGet("help.fld.file"));
    FieldU(I18nGet("pe.size"), pe->size, false, I18nGet("help.fld.size"));
    FieldCopy(I18nGet("pe.hash_sha256"), pe->sha256, I18nGet("help.fld.hash"));
    if (pe->imphash[0])
        FieldCopy(I18nGet("pe.imphash"), pe->imphash, I18nGet("help.fld.imphash"));
    FieldIdent(I18nGet("pe.compiler"), pe->compiler, pe->compiler_detected, pe->compiler_conf, I18nGet("help.fld.compiler"));
    FieldIdent(I18nGet("pe.packer"), pe->packer, pe->packer_detected, pe->packer_conf, I18nGet("help.fld.packer"));
    FieldIdent(I18nGet("pe.protector"), pe->protector, pe->protector_detected, pe->protector_conf, I18nGet("help.fld.protector"));
    if (pe->has_com)
        FieldIdent(I18nGet("pe.obfuscator"), pe->obfuscator, pe->obfuscator_detected, pe->obfuscator_conf, I18nGet("help.fld.obfuscator"));
    Field(I18nGet("pe.arch"), pe->machine_s, I18nGet("help.fld.arch"));
    Field(I18nGet("pe.kind"), pe->pe32plus ? "PE32+" : "PE32", I18nGet("help.fld.kind"));
    Field(I18nGet("pe.subsystem"), pe->subsystem_s, I18nGet("help.fld.subsystem"));
    FieldU(I18nGet("pe.sections"), (uint64_t)pe->section_n, false, I18nGet("help.fld.nsec"));
    FieldU(I18nGet("pe.entry_rva"), pe->entry_rva, true, I18nGet("help.fld.aep"));
    if (pe->overlay_size)
        FieldU(I18nGet("pe.overlay_bytes"), pe->overlay_size, false, I18nGet("help.fld.overlay"));

    const AnalysisReport& rep = pe->report;
    if (rep.summary.headline_key[0])
    {
        ImGui::Spacing();
        UiSection(I18nGet("finding.summary.title"));
        ImGui::TextWrapped("%s", I18nGet(rep.summary.headline_key));
    }
    if (rep.summary.start_here_n > 0)
    {
        ImGui::Spacing();
        UiSection(I18nGet("finding.start_here"));
        float row_h = ImGui::GetFrameHeight();
        for (int i = 0; i < rep.summary.start_here_n; i++)
        {
            int idx = rep.summary.start_here[i];
            if (idx < 0 || idx >= (int)rep.findings.size())
                continue;
            const FindingItem& f = rep.findings[(size_t)idx];
            ImGui::PushID(2000 + idx);
            char line[256];
            snprintf(line, sizeof(line), "%d. %s", i + 1, FindingText(f.title_key));
            if (ImGui::Selectable(line, g_find_sel == idx, 0, ImVec2(0.f, row_h)))
            {
                g_find_sel = idx;
                SelectionSet("finding", f.id, FindingText(f.title_key), f.evidence_text, f.file_off, 0);
                NavOpenView("view.findings");
                NavShowEvidence();
            }
            ImGui::PopID();
        }
    }
    if (!pe->detections.empty())
    {
        ImGui::Spacing();
        UiSection(I18nGet("detect.title"));
        char nbuf[48];
        snprintf(nbuf, sizeof(nbuf), "%d", (int)pe->detections.size());
        Field(I18nGet("detect.title"), nbuf, nullptr);
        int show = (int)pe->detections.size();
        if (show > 3)
            show = 3;
        for (int i = 0; i < show; i++)
            ImGui::BulletText("%s", pe->detections[i].product.c_str());
        if (UiButton(I18nGet("detect.title")))
            InspectorSelect("detection");
    }
}

static void DrawHeaders(const PeFile* pe)
{
    FieldU(I18nGet("pe.field.e_lfanew"), pe->e_lfanew, true, I18nGet("help.fld.e_lfanew"));
    Field(I18nGet("pe.arch"), pe->machine_s, I18nGet("help.fld.arch"));
    FieldU(I18nGet("pe.field.characteristics"), pe->chars, true, I18nGet("help.fld.characteristics"));
    Field(I18nGet("pe.kind"), pe->pe32plus ? "PE32+" : "PE32", I18nGet("help.fld.kind"));
    FieldU(I18nGet("pe.field.address_of_entry"), pe->entry_rva, true, I18nGet("help.fld.aep"));
    FieldU(I18nGet("pe.image_base"), pe->image_base, true, I18nGet("help.fld.imagebase"));
    FieldU(I18nGet("pe.field.section_alignment"), pe->section_align, true, I18nGet("help.fld.secalign"));
    FieldU(I18nGet("pe.field.file_alignment"), pe->file_align, true, I18nGet("help.fld.filealign"));
    FieldU(I18nGet("pe.field.size_of_image"), pe->size_of_image, true, I18nGet("help.fld.sizeofimage"));
    Field(I18nGet("pe.subsystem"), pe->subsystem_s, I18nGet("help.fld.subsystem"));
    FieldU(I18nGet("pe.dll_characteristics"), pe->dllchars, true, I18nGet("help.fld.dllchars"));
    FieldYesNo(I18nGet("pe.nx_dep"), (pe->dllchars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0,
        I18nGet("help.fld.nx"), I18nGet("help.fld.nx"));
    FieldYesNo(I18nGet("pe.aslr"), (pe->dllchars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0,
        I18nGet("help.fld.aslr"), I18nGet("help.fld.aslr"));
    FieldYesNo(I18nGet("pe.cfg"), (pe->dllchars & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0,
        I18nGet("help.fld.cfg"), I18nGet("help.fld.cfg"));
    FieldLabel(I18nGet("pe.checksum"), I18nGet("help.fld.checksum"));
    ImGui::SameLine(FieldLabelCol());
    ImGui::AlignTextToFramePadding();
    const char* cks = pe->checksum_ok ? I18nGet("pe.checksum_ok") : I18nGet("pe.checksum_bad");
    ImGui::TextUnformatted(cks);
    ImGui::SameLine(0.f, ThemeBadgeGap());
    UiBadge("ck", cks, pe->checksum_ok ? ThemeColSuccess() : ThemeColWarning(), I18nGet("help.fld.checksum"));
    FieldU(I18nGet("pe.checksum_field"), pe->checksum, true, I18nGet("help.fld.checksum"));
    FieldU(I18nGet("pe.checksum_computed"), pe->checksum_computed, true, I18nGet("help.fld.checksum"));
    if (!pe->rich.empty())
    {
        ImGui::Spacing();
        ImGui::TextUnformatted(I18nGet("pe.rich_header"));
        for (const PeRichEntry& e : pe->rich)
        {
            char line[64];
            snprintf(line, sizeof(line), I18nGet("pe.rich_entry"), e.prod, e.build, e.count);
            ImGui::TextUnformatted(line);
        }
    }
}

static void DrawSection(const PeFile* pe, int i)
{
    if (i < 0 || i >= pe->section_n)
        return;
    const PeSection& s = pe->sections[i];
    Field(I18nGet("pe.field.name"), s.name, I18nGet("help.fld.secname"));
    FieldU(I18nGet("pe.field.virtual_address"), s.vaddr, true, I18nGet("help.fld.vaddr"));
    FieldU(I18nGet("pe.field.virtual_size"), s.vsize, true, I18nGet("help.fld.vsize"));
    FieldU(I18nGet("pe.field.raw_ptr"), s.rawptr, true, I18nGet("help.fld.rawptr"));
    FieldU(I18nGet("pe.field.raw_size"), s.rawsize, true, I18nGet("help.fld.rawsize"));
    FieldU(I18nGet("pe.field.characteristics"), s.chars, true, I18nGet("help.fld.secchars"));
    if (UiButton(I18nGet("menu.go")) && s.rawptr)
        GoHex(s.rawptr);
}

float SplitListW(float* sz)
{
    return UiPersistSplitW("list", sz, kSplitListFrac, ThemePx(80.f), ThemePx(160.f));
}

static void SplitV(const char* id, float* sz, const char* key, float sign, float min_sz)
{
    ImGui::PushID(id);
    ImVec2 p = ImGui::GetCursorScreenPos();
    float h = ImGui::GetContentRegionAvail().y;
    float hit = ThemeSplitHit();
    ImGui::InvisibleButton("sp", ImVec2(hit, h));
    bool hovered = ImGui::IsItemHovered();
    bool active = ImGui::IsItemActive();
    if (hovered || active)
        ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeEW);
    float t = UiHoverT(ImGui::GetItemID(), hovered || active);
    if (active)
        t = 1.f;
    ImDrawList* dl = ImGui::GetWindowDrawList();
    float x = p.x + hit * 0.5f;
    dl->AddRectFilled(ImVec2(x - 1.f, p.y), ImVec2(x + 1.f, p.y + h),
        UiLerpCol(ThemeColBorder(), ThemeColAccent(), t));
    if (active)
    {
        *sz += sign * ImGui::GetIO().MouseDelta.x;
        if (*sz < min_sz)
            *sz = min_sz;
    }
    if (key && key[0] && ImGui::IsItemDeactivated())
        LayoutSavePx(key, *sz);
    ImGui::PopID();
}

void SplitH(const char* id, float* sz, const char* key, float sign, float min_sz, float max_sz)
{
    ImGui::PushID(id);
    ImVec2 p = ImGui::GetCursorScreenPos();
    float w = ImGui::GetContentRegionAvail().x;
    float hit = ThemeSplitHit();
    ImGui::InvisibleButton("sp", ImVec2(w, hit));
    bool hovered = ImGui::IsItemHovered();
    bool active = ImGui::IsItemActive();
    if (hovered || active)
        ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeNS);
    float t = UiHoverT(ImGui::GetItemID(), hovered || active);
    if (active)
        t = 1.f;
    ImDrawList* dl = ImGui::GetWindowDrawList();
    float y = p.y + hit * 0.5f;
    dl->AddRectFilled(ImVec2(p.x, y - 1.f), ImVec2(p.x + w, y + 1.f),
        UiLerpCol(ThemeColBorder(), ThemeColAccent(), t));
    if (active)
    {
        *sz += sign * ImGui::GetIO().MouseDelta.y;
        if (*sz < min_sz)
            *sz = min_sz;
        if (max_sz > min_sz && *sz > max_sz)
            *sz = max_sz;
    }
    if (key && key[0] && ImGui::IsItemDeactivated())
        LayoutSavePx(key, *sz);
    ImGui::PopID();
}

void SplitListHandle(const char* id, float* sz, const char* key)
{
    ImGui::SameLine(0.f, 0.f);
    SplitV(id, sz, key, 1.f, ThemePx(80.f));
    ImGui::SameLine(0.f, 0.f);
}

static void DrawImportDll(const PeFile* pe, int i)
{
    if (i < 0 || i >= (int)pe->imports.size())
        return;
    const PeImportDll& d = pe->imports[i];
    Field(I18nGet("pe.field.dll"), d.name.c_str());
    Field(I18nGet("pe.delay"), d.delay ? I18nGet("pe.yes") : I18nGet("pe.no"), I18nGet("help.fld.delay"));
    Field(I18nGet("pe.bound"), d.bound ? I18nGet("pe.yes") : I18nGet("pe.no"), I18nGet("help.fld.bound"));
    FieldU(I18nGet("pe.functions"), d.fns.size(), false);
    ImGui::Spacing();
    UiTableColDef fn_cols[] = {
        { "name", I18nGet("pe.field.name"), 0, 0.f },
        { "hint", I18nGet("pe.col.hint_ord"), 0, 72.f },
    };
    if (!UiBeginPersistTable("import_fns", fn_cols, 2,
        ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable))
        return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableHeadersRow();
    ImGuiListClipper clipper;
    clipper.Begin((int)d.fns.size());
    while (clipper.Step())
    {
        for (int fi = clipper.DisplayStart; fi < clipper.DisplayEnd; fi++)
        {
            const PeImportFn& f = d.fns[fi];
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(f.name.empty() ? I18nGet("pe.export.ordinal") : f.name.c_str());
            ImGui::TableNextColumn();
            if (f.ordinal)
                ImGui::Text("#%u", f.ordinal);
            else
                ImGui::Text("%u", f.hint);
        }
    }
    UiEndPersistTable();
}

static void DrawSections(const PeFile* pe)
{
    ImGui::BeginChild("sec_list", ImVec2(SplitListW(&g_split_sec), 0.f), ImGuiChildFlags_Borders);
    if (pe->section_n == 0)
        EmptyHint();
    else
    {
        UiTableColDef sec_cols[] = {
            { "name", I18nGet("pe.field.name"), 0, 0.f },
            { "va", I18nGet("pe.col.va"), 0, 88.f },
            { "vsize", I18nGet("pe.col.vsize"), 0, 88.f },
            { "raw_ptr", I18nGet("pe.col.raw_ptr"), 0, 88.f },
            { "raw_size", I18nGet("pe.col.raw_size"), 0, 88.f },
        };
        if (UiBeginPersistTable("sections", sec_cols, 5,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable |
            ImGuiTableFlags_SizingStretchProp))
        {
            if (g_sec_sel < 0 || g_sec_sel >= pe->section_n)
                g_sec_sel = 0;
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableHeadersRow();
        for (int i = 0; i < pe->section_n; i++)
        {
            const PeSection& s = pe->sections[i];
            ImGui::PushID(i);
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            const char* name = s.name[0] ? s.name : "(empty)";
            if (ImGui::Selectable(name, g_sec_sel == i, ImGuiSelectableFlags_SpanAllColumns))
            {
                g_sec_sel = i;
                char sid[32];
                snprintf(sid, sizeof(sid), "sec:%d", i);
                SelectionSet("section", sid, name, nullptr, s.rawptr, s.rawsize);
            }
            ImGui::TableNextColumn();
            ImGui::Text("%08X", s.vaddr);
            ImGui::TableNextColumn();
            ImGui::Text("%08X", s.vsize);
            ImGui::TableNextColumn();
            ImGui::Text("%08X", s.rawptr);
            ImGui::TableNextColumn();
            ImGui::Text("%08X", s.rawsize);
            ImGui::PopID();
        }
        UiEndPersistTable();
        }
    }
    ImGui::EndChild();
    SplitListHandle("sec_sp", &g_split_sec, "split.sections");
    ImGui::BeginChild("sec_prev", ImVec2(0.f, 0.f), ImGuiChildFlags_Borders);
    if (pe->section_n == 0)
        EmptyHint();
    else
        DrawSection(pe, g_sec_sel);
    ImGui::EndChild();
}

static bool ImportDllMatches(const PeImportDll& d, const char* filter)
{
    if (!filter || !filter[0])
        return true;
    if (strstr(d.name.c_str(), filter))
        return true;
    for (const PeImportFn& f : d.fns)
    {
        if (strstr(f.name.c_str(), filter))
            return true;
    }
    return false;
}

static void DrawImports(const PeFile* pe)
{
    ImGui::InputTextWithHint("##impf", I18nGet("welcome.window_filter"), g_imp_filter, (int)sizeof(g_imp_filter));
    ImGui::BeginChild("imp_list", ImVec2(SplitListW(&g_split_imp), 0.f), ImGuiChildFlags_Borders);
    if (pe->imports.empty())
        EmptyHint();
    int shown = 0;
    bool sel_visible = false;
    for (int i = 0; i < (int)pe->imports.size(); i++)
    {
        const PeImportDll& d = pe->imports[i];
        if (!ImportDllMatches(d, g_imp_filter))
            continue;
        shown++;
        ImGui::PushID(i);
        char lab[192];
        if (d.delay)
            snprintf(lab, sizeof(lab), "%s  [%s]", d.name.c_str(), I18nGet("pe.delay"));
        else
            snprintf(lab, sizeof(lab), "%s", d.name.c_str());
        if (ImGui::Selectable(lab, g_imp_sel == i))
        {
            g_imp_sel = i;
            char iid[32];
            snprintf(iid, sizeof(iid), "imp:%d", i);
            SelectionSet("import", iid, d.name.c_str(), nullptr, 0, 0);
        }
        if (g_imp_sel == i)
            sel_visible = true;
        ImGui::PopID();
    }
    if (!pe->imports.empty() && shown == 0)
        EmptyHint();
    ImGui::EndChild();
    SplitListHandle("imp_sp", &g_split_imp, "split.imports");
    ImGui::BeginChild("imp_prev", ImVec2(0.f, 0.f), ImGuiChildFlags_Borders);
    if (pe->imports.empty())
        EmptyHint();
    else
    {
        if (!sel_visible)
        {
            g_imp_sel = -1;
            for (int i = 0; i < (int)pe->imports.size(); i++)
            {
                if (!ImportDllMatches(pe->imports[i], g_imp_filter))
                    continue;
                g_imp_sel = i;
                break;
            }
        }
        if (g_imp_sel < 0 || g_imp_sel >= (int)pe->imports.size())
            EmptyHint();
        else
            DrawImportDll(pe, g_imp_sel);
    }
    ImGui::EndChild();
}

static void DrawExportRow(const PeExportFn& e, int i)
{
    ImGui::PushID(i);
    ImGui::TableNextRow();
    ImGui::TableNextColumn();
    char ord[16];
    snprintf(ord, sizeof(ord), "%u", e.ordinal);
    if (ImGui::Selectable(ord, g_exp_sel == i, ImGuiSelectableFlags_SpanAllColumns))
        g_exp_sel = i;
    ImGui::TableNextColumn();
    ImGui::TextUnformatted(e.name.empty() ? I18nGet("pe.export.ordinal") : e.name.c_str());
    ImGui::TableNextColumn();
    if (e.forwarded)
        ImGui::TextUnformatted(e.forwarder);
    else
        ImGui::Text("%08X", e.rva);
    ImGui::PopID();
}

static void DrawExports(const PeFile* pe)
{
    ImGui::InputTextWithHint("##expf", I18nGet("welcome.window_filter"), g_exp_filter, (int)sizeof(g_exp_filter));
    if (pe->exports.empty())
    {
        EmptyHint();
        return;
    }

    static std::vector<int> idx;
    static char last_filter[128];
    static char last_path[MAX_PATH];
    if (strcmp(last_path, pe->path) != 0 || strcmp(last_filter, g_exp_filter) != 0)
    {
        snprintf(last_path, sizeof(last_path), "%s", pe->path);
        snprintf(last_filter, sizeof(last_filter), "%s", g_exp_filter);
        idx.clear();
        for (int i = 0; i < (int)pe->exports.size(); i++)
        {
            const PeExportFn& e = pe->exports[i];
            if (!g_exp_filter[0] ||
                strstr(e.name.c_str(), g_exp_filter) ||
                strstr(e.forwarder, g_exp_filter))
                idx.push_back(i);
        }
    }
    if (idx.empty())
    {
        EmptyHint();
        return;
    }
    UiTableColDef exp_cols[] = {
        { "ordinal", I18nGet("pe.col.ordinal"), ImGuiTableColumnFlags_WidthFixed, 80.f },
        { "name", I18nGet("pe.field.name"), 0, 0.f },
        { "addr", I18nGet("pe.col.address"), 0, 88.f },
    };
    if (!UiBeginPersistTable("exports", exp_cols, 3,
        ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable))
        return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableHeadersRow();
    ImGuiListClipper clipper;
    clipper.Begin((int)idx.size());
    while (clipper.Step())
    {
        for (int n = clipper.DisplayStart; n < clipper.DisplayEnd; n++)
            DrawExportRow(pe->exports[idx[n]], idx[n]);
    }
    UiEndPersistTable();
}

static void DrawCom(PeFile* pe)
{
    ImGui::TextUnformatted(I18nGet("pe.com"));
    ImGui::Spacing();
    if (pe->clr_off)
    {
        ImGui::TextUnformatted(I18nGet("pe.clr_dotnet"));
        int maj = pe->clr_major;
        int minv = pe->clr_minor;
        if (ImGui::InputInt(I18nGet("pe.clr_major"), &maj))
        {
            pe->clr_major = (uint16_t)maj;
            PePatchClr();
            MarkDirt(DirtCom);
        }
        if (ImGui::InputInt(I18nGet("pe.clr_minor"), &minv))
        {
            pe->clr_minor = (uint16_t)minv;
            PePatchClr();
            MarkDirt(DirtCom);
        }
        bool il = (pe->clr_flags & 0x1) != 0;
        bool bit32 = (pe->clr_flags & 0x2) != 0;
        bool strong = (pe->clr_flags & 0x8) != 0;
        if (UiCheckbox("ilonly", I18nGet("pe.clr_ilonly"), &il))
        {
            if (il) pe->clr_flags |= 0x1; else pe->clr_flags &= ~0x1u;
            PePatchClr();
            MarkDirt(DirtCom);
        }
        if (UiCheckbox("bit32", I18nGet("pe.clr_32bit"), &bit32))
        {
            if (bit32) pe->clr_flags |= 0x2; else pe->clr_flags &= ~0x2u;
            PePatchClr();
            MarkDirt(DirtCom);
        }
        if (UiCheckbox("sn", I18nGet("pe.clr_strongname"), &strong))
        {
            if (strong) pe->clr_flags |= 0x8; else pe->clr_flags &= ~0x8u;
            PePatchClr();
            MarkDirt(DirtCom);
        }
        FieldU(I18nGet("pe.clr_entry_token"), pe->clr_entry, true);
    }
    else
        ImGui::TextUnformatted(I18nGet("pe.no_clr"));

    ImGui::Spacing();
    ImGui::TextUnformatted(I18nGet("pe.typelib"));
    if (pe->typelibs.empty())
        EmptyHint();
    for (int i = 0; i < (int)pe->typelibs.size(); i++)
    {
        PeTypelib& t = pe->typelibs[i];
        ImGui::PushID(i);
        Field(I18nGet("pe.field.name"), t.name);
        FieldU(I18nGet("pe.col.offset"), t.file_off, true);
        FieldU(I18nGet("pe.col.size"), t.size, false);
        if (t.msft)
        {
            int ver = (int)t.version;
            if (ImGui::InputInt(I18nGet("pe.tlib_ver"), &ver))
            {
                t.version = (uint32_t)ver;
                PePatchTypelib(i);
                MarkDirt(DirtCom);
            }
        }
        else
            ImGui::TextUnformatted(I18nGet("pe.tlib_raw"));
        ImGui::PopID();
        ImGui::Spacing();
    }
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    ImGui::TextWrapped("%s", I18nGet("pe.recompile_hint"));
    ImGui::PopStyleColor();
}

static void DrawVersion(PeFile* pe)
{
    if (pe->versions.empty())
    {
        ImGui::TextUnformatted(I18nGet("pe.no_version"));
        return;
    }
    ImGui::TextUnformatted(I18nGet("pe.version"));
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    ImGui::TextWrapped("%s", I18nGet("pe.version_hint"));
    ImGui::PopStyleColor();
    ImGui::Spacing();
    for (int vi = 0; vi < (int)pe->versions.size(); vi++)
    {
        PeVerInfo& v = pe->versions[vi];
        ImGui::PushID(vi);
        ImGui::SeparatorText(v.name);
        int f[4] = { v.file[0], v.file[1], v.file[2], v.file[3] };
        int p[4] = { v.prod[0], v.prod[1], v.prod[2], v.prod[3] };
        ImGui::SetNextItemWidth(280.f);
        if (ImGui::InputInt4(I18nGet("pe.file_ver"), f))
        {
            for (int i = 0; i < 4; i++)
                v.file[i] = (uint16_t)(f[i] < 0 ? 0 : f[i]);
            if (!PePatchVerFixed(vi))
                UiToastPush(UiToastWarning, I18nGet("toast.ver_fit.title"), I18nGet("toast.ver_fit.body"));
            else
                MarkDirt(DirtVer);
        }
        ImGui::SetNextItemWidth(280.f);
        if (ImGui::InputInt4(I18nGet("pe.prod_ver"), p))
        {
            for (int i = 0; i < 4; i++)
                v.prod[i] = (uint16_t)(p[i] < 0 ? 0 : p[i]);
            if (!PePatchVerFixed(vi))
                UiToastPush(UiToastWarning, I18nGet("toast.ver_fit.title"), I18nGet("toast.ver_fit.body"));
            else
                MarkDirt(DirtVer);
        }
        ImGui::Spacing();
        for (int si = 0; si < (int)v.strings.size(); si++)
        {
            PeVerString& s = v.strings[si];
            ImGui::PushID(si);
            ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x);
            ImGui::InputText(s.key, s.value, sizeof(s.value));
            if (ImGui::IsItemDeactivatedAfterEdit())
            {
                if (!PePatchVerString(vi, si, s.value))
                    UiToastPush(UiToastWarning, I18nGet("toast.ver_fit.title"), I18nGet("toast.ver_fit.body"));
                else
                    MarkDirt(DirtVer);
            }
            ImGui::PopID();
        }
        ImGui::PopID();
        ImGui::Spacing();
    }
}

static void DrawIcons(PeFile* pe)
{
    if (pe->icons.empty())
    {
        ImGui::TextUnformatted(I18nGet("pe.no_icons"));
        return;
    }
    ImGui::TextUnformatted(I18nGet("pe.icons"));
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    ImGui::TextWrapped("%s", I18nGet("pe.icon_hint"));
    ImGui::PopStyleColor();
    ImGui::Spacing();
    if (g_icon_sel < 0 || g_icon_sel >= (int)pe->icons.size())
        g_icon_sel = 0;

    int col = 0;
    for (int i = 0; i < (int)pe->icons.size(); i++)
    {
        const PeIconImg& ic = pe->icons[i];
        if (col && (col % 8) == 0)
            ;
        else if (col)
            ImGui::SameLine();
        ImGui::PushID(i);
        int tw = 0, th = 0;
        ID3D11ShaderResourceView* srv = IconPreview(ic, &tw, &th);
        ImVec2 sz(64.f, 64.f);
        bool hit = false;
        if (srv)
            hit = ImGui::ImageButton("ic", ImTextureRef((void*)srv), sz);
        else
            hit = ImGui::Button("?", sz);
        if (hit)
            g_icon_sel = i;
        if (g_icon_sel == i)
        {
            ImVec2 a = ImGui::GetItemRectMin();
            ImVec2 b = ImGui::GetItemRectMax();
            ImGui::GetWindowDrawList()->AddRect(a, b, ThemeColAccent(), 0.f, 0, 2.f);
        }
        ImGui::PopID();
        col++;
    }

    ImGui::Spacing();
    const PeIconImg& ic = pe->icons[g_icon_sel];
    char lab[80];
    snprintf(lab, sizeof(lab), "ICON %u  %dx%d  %d bpp  %u bytes", ic.id, ic.w, ic.h, ic.bpp, ic.size);
    ImGui::TextUnformatted(lab);
    FieldU(I18nGet("pe.col.offset"), ic.file_off, true);
    if (UiButton(I18nGet("pe.icon_export")))
    {
        char path[MAX_PATH];
        char sug[64];
        snprintf(sug, sizeof(sug), "icon_%u.ico", ic.id);
        if (AppPickSaveFilter(path, MAX_PATH, L"Icon\0*.ico\0All\0*.*\0", L"Export icon", sug))
        {
            if (PeExportIco(g_icon_sel, path))
                UiToastPush(UiToastSuccess, I18nGet("toast.icon_export.title"), I18nGet("toast.icon_export.body"));
            else
                UiToastPush(UiToastError, I18nGet("toast.export.fail.title"), I18nGet("toast.export.fail.body"));
        }
    }
    ImGui::SameLine();
    if (UiButton(I18nGet("pe.icon_replace")))
    {
        char path[MAX_PATH];
        if (AppPickOpenFilter(path, MAX_PATH, L"Icon\0*.ico;*.png\0All\0*.*\0", L"Replace icon"))
        {
            if (PeReplaceIco(g_icon_sel, path))
            {
                NukeIconTex();
                MarkDirt(DirtIco);
                UiToastPush(UiToastSuccess, I18nGet("toast.icon_replace.title"), I18nGet("toast.icon_replace.body"));
            }
            else
                UiToastPush(UiToastWarning, I18nGet("toast.icon_size.title"), I18nGet("toast.icon_size.body"));
        }
    }
}

static void DrawHex()
{
    HexViewDraw();
}

static const char* PatchStatusKey(const PatchOp& op, const uint8_t* cur, size_t n)
{
    if (op.kind == PatchKindSaveMarker)
        return "patch.status.save";
    if (!cur || (uint64_t)op.offset + op.after.size() > n)
        return "patch.status.unsaved";
    bool now_after = memcmp(cur + op.offset, op.after.data(), op.after.size()) == 0;
    PatchByteState st = PatchColor(op.offset, cur[op.offset]);
    if (now_after && st == PatchByteSaved)
        return "patch.status.saved";
    if (now_after && st == PatchByteUnsaved)
        return "patch.status.unsaved";
    if (st == PatchByteUnsaved)
        return "patch.status.unsaved";
    if (st == PatchByteSaved)
        return "patch.status.saved";
    return "patch.status.reverted";
}

static void DrawChanges()
{
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    ImGui::TextWrapped("%s", I18nGet("patch.hint"));
    ImGui::PopStyleColor();
    ImGui::Spacing();
    if (UiButton(I18nGet("patch.undo")) && PatchCanUndo())
    {
        PatchUndo();
        MarkDirt(DirtHex);
    }
    ImGui::SameLine();
    if (UiButton(I18nGet("patch.redo")) && PatchCanRedo())
    {
        PatchRedo();
        MarkDirt(DirtHex);
    }

    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
        !ImGui::GetIO().WantTextInput)
    {
        if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_Z, ImGuiInputFlags_RouteFocused) && PatchCanUndo())
        {
            PatchUndo();
            MarkDirt(DirtHex);
        }
        if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_Y, ImGuiInputFlags_RouteFocused) && PatchCanRedo())
        {
            PatchRedo();
            MarkDirt(DirtHex);
        }
    }

    const std::vector<PatchOp>& hist = PatchHistory();
    size_t n = 0;
    uint8_t* cur = PeJobBytes(&n);
    ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable |
        ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_HighlightHoveredColumn;
    ImVec2 sz(0.f, ImGui::GetContentRegionAvail().y);
    if (sz.y < ThemePx(120.f))
        sz.y = ThemePx(120.f);
    UiTableColDef patch_cols[] = {
        { "seq", I18nGet("patch.col.seq"), ImGuiTableColumnFlags_WidthFixed, 56.f },
        { "addr", I18nGet("patch.col.addr"), 0, 0.f },
        { "before", I18nGet("patch.col.before"), 0, 0.f },
        { "after", I18nGet("patch.col.after"), 0, 0.f },
        { "status", I18nGet("patch.col.status"), 0, 0.f },
        { "source", I18nGet("patch.col.source"), 0, 0.f },
    };
    if (!UiBeginPersistTable("patch_history", patch_cols, 6, flags, sz))
        return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableHeadersRow();

    for (int i = 0; i < (int)hist.size(); i++)
    {
        const PatchOp& op = hist[(size_t)i];
        ImGui::PushID(i);
        ImGui::TableNextRow(ImGuiTableRowFlags_None, ThemeRowH());
        ImGui::TableSetColumnIndex(0);
        char seq[16];
        snprintf(seq, sizeof(seq), "%llu", (unsigned long long)op.seq);
        bool sel = g_patch_row == i;
        if (ImGui::Selectable(seq, sel, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap,
            ImVec2(0.f, ThemeRowH() - ThemePx(4.f))))
            g_patch_row = i;
        if (ImGui::IsItemHovered())
            ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
        if (UiBeginPopupContextItem("pctx"))
        {
            if (op.kind == PatchKindBytes && ImGui::MenuItem(I18nGet("pe.analysis_hex")))
                GoHex(op.offset);
            char clip[256];
            if (op.kind == PatchKindBytes)
            {
                char ba[64], aa[64];
                PatchFmtBytes(op.before, ba, (int)sizeof(ba));
                PatchFmtBytes(op.after, aa, (int)sizeof(aa));
                if (op.rva)
                    snprintf(clip, sizeof(clip), "File 0x%X / RVA 0x%X: %s -> %s", op.offset, op.rva, ba, aa);
                else
                    snprintf(clip, sizeof(clip), "File 0x%X: %s -> %s", op.offset, ba, aa);
                if (ImGui::MenuItem(I18nGet("patch.copy")))
                    ImGui::SetClipboardText(clip);
            }
            if (op.kind == PatchKindBytes && PatchCanUndo() &&
                !PatchHistory().empty() && ImGui::MenuItem(I18nGet("patch.undo_op")))
            {
                if (PatchUndoSeq(op.seq))
                    MarkDirt(DirtHex);
            }
            UiEndPopup();
        }
        ImGui::TableSetColumnIndex(1);
        if (op.kind == PatchKindSaveMarker)
            ImGui::TextUnformatted(I18nGet("patch.status.save"));
        else if (op.rva)
            ImGui::Text("0x%X / RVA 0x%X", op.offset, op.rva);
        else
            ImGui::Text("0x%X", op.offset);
        ImGui::TableSetColumnIndex(2);
        if (op.kind == PatchKindBytes)
        {
            char ba[64];
            PatchFmtBytes(op.before, ba, (int)sizeof(ba));
            ImGui::TextUnformatted(ba);
        }
        ImGui::TableSetColumnIndex(3);
        if (op.kind == PatchKindBytes)
        {
            char aa[64];
            PatchFmtBytes(op.after, aa, (int)sizeof(aa));
            ImGui::TextUnformatted(aa);
        }
        ImGui::TableSetColumnIndex(4);
        ImGui::TextUnformatted(I18nGet(PatchStatusKey(op, cur, n)));
        ImGui::TableSetColumnIndex(5);
        if (op.kind == PatchKindBytes)
            ImGui::TextUnformatted(I18nGet(PatchSourceI18n(op.source)));
        if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0) && op.kind == PatchKindBytes)
            GoHex(op.offset);
        ImGui::PopID();
    }
    UiEndPersistTable();
}

static bool LeafIsImage(const PeRsrcLeaf& L)
{
    if (L.type_id == 1 || L.type_id == 2 || L.type_id == 3)
        return true;
    if (L.type_id == 12 || L.type_id == 14)
        return true;
    if (_stricmp(L.type_name, "ICON") == 0 || _stricmp(L.type_name, "CURSOR") == 0)
        return true;
    if (_stricmp(L.type_name, "BITMAP") == 0)
        return true;
    if (_stricmp(L.type_name, "GROUP_ICON") == 0 || _stricmp(L.type_name, "GROUP_CURSOR") == 0)
        return true;
    return false;
}

static bool LeafIsGroupImage(const PeRsrcLeaf& L)
{
    if (L.type_id == 12 || L.type_id == 14)
        return true;
    if (_stricmp(L.type_name, "GROUP_ICON") == 0 || _stricmp(L.type_name, "GROUP_CURSOR") == 0)
        return true;
    return false;
}

static void DrawRsrcImage(ID3D11ShaderResourceView* srv, float box)
{
    ImVec2 sz(box, box);
    if (srv)
        ImGui::Image(ImTextureRef((void*)srv), sz);
    else
        ImGui::Dummy(sz);
}

static void DrawRsrcPeek(PeFile* pe, const PeRsrcLeaf& L)
{
    Field(I18nGet("pe.col.type"), L.type_name, I18nGet("help.fld.rsrctype"));
    Field(I18nGet("pe.field.name"), L.name, I18nGet("help.fld.rsrcname"));
    FieldU(I18nGet("pe.col.lang"), L.lang, true, I18nGet("help.fld.rsrclang"));
    FieldU(I18nGet("pe.col.rva"), L.rva, true, I18nGet("help.fld.rsrcrva"));
    FieldU(I18nGet("pe.col.offset"), L.file_off, true, I18nGet("help.fld.rsrcoff"));
    FieldU(I18nGet("pe.col.size"), L.size, false, I18nGet("help.fld.rsrcsize"));

    const PeIconImg* ic = nullptr;
    for (int i = 0; i < (int)pe->icons.size(); i++)
    {
        if (pe->icons[i].file_off == L.file_off)
        {
            ic = &pe->icons[i];
            break;
        }
    }
    if (!ic && LeafIsImage(L) && !LeafIsGroupImage(L))
    {
        for (int i = 0; i < (int)pe->icons.size(); i++)
        {
            if (pe->icons[i].id == (uint16_t)L.name_id)
            {
                ic = &pe->icons[i];
                break;
            }
        }
    }
    if (ic)
    {
        ImGui::Spacing();
        int tw = 0, th = 0;
        DrawRsrcImage(IconPreview(*ic, &tw, &th), ThemePx(96.f));
        ImGui::Text("%dx%d  %d bpp", ic->w, ic->h, ic->bpp);
    }
    else if (LeafIsGroupImage(L) && !pe->icons.empty())
    {
        ImGui::Spacing();
        int shown = 0;
        for (int i = 0; i < (int)pe->icons.size(); i++)
        {
            const PeIconImg& img = pe->icons[i];
            if (L.lang && img.lang && img.lang != L.lang)
                continue;
            if (shown && (shown % 6) != 0)
                ImGui::SameLine();
            int tw = 0, th = 0;
            DrawRsrcImage(IconPreview(img, &tw, &th), ThemePx(48.f));
            shown++;
            if (shown >= 12)
                break;
        }
    }
    else if (LeafIsImage(L) || L.size >= 16)
    {
        int tw = 0, th = 0;
        ID3D11ShaderResourceView* srv = BytesPreview(L.file_off, L.size, &tw, &th);
        if (srv)
        {
            ImGui::Spacing();
            DrawRsrcImage(srv, ThemePx(96.f));
            if (tw > 0 && th > 0)
                ImGui::Text("%dx%d", tw, th);
        }
    }

    size_t n = 0;
    uint8_t* b = PeJobBytes(&n);
    if (!b || L.file_off >= n)
        return;
    ImGui::Spacing();
    ImGui::TextUnformatted(I18nGet("pe.rsrc_bytes"));
    char line[160];
    int p = 0;
    uint32_t room = (uint32_t)(n - L.file_off);
    uint32_t show = L.size < 24 ? L.size : 24;
    if (show > room)
        show = room;
    for (uint32_t i = 0; i < show && p < (int)sizeof(line) - 4; i++)
        p += snprintf(line + p, sizeof(line) - p, "%02X ", b[L.file_off + i]);
    if (ImFont* mono = ThemeFontMono())
        ImGui::PushFont(mono);
    ImGui::TextUnformatted(line);
    if (ThemeFontMono())
        ImGui::PopFont();
    if (UiButton(I18nGet("pe.rsrc_hex")))
        GoHex(L.file_off);
}

static void DrawRsrcFilters(const PeFile* pe)
{
    (void)pe;
    struct Filter
    {
        const char* id;
        const char* key;
        int kind;
        unsigned dirt;
    };
    const Filter fs[4] = {
        { "all", "pe.rsrc_all", 0, 0 },
        { "ver", "pe.version", 1, DirtVer },
        { "icons", "pe.icons", 2, DirtIco },
        { "com", "pe.com", 3, DirtCom },
    };
    float avail = ImGui::GetContentRegionAvail().x;
    float x = 0.f;
    for (int i = 0; i < 4; i++)
    {
        const char* lab = I18nGet(fs[i].key);
        bool dirty = fs[i].dirt && (g_dirt & fs[i].dirt) != 0;
        float w = ImGui::CalcTextSize(lab).x + 24.f;
        if (dirty)
            w += 12.f;
        if (i && x + w > avail)
            x = 0.f;
        else if (i)
        {
            ImGui::SameLine(0.f, ThemeSpaceXs());
            x += ThemeSpaceXs();
        }
        RsrcBtn(fs[i].id, lab, fs[i].kind, dirty, w);
        x += w;
    }
}

static int AnalysisRootForOff(const PeFile* pe, uint32_t off)
{
    if (!pe || !off)
        return -1;
    for (int i = 0; i < (int)pe->analysis.size(); i++)
    {
        if (pe->analysis[i].file_off == off)
            return i;
    }
    return -1;
}

static void DrawRsrc(PeFile* pe)
{
    if (g_rsrc_kind < 0 || g_rsrc_kind > 3)
        g_rsrc_kind = 0;
    DrawRsrcFilters(pe);

    int rows = 0;
    if (g_rsrc_kind == 1)
        rows = (int)pe->versions.size();
    else if (g_rsrc_kind == 2)
        rows = (int)pe->icons.size();
    else if (g_rsrc_kind == 3)
        rows = (pe->clr_off ? 1 : 0) + (int)pe->typelibs.size();
    else
        rows = (int)pe->rsrc.size();
    if (g_rsrc_row < 0 || g_rsrc_row >= rows)
        g_rsrc_row = 0;

    ImGui::BeginChild("rsrc_list", ImVec2(SplitListW(&g_split_rsrc), 0.f), ImGuiChildFlags_Borders);
    if (rows == 0)
        EmptyHint();
    for (int i = 0; i < rows; i++)
    {
        char lab[176];
        if (g_rsrc_kind == 1)
            snprintf(lab, sizeof(lab), "%s  %s", I18nGet("pe.rsrc.version"), pe->versions[i].name);
        else if (g_rsrc_kind == 2)
        {
            const PeIconImg& ic = pe->icons[i];
            snprintf(lab, sizeof(lab), "%s %u  %dx%d", I18nGet("pe.rsrc.icon"), ic.id, ic.w, ic.h);
        }
        else if (g_rsrc_kind == 3)
        {
            if (pe->clr_off && i == 0)
                snprintf(lab, sizeof(lab), "%s", I18nGet("pe.rsrc.clr"));
            else
            {
                int ti = i - (pe->clr_off ? 1 : 0);
                snprintf(lab, sizeof(lab), "%s  %s", I18nGet("pe.rsrc.typelib"), pe->typelibs[ti].name);
            }
        }
        else
        {
            const PeRsrcLeaf& L = pe->rsrc[i];
            snprintf(lab, sizeof(lab), "%s  %s", L.type_name, L.name);
        }
        ImGui::PushID(i);
        if (ImGui::Selectable(lab, g_rsrc_row == i))
        {
            g_rsrc_row = i;
            if (g_rsrc_kind == 2)
                g_icon_sel = i;
        }
        ImGui::PopID();
    }
    ImGui::EndChild();
    SplitListHandle("rsrc_sp", &g_split_rsrc, "split.resources");
    ImGui::BeginChild("rsrc_prev", ImVec2(0.f, 0.f), ImGuiChildFlags_Borders);
    if (g_rsrc_kind == 1)
        DrawVersion(pe);
    else if (g_rsrc_kind == 2)
        DrawIcons(pe);
    else if (g_rsrc_kind == 3)
        DrawCom(pe);
    else if (rows == 0)
        EmptyHint();
    else
    {
        const PeRsrcLeaf& L = pe->rsrc[g_rsrc_row];
        int ri = AnalysisRootForOff(pe, L.file_off);
        if (LeafIsImage(L))
            DrawRsrcPeek(pe, L);
        else if (ri >= 0)
        {
            g_an_root = ri;
            DrawArtifactBundle(pe, &pe->analysis[ri], true);
        }
        else
            DrawRsrcPeek(pe, L);
    }
    ImGui::EndChild();
}

static const char* RelocTypeName(uint8_t t)
{
    if (t == IMAGE_REL_BASED_ABSOLUTE) return "ABS";
    if (t == IMAGE_REL_BASED_HIGHLOW) return "HIGHLOW";
    if (t == IMAGE_REL_BASED_DIR64) return "DIR64";
    return "OTHER";
}

static void DrawRelocs(const PeFile* pe)
{
    FieldU(I18nGet("pe.reloc_blocks"), pe->relocs.size(), false, I18nGet("help.fld.relocs"));
    if (pe->relocs.empty())
    {
        EmptyHint();
        return;
    }
    if (g_reloc_sel < 0 || g_reloc_sel >= (int)pe->relocs.size())
        g_reloc_sel = 0;
    UiTableColDef relb_cols[] = {
        { "page_rva", I18nGet("pe.col.page_rva"), 0, 88.f },
        { "size", I18nGet("pe.col.size"), 0, 72.f },
        { "entries", I18nGet("pe.col.entries"), 0, 72.f },
        { "hl64", I18nGet("pe.col.hl64"), 0, 88.f },
    };
    if (UiBeginPersistTable("reloc_blocks", relb_cols, 4,
        ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
        ImVec2(-1.f, ThemePx(160.f))))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();
        for (int i = 0; i < (int)pe->relocs.size(); i++)
        {
            const PeRelocBlock& b = pe->relocs[i];
            ImGui::PushID(i);
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            char id[32];
            snprintf(id, sizeof(id), "%08X", b.page_rva);
            if (ImGui::Selectable(id, g_reloc_sel == i, ImGuiSelectableFlags_SpanAllColumns))
                g_reloc_sel = i;
            ImGui::TableNextColumn();
            ImGui::Text("%u", b.block_size);
            ImGui::TableNextColumn();
            ImGui::Text("%zu", b.entries.size());
            ImGui::TableNextColumn();
            ImGui::Text("%u / %u", b.type_highlow, b.type_dir64);
            ImGui::PopID();
        }
        UiEndPersistTable();
    }
    const PeRelocBlock& b = pe->relocs[g_reloc_sel];
    UiTableColDef rele_cols[] = {
        { "type", I18nGet("pe.col.type"), 0, 72.f },
        { "off", I18nGet("pe.col.off"), 0, 56.f },
        { "rva", I18nGet("pe.col.rva"), 0, 88.f },
        { "file", I18nGet("pe.col.file"), 0, 88.f },
    };
    if (UiBeginPersistTable("reloc_entries", rele_cols, 4,
        ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();
        int show = (int)b.entries.size();
        if (show > 4096)
            show = 4096;
        ImGuiListClipper clip;
        clip.Begin(show);
        while (clip.Step())
        {
            for (int i = clip.DisplayStart; i < clip.DisplayEnd; i++)
            {
                const PeRelocEntry& e = b.entries[i];
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(RelocTypeName(e.type));
                ImGui::TableNextColumn();
                ImGui::Text("%03X", e.offset);
                ImGui::TableNextColumn();
                ImGui::Text("%08X", e.rva);
                ImGui::TableNextColumn();
                ImGui::PushID(i);
                char off[16];
                snprintf(off, sizeof(off), "%08X", e.file_off);
                if (e.file_off)
                {
                    if (ImGui::Selectable(off, false))
                        GoHex(e.file_off);
                }
                else
                    ImGui::TextUnformatted(off);
                ImGui::PopID();
            }
        }
        UiEndPersistTable();
    }
}

static void DrawTls(const PeFile* pe)
{
    Field(I18nGet("pe.tls"), pe->tls.present ? I18nGet("pe.yes") : I18nGet("pe.no"), I18nGet("help.fld.tls"));
    if (!pe->tls.present)
        return;
    FieldU(I18nGet("pe.tls.start_raw"), pe->tls.start_raw, true);
    FieldU(I18nGet("pe.tls.end_raw"), pe->tls.end_raw, true);
    FieldU(I18nGet("pe.tls.index_va"), pe->tls.index_va, true);
    FieldU(I18nGet("pe.tls.callbacks_va"), pe->tls.callbacks_va, true);
    FieldU(I18nGet("pe.tls.zero_fill"), pe->tls.zero_fill, false);
    FieldU(I18nGet("pe.functions"), pe->tls.callback_rvas.size(), false);
    for (uint32_t i = 0; i < (uint32_t)pe->tls.callback_rvas.size(); i++)
    {
        uint32_t rva = pe->tls.callback_rvas[i];
        PeAddr a;
        PeAddrFromRva(pe, rva, &a);
        ImGui::PushID((int)i);
        char lab[48];
        snprintf(lab, sizeof(lab), "rva %08X", rva);
        if (ImGui::Selectable(lab, false) && a.valid)
            GoHex((uint32_t)a.file_off);
        ImGui::PopID();
    }
}

static void DrawDebug(const PeFile* pe)
{
    Field("PDB", pe->pdb_path[0] ? pe->pdb_path : I18nGet("pe.none"), I18nGet("help.fld.pdb"));
    if (pe->debug.empty())
    {
        EmptyHint();
        return;
    }
    UiTableColDef dbg_cols[] = {
        { "type", I18nGet("pe.col.type"), 0, 0.f },
        { "time", I18nGet("pe.col.time"), 0, 88.f },
        { "size", I18nGet("pe.col.size"), 0, 72.f },
        { "file", I18nGet("pe.col.file"), 0, 88.f },
        { "extra", I18nGet("pe.col.extra"), 0, 0.f },
    };
    if (UiBeginPersistTable("debug", dbg_cols, 5,
        ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();
        for (const PeDebugEntry& e : pe->debug)
        {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(e.type_name);
            ImGui::TableNextColumn();
            ImGui::Text("%08X", e.timestamp);
            ImGui::TableNextColumn();
            ImGui::Text("%u", e.size);
            ImGui::TableNextColumn();
            ImGui::Text("%08X", e.file_off);
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(e.extra);
        }
        UiEndPersistTable();
    }
}

static void DrawEntropy(const PeFile* pe)
{
    if (pe->entropy.empty())
    {
        EmptyHint();
        return;
    }
    UiTableColDef ent_cols[] = {
        { "range", I18nGet("pe.range"), 0, 0.f },
        { "offset", I18nGet("pe.col.offset"), 0, 88.f },
        { "size", I18nGet("pe.col.size"), 0, 72.f },
        { "entropy", I18nGet("pe.entropy"), 0, 72.f },
    };
    if (UiBeginPersistTable("entropy", ent_cols, 4,
        ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();
        for (const PeEntropyRange& r : pe->entropy)
        {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(r.label);
            ImGui::TableNextColumn();
            ImGui::Text("%llX", (unsigned long long)r.offset);
            ImGui::TableNextColumn();
            ImGui::Text("%llu", (unsigned long long)r.size);
            ImGui::TableNextColumn();
            ImGui::Text("%.3f", r.entropy);
        }
        UiEndPersistTable();
    }
}

static void DrawStrings(const PeFile* pe)
{
    ImGui::InputTextWithHint("##sf", I18nGet("welcome.window_filter"), g_str_filter, (int)sizeof(g_str_filter));
    if (pe->strings.empty())
    {
        EmptyHint();
        return;
    }
    UiTableColDef str_cols[] = {
        { "off", I18nGet("pe.col.off"), ImGuiTableColumnFlags_WidthFixed, 88.f },
        { "enc", I18nGet("pe.col.enc"), ImGuiTableColumnFlags_WidthFixed, 44.f },
        { "text", I18nGet("pe.col.text"), 0, 0.f },
    };
    if (UiBeginPersistTable("strings", str_cols, 3,
        ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();
        int shown = 0;
        auto draw_str_row = [&](int i)
        {
            const PeStringEntry& s = pe->strings[i];
            ImGui::PushID(i);
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            char id[32];
            snprintf(id, sizeof(id), "%llX", (unsigned long long)s.file_off);
            if (ImGui::Selectable(id, false, ImGuiSelectableFlags_SpanAllColumns))
                GoHex((uint32_t)s.file_off);
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(s.utf16 ? I18nGet("pe.str_enc_u16") : I18nGet("pe.str_enc_ascii"));
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(s.text.c_str());
            ImGui::PopID();
        };
        if (!g_str_filter[0])
        {
            int n = (int)pe->strings.size();
            if (n > 4000)
                n = 4000;
            shown = n;
            ImGuiListClipper clip;
            clip.Begin(n);
            while (clip.Step())
            {
                for (int i = clip.DisplayStart; i < clip.DisplayEnd; i++)
                    draw_str_row(i);
            }
        }
        else
        {
            for (int i = 0; i < (int)pe->strings.size(); i++)
            {
                if (!strstr(pe->strings[i].text.c_str(), g_str_filter))
                    continue;
                draw_str_row(i);
                if (++shown >= 4000)
                    break;
            }
        }
        UiEndPersistTable();
        if (shown == 0)
            EmptyHint();
    }
}

static void DrawTree(const PeFile* pe)
{
    Node("headers", I18nGet("pe.headers"), IconCpu, true, false);
    Node("sections", I18nGet("pe.sections"), IconBox, true, false);
    Node("imports", I18nGet("pe.imports"), IconImport, true, false);
    Node("exports", I18nGet("pe.exports"), IconExport, true, false);
    if (!pe->relocs.empty())
        Node("relocs", I18nGet("pe.relocs"), IconGo, true, false);
    if (pe->tls.present)
        Node("tls", I18nGet("pe.tls"), IconShield, true, false);
    if (!pe->debug.empty())
        Node("debug", I18nGet("pe.debug"), IconSearch, true, false);
    if (pe->has_resource || pe->has_com || !pe->typelibs.empty() || !pe->versions.empty() || !pe->icons.empty())
    {
        bool rdirty = (g_dirt & (DirtVer | DirtIco | DirtCom)) != 0;
        Node("rsrc", I18nGet("pe.resources"), IconFolder, true, rdirty);
    }
    if (pe->overlay_size)
        Node("overlay", I18nGet("pe.tree.overlay"), IconFile, true, false);
}

static bool PaneDirty()
{
    if (strcmp(g_sel, "hex") == 0)
        return (g_dirt & DirtHex) != 0;
    if (strcmp(g_sel, "changes") == 0)
        return (g_dirt & DirtHex) != 0;
    if (strcmp(g_sel, "rsrc") == 0)
    {
        if (g_rsrc_kind == 1) return (g_dirt & DirtVer) != 0;
        if (g_rsrc_kind == 2) return (g_dirt & DirtIco) != 0;
        if (g_rsrc_kind == 3) return (g_dirt & DirtCom) != 0;
        return (g_dirt & (DirtVer | DirtIco | DirtCom)) != 0;
    }
    return false;
}

static void TickSave()
{
    if (!g_save_phase)
        return;
    if (g_save_phase == 3)
        return;
    g_save_t += ImGui::GetIO().DeltaTime;
    if (g_save_phase == 1)
    {
        if (g_save_t > 0.32f && g_con_n < 2)
            ConLog(I18nGet("save.log_image"));
        if (g_save_t > 0.68f && !g_save_wrote)
        {
            PeSaveStatus st = PeJobSaveEx(g_save_dst, g_save_skip_backup);
            g_save_wrote = true;
            if (st == PeSaveBackupFailed)
            {
                ConLog(I18nGet("pe.backup_fail"));
                g_save_ok = false;
                g_save_phase = 3;
                g_save_t = 0.f;
                return;
            }
            g_save_ok = (st == PeSaveOk);
            if (g_save_ok && PeJobBackupPath()[0])
            {
                char line[192];
                snprintf(line, sizeof(line), "%s  %s", I18nGet("pe.backup_ok"), FileNameOf(PeJobBackupPath()));
                ConLog(line);
            }
            ConLog(g_save_ok ? I18nGet("save.log_flush") : I18nGet("pe.save_fail"));
        }
        if (g_save_t > 1.12f && g_save_wrote)
        {
            char sum[192];
            if (g_save_ok)
            {
                snprintf(sum, sizeof(sum), "%s  %s", I18nGet("save.summary_ok"), FileNameOf(g_save_dst));
                g_dirt = 0;
                HexViewOnSaved();
                char backup_body[160];
                if (PeJobBackupPath()[0])
                    snprintf(backup_body, sizeof(backup_body), "%s %s",
                        I18nGet("toast.save.success.body"), FileNameOf(PeJobBackupPath()));
                else
                    snprintf(backup_body, sizeof(backup_body), "%s", I18nGet("toast.save.success.body"));
                UiToastPush(UiToastSuccess, I18nGet("toast.save.success.title"), backup_body);
            }
            else
            {
                snprintf(sum, sizeof(sum), "%s", I18nGet("save.summary_fail"));
                UiToastPush(UiToastError, I18nGet("toast.save.fail.title"), I18nGet("toast.save.fail.body"));
            }
            ConLog(sum);
            g_save_phase = 2;
            g_save_t = 0.f;
        }
    }
    else if (g_save_phase == 2 && g_save_t > 2.6f)
        g_save_phase = 0;
}

static void DrawSaveOverlay()
{
    if (!g_save_phase)
        return;
    ImVec2 wp = ImGui::GetWindowPos();
    ImVec2 ws = ImGui::GetWindowSize();
    ImDrawList* dl = ImGui::GetForegroundDrawList();
    float dim_t = 1.f;
    if (UiAnimEnabled() && g_save_phase != 3)
    {
        if (g_save_phase == 1)
            dim_t = UiEaseOut(g_save_t / 0.25f);
        else if (g_save_t > 2.1f)
            dim_t = 1.f - UiEaseOut((g_save_t - 2.1f) / 0.5f);
        if (dim_t < 0.f)
            dim_t = 0.f;
        if (dim_t > 1.f)
            dim_t = 1.f;
    }
    dl->AddRectFilled(wp, ImVec2(wp.x + ws.x, wp.y + ws.y), ThemeColBgA(0.82f * dim_t));
    ImGui::SetNextWindowPos(wp);
    ImGui::SetNextWindowSize(ws);
    ImGui::Begin("##saveov", nullptr,
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoBackground |
        ImGuiWindowFlags_NoNav);

    if (g_save_phase == 3)
    {
        ImVec2 avail = ImGui::GetContentRegionAvail();
        ImGui::SetCursorPos(ImVec2(avail.x * 0.18f, avail.y * 0.32f));
        ImGui::BeginChild("##bakfail", ImVec2(avail.x * 0.64f, ThemePx(180.f)), ImGuiChildFlags_None);
        ImGui::TextWrapped("%s", I18nGet("pe.backup_fail_detail"));
        ImGui::Spacing();
        if (UiButton(I18nGet("pe.save_anyway"), ImVec2(0, 0), 1))
        {
            g_save_skip_backup = true;
            g_save_phase = 1;
            g_save_t = 0.60f;
            g_save_wrote = false;
            ConLog(I18nGet("pe.save_anyway"));
        }
        ImGui::SameLine();
        if (UiButton(I18nGet("pe.save_cancel")))
            g_save_phase = 0;
        ImGui::EndChild();
        ImGui::End();
        return;
    }

    ImGui::Dummy(ImGui::GetContentRegionAvail());

    ImVec2 c(wp.x + ws.x * 0.5f, wp.y + ws.y * 0.36f);
    const float rad = 56.f * (0.82f + 0.18f * dim_t);
    UiSpinner(c, rad, g_save_phase == 1 ? -1.f : 1.f);

    float ch = ws.y * 0.26f;
    if (ch < 100.f)
        ch = 100.f;
    ImVec2 ca(wp.x + 28.f, wp.y + ws.y - ch - 18.f);
    ImVec2 cb(wp.x + ws.x - 28.f, wp.y + ws.y - 18.f);
    dl->AddRectFilled(ca, cb, ThemeColBgA(0.42f));
    dl->AddRect(ca, cb, ThemeColBorderA(0.55f));
    float y = ca.y + 10.f;
    for (int i = 0; i < g_con_n; i++)
    {
        bool last = (i == g_con_n - 1);
        ImU32 col = last && g_save_phase == 2 ? ThemeColFg() : ThemeColFgA(0.38f);
        dl->AddText(ImVec2(ca.x + 14.f, y), col, g_con[i]);
        y += ImGui::GetFontSize() + 4.f;
    }
    ImGui::End();
}

static void FillTree()
{
    static bool logged_busy;
    if (PeJobBusy())
    {
        if (!logged_busy)
        {
            LogInfo(LogBuiltinAnalyzer, "%s", I18nGet("pe.analyzing"));
            logged_busy = true;
        }
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
        ImGui::TextUnformatted(I18nGet("pe.analyzing"));
        ImGui::PopStyleColor();
        return;
    }
    logged_busy = false;
    if (PeJobFailed())
    {
        ImGui::TextUnformatted(I18nGet("pe.fail"));
        if (PeJobError()[0])
        {
            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
            ImGui::TextWrapped("%s", PeJobError());
            ImGui::PopStyleColor();
        }
        return;
    }
    const PeFile* pe = PeJobResult();
    if (!pe)
        return;
    static char seen[MAX_PATH];
    if (strcmp(seen, pe->path) != 0)
    {
        snprintf(seen, sizeof(seen), "%s", pe->path);
        snprintf(g_sel, sizeof(g_sel), "overview");
        g_icon_sel = 0;
        g_sec_sel = 0;
        g_imp_sel = 0;
        g_exp_sel = 0;
        g_reloc_sel = 0;
        g_rsrc_row = 0;
        g_imp_filter[0] = 0;
        g_exp_filter[0] = 0;
        g_str_filter[0] = 0;
        g_dirt = 0;
        g_rsrc_kind = 0;
        g_an_root = 0;
        g_an_child = -1;
        g_an_grand = -1;
        size_t bn = 0;
        const uint8_t* bb = PeJobBytes(&bn);
        HexViewOpen(bb, bn);
        NukeIconTex();
        LogSuccess(LogBuiltinAnalyzer, "Opened %s", FileNameOf(pe->path));
        g_sel_bar_y = -1.f;
    }
    DrawTree(pe);
    if (g_sel_bar_y >= 0.f)
    {
        ImDrawList* dl = ImGui::GetWindowDrawList();
        ImVec2 a(g_sel_bar_x0, g_sel_bar_y);
        ImVec2 b(g_sel_bar_x1, g_sel_bar_y + g_sel_bar_h);
        dl->AddRectFilled(a, b, ThemeColAccentA(22.f / 255.f));
        UiAccentBar(a, b, 1.f, dl);
    }
}

static void FillCons()
{
    ConsoleViewDraw();
}

static bool DrawJobGate()
{
    if (PeJobBusy())
    {
        ImVec2 avail = ImGui::GetContentRegionAvail();
        ImVec2 c(ImGui::GetCursorScreenPos().x + avail.x * 0.5f,
            ImGui::GetCursorScreenPos().y + (avail.y > 8.f ? avail.y * 0.42f : ThemePx(40.f)));
        float p = PeJobProgress();
        UiSpinner(c, ThemePx(28.f), p);
        const char* msg = I18nGet("pe.analyzing");
        ImVec2 ts = ImGui::CalcTextSize(msg);
        ImDrawList* dl = ImGui::GetWindowDrawList();
        dl->AddText(ImVec2(c.x - ts.x * 0.5f, c.y + ThemePx(40.f)), ThemeColMuted(), msg);
        return false;
    }
    if (PeJobFailed())
    {
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColAccent()));
        ImGui::TextWrapped("%s", PeJobError()[0] ? PeJobError() : I18nGet("pe.fail"));
        ImGui::PopStyleColor();
        return false;
    }
    return PeJobResult() != nullptr;
}

static void DrawWsNavigator()
{
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(ThemeSpaceSm(), ThemeSpaceSm()));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(ThemePx(10.f), ThemeSpaceXs()));
    FillTree();
    ImGui::PopStyleVar(2);
}

static void DrawWsOverview()
{
    if (!DrawJobGate())
        return;
    DrawOverview(PeJobResult());
}

static void DrawWsHex()
{
    if (!DrawJobGate())
        return;
    DrawHex();
}

static void DrawWsFindings()
{
    if (!DrawJobGate())
        return;
    DrawFindings(PeJobResult());
}

static void DrawWsDetection()
{
    if (!DrawJobGate())
        return;
    DrawDetection(PeJobResult());
}

static void DrawWsNamed()
{
    if (!DrawJobGate())
        return;
    const char* id = WorkspaceCurrentId();
    PeFile* pe = PeJobResultMut();
    if (!pe)
        return;
    if (strcmp(id, "view.headers") == 0) { DrawHeaders(pe); return; }
    if (strcmp(id, "view.sections") == 0) { DrawSections(pe); return; }
    if (strcmp(id, "view.imports") == 0) { DrawImports(pe); return; }
    if (strcmp(id, "view.exports") == 0) { DrawExports(pe); return; }
    if (strcmp(id, "view.relocs") == 0) { DrawRelocs(pe); return; }
    if (strcmp(id, "view.tls") == 0) { DrawTls(pe); return; }
    if (strcmp(id, "view.debug") == 0) { DrawDebug(pe); return; }
    if (strcmp(id, "view.entropy") == 0) { DrawEntropy(pe); return; }
    if (strcmp(id, "view.strings") == 0) { DrawStrings(pe); return; }
    if (strcmp(id, "view.analysis") == 0) { DrawAnalysis(pe); return; }
    if (strcmp(id, "view.resources") == 0) { DrawRsrc(pe); return; }
    if (strcmp(id, "view.overlay") == 0)
    {
        FieldU(I18nGet("pe.col.offset"), pe->overlay_off, true, I18nGet("help.fld.rsrcoff"));
        FieldU(I18nGet("pe.col.size"), pe->overlay_size, false, I18nGet("help.fld.overlay"));
        return;
    }
    if (strcmp(id, "panel.patch_history") == 0)
        DrawChanges();
}

static void DrawWsConsole()
{
    FillCons();
}

static void DrawWsPlugin()
{
    if (!DrawJobGate())
        return;
    PluginDrawView(WorkspaceCurrentId());
}

static void DrawWsProperties()
{
    const Selection& s = SelectionGet();
    if (!s.kind[0])
    {
        UiEmpty(I18nGet("panel.properties.empty"), I18nGet("panel.properties.empty_hint"));
        return;
    }
    const PeFile* pe = PeJobResult();
    UiSection(I18nGet("panel.properties"));
    if (pe && strcmp(s.kind, "section") == 0)
    {
        int i = g_sec_sel;
        if (strncmp(s.id, "sec:", 4) == 0)
            i = atoi(s.id + 4);
        DrawSection(pe, i);
        return;
    }
    if (pe && strcmp(s.kind, "import") == 0)
    {
        int i = g_imp_sel;
        if (strncmp(s.id, "imp:", 4) == 0)
            i = atoi(s.id + 4);
        DrawImportDll(pe, i);
        return;
    }
    ImGui::TextUnformatted(s.title[0] ? s.title : s.id);
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    ImGui::TextUnformatted(s.kind);
    if (s.id[0] && strcmp(s.id, s.title) != 0)
        ImGui::TextUnformatted(s.id);
    ImGui::PopStyleColor();
    if (s.off)
        FieldU(I18nGet("pe.col.offset"), s.off, true, I18nGet("help.fld.rsrcoff"));
    if (s.size)
        FieldU(I18nGet("pe.col.size"), s.size, false, nullptr);
    size_t hoff = 0, hn = 0;
    if (HexViewCursor(&hoff, &hn) && hn)
        FieldU(I18nGet("pe.hex"), (uint64_t)hoff, true, nullptr);
}

static void DrawWsEvidence()
{
    const Selection& s = SelectionGet();
    bool known = strcmp(s.kind, "finding") == 0 || strcmp(s.kind, "detection") == 0 ||
        strcmp(s.kind, "resource") == 0 || strcmp(s.kind, "artifact") == 0;
    if (!s.body[0] && !known)
    {
        UiEmpty(I18nGet("panel.evidence.empty"), I18nGet("panel.evidence.empty_hint"));
        return;
    }
    UiSection(I18nGet("panel.evidence"));
    if (s.body[0])
        ImGui::TextWrapped("%s", s.body);
    else if (s.title[0] && (strcmp(s.kind, "resource") == 0 || strcmp(s.kind, "artifact") == 0))
        ImGui::TextWrapped("%s", s.title);
    const PeFile* pe = PeJobResult();
    if (pe && strcmp(s.kind, "finding") == 0 && g_find_sel >= 0 &&
        g_find_sel < (int)pe->report.findings.size())
    {
        const FindingItem& f = pe->report.findings[(size_t)g_find_sel];
        if (f.evidence_text[0] && strcmp(f.evidence_text, s.body) != 0)
        {
            ImGui::Spacing();
            ImGui::TextWrapped("%s", f.evidence_text);
        }
        if (f.file_off && UiButton(I18nGet("finding.action.open_hex")))
            NavOpenInHex(f.file_off);
    }
    if (pe && strcmp(s.kind, "detection") == 0)
    {
        for (const DetectionResult& r : pe->detections)
        {
            if (r.product_key != s.id && r.product != s.title)
                continue;
            for (const DetectEvidence& e : r.evidence)
            {
                ImGui::BulletText("%s", e.detail.empty() ? e.condition.c_str() : e.detail.c_str());
            }
            break;
        }
    }
}

static bool DirtyHex()
{
    return PaneDirty();
}

static void EnsureViews()
{
    static bool core;
    if (!core)
    {
        core = true;
        auto add = [](const char* id, const char* key, int icon, WsRegion region, bool util,
            bool open, WsMenu menu, float mw, float mh, void (*draw)(), bool (*dirty)() = nullptr)
        {
            WsDesc d{};
            d.id = id;
            d.title_key = key;
            d.icon = icon;
            d.def_region = region;
            d.utility = util;
            d.closable = true;
            d.default_open = open;
            d.menu = menu;
            d.min_w = mw;
            d.min_h = mh;
            d.draw = draw;
            d.dirty = dirty;
            WorkspaceRegister(d);
        };

        add("panel.navigator", "view.navigator", IconTree, WsLeft, true, true, WsMenuPanel, 180.f, 0.f, DrawWsNavigator);
        add("view.overview", "pe.overview", IconFile, WsCenter, false, true, WsMenuView, 280.f, 0.f, DrawWsOverview);
        add("view.hex", "pe.hex", IconHex, WsCenter, false, true, WsMenuView, 280.f, 0.f, DrawWsHex, DirtyHex);
        add("view.findings", "pe.findings", IconEye, WsCenter, false, false, WsMenuView, 280.f, 0.f, DrawWsFindings);
        add("view.detection", "detect.title", IconShield, WsCenter, false, false, WsMenuView, 280.f, 0.f, DrawWsDetection);
        add("view.resources", "pe.resources", IconFolder, WsCenter, false, false, WsMenuView, 280.f, 0.f, DrawWsNamed);
        add("view.analysis", "view.analysis", IconSearch, WsCenter, false, false, WsMenuView, 280.f, 0.f, DrawWsNamed);
        add("view.strings", "pe.strings", IconEdit, WsCenter, false, false, WsMenuView, 280.f, 0.f, DrawWsNamed);
        add("view.entropy", "pe.entropy", IconCpu, WsCenter, false, false, WsMenuView, 280.f, 0.f, DrawWsNamed);
        add("view.headers", "pe.headers", IconCpu, WsCenter, false, false, WsMenuNone, 280.f, 0.f, DrawWsNamed);
        add("view.sections", "pe.sections", IconBox, WsCenter, false, false, WsMenuNone, 280.f, 0.f, DrawWsNamed);
        add("view.imports", "pe.imports", IconImport, WsCenter, false, false, WsMenuNone, 280.f, 0.f, DrawWsNamed);
        add("view.exports", "pe.exports", IconExport, WsCenter, false, false, WsMenuNone, 280.f, 0.f, DrawWsNamed);
        add("view.relocs", "pe.relocs", IconGo, WsCenter, false, false, WsMenuNone, 280.f, 0.f, DrawWsNamed);
        add("view.tls", "pe.tls", IconShield, WsCenter, false, false, WsMenuNone, 280.f, 0.f, DrawWsNamed);
        add("view.debug", "pe.debug", IconSearch, WsCenter, false, false, WsMenuNone, 280.f, 0.f, DrawWsNamed);
        add("view.overlay", "pe.tree.overlay", IconFile, WsCenter, false, false, WsMenuNone, 280.f, 0.f, DrawWsNamed);
        add("panel.properties", "panel.properties", IconInfo, WsRight, true, true, WsMenuPanel, 220.f, 0.f, DrawWsProperties);
        add("panel.evidence", "panel.evidence", IconSearch, WsRight, true, true, WsMenuPanel, 220.f, 0.f, DrawWsEvidence);
        add("panel.console", "view.console", IconEdit, WsBottom, true, true, WsMenuPanel, 0.f, 96.f, DrawWsConsole);
        add("panel.patch_history", "panel.patch_history", IconEdit, WsBottom, true, false, WsMenuPanel, 0.f, 96.f, DrawWsNamed, DirtyHex);
    }

    int pv = PluginViewCount();
    for (int i = 0; i < pv; i++)
    {
        char id[32];
        PluginViewSelId(i, id, (int)sizeof(id));
        WsDesc d{};
        d.id = id;
        d.title_lit = PluginViewLabel(i);
        d.icon = IconSearch;
            d.def_region = (WsRegion)PluginViewRegion(i);
            d.closable = true;
            d.default_open = PluginViewDefaultOpen(i) ? true : false;
            d.utility = PluginViewUtility(i) ? true : false;
            d.menu = (WsMenu)PluginViewMenuGroup(i);
            d.min_w = PluginViewMinW(i);
            d.min_h = PluginViewMinH(i);
        d.draw = DrawWsPlugin;
        WorkspaceRegister(d);
    }
}

static const char* SelCaption()
{
    if (strcmp(g_sel, "overview") == 0) return I18nGet("pe.overview");
    if (strcmp(g_sel, "headers") == 0) return I18nGet("pe.headers");
    if (strcmp(g_sel, "hex") == 0) return I18nGet("pe.hex");
    if (strcmp(g_sel, "changes") == 0) return I18nGet("patch.title");
    if (PluginSelIsView(g_sel)) return PluginViewLabel(atoi(g_sel + 6));
    if (strcmp(g_sel, "rsrc") == 0) return I18nGet("pe.resources");
    if (strcmp(g_sel, "imports") == 0) return I18nGet("pe.imports");
    if (strcmp(g_sel, "exports") == 0) return I18nGet("pe.exports");
    if (strcmp(g_sel, "relocs") == 0) return I18nGet("pe.relocs");
    if (strcmp(g_sel, "tls") == 0) return I18nGet("pe.tls");
    if (strcmp(g_sel, "debug") == 0) return I18nGet("pe.debug");
    if (strcmp(g_sel, "entropy") == 0) return I18nGet("pe.entropy");
    if (strcmp(g_sel, "strings") == 0) return I18nGet("pe.strings");
    if (strcmp(g_sel, "detection") == 0) return I18nGet("detect.title");
    if (strcmp(g_sel, "analysis") == 0) return I18nGet("engine.results");
    if (strcmp(g_sel, "findings") == 0) return I18nGet("pe.findings");
    return g_sel;
}

static void DrawStatusBar()
{
    ImVec2 p0 = ImGui::GetCursorScreenPos();
    float w = ImGui::GetContentRegionAvail().x;
    float h = ImGui::GetFrameHeight();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(p0, ImVec2(p0.x + w, p0.y + h), ThemeColBg());
    dl->AddLine(p0, ImVec2(p0.x + w, p0.y), ThemeColBorder());
    ImGui::BeginChild("statusbar", ImVec2(w, h), ImGuiChildFlags_None,
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

    if (ImFont* sm = ThemeFontSmall())
        ImGui::PushFont(sm);

    bool busy = PeJobBusy();
    const char* path = PeJobPath();
    if (busy)
        ImGui::TextUnformatted(I18nGet("status.analyzing"));
    else if (PeJobFailed())
        ImGui::TextUnformatted(I18nGet("pe.fail"));
    else if (path[0])
    {
        ImGui::TextUnformatted(FileNameOf(path));
        ImGui::SameLine(0.f, 0.f);
        ImGui::TextDisabled("  ·  %s", SelCaption());
        size_t hoff = 0, hn = 0;
        uint32_t soff = SelectionGet().off;
        if (HexViewCursor(&hoff, &hn) && hn)
        {
            ImGui::SameLine(0.f, 0.f);
            ImGui::TextDisabled("  ·  0x%llX", (unsigned long long)hoff);
        }
        else if (soff)
        {
            ImGui::SameLine(0.f, 0.f);
            ImGui::TextDisabled("  ·  0x%X", soff);
        }
        if (PeJobDirty() || g_dirt)
        {
            ImGui::SameLine(0.f, 0.f);
            ImGui::TextDisabled("  ·  ");
            ImGui::SameLine(0.f, 0.f);
            ImGui::TextUnformatted(I18nGet("status.dirty"));
        }
    }
    else
        ImGui::TextDisabled("%s", I18nGet("status.ready"));

    if (ThemeFontSmall())
        ImGui::PopFont();
    ImGui::EndChild();
}

void InspectorDraw()
{
    TickSave();
    LoadViewLayout();
    EnsureViews();
    if (!g_save_phase)
    {
        if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_O))
        {
            char path[MAX_PATH];
            if (AppPickOpenPe(path, MAX_PATH))
                AppOpenPath(path);
        }
        if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_S) && PeJobResult())
            DoSave(false);
        if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_S) && PeJobResult())
            DoSave(true);
    }

    DrawMenubar();

    ImVec2 av = ImGui::GetContentRegionAvail();
    float status_h = ImGui::GetFrameHeight();
    av.y -= status_h;
    if (av.y < ThemePx(80.f))
        av.y = ThemePx(80.f);

    WorkspaceDraw(ImVec2(av.x, av.y));
    WorkspaceTickSave();

    DrawStatusBar();
    DrawSaveOverlay();
}
