#include "app/inspector.h"
#include "app/app.h"
#include "pe/pe.h"
#include "ui/theme.h"
#include "ui/icons.h"
#include "ui/widgets.h"
#include "ui/tex.h"
#include "i18n/i18n.h"
#include "persist/settings.h"

#include "imgui.h"
// credit: https://github.com/ocornut/imgui_club
#include "imgui_memory_editor.h"

#include <windows.h>
#include <d3d11.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <math.h>
#include <vector>

static char g_sel[96] = "overview";
static char g_save_msg[160];
static MemoryEditor g_hex;
static bool g_hex_primed;
static size_t g_hex_goto = (size_t)-1;
static int g_icon_sel = 0;
static unsigned g_dirt;
static int g_rsrc_kind; // 0 all, 1 version, 2 icons, 3 com
static int g_rsrc_row;
static int g_save_phase; // 0 idle, 1 spinning, 2 summary
static float g_save_t;
static bool g_save_wrote;
static bool g_save_ok;
static char g_save_dst[MAX_PATH];
static char g_con[14][192];
static int g_con_n;

enum
{
    DockLeft = 0,
    DockRight = 1,
    DockTop = 2,
    DockBottom = 3,
};

static bool  g_tree_on = true;
static bool  g_cons_on = true;
static int   g_tree_dock = DockLeft;
static int   g_cons_dock = DockBottom;
static float g_tree_sz = 248.f;
static float g_cons_sz = 148.f;
static int   g_tree_pri = 1;
static int   g_cons_pri = 0;

static char g_ulog[96][220];
static int  g_ulog_i;
static int  g_ulog_n;
static float g_sel_bar_y = -1.f;
static float g_sel_bar_h;
static float g_sel_bar_x0;
static float g_sel_bar_x1;

static void UiLog(const char* fmt, ...)
{
    if (!fmt)
        return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_ulog[g_ulog_i], 220, fmt, ap);
    va_end(ap);
    g_ulog_i = (g_ulog_i + 1) % 96;
    if (g_ulog_n < 96)
        g_ulog_n++;
}

static void LoadViewLayout()
{
    static bool once;
    if (once)
        return;
    once = true;
    g_tree_on = SettingsGetBool("view.tree", true);
    g_cons_on = SettingsGetBool("view.console", true);
    g_tree_dock = SettingsGetInt("view.tree_dock", DockLeft);
    g_cons_dock = SettingsGetInt("view.console_dock", DockBottom);
    int tw = SettingsGetInt("view.tree_w", 248);
    int ch = SettingsGetInt("view.console_h", 148);
    g_tree_sz = tw < 160 ? 160.f : (float)tw;
    g_cons_sz = ch < 72 ? 72.f : (float)ch;
    g_tree_pri = SettingsGetInt("view.tree_pri", 1);
    g_cons_pri = SettingsGetInt("view.console_pri", 0);
    if (g_tree_dock < 0 || g_tree_dock > 3)
        g_tree_dock = DockLeft;
    if (g_cons_dock < 0 || g_cons_dock > 3)
        g_cons_dock = DockBottom;
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
    UiLog("%s", s);
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

static ID3D11ShaderResourceView* IconPreview(const PeIconImg& ic, int* w, int* h)
{
    for (IconTex& t : g_icon_tex)
    {
        if (t.off == ic.file_off)
        {
            if (w) *w = t.w;
            if (h) *h = t.h;
            return t.srv;
        }
    }
    size_t n = 0;
    uint8_t* b = PeJobBytes(&n);
    if (!b || ic.file_off + ic.size > n)
        return nullptr;
    IconTex t{};
    t.off = ic.file_off;
    if (TexLoadPeIcon(b + ic.file_off, ic.size, &t.srv, &t.w, &t.h))
    {
        if (w) *w = t.w;
        if (h) *h = t.h;
        g_icon_tex.push_back(t);
        return t.srv;
    }
    return nullptr;
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
    ConClear();
    ConLog(I18nGet("save.log_hold"));
}

static void GoHex(uint32_t off)
{
    InspectorSelect("hex");
    g_hex_goto = off;
}

void InspectorSelect(const char* id)
{
    if (!id || !id[0])
        return;
    if (strcmp(g_sel, id) != 0)
        UiLog("select %s", id);
    snprintf(g_sel, sizeof(g_sel), "%s", id);
}

static const char* FileNameOf(const char* path)
{
    const char* slash = strrchr(path, '\\');
    const char* fwd = strrchr(path, '/');
    if (fwd && (!slash || fwd > slash))
        slash = fwd;
    return slash ? slash + 1 : path;
}

static void Field(const char* k, const char* v, const char* help = nullptr)
{
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(ThemeColMuted()), "%s", k);
    if (help && help[0])
    {
        ImGui::SameLine(0.f, 6.f);
        ImGui::PushID(k);
        UiHelpMark(help);
        ImGui::PopID();
    }
    ImGui::SameLine(220.f);
    ImGui::TextUnformatted(v ? v : "");
}

static void FieldU(const char* k, uint64_t v, bool hex, const char* help = nullptr)
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
    // TreeNodeEx + leaf/selected flags
    // credit: https://github.com/ocornut/imgui (third_party/imgui, MIT)
    bool sel = strcmp(g_sel, id) == 0;
    if (strcmp(id, "rsrc") == 0 && (strcmp(g_sel, "ver") == 0 || strcmp(g_sel, "icons") == 0 || strcmp(g_sel, "com") == 0))
        sel = true;
    ImGuiTreeNodeFlags f = ImGuiTreeNodeFlags_SpanAvailWidth | ImGuiTreeNodeFlags_OpenOnArrow |
        ImGuiTreeNodeFlags_FramePadding;
    if (leaf)
        f |= ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_NoTreePushOnOpen;
    if (sel)
        f |= ImGuiTreeNodeFlags_Selected;
    bool open = ImGui::TreeNodeEx(id, f, "   %s", label);
    if (ImGui::IsItemClicked())
    {
        InspectorSelect(id);
        if (strcmp(id, "rsrc") == 0)
            g_rsrc_kind = 0;
    }
    ImVec2 a = ImGui::GetItemRectMin();
    ImVec2 b = ImGui::GetItemRectMax();
    float h = b.y - a.y;
    float pad = ImGui::GetTreeNodeToLabelSpacing();
    float ht = UiHoverT(ImGui::GetItemID(), ImGui::IsItemHovered() || sel);
    UiHoverSweep(a, b, ht);
    if (sel)
    {
        g_sel_bar_x0 = a.x;
        g_sel_bar_x1 = b.x;
        if (g_sel_bar_y < 0.f || !UiAnimEnabled())
        {
            g_sel_bar_y = a.y;
            g_sel_bar_h = h;
        }
        else
        {
            float k = 1.f - expf(-18.f * ImGui::GetIO().DeltaTime);
            g_sel_bar_y += (a.y - g_sel_bar_y) * k;
            g_sel_bar_h += (h - g_sel_bar_h) * k;
        }
    }
    IconDraw(icon, ImVec2(a.x + pad * 0.55f, a.y + h * 0.5f), 6.f,
        sel ? ThemeColAccent() : UiLerpCol(ThemeColMuted(), ThemeColAccent(), ht));
    if (dirty)
    {
        float pulse = UiAnimEnabled() ? 0.55f + 0.45f * (0.5f + 0.5f * sinf((float)ImGui::GetTime() * 5.f)) : 1.f;
        ImU32 dc = ThemeWithAlpha(ThemeColAccent(), pulse);
        ImGui::GetWindowDrawList()->AddText(ImVec2(b.x - 18.f, a.y + (h - ImGui::GetFontSize()) * 0.5f),
            dc, "!");
    }
    return open;
}

static bool RsrcBtn(const char* id, const char* label, int kind, bool dirty)
{
    bool sel = strcmp(g_sel, "rsrc") == 0 && g_rsrc_kind == kind;
    if (strcmp(g_sel, id) == 0)
        sel = true;
    ImGui::PushID(id);
    ImVec2 p = ImGui::GetCursorScreenPos();
    float w = ImGui::GetContentRegionAvail().x;
    float h = ImGui::GetFrameHeight();
    bool hit = ImGui::InvisibleButton("hit", ImVec2(w, h));
    ImVec2 q = ImGui::GetItemRectMax();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    float ht = UiHoverT(ImGui::GetItemID(), ImGui::IsItemHovered() || sel);
    dl->AddRectFilled(p, q, UiLerpCol(ThemeColCard(), ThemeColHover(), sel ? 1.f : ht));
    dl->AddRect(p, q, UiLerpCol(ThemeColBorder(), ThemeColAccent(), sel ? 1.f : ht));
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
        UiLog("resource filter %s", label);
    }
    return hit;
}

static bool TopMenu(const char* id, const char* label)
{
    ImGui::PushID(id);
    ImGui::PushStyleColor(ImGuiCol_Button, ThemeVec4Transparent());
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImGui::ColorConvertU32ToFloat4(ThemeColHover()));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImGui::ColorConvertU32ToFloat4(ThemeColHover()));
    bool press = ImGui::Button(label);
    ImGui::PopStyleColor(3);
    float ht = UiHoverT(ImGui::GetItemID(), ImGui::IsItemHovered() || ImGui::IsPopupOpen("##drop"));
    UiHoverSweep(ImGui::GetItemRectMin(), ImGui::GetItemRectMax(), ht);
    if (press)
        ImGui::OpenPopup("##drop");
    bool open = ImGui::BeginPopup("##drop");
    if (!open)
        ImGui::PopID();
    else
        UiPopupFadePush();
    return open;
}

static void TopMenuEnd()
{
    UiPopupFadePop();
    ImGui::EndPopup();
    ImGui::PopID();
}

static void ViewDockMenu(const char* title, bool* vis, int* dock, int* pri,
    const char* kvis, const char* kdock, const char* kpri, const char* ksz)
{
    (void)ksz;
    if (!ImGui::BeginMenu(title))
        return;
    if (ImGui::MenuItem(I18nGet("view.visible"), nullptr, *vis))
    {
        *vis = !*vis;
        SettingsSetBool(kvis, *vis);
        UiLog("%s %s", title, *vis ? "shown" : "hidden");
    }
    ImGui::Separator();
    if (ImGui::BeginMenu(I18nGet("view.dock")))
    {
        const char* labs[4] = {
            I18nGet("view.dock_left"), I18nGet("view.dock_right"),
            I18nGet("view.dock_top"), I18nGet("view.dock_bottom")
        };
        for (int d = 0; d < 4; d++)
        {
            if (ImGui::MenuItem(labs[d], nullptr, *dock == d))
            {
                *dock = d;
                SettingsSetInt(kdock, d);
                UiLog("%s dock %s", title, labs[d]);
            }
        }
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu(I18nGet("view.priority")))
    {
        for (int p = 0; p <= 2; p++)
        {
            char lab[8];
            snprintf(lab, sizeof(lab), "%d", p);
            if (ImGui::MenuItem(lab, nullptr, *pri == p))
            {
                *pri = p;
                SettingsSetInt(kpri, p);
            }
        }
        ImGui::EndMenu();
    }
    ImGui::EndMenu();
}

static void DrawMenubar()
{
    ImVec2 p0 = ImGui::GetCursorScreenPos();
    float w = ImGui::GetContentRegionAvail().x;
    float h = ImGui::GetFrameHeight();
    ImGui::GetWindowDrawList()->AddRectFilled(p0, ImVec2(p0.x + w, p0.y + h), ThemeColBg());
    ImGui::GetWindowDrawList()->AddLine(ImVec2(p0.x, p0.y + h), ImVec2(p0.x + w, p0.y + h), ThemeColBorder());
    ImGui::BeginChild("menubar", ImVec2(w, h), ImGuiChildFlags_None,
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

    bool busy = PeJobBusy();
    bool ready = PeJobResult() != nullptr && !busy;
    bool locked = g_save_phase != 0;

    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10.f, 4.f));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.f, 0.f));

    if (TopMenu("file", I18nGet("menu.file")))
    {
        if (ImGui::MenuItem(I18nGet("welcome.open"), "Ctrl+O", false, !locked))
        {
            char path[MAX_PATH];
            if (AppPickOpenPe(path, MAX_PATH))
                AppOpenPath(path);
        }
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
        ImGui::MenuItem(I18nGet("menu.save_all"), nullptr, false, false);
        ImGui::Separator();
        if (ImGui::MenuItem(I18nGet("pe.close"), nullptr, false, (ready || busy) && !locked))
            AppSetPage(AppPageWelcome);
        ImGui::Separator();
        if (ImGui::MenuItem(I18nGet("welcome.settings"), nullptr, false, !locked))
            AppOpenSettings();
        TopMenuEnd();
    }
    ImGui::SameLine(0.f, 0.f);
    if (TopMenu("edit", I18nGet("menu.edit")))
    {
        if (ImGui::MenuItem(I18nGet("pe.hex"), nullptr, false, ready && !locked))
            InspectorSelect("hex");
        ImGui::Separator();
        ImGui::MenuItem(I18nGet("menu.undo"), "Ctrl+Z", false, false);
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
        ViewDockMenu(I18nGet("view.tree"), &g_tree_on, &g_tree_dock, &g_tree_pri,
            "view.tree", "view.tree_dock", "view.tree_pri", "view.tree_w");
        ViewDockMenu(I18nGet("view.console"), &g_cons_on, &g_cons_dock, &g_cons_pri,
            "view.console", "view.console_dock", "view.console_pri", "view.console_h");
        ImGui::Separator();
        if (ImGui::MenuItem(I18nGet("welcome.settings"), nullptr, false, !locked))
            AppOpenSettings();
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
    if (TopMenu("run", I18nGet("menu.run")))
    {
        ImGui::MenuItem(I18nGet("menu.run_none"), nullptr, false, false);
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
            ImVec2(wp.x + ww - ts.x - 10.f, wp.y + (h - ts.y) * 0.5f),
            ThemeColMuted(), cap);
    }
    ImGui::EndChild();
}

static void DrawOverview(const PeFile* pe)
{
    Field(I18nGet("pe.file"), pe->path, I18nGet("help.fld.file"));
    FieldU(I18nGet("pe.size"), pe->size, false, I18nGet("help.fld.size"));
    Field("SHA-256", pe->sha256, I18nGet("help.fld.sha"));
    Field(I18nGet("pe.compiler"), pe->compiler, I18nGet("help.fld.compiler"));
    Field(I18nGet("pe.packer"), pe->packer, I18nGet("help.fld.packer"));
    Field(I18nGet("pe.arch"), pe->machine_s, I18nGet("help.fld.arch"));
    Field(I18nGet("pe.kind"), pe->pe32plus ? "PE32+" : "PE32", I18nGet("help.fld.kind"));
    Field(I18nGet("pe.subsystem"), pe->subsystem_s, I18nGet("help.fld.subsystem"));
    FieldU(I18nGet("pe.sections"), (uint64_t)pe->section_n, false, I18nGet("help.fld.nsec"));
    FieldU("Entry RVA", pe->entry_rva, true, I18nGet("help.fld.aep"));
    FieldU("ImageBase", pe->image_base, true, I18nGet("help.fld.imagebase"));
    Field("CLR / COM", pe->has_com || !pe->typelibs.empty() ? I18nGet("pe.yes") : I18nGet("pe.no"),
        I18nGet("help.fld.clr"));
    if (pe->overlay_size)
        FieldU("Overlay", pe->overlay_size, false, I18nGet("help.fld.overlay"));
}

static void DrawHeaders(const PeFile* pe)
{
    FieldU("e_lfanew", pe->e_lfanew, true, I18nGet("help.fld.e_lfanew"));
    Field(I18nGet("pe.arch"), pe->machine_s, I18nGet("help.fld.arch"));
    FieldU("Characteristics", pe->chars, true, I18nGet("help.fld.characteristics"));
    Field(I18nGet("pe.kind"), pe->pe32plus ? "PE32+" : "PE32", I18nGet("help.fld.kind"));
    FieldU("AddressOfEntryPoint", pe->entry_rva, true, I18nGet("help.fld.aep"));
    FieldU("ImageBase", pe->image_base, true, I18nGet("help.fld.imagebase"));
    FieldU("SectionAlignment", pe->section_align, true, I18nGet("help.fld.secalign"));
    FieldU("FileAlignment", pe->file_align, true, I18nGet("help.fld.filealign"));
    FieldU("SizeOfImage", pe->size_of_image, true, I18nGet("help.fld.sizeofimage"));
    Field(I18nGet("pe.subsystem"), pe->subsystem_s, I18nGet("help.fld.subsystem"));
    if (!pe->rich.empty())
    {
        ImGui::Spacing();
        ImGui::TextUnformatted("Rich");
        for (const PeRichEntry& e : pe->rich)
            ImGui::Text("  prod %u  build %u  x%u", e.prod, e.build, e.count);
    }
}

static void DrawSection(const PeFile* pe, int i)
{
    if (i < 0 || i >= pe->section_n)
        return;
    const PeSection& s = pe->sections[i];
    Field("Name", s.name, I18nGet("help.fld.secname"));
    FieldU("VirtualAddress", s.vaddr, true, I18nGet("help.fld.vaddr"));
    FieldU("VirtualSize", s.vsize, true, I18nGet("help.fld.vsize"));
    FieldU("PointerToRawData", s.rawptr, true, I18nGet("help.fld.rawptr"));
    FieldU("SizeOfRawData", s.rawsize, true, I18nGet("help.fld.rawsize"));
    FieldU("Characteristics", s.chars, true, I18nGet("help.fld.secchars"));
}

static void DrawImportDll(const PeFile* pe, int i)
{
    if (i < 0 || i >= (int)pe->imports.size())
        return;
    const PeImportDll& d = pe->imports[i];
    Field("DLL", d.name.c_str());
    FieldU(I18nGet("pe.functions"), d.fns.size(), false);
    ImGui::Spacing();
    for (const PeImportFn& f : d.fns)
        ImGui::Text("  %s", f.name.c_str());
}

static void DrawCom(PeFile* pe)
{
    ImGui::TextUnformatted(I18nGet("pe.com"));
    ImGui::Spacing();
    if (pe->clr_off)
    {
        ImGui::TextUnformatted(".NET CLR");
        int maj = pe->clr_major;
        int minv = pe->clr_minor;
        if (ImGui::InputInt("CLR major", &maj))
        {
            pe->clr_major = (uint16_t)maj;
            PePatchClr();
            MarkDirt(DirtCom);
        }
        if (ImGui::InputInt("CLR minor", &minv))
        {
            pe->clr_minor = (uint16_t)minv;
            PePatchClr();
            MarkDirt(DirtCom);
        }
        bool il = (pe->clr_flags & 0x1) != 0;
        bool bit32 = (pe->clr_flags & 0x2) != 0;
        bool strong = (pe->clr_flags & 0x8) != 0;
        if (UiCheckbox("ilonly", "ILONLY", &il))
        {
            if (il) pe->clr_flags |= 0x1; else pe->clr_flags &= ~0x1u;
            PePatchClr();
            MarkDirt(DirtCom);
        }
        if (UiCheckbox("bit32", "32BITREQUIRED", &bit32))
        {
            if (bit32) pe->clr_flags |= 0x2; else pe->clr_flags &= ~0x2u;
            PePatchClr();
            MarkDirt(DirtCom);
        }
        if (UiCheckbox("sn", "STRONGNAMESIGNED", &strong))
        {
            if (strong) pe->clr_flags |= 0x8; else pe->clr_flags &= ~0x8u;
            PePatchClr();
            MarkDirt(DirtCom);
        }
        FieldU("EntryPointToken", pe->clr_entry, true);
    }
    else
        ImGui::TextUnformatted(I18nGet("pe.no_clr"));

    ImGui::Spacing();
    ImGui::TextUnformatted("TYPELIB");
    if (pe->typelibs.empty())
        ImGui::TextUnformatted(I18nGet("pe.none"));
    for (int i = 0; i < (int)pe->typelibs.size(); i++)
    {
        PeTypelib& t = pe->typelibs[i];
        ImGui::PushID(i);
        Field("Name", t.name);
        FieldU("Offset", t.file_off, true);
        FieldU("Size", t.size, false);
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

static void HexWrite(ImU8* mem, size_t off, ImU8 d, void*)
{
    mem[off] = d;
    MarkDirt(DirtHex);
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
                snprintf(g_save_msg, sizeof(g_save_msg), "%s", I18nGet("pe.ver_fit"));
            else
                MarkDirt(DirtVer);
        }
        ImGui::SetNextItemWidth(280.f);
        if (ImGui::InputInt4(I18nGet("pe.prod_ver"), p))
        {
            for (int i = 0; i < 4; i++)
                v.prod[i] = (uint16_t)(p[i] < 0 ? 0 : p[i]);
            if (!PePatchVerFixed(vi))
                snprintf(g_save_msg, sizeof(g_save_msg), "%s", I18nGet("pe.ver_fit"));
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
                    snprintf(g_save_msg, sizeof(g_save_msg), "%s", I18nGet("pe.ver_fit"));
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
    FieldU("Offset", ic.file_off, true);
    if (UiButton(I18nGet("pe.icon_export")))
    {
        char path[MAX_PATH];
        char sug[64];
        snprintf(sug, sizeof(sug), "icon_%u.ico", ic.id);
        if (AppPickSaveFilter(path, MAX_PATH, L"Icon\0*.ico\0All\0*.*\0", L"Export icon", sug))
        {
            if (PeExportIco(g_icon_sel, path))
                snprintf(g_save_msg, sizeof(g_save_msg), "%s", I18nGet("pe.icon_exported"));
            else
                snprintf(g_save_msg, sizeof(g_save_msg), "%s", I18nGet("pe.save_fail"));
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
                snprintf(g_save_msg, sizeof(g_save_msg), "%s", I18nGet("pe.icon_replaced"));
            }
            else
                snprintf(g_save_msg, sizeof(g_save_msg), "%s", I18nGet("pe.icon_size"));
        }
    }
}

static void DrawHex()
{
    size_t n = 0;
    uint8_t* b = PeJobBytes(&n);
    if (!b || !n)
    {
        ImGui::TextUnformatted(I18nGet("pe.none"));
        return;
    }

    if (!g_hex_primed)
    {
        g_hex.ReadOnly = false;
        g_hex.OptShowDataPreview = true;
        g_hex.WriteFn = HexWrite;
        g_hex_primed = true;
    }
    ImVec4 hl = ImGui::ColorConvertU32ToFloat4(ThemeColAccent());
    hl.w = 0.35f;
    g_hex.HighlightColor = ImGui::ColorConvertFloat4ToU32(hl);
    if (g_hex_goto != (size_t)-1)
    {
        g_hex.GotoAddrAndHighlight(g_hex_goto, g_hex_goto + 1);
        g_hex_goto = (size_t)-1;
    }

    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    ImGui::TextWrapped("%s", I18nGet("pe.hex_hint"));
    ImGui::PopStyleColor();

    if (ImFont* mono = ThemeFontMono())
        ImGui::PushFont(mono);
    g_hex.DrawContents(b, n);
    if (ThemeFontMono())
        ImGui::PopFont();
}

static void DrawRsrcPeek(const PeRsrcLeaf& L)
{
    Field("Type", L.type_name, I18nGet("help.fld.rsrctype"));
    Field("Name", L.name, I18nGet("help.fld.rsrcname"));
    FieldU("Lang", L.lang, true, I18nGet("help.fld.rsrclang"));
    FieldU("RVA", L.rva, true, I18nGet("help.fld.rsrcrva"));
    FieldU("Offset", L.file_off, true, I18nGet("help.fld.rsrcoff"));
    FieldU("Size", L.size, false, I18nGet("help.fld.rsrcsize"));
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

static void DrawRsrc(PeFile* pe)
{
    float avail = ImGui::GetContentRegionAvail().x;
    float list_w = avail * 0.36f;
    if (list_w < 180.f)
        list_w = 180.f;
    ImGui::BeginChild("rsrc_list", ImVec2(list_w, 0.f), ImGuiChildFlags_Borders);

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

    if (rows == 0)
        ImGui::TextUnformatted(I18nGet("pe.none"));

    for (int i = 0; i < rows; i++)
    {
        char lab[128];
        if (g_rsrc_kind == 1)
            snprintf(lab, sizeof(lab), "VERSION  %s", pe->versions[i].name);
        else if (g_rsrc_kind == 2)
        {
            const PeIconImg& ic = pe->icons[i];
            snprintf(lab, sizeof(lab), "ICON %u  %dx%d", ic.id, ic.w, ic.h);
        }
        else if (g_rsrc_kind == 3)
        {
            if (pe->clr_off && i == 0)
                snprintf(lab, sizeof(lab), ".NET CLR");
            else
            {
                int ti = i - (pe->clr_off ? 1 : 0);
                snprintf(lab, sizeof(lab), "TYPELIB  %s", pe->typelibs[ti].name);
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
    ImGui::SameLine();
    ImGui::BeginChild("rsrc_prev", ImVec2(0.f, 0.f), ImGuiChildFlags_Borders);
    if (rows == 0)
        ImGui::TextUnformatted(I18nGet("pe.rsrc_preview"));
    else if (g_rsrc_kind == 1)
        DrawVersion(pe);
    else if (g_rsrc_kind == 2)
        DrawIcons(pe);
    else if (g_rsrc_kind == 3)
        DrawCom(pe);
    else
        DrawRsrcPeek(pe->rsrc[g_rsrc_row]);
    ImGui::EndChild();
}

static void DrawDetail(PeFile* pe)
{
    if (strcmp(g_sel, "overview") == 0) { DrawOverview(pe); return; }
    if (strcmp(g_sel, "headers") == 0) { DrawHeaders(pe); return; }
    if (strcmp(g_sel, "sections") == 0)
    {
        FieldU(I18nGet("pe.sections"), (uint64_t)pe->section_n, false);
        return;
    }
    if (strncmp(g_sel, "sec:", 4) == 0) { DrawSection(pe, atoi(g_sel + 4)); return; }
    if (strcmp(g_sel, "imports") == 0)
    {
        FieldU("DLLs", pe->imports.size(), false);
        return;
    }
    if (strncmp(g_sel, "imp:", 4) == 0) { DrawImportDll(pe, atoi(g_sel + 4)); return; }
    if (strcmp(g_sel, "exports") == 0)
    {
        for (const PeExportFn& e : pe->exports)
            ImGui::Text("  %s", e.name.c_str());
        return;
    }
    if (strcmp(g_sel, "ver") == 0)
    {
        snprintf(g_sel, sizeof(g_sel), "rsrc");
        g_rsrc_kind = 1;
    }
    if (strcmp(g_sel, "icons") == 0)
    {
        snprintf(g_sel, sizeof(g_sel), "rsrc");
        g_rsrc_kind = 2;
    }
    if (strcmp(g_sel, "com") == 0)
    {
        snprintf(g_sel, sizeof(g_sel), "rsrc");
        g_rsrc_kind = 3;
    }
    if (strcmp(g_sel, "rsrc") == 0) { DrawRsrc(pe); return; }
    if (strcmp(g_sel, "hex") == 0) { DrawHex(); return; }
    if (strcmp(g_sel, "overlay") == 0)
    {
        FieldU("Offset", pe->overlay_off, true, I18nGet("help.fld.rsrcoff"));
        FieldU("Size", pe->overlay_size, false, I18nGet("help.fld.overlay"));
        return;
    }
    DrawOverview(pe);
}

static void DrawTree(const PeFile* pe)
{
    Node("overview", I18nGet("pe.overview"), IconFile, true, false);
    Node("headers", I18nGet("pe.headers"), IconCpu, true, false);
    if (Node("sections", I18nGet("pe.sections"), IconBox, false, false))
    {
        for (int i = 0; i < pe->section_n; i++)
        {
            char id[32];
            snprintf(id, sizeof(id), "sec:%d", i);
            Node(id, pe->sections[i].name[0] ? pe->sections[i].name : "(empty)", IconFile, true, false);
        }
        ImGui::TreePop();
    }
    if (pe->has_import && Node("imports", I18nGet("pe.imports"), IconImport, false, false))
    {
        for (int i = 0; i < (int)pe->imports.size(); i++)
        {
            char id[32];
            snprintf(id, sizeof(id), "imp:%d", i);
            Node(id, pe->imports[i].name.c_str(), IconFile, true, false);
        }
        ImGui::TreePop();
    }
    if (pe->has_export)
        Node("exports", I18nGet("pe.exports"), IconExport, true, false);
    Node("hex", I18nGet("pe.hex"), IconHex, true, (g_dirt & DirtHex) != 0);
    if (pe->has_resource || pe->has_com || !pe->typelibs.empty() || !pe->versions.empty() || !pe->icons.empty())
    {
        bool rdirty = (g_dirt & (DirtVer | DirtIco | DirtCom)) != 0;
        if (Node("rsrc", I18nGet("pe.resources"), IconFolder, false, rdirty))
        {
            RsrcBtn("ver", I18nGet("pe.version"), 1, (g_dirt & DirtVer) != 0);
            RsrcBtn("icons", I18nGet("pe.icons"), 2, (g_dirt & DirtIco) != 0);
            RsrcBtn("com", I18nGet("pe.com"), 3, (g_dirt & DirtCom) != 0);
            ImGui::TreePop();
        }
    }
    if (pe->overlay_size)
        Node("overlay", "Overlay", IconFile, true, false);
}

static bool PaneDirty()
{
    if (strcmp(g_sel, "hex") == 0)
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
    g_save_t += ImGui::GetIO().DeltaTime;
    if (g_save_phase == 1)
    {
        if (g_save_t > 0.32f && g_con_n < 2)
            ConLog(I18nGet("save.log_image"));
        if (g_save_t > 0.68f && !g_save_wrote)
        {
            g_save_ok = PeJobSave(g_save_dst);
            g_save_wrote = true;
            ConLog(g_save_ok ? I18nGet("save.log_flush") : I18nGet("pe.save_fail"));
        }
        if (g_save_t > 1.12f && g_save_wrote)
        {
            char sum[192];
            if (g_save_ok)
            {
                snprintf(sum, sizeof(sum), "%s  %s", I18nGet("save.summary_ok"), FileNameOf(g_save_dst));
                g_dirt = 0;
            }
            else
                snprintf(sum, sizeof(sum), "%s", I18nGet("save.summary_fail"));
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
    if (UiAnimEnabled())
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
            UiLog("%s", I18nGet("pe.analyzing"));
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
        return;
    }
    const PeFile* pe = PeJobResult();
    if (!pe)
        return;
    static char seen[260];
    if (strcmp(seen, pe->path) != 0)
    {
        snprintf(seen, sizeof(seen), "%s", pe->path);
        snprintf(g_sel, sizeof(g_sel), "overview");
        g_save_msg[0] = 0;
        g_icon_sel = 0;
        g_dirt = 0;
        g_rsrc_kind = 0;
        NukeIconTex();
        UiLog("opened %s", FileNameOf(pe->path));
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

static void FillBody()
{
    static char fade_sel[96];
    static float fade_t = 1.f;
    if (strcmp(fade_sel, g_sel) != 0)
    {
        snprintf(fade_sel, sizeof(fade_sel), "%s", g_sel);
        fade_t = 0.f;
    }
    if (!UiAnimEnabled())
        fade_t = 1.f;
    else
    {
        fade_t += ImGui::GetIO().DeltaTime * 6.5f;
        if (fade_t > 1.f)
            fade_t = 1.f;
    }
    float e = UiEaseOut(fade_t);
    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, 0.4f + 0.6f * e);
    if (PeJobBusy())
    {
        ImVec2 avail = ImGui::GetContentRegionAvail();
        ImVec2 c(ImGui::GetCursorScreenPos().x + avail.x * 0.5f, ImGui::GetCursorScreenPos().y + avail.y * 0.42f);
        float p = PeJobProgress();
        UiSpinner(c, 28.f, p);
        const char* msg = I18nGet("pe.analyzing");
        ImVec2 ts = ImGui::CalcTextSize(msg);
        ImDrawList* dl = ImGui::GetWindowDrawList();
        dl->AddText(ImVec2(c.x - ts.x * 0.5f, c.y + 40.f), ThemeColMuted(), msg);
        char pct[32];
        snprintf(pct, sizeof(pct), "%d%%", (int)(p * 100.f));
        ImVec2 ps = ImGui::CalcTextSize(pct);
        dl->AddText(ImVec2(c.x - ps.x * 0.5f, c.y + 62.f), ThemeColFg(), pct);
    }
    else if (PeJobFailed())
    {
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColAccent()));
        ImGui::TextWrapped("%s", PeJobError()[0] ? PeJobError() : I18nGet("pe.fail"));
        ImGui::PopStyleColor();
    }
    else if (PeFile* pe = PeJobResultMut())
        DrawDetail(pe);
    ImGui::PopStyleVar();
}

static void FillCons()
{
    if (ImFont* mono = ThemeFontMono())
        ImGui::PushFont(mono);
    if (g_ulog_n == 0)
    {
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
        ImGui::TextUnformatted(I18nGet("view.console_empty"));
        ImGui::PopStyleColor();
    }
    else
    {
        for (int k = 0; k < g_ulog_n; k++)
        {
            int idx = (g_ulog_i - g_ulog_n + k + 96) % 96;
            ImGui::TextUnformatted(g_ulog[idx]);
        }
        if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 8.f)
            ImGui::SetScrollHereY(1.f);
    }
    if (ThemeFontMono())
        ImGui::PopFont();
}

static void SplitV(const char* id, float* sz, const char* key, float sign)
{
    ImGui::PushID(id);
    ImGui::InvisibleButton("sp", ImVec2(5.f, ImGui::GetContentRegionAvail().y));
    if (ImGui::IsItemHovered() || ImGui::IsItemActive())
        ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeEW);
    if (ImGui::IsItemActive())
    {
        *sz += sign * ImGui::GetIO().MouseDelta.x;
        if (*sz < 160.f)
            *sz = 160.f;
    }
    if (ImGui::IsItemDeactivated())
        SettingsSetInt(key, (int)*sz);
    ImGui::PopID();
}

static void SplitH(const char* id, float* sz, const char* key, float sign)
{
    ImGui::PushID(id);
    ImGui::InvisibleButton("sp", ImVec2(ImGui::GetContentRegionAvail().x, 5.f));
    if (ImGui::IsItemHovered() || ImGui::IsItemActive())
        ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeNS);
    if (ImGui::IsItemActive())
    {
        *sz += sign * ImGui::GetIO().MouseDelta.y;
        if (*sz < 72.f)
            *sz = 72.f;
    }
    if (ImGui::IsItemDeactivated())
        SettingsSetInt(key, (int)*sz);
    ImGui::PopID();
}

static void HostPane(const char* id, ImVec2 sz, int which)
{
    ImGui::BeginChild(id, sz, ImGuiChildFlags_Borders);
    if (which == 0)
        FillTree();
    else
        FillCons();
    ImGui::EndChild();
}

static void HostPair(const char* id, ImVec2 sz, int a, int b, bool stack_vert)
{
    ImGui::BeginChild(id, sz, ImGuiChildFlags_None);
    if (stack_vert)
    {
        float h = ImGui::GetContentRegionAvail().y * 0.5f;
        HostPane("p0", ImVec2(0.f, h), a);
        HostPane("p1", ImVec2(0.f, 0.f), b);
    }
    else
    {
        float w = ImGui::GetContentRegionAvail().x * 0.5f;
        HostPane("p0", ImVec2(w, 0.f), a);
        ImGui::SameLine(0.f, 0.f);
        HostPane("p1", ImVec2(0.f, 0.f), b);
    }
    ImGui::EndChild();
}

static void DockStrip(int dock, bool as_row)
{
    bool t = g_tree_on && g_tree_dock == dock;
    bool c = g_cons_on && g_cons_dock == dock;
    if (!t && !c)
        return;
    int first = 0, second = 1;
    if (t && c && g_cons_pri > g_tree_pri)
    {
        first = 1;
        second = 0;
    }
    float tsz = g_tree_sz;
    float csz = g_cons_sz;
    if (as_row)
    {
        if (t && c)
            HostPair("strip", ImVec2(0.f, tsz + csz), first, second, true);
        else if (t)
            HostPane("strip_t", ImVec2(0.f, tsz), 0);
        else
            HostPane("strip_c", ImVec2(0.f, csz), 1);
    }
    else
    {
        float w = tsz;
        if (c && (!t || csz > w))
            w = csz;
        if (t && c)
            HostPair("col", ImVec2(w, 0.f), first, second, true);
        else if (t)
            HostPane("col_t", ImVec2(w, 0.f), 0);
        else
            HostPane("col_c", ImVec2(w, 0.f), 1);
    }
}

void InspectorDraw()
{
    TickSave();
    LoadViewLayout();
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
    if (g_tree_sz > av.x * 0.6f)
        g_tree_sz = av.x * 0.6f;
    if (g_cons_sz > av.y * 0.55f)
        g_cons_sz = av.y * 0.55f;

    bool top = (g_tree_on && g_tree_dock == DockTop) || (g_cons_on && g_cons_dock == DockTop);
    bool bot = (g_tree_on && g_tree_dock == DockBottom) || (g_cons_on && g_cons_dock == DockBottom);
    float top_h = 0.f;
    float bot_h = 0.f;
    if (g_tree_on && g_tree_dock == DockTop)
        top_h += g_tree_sz;
    if (g_cons_on && g_cons_dock == DockTop)
        top_h += g_cons_sz;
    if (g_tree_on && g_tree_dock == DockBottom)
        bot_h += g_tree_sz;
    if (g_cons_on && g_cons_dock == DockBottom)
        bot_h += g_cons_sz;

    float mid_h = av.y - (top ? top_h + 5.f : 0.f) - (bot ? bot_h + 5.f : 0.f);
    if (mid_h < 64.f)
        mid_h = 64.f;

    if (top)
        DockStrip(DockTop, true);

    ImGui::BeginChild("mid", ImVec2(av.x, mid_h), ImGuiChildFlags_None);
    bool left = (g_tree_on && g_tree_dock == DockLeft) || (g_cons_on && g_cons_dock == DockLeft);
    bool right = (g_tree_on && g_tree_dock == DockRight) || (g_cons_on && g_cons_dock == DockRight);
    if (left)
    {
        DockStrip(DockLeft, false);
        ImGui::SameLine(0.f, 0.f);
        float* sz = (g_tree_on && g_tree_dock == DockLeft) ? &g_tree_sz : &g_cons_sz;
        const char* key = (g_tree_on && g_tree_dock == DockLeft) ? "view.tree_w" : "view.console_h";
        SplitV("lsplit", sz, key, 1.f);
        ImGui::SameLine(0.f, 0.f);
    }

    float right_w = 0.f;
    if (g_tree_on && g_tree_dock == DockRight)
        right_w = g_tree_sz;
    if (g_cons_on && g_cons_dock == DockRight)
    {
        if (!right_w || g_cons_sz > right_w)
            right_w = g_cons_sz;
    }
    float body_w = ImGui::GetContentRegionAvail().x - (right ? right_w + 5.f : 0.f);
    if (body_w < 80.f)
        body_w = 80.f;
    ImGui::BeginChild("pe_body", ImVec2(body_w, 0.f), ImGuiChildFlags_None);
    FillBody();
    ImGui::EndChild();
    if (PaneDirty())
    {
        ImVec2 a = ImGui::GetItemRectMin();
        ImVec2 b = ImGui::GetItemRectMax();
        ImGui::GetWindowDrawList()->AddRect(a, b, ThemeColAccent(), 0.f, 0, 2.f);
    }
    if (right)
    {
        ImGui::SameLine(0.f, 0.f);
        float* sz = (g_tree_on && g_tree_dock == DockRight) ? &g_tree_sz : &g_cons_sz;
        const char* key = (g_tree_on && g_tree_dock == DockRight) ? "view.tree_w" : "view.console_h";
        SplitV("rsplit", sz, key, -1.f);
        ImGui::SameLine(0.f, 0.f);
        DockStrip(DockRight, false);
    }
    ImGui::EndChild();

    if (bot)
    {
        float* sz = (g_cons_on && g_cons_dock == DockBottom) ? &g_cons_sz : &g_tree_sz;
        const char* key = (g_cons_on && g_cons_dock == DockBottom) ? "view.console_h" : "view.tree_w";
        SplitH("bsplit", sz, key, -1.f);
        DockStrip(DockBottom, true);
    }

    DrawSaveOverlay();
}
