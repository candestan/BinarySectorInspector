#include "app/inspector.h"
#include "app/app.h"
#include "pe/pe.h"
#include "ui/theme.h"
#include "ui/icons.h"
#include "ui/widgets.h"
#include "ui/tex.h"
#include "i18n/i18n.h"

#include "imgui.h"
// credit: https://github.com/ocornut/imgui_club
#include "imgui_memory_editor.h"

#include <windows.h>
#include <d3d11.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <vector>

static char g_sel[96] = "overview";
static char g_save_msg[160];
static MemoryEditor g_hex;
static bool g_hex_primed;
static size_t g_hex_goto = (size_t)-1;
static int g_icon_sel = 0;

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
    char path[MAX_PATH];
    if (save_as || !PeJobPath()[0])
    {
        if (!AppPickSavePe(path, MAX_PATH))
            return;
    }
    else
        snprintf(path, MAX_PATH, "%s", PeJobPath());
    if (PeJobSave(path))
        snprintf(g_save_msg, sizeof(g_save_msg), "%s", I18nGet("pe.saved"));
    else
        snprintf(g_save_msg, sizeof(g_save_msg), "%s", I18nGet("pe.save_fail"));
}

static void GoHex(uint32_t off)
{
    InspectorSelect("hex");
    g_hex_goto = off;
}

void InspectorSelect(const char* id)
{
    if (id && id[0])
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

static void Field(const char* k, const char* v)
{
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(ThemeColMuted()), "%s", k);
    ImGui::SameLine(200.f);
    ImGui::TextUnformatted(v ? v : "");
}

static void FieldU(const char* k, uint64_t v, bool hex)
{
    char buf[48];
    if (hex)
        snprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)v);
    else
        snprintf(buf, sizeof(buf), "%llu", (unsigned long long)v);
    Field(k, buf);
}

static bool Node(const char* id, const char* label, int icon, bool leaf)
{
    // TreeNodeEx + leaf/selected flags
    // credit: https://github.com/ocornut/imgui (third_party/imgui, MIT)
    bool sel = strcmp(g_sel, id) == 0;
    ImGuiTreeNodeFlags f = ImGuiTreeNodeFlags_SpanAvailWidth | ImGuiTreeNodeFlags_OpenOnArrow |
        ImGuiTreeNodeFlags_FramePadding;
    if (leaf)
        f |= ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_NoTreePushOnOpen;
    if (sel)
        f |= ImGuiTreeNodeFlags_Selected;
    bool open = ImGui::TreeNodeEx(id, f, "   %s", label);
    if (ImGui::IsItemClicked())
        snprintf(g_sel, sizeof(g_sel), "%s", id);
    ImVec2 a = ImGui::GetItemRectMin();
    float h = ImGui::GetItemRectSize().y;
    float pad = ImGui::GetTreeNodeToLabelSpacing();
    IconDraw(icon, ImVec2(a.x + pad * 0.55f, a.y + h * 0.5f), 6.f, sel ? ThemeColAccent() : ThemeColMuted());
    return open;
}

static void DrawMenubar()
{
    ImVec2 p0 = ImGui::GetCursorScreenPos();
    float w = ImGui::GetContentRegionAvail().x;
    float h = ImGui::GetFrameHeight() + 4.f;
    ImGui::GetWindowDrawList()->AddRectFilled(p0, ImVec2(p0.x + w, p0.y + h), ThemeColBg());
    ImGui::GetWindowDrawList()->AddLine(ImVec2(p0.x, p0.y + h), ImVec2(p0.x + w, p0.y + h), ThemeColBorder());
    ImGui::BeginChild("menubar", ImVec2(w, h), ImGuiChildFlags_None, ImGuiWindowFlags_NoScrollbar);
    ImGui::SetCursorPos(ImVec2(6.f, 2.f));

    bool busy = PeJobBusy();
    bool ready = PeJobResult() != nullptr && !busy;

    if (IconBeginMenu(IconFile, I18nGet("menu.file")))
    {
        if (IconMenuItem(IconFolder, I18nGet("welcome.open"), "Ctrl+O"))
        {
            char path[MAX_PATH];
            if (AppPickOpenPe(path, MAX_PATH))
                AppOpenPath(path);
        }
        if (IconMenuItem(IconSave, I18nGet("pe.save"), "Ctrl+S", ready))
            DoSave(false);
        if (IconMenuItem(IconSave, I18nGet("menu.save_as"), nullptr, ready))
            DoSave(true);
        ImGui::Separator();
        if (IconMenuItem(IconClose, I18nGet("pe.close"), nullptr, ready || busy))
            AppSetPage(AppPageWelcome);
        if (IconMenuItem(IconGear, I18nGet("welcome.settings")))
            AppOpenSettings();
        ImGui::EndMenu();
    }
    ImGui::SameLine(0.f, 2.f);
    if (IconBeginMenu(IconEdit, I18nGet("menu.edit")))
    {
        if (IconMenuItem(IconHex, I18nGet("pe.hex"), nullptr, ready))
            InspectorSelect("hex");
        if (IconMenuItem(IconEdit, I18nGet("pe.version"), nullptr, ready))
            InspectorSelect("ver");
        if (IconMenuItem(IconImage, I18nGet("pe.icons"), nullptr, ready))
            InspectorSelect("icons");
        if (IconMenuItem(IconCom, I18nGet("pe.com"), nullptr, ready))
            InspectorSelect("com");
        ImGui::EndMenu();
    }
    ImGui::SameLine(0.f, 2.f);
    if (IconBeginMenu(IconBox, I18nGet("menu.selection")))
    {
        if (IconMenuItem(IconFile, I18nGet("pe.overview"), nullptr, ready))
            InspectorSelect("overview");
        if (IconMenuItem(IconCpu, I18nGet("pe.headers"), nullptr, ready))
            InspectorSelect("headers");
        if (IconMenuItem(IconFolder, I18nGet("pe.resources"), nullptr, ready))
            InspectorSelect("rsrc");
        if (IconMenuItem(IconHex, I18nGet("pe.hex"), nullptr, ready))
            InspectorSelect("hex");
        ImGui::EndMenu();
    }
    ImGui::SameLine(0.f, 2.f);
    if (IconBeginMenu(IconEye, I18nGet("menu.view")))
    {
        if (IconMenuItem(IconTree, I18nGet("pe.overview"), nullptr, ready))
            InspectorSelect("overview");
        if (IconMenuItem(IconHex, I18nGet("pe.hex"), nullptr, ready))
            InspectorSelect("hex");
        if (IconMenuItem(IconImage, I18nGet("pe.icons"), nullptr, ready))
            InspectorSelect("icons");
        if (IconMenuItem(IconEdit, I18nGet("pe.version"), nullptr, ready))
            InspectorSelect("ver");
        if (IconMenuItem(IconGear, I18nGet("welcome.settings")))
            AppOpenSettings();
        ImGui::EndMenu();
    }
    ImGui::SameLine(0.f, 2.f);
    if (IconBeginMenu(IconGo, I18nGet("menu.go")))
    {
        const PeFile* pe = PeJobResult();
        uint32_t ep = pe ? PeRvaToFileOff(pe->entry_rva) : 0;
        if (IconMenuItem(IconPlay, I18nGet("menu.go_entry"), nullptr, ready && ep))
            GoHex(ep);
        if (IconMenuItem(IconFile, I18nGet("menu.go_overlay"), nullptr, ready && pe && pe->overlay_size))
            GoHex(pe->overlay_off);
        if (IconMenuItem(IconFolder, I18nGet("pe.resources"), nullptr, ready))
            InspectorSelect("rsrc");
        if (IconMenuItem(IconCom, I18nGet("pe.com"), nullptr, ready))
            InspectorSelect("com");
        ImGui::EndMenu();
    }
    ImGui::SameLine(0.f, 2.f);
    if (IconBeginMenu(IconPlay, I18nGet("menu.run")))
    {
        IconMenuItem(IconPlay, I18nGet("menu.run_none"), nullptr, false);
        const PeFile* pe = PeJobResult();
        uint32_t ep = pe ? PeRvaToFileOff(pe->entry_rva) : 0;
        if (IconMenuItem(IconGo, I18nGet("menu.go_entry"), nullptr, ready && ep))
            GoHex(ep);
        ImGui::EndMenu();
    }

    const char* path = PeJobPath();
    if (path[0])
    {
        ImGui::SameLine();
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
        if (PeJobDirty())
            ImGui::TextUnformatted("*");
        ImGui::SameLine();
        ImGui::TextUnformatted(FileNameOf(path));
        ImGui::PopStyleColor();
    }
    ImGui::EndChild();
    ImGui::SetCursorScreenPos(ImVec2(p0.x, p0.y + h + 8.f));
}

static void DrawOverview(const PeFile* pe)
{
    Field(I18nGet("pe.file"), pe->path);
    FieldU(I18nGet("pe.size"), pe->size, false);
    Field("SHA-256", pe->sha256);
    Field(I18nGet("pe.compiler"), pe->compiler);
    Field(I18nGet("pe.packer"), pe->packer);
    Field(I18nGet("pe.arch"), pe->machine_s);
    Field(I18nGet("pe.kind"), pe->pe32plus ? "PE32+" : "PE32");
    Field(I18nGet("pe.subsystem"), pe->subsystem_s);
    FieldU(I18nGet("pe.sections"), (uint64_t)pe->section_n, false);
    FieldU("Entry RVA", pe->entry_rva, true);
    FieldU("ImageBase", pe->image_base, true);
    Field("CLR / COM", pe->has_com || !pe->typelibs.empty() ? I18nGet("pe.yes") : I18nGet("pe.no"));
    if (pe->overlay_size)
        FieldU("Overlay", pe->overlay_size, false);
}

static void DrawHeaders(const PeFile* pe)
{
    FieldU("e_lfanew", pe->e_lfanew, true);
    Field(I18nGet("pe.arch"), pe->machine_s);
    FieldU("Characteristics", pe->chars, true);
    Field(I18nGet("pe.kind"), pe->pe32plus ? "PE32+" : "PE32");
    FieldU("AddressOfEntryPoint", pe->entry_rva, true);
    FieldU("ImageBase", pe->image_base, true);
    FieldU("SectionAlignment", pe->section_align, true);
    FieldU("FileAlignment", pe->file_align, true);
    FieldU("SizeOfImage", pe->size_of_image, true);
    Field(I18nGet("pe.subsystem"), pe->subsystem_s);
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
    Field("Name", s.name);
    FieldU("VirtualAddress", s.vaddr, true);
    FieldU("VirtualSize", s.vsize, true);
    FieldU("PointerToRawData", s.rawptr, true);
    FieldU("SizeOfRawData", s.rawsize, true);
    FieldU("Characteristics", s.chars, true);
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
        }
        if (ImGui::InputInt("CLR minor", &minv))
        {
            pe->clr_minor = (uint16_t)minv;
            PePatchClr();
        }
        bool il = (pe->clr_flags & 0x1) != 0;
        bool bit32 = (pe->clr_flags & 0x2) != 0;
        bool strong = (pe->clr_flags & 0x8) != 0;
        if (UiCheckbox("ilonly", "ILONLY", &il))
        {
            if (il) pe->clr_flags |= 0x1; else pe->clr_flags &= ~0x1u;
            PePatchClr();
        }
        if (UiCheckbox("bit32", "32BITREQUIRED", &bit32))
        {
            if (bit32) pe->clr_flags |= 0x2; else pe->clr_flags &= ~0x2u;
            PePatchClr();
        }
        if (UiCheckbox("sn", "STRONGNAMESIGNED", &strong))
        {
            if (strong) pe->clr_flags |= 0x8; else pe->clr_flags &= ~0x8u;
            PePatchClr();
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
    PeJobTouch();
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
        }
        ImGui::SetNextItemWidth(280.f);
        if (ImGui::InputInt4(I18nGet("pe.prod_ver"), p))
        {
            for (int i = 0; i < 4; i++)
                v.prod[i] = (uint16_t)(p[i] < 0 ? 0 : p[i]);
            if (!PePatchVerFixed(vi))
                snprintf(g_save_msg, sizeof(g_save_msg), "%s", I18nGet("pe.ver_fit"));
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

static void DrawRsrc(const PeFile* pe)
{
    if (!pe->versions.empty() && UiButton(I18nGet("pe.version")))
        InspectorSelect("ver");
    if (!pe->icons.empty())
    {
        ImGui::SameLine();
        if (UiButton(I18nGet("pe.icons")))
            InspectorSelect("icons");
    }
    ImGui::SameLine();
    if (UiButton(I18nGet("pe.com")))
        InspectorSelect("com");
    ImGui::Spacing();
    for (int i = 0; i < (int)pe->rsrc.size(); i++)
    {
        const PeRsrcLeaf& L = pe->rsrc[i];
        ImGui::PushID(i);
        char row[160];
        snprintf(row, sizeof(row), "%s  %s  lang %u  +%08X  %u", L.type_name, L.name, L.lang, L.file_off, L.size);
        if (ImGui::Selectable(row))
            GoHex(L.file_off);
        ImGui::PopID();
    }
    if (pe->rsrc.empty())
        ImGui::TextUnformatted(I18nGet("pe.none"));
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
    if (strcmp(g_sel, "rsrc") == 0) { DrawRsrc(pe); return; }
    if (strcmp(g_sel, "ver") == 0) { DrawVersion(pe); return; }
    if (strcmp(g_sel, "icons") == 0) { DrawIcons(pe); return; }
    if (strcmp(g_sel, "com") == 0) { DrawCom(pe); return; }
    if (strcmp(g_sel, "hex") == 0) { DrawHex(); return; }
    if (strcmp(g_sel, "overlay") == 0)
    {
        FieldU("Offset", pe->overlay_off, true);
        FieldU("Size", pe->overlay_size, false);
        return;
    }
    DrawOverview(pe);
}

static void DrawTree(const PeFile* pe)
{
    Node("overview", I18nGet("pe.overview"), IconFile, true);
    Node("headers", I18nGet("pe.headers"), IconCpu, true);
    if (Node("sections", I18nGet("pe.sections"), IconBox, false))
    {
        for (int i = 0; i < pe->section_n; i++)
        {
            char id[32];
            snprintf(id, sizeof(id), "sec:%d", i);
            Node(id, pe->sections[i].name[0] ? pe->sections[i].name : "(empty)", IconFile, true);
        }
        ImGui::TreePop();
    }
    if (pe->has_import && Node("imports", I18nGet("pe.imports"), IconImport, false))
    {
        for (int i = 0; i < (int)pe->imports.size(); i++)
        {
            char id[32];
            snprintf(id, sizeof(id), "imp:%d", i);
            Node(id, pe->imports[i].name.c_str(), IconFile, true);
        }
        ImGui::TreePop();
    }
    if (pe->has_export)
        Node("exports", I18nGet("pe.exports"), IconExport, true);
    if (pe->has_resource || pe->has_com || !pe->typelibs.empty())
    {
        if (Node("rsrc", I18nGet("pe.resources"), IconFolder, false))
        {
            Node("ver", I18nGet("pe.version"), IconEdit, true);
            Node("icons", I18nGet("pe.icons"), IconImage, true);
            Node("com", I18nGet("pe.com"), IconCom, true);
            ImGui::TreePop();
        }
    }
    if (pe->overlay_size)
        Node("overlay", "Overlay", IconFile, true);
}

void InspectorDraw()
{
    if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_O))
    {
        char path[MAX_PATH];
        if (AppPickOpenPe(path, MAX_PATH))
            AppOpenPath(path);
    }
    if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_S) && PeJobResult())
        DoSave(false);

    DrawMenubar();
    if (g_save_msg[0])
    {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(ThemeColAccent()), "%s", g_save_msg);
    }

    ImVec2 body = ImGui::GetContentRegionAvail();
    const float tree_w = 220.f;

    ImGui::BeginChild("pe_tree", ImVec2(tree_w, body.y), ImGuiChildFlags_Borders);
    if (PeJobBusy())
    {
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
        ImGui::TextUnformatted(I18nGet("pe.analyzing"));
        ImGui::PopStyleColor();
    }
    else if (PeJobFailed())
        ImGui::TextUnformatted(I18nGet("pe.fail"));
    else if (const PeFile* pe = PeJobResult())
    {
        static char seen[260];
        if (strcmp(seen, pe->path) != 0)
        {
            snprintf(seen, sizeof(seen), "%s", pe->path);
            snprintf(g_sel, sizeof(g_sel), "overview");
            g_save_msg[0] = 0;
            g_icon_sel = 0;
            NukeIconTex();
        }
        DrawTree(pe);
    }
    ImGui::EndChild();
    ImGui::SameLine();
    ImGui::BeginChild("pe_body", ImVec2(body.x - tree_w - 8.f, body.y), ImGuiChildFlags_None);

    if (PeJobBusy())
    {
        ImVec2 avail = ImGui::GetContentRegionAvail();
        ImVec2 c(ImGui::GetCursorScreenPos().x + avail.x * 0.5f, ImGui::GetCursorScreenPos().y + avail.y * 0.42f);
        float p = PeJobProgress();
        UiSpinner(c, 28.f, p);
        const char* msg = I18nGet("pe.analyzing");
        ImVec2 ts = ImGui::CalcTextSize(msg);
        ImGui::SetCursorScreenPos(ImVec2(c.x - ts.x * 0.5f, c.y + 40.f));
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
        ImGui::TextUnformatted(msg);
        ImGui::PopStyleColor();
        char pct[32];
        snprintf(pct, sizeof(pct), "%d%%", (int)(p * 100.f));
        ImVec2 ps = ImGui::CalcTextSize(pct);
        ImGui::SetCursorScreenPos(ImVec2(c.x - ps.x * 0.5f, c.y + 62.f));
        ImGui::TextUnformatted(pct);
    }
    else if (PeJobFailed())
    {
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColAccent()));
        ImGui::TextWrapped("%s", PeJobError()[0] ? PeJobError() : I18nGet("pe.fail"));
        ImGui::PopStyleColor();
    }
    else if (PeFile* pe = PeJobResultMut())
        DrawDetail(pe);

    ImGui::EndChild();
}
