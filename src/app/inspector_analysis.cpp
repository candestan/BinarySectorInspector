#include "app/inspector.h"
#include "app/inspector_internal.h"
#include "app/app.h"
#include "pe/pe.h"
#include "detect/detect.h"
#include "log/log.h"
#include "ui/theme.h"
#include "ui/icons.h"
#include "ui/widgets.h"
#include "ui/selection.h"
#include "ui/workspace.h"
#include "ui/hex_view.h"
#include "i18n/i18n.h"
#include "tool/tool.h"
#include "findings/findings.h"
#include "imgui.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <vector>
#include <string>
#include <algorithm>
#include <ctype.h>

static const char* AnalysisKindKey(AnalysisKind k)
{
    switch (k)
    {
    case AnalysisKindPayload: return "pe.analysis_kind.payload";
    case AnalysisKindArchive: return "pe.analysis_kind.archive";
    case AnalysisKindScript: return "pe.analysis_kind.script";
    case AnalysisKindRuntime: return "pe.analysis_kind.runtime";
    case AnalysisKindMetadata: return "pe.analysis_kind.metadata";
    case AnalysisKindAssembly: return "pe.analysis_kind.assembly";
    default: return "pe.analysis_kind.unknown";
    }
}

static void ArtifactVisLabel(const AnalysisArtifact& a, char* lab, int cap)
{
    if (a.flag_main)
        snprintf(lab, cap, "%s  (%s)", a.label, I18nGet("pe.analysis_main"));
    else
        snprintf(lab, cap, "%s", a.label[0] ? a.label : I18nGet("pe.analysis"));
}

static const wchar_t* ExportFilter(const char* suggest)
{
    const char* ext = suggest ? strrchr(suggest, '.') : nullptr;
    if (ext && _stricmp(ext, ".txt") == 0)
        return L"Text\0*.txt\0All\0*.*\0";
    if (ext && _stricmp(ext, ".pyc") == 0)
        return L"Python bytecode\0*.pyc\0All\0*.*\0";
    if (ext && _stricmp(ext, ".py") == 0)
        return L"Python\0*.py\0All\0*.*\0";
    if (ext && (_stricmp(ext, ".bin") == 0 || _stricmp(ext, ".dat") == 0))
        return L"Binary\0*.bin\0All\0*.*\0";
    return L"All\0*.*\0";
}

static void DumpAnalysisExport(const PeFile* pe, const AnalysisArtifact* art, const AnalysisExport* ex)
{
    if (!pe || !art || !ex)
        return;
    char path[MAX_PATH];
    const char* sug = ex->suggest[0] ? ex->suggest : "dump.bin";
    const char* title_u8 = I18nGet(ex->i18n_key[0] ? ex->i18n_key : "pe.analysis_dump_raw");
    wchar_t title[80];
    if (!MultiByteToWideChar(CP_UTF8, 0, title_u8, -1, title, 80))
        wcscpy_s(title, L"Dump");
    if (!AppPickSaveFilter(path, MAX_PATH, ExportFilter(sug), title, sug))
        return;
    size_t n = 0;
    uint8_t* b = PeJobBytes(&n);
    bool ok = AnalyzeExport(pe, b, n, art, ex, path);
    if (ok)
        UiToastPush(UiToastSuccess, I18nGet("toast.export.success.title"), I18nGet("toast.export.success.body"));
    else
        UiToastPush(UiToastError, I18nGet("toast.export.fail.title"), I18nGet("toast.export.fail.body"));
    LogInfo(LogBuiltinUI, "Dump %s: %s", art->label, ok ? path : "failed");
}

static bool WriteUtf8File(const char* path, const std::string& body)
{
    wchar_t wpath[MAX_PATH];
    if (!MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, MAX_PATH))
        return false;
    HANDLE h = CreateFileW(wpath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    DWORD wr = 0;
    BOOL ok = WriteFile(h, body.data(), (DWORD)body.size(), &wr, nullptr);
    CloseHandle(h);
    return ok && wr == (DWORD)body.size();
}

static void RunToolOnArt(const PeFile* pe, const AnalysisArtifact* art, const ToolDescriptor* tool)
{
    if (!pe || !art || !tool || !tool->run)
        return;
    size_t n = 0;
    uint8_t* b = PeJobBytes(&n);
    std::string out;
    char sug[160] = "out.txt";
    char err[64] = "tool.decompile_fail";
    if (!tool->run(art, b, n, &out, sug, (int)sizeof(sug), err, (int)sizeof(err)))
    {
        UiToastPush(UiToastError, I18nGet("toast.tool.fail.title"), I18nGet(err[0] ? err : "tool.decompile_fail"));
        return;
    }
    char path[MAX_PATH];
    const char* title_u8 = I18nGet(tool->action_i18n ? tool->action_i18n : "tool.decompile");
    wchar_t title[80];
    if (!MultiByteToWideChar(CP_UTF8, 0, title_u8, -1, title, 80))
        wcscpy_s(title, L"Export");
    if (!AppPickSaveFilter(path, MAX_PATH, ExportFilter(sug), title, sug))
        return;
    bool ok = WriteUtf8File(path, out);
    if (ok)
        UiToastPush(UiToastSuccess, I18nGet("toast.export.success.title"), I18nGet("toast.export.success.body"));
    else
        UiToastPush(UiToastError, I18nGet("toast.export.fail.title"), I18nGet("toast.export.fail.body"));
}

static void DrawArtifactExports(const PeFile* pe, const AnalysisArtifact* art)
{
    if (!pe || !art)
        return;
    int btn = 0;
    for (int i = 0; i < (int)art->exports.size(); i++)
    {
        const AnalysisExport& ex = art->exports[i];
        const char* lab = I18nGet(ex.i18n_key[0] ? ex.i18n_key : "pe.analysis_dump_raw");
        ImGui::PushID(i);
        if (btn)
            ImGui::SameLine();
        if (UiButton(lab))
            DumpAnalysisExport(pe, art, &ex);
        btn++;
        ImGui::PopID();
    }
    const ToolDescriptor* tools[8];
    int tn = ToolMatchMedia(art->media, tools, 8);
    for (int i = 0; i < tn; i++)
    {
        ImGui::PushID(1000 + i);
        if (btn)
            ImGui::SameLine();
        const char* lab = I18nGet(tools[i]->action_i18n ? tools[i]->action_i18n : "tool.action");
        if (UiButton(lab))
            RunToolOnArt(pe, art, tools[i]);
        if (ImGui::IsItemHovered())
            UiTooltip(tools[i]->description);
        btn++;
        ImGui::PopID();
    }
}

static void RebuildArtView(const AnalysisArtifact& a, char* out, int cap)
{
    if (!out || cap <= 1)
        return;
    int n = 0;
    auto put = [&](const char* fmt, ...)
    {
        if (n >= cap - 1)
            return;
        va_list ap;
        va_start(ap, fmt);
        int w = vsnprintf(out + n, (size_t)(cap - n), fmt, ap);
        va_end(ap);
        if (w > 0)
            n += w;
        if (n >= cap)
            n = cap - 1;
    };
    put("# %s\n", a.label[0] ? a.label : a.id);
    for (const AnalysisProp& p : a.props)
        put("# %s: %s\n", p.key, p.value);
    if (a.flag_main)
        put("# %s\n", I18nGet("pe.analysis_main"));
    if (!a.names.empty())
    {
        put("# names: ");
        for (size_t i = 0; i < a.names.size(); i++)
        {
            if (i)
                put(", ");
            put("%s", a.names[i].c_str());
        }
        put("\n");
    }
    put("\n");
    if (a.strings.empty())
        put("%s\n", I18nGet("pe.analysis_no_strings"));
    for (size_t i = 0; i < a.strings.size(); i++)
    {
        put("'''\n%s\n'''\n\n", a.strings[i].c_str());
        if (n > cap - 64)
        {
            put("...\n");
            break;
        }
    }
    out[n < cap ? n : cap - 1] = 0;
}

static void CopyClip(const char* s)
{
    if (s && s[0])
        ImGui::SetClipboardText(s);
}

static bool ContainsI(const char* hay, const char* needle)
{
    if (!needle || !needle[0])
        return true;
    if (!hay)
        return false;
    size_t nl = strlen(needle);
    for (const char* p = hay; *p; p++)
    {
        size_t i = 0;
        while (i < nl && p[i] &&
            tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i]))
            i++;
        if (i == nl)
            return true;
    }
    return false;
}

static uint32_t ArtifactFileOff(const PeFile* pe, const AnalysisArtifact* art)
{
    if (!art)
        return 0;
    if (art->file_off)
        return art->file_off;
    if (art->rva)
        return PeImageRvaToOff(pe, art->rva);
    return 0;
}

static void ArtifactContextMenu(const PeFile* pe, const AnalysisArtifact* art)
{
    if (!pe || !art || !UiBeginPopupContextItem("anctx"))
        return;
    if (ImGui::MenuItem(I18nGet("ui.copy"), nullptr, false, art->label[0] != 0))
        CopyClip(art->label);
    uint32_t off = ArtifactFileOff(pe, art);
    if (art->rva)
    {
        if (ImGui::MenuItem(I18nGet("ui.copy_address")))
        {
            char buf[16];
            snprintf(buf, sizeof(buf), "%08X", art->rva);
            CopyClip(buf);
        }
    }
    if (off && ImGui::MenuItem(I18nGet("pe.analysis_hex")))
        GoHex(off);
    if (!art->exports.empty())
        ImGui::Separator();
    for (int i = 0; i < (int)art->exports.size(); i++)
    {
        const AnalysisExport& ex = art->exports[i];
        const char* lab = I18nGet(ex.i18n_key[0] ? ex.i18n_key : "pe.analysis_dump_raw");
        ImGui::PushID(i);
        if (ImGui::MenuItem(lab))
            DumpAnalysisExport(pe, art, &ex);
        ImGui::PopID();
    }
    UiEndPopup();
}

static void DrawAnalysisTable(const PeFile* pe, const AnalysisArtifact* art, const AnalysisTable& tb, int idx)
{
    ImGui::PushID(idx);
    if (tb.title_i18n[0])
        ImGui::TextUnformatted(I18nGet(tb.title_i18n));
    static char filt_id[32];
    static char filter[128];
    if (strcmp(filt_id, tb.id) != 0)
    {
        snprintf(filt_id, sizeof(filt_id), "%s", tb.id);
        filter[0] = 0;
    }
    ImGui::SetNextItemWidth(-1.f);
    ImGui::InputTextWithHint("##anfilt", I18nGet("pe.analysis_search"), filter, sizeof(filter));

    std::vector<int> vis;
    vis.reserve(tb.rows.size());
    for (int i = 0; i < (int)tb.rows.size(); i++)
    {
        bool hit = filter[0] == 0;
        if (!hit)
        {
            for (int c = 0; c < tb.col_n && !hit; c++)
                hit = ContainsI(tb.rows[i].cells[c], filter);
        }
        if (hit)
            vis.push_back(i);
    }

    ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable |
        ImGuiTableFlags_Sortable | ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_BordersInnerV;
    ImVec2 sz(0.f, ImGui::GetContentRegionAvail().y);
    if (sz.y < ThemePx(120.f))
        sz.y = ThemePx(120.f);
    UiTableColDef an_cols[AnalysisTableMaxCols];
    int an_n = tb.col_n > 0 ? tb.col_n : 1;
    if (an_n > AnalysisTableMaxCols)
        an_n = AnalysisTableMaxCols;
    for (int c = 0; c < an_n; c++)
    {
        an_cols[c].id = tb.col_i18n[c][0] ? tb.col_i18n[c] : "col";
        an_cols[c].label = I18nGet(tb.col_i18n[c]);
        an_cols[c].flags = 0;
        an_cols[c].def_w = 0.f;
    }
    char an_tid[64];
    snprintf(an_tid, sizeof(an_tid), "analysis.%s", tb.id[0] ? tb.id : "table");
    if (!UiBeginPersistTable(an_tid, an_cols, an_n, flags, sz))
    {
        ImGui::PopID();
        return;
    }
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableHeadersRow();

    if (ImGuiTableSortSpecs* specs = ImGui::TableGetSortSpecs())
    {
        if (specs->SpecsCount > 0)
        {
            int col = specs->Specs[0].ColumnIndex;
            int dir = specs->Specs[0].SortDirection == ImGuiSortDirection_Descending ? -1 : 1;
            if (col < 0 || col >= tb.col_n)
                col = 0;
            std::sort(vis.begin(), vis.end(), [&](int a, int b)
            {
                int cmp = _stricmp(tb.rows[a].cells[col], tb.rows[b].cells[col]);
                if (!cmp)
                    cmp = (int)tb.rows[a].rva - (int)tb.rows[b].rva;
                return dir < 0 ? cmp > 0 : cmp < 0;
            });
        }
        specs->SpecsDirty = false;
    }

    if (vis.empty())
    {
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(I18nGet("pe.analysis_no_rows"));
    }
    else
    {
        ImGuiListClipper clip;
        clip.Begin((int)vis.size());
        while (clip.Step())
        {
            for (int n = clip.DisplayStart; n < clip.DisplayEnd; n++)
            {
                const AnalysisTableRow& row = tb.rows[vis[n]];
                ImGui::PushID(vis[n]);
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                char first[164];
                if (row.cells[0][0])
                    snprintf(first, sizeof(first), "%s", row.cells[0]);
                else
                    snprintf(first, sizeof(first), "##row");
                bool sel = ImGui::Selectable(first, false,
                    ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap);
                uint32_t off = row.file_off;
                if (!off && row.rva)
                    off = PeImageRvaToOff(pe, row.rva);
                if (sel && off)
                    GoHex(off);
                if (UiBeginPopupContextItem("rowctx"))
                {
                    if (ImGui::MenuItem(I18nGet("ui.copy_row")))
                    {
                        char line[512];
                        int p = 0;
                        for (int c = 0; c < tb.col_n && p < (int)sizeof(line) - 2; c++)
                        {
                            if (c)
                                line[p++] = '\t';
                            p += snprintf(line + p, sizeof(line) - p, "%s", row.cells[c]);
                        }
                        CopyClip(line);
                    }
                    if (row.rva && ImGui::MenuItem(I18nGet("ui.copy_address")))
                    {
                        char buf[16];
                        snprintf(buf, sizeof(buf), "%08X", row.rva);
                        CopyClip(buf);
                    }
                    if (off && ImGui::MenuItem(I18nGet("pe.analysis_hex")))
                        GoHex(off);
                    if (art && !art->exports.empty())
                    {
                        ImGui::Separator();
                        for (int e = 0; e < (int)art->exports.size(); e++)
                        {
                            const AnalysisExport& ex = art->exports[e];
                            ImGui::PushID(e);
                            if (ImGui::MenuItem(I18nGet(ex.i18n_key[0] ? ex.i18n_key : "pe.analysis_dump_raw")))
                                DumpAnalysisExport(pe, art, &ex);
                            ImGui::PopID();
                        }
                    }
                    UiEndPopup();
                }
                for (int c = 1; c < tb.col_n; c++)
                {
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(row.cells[c]);
                }
                ImGui::PopID();
            }
        }
    }
    UiEndPersistTable();
    ImGui::PopID();
}

static void DrawArtifactBody(const PeFile* pe, const AnalysisArtifact* art)
{
    if (!pe || !art)
        return;
    Field(I18nGet("pe.analysis_kind"), I18nGet(AnalysisKindKey(art->kind)));
    if (art->status_i18n[0])
    {
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColAccent()));
        ImGui::TextWrapped("%s", I18nGet(art->status_i18n));
        ImGui::PopStyleColor();
    }
    for (const AnalysisProp& p : art->props)
    {
        if (strcmp(p.key, "header") == 0 && strcmp(p.value, "mismatch") == 0)
        {
            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColAccent()));
            ImGui::TextWrapped("%s", I18nGet("pe.analysis_header_warn"));
            ImGui::PopStyleColor();
        }
        Field(p.key, p.value);
    }
    if (art->rva)
        FieldU(I18nGet("pe.col.rva"), art->rva, true);
    if (art->file_off)
        FieldU(I18nGet("pe.col.offset"), art->file_off, true, I18nGet("help.fld.rsrcoff"));
    if (art->size)
        FieldU(I18nGet("pe.col.size"), art->size, false, I18nGet("help.fld.rsrcsize"));
    DrawArtifactExports(pe, art);
    uint32_t hex_off = ArtifactFileOff(pe, art);
    if (hex_off)
    {
        ImGui::SameLine();
        ImGui::PushID(art);
        ImGui::PushID((int)hex_off);
        if (UiButton(I18nGet("pe.analysis_hex")))
            GoHex(hex_off);
        ImGui::PopID();
        ImGui::PopID();
    }
    for (int t = 0; t < (int)art->tables.size(); t++)
        DrawAnalysisTable(pe, art, art->tables[t], t);
    if (!art->names.empty() || !art->strings.empty())
    {
        static char view[65536];
        static uint32_t view_off;
        static char view_path[MAX_PATH];
        if (view_off != art->file_off || strcmp(view_path, pe->path) != 0)
        {
            RebuildArtView(*art, view, (int)sizeof(view));
            view_off = art->file_off;
            snprintf(view_path, sizeof(view_path), "%s", pe->path);
        }
        ImGui::TextUnformatted(I18nGet("pe.analysis_strings"));
        ImVec2 sz(0.f, ImGui::GetContentRegionAvail().y);
        if (sz.y < ThemePx(80.f))
            sz.y = ThemePx(80.f);
        if (ImFont* mono = ThemeFontMono())
            ImGui::PushFont(mono);
        ImGui::InputTextMultiline("##anview", view, sizeof(view), sz, ImGuiInputTextFlags_ReadOnly);
        if (ThemeFontMono())
            ImGui::PopFont();
    }
}

static int DefaultChildIndex(const AnalysisArtifact& root)
{
    for (int i = 0; i < (int)root.children.size(); i++)
    {
        if (root.children[i].flag_main)
            return i;
    }
    return root.children.empty() ? -1 : 0;
}

void DrawArtifactBundle(PeFile* pe, const AnalysisArtifact* root, bool picker)
{
    if (!pe || !root)
    {
        ImGui::TextUnformatted(I18nGet("pe.analysis_none"));
        return;
    }
    DrawArtifactBody(pe, root);
    if (!root->children.empty() && picker)
    {
        if (g_an_child < 0 || g_an_child >= (int)root->children.size())
            g_an_child = DefaultChildIndex(*root);
        char preview[176];
        ArtifactVisLabel(root->children[g_an_child], preview, (int)sizeof(preview));
        char combo_id[80];
        snprintf(combo_id, sizeof(combo_id), "%s##anmod", I18nGet("pe.analysis_item"));
        if (ImGui::BeginCombo(combo_id, preview))
        {
            for (int i = 0; i < (int)root->children.size(); i++)
            {
                char lab[192];
                ArtifactVisLabel(root->children[i], lab, (int)sizeof(lab));
                ImGui::PushID(i);
                bool sel = (g_an_child == i);
                char row[208];
                snprintf(row, sizeof(row), "%s##an%d", lab, i);
                if (ImGui::Selectable(row, sel))
                    g_an_child = i;
                if (sel)
                    ImGui::SetItemDefaultFocus();
                ImGui::PopID();
            }
            ImGui::EndCombo();
        }
        if (g_an_child >= 0 && g_an_child < (int)root->children.size())
            DrawArtifactBody(pe, &root->children[g_an_child]);
    }
}

static const AnalysisArtifact* SelectedArtifact(const PeFile* pe)
{
    if (!pe || g_an_root < 0 || g_an_root >= (int)pe->analysis.size())
        return nullptr;
    const AnalysisArtifact& root = pe->analysis[g_an_root];
    if (g_an_child < 0)
        return &root;
    if (g_an_child < (int)root.children.size())
        return &root.children[g_an_child];
    return &root;
}

static bool AnalysisSelectable(const PeFile* pe, const AnalysisArtifact* art, int root_i, int child_i)
{
    char lab[192];
    ArtifactVisLabel(*art, lab, (int)sizeof(lab));
    char row[224];
    snprintf(row, sizeof(row), "%s##an_%d_%d", lab, root_i, child_i);
    bool sel = (g_an_root == root_i && g_an_child == child_i);
    bool hit = ImGui::Selectable(row, sel);
    if (hit)
    {
        g_an_root = root_i;
        g_an_child = child_i;
        uint32_t off = ArtifactFileOff(pe, art);
        SelectionSet("artifact", art->id[0] ? art->id : lab, lab, art->label, off, 0);
    }
    ArtifactContextMenu(pe, art);
    return hit;
}

void DrawAnalysis(PeFile* pe)
{
    ImGui::TextUnformatted(I18nGet("engine.results"));
    ImGui::SameLine(0.f, ThemeSpaceXs());
    UiHelpMark(I18nGet("help.analysis"));
    ImGui::Spacing();
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    ImGui::TextWrapped("%s", I18nGet("engine.results_hint"));
    ImGui::PopStyleColor();
    ImGui::Spacing();
    if (pe->analysis.empty())
    {
        EmptyHint("engine.results_none");
        return;
    }
    if (g_an_root < 0 || g_an_root >= (int)pe->analysis.size())
        g_an_root = 0;

    const int kMaxTreeChildren = 32;
    ImGui::BeginChild("an_list", ImVec2(SplitListW(&g_split_an), 0.f), ImGuiChildFlags_Borders);

    std::vector<std::string> groups;
    for (const AnalysisArtifact& root : pe->analysis)
    {
        const char* g = root.group[0] ? root.group : I18nGet("pe.analysis");
        bool seen = false;
        for (const std::string& x : groups)
        {
            if (x == g)
            {
                seen = true;
                break;
            }
        }
        if (!seen)
            groups.push_back(g);
    }

    for (int gi = 0; gi < (int)groups.size(); gi++)
    {
        ImGui::PushID(gi);
        ImGui::SetNextItemOpen(true, ImGuiCond_Once);
        if (ImGui::TreeNodeEx("grp", ImGuiTreeNodeFlags_SpanAvailWidth | ImGuiTreeNodeFlags_FramePadding,
            "%s", groups[gi].c_str()))
        {
            for (int r = 0; r < (int)pe->analysis.size(); r++)
            {
                const AnalysisArtifact& root = pe->analysis[r];
                const char* g = root.group[0] ? root.group : I18nGet("pe.analysis");
                if (groups[gi] != g)
                    continue;
                ImGui::PushID(r);
                AnalysisSelectable(pe, &root, r, -1);
                int shown = (int)root.children.size();
                if (shown > kMaxTreeChildren)
                    shown = kMaxTreeChildren;
                for (int c = 0; c < shown; c++)
                {
                    ImGui::PushID(c);
                    ImGui::Indent(ThemeSpaceMd());
                    AnalysisSelectable(pe, &root.children[c], r, c);
                    ImGui::Unindent(ThemeSpaceMd());
                    ImGui::PopID();
                }
                if ((int)root.children.size() > kMaxTreeChildren)
                {
                    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
                    ImGui::Text("%s (%zu)", I18nGet("pe.analysis_more"), root.children.size() - (size_t)kMaxTreeChildren);
                    ImGui::PopStyleColor();
                }
                ImGui::PopID();
            }
            ImGui::TreePop();
        }
        ImGui::PopID();
    }
    ImGui::EndChild();
    SplitListHandle("an_sp", &g_split_an, "split.analysis");
    ImGui::BeginChild("an_prev", ImVec2(0.f, 0.f), ImGuiChildFlags_Borders);
    const AnalysisArtifact* cur = SelectedArtifact(pe);
    if (cur)
        DrawArtifactBody(pe, cur);
    ImGui::EndChild();
}


static const char* DetectCatKey(DetectCategory cat)
{
    switch (cat)
    {
    case DetectCatPacker: return "detect.cat.packer";
    case DetectCatProtector: return "detect.cat.protector";
    case DetectCatCompiler: return "detect.cat.compiler";
    case DetectCatToolchain: return "detect.cat.toolchain";
    case DetectCatDotNetObfuscator: return "detect.cat.dotnet";
    default: return "detect.cat.packer";
    }
}

static const char* DetectSrcKey(DetectSource src)
{
    if (src == DetectSrcUser)
        return "detect.source.user";
    if (src == DetectSrcPack)
        return "detect.source.pack";
    return "detect.source.builtin";
}

void DrawDetection(const PeFile* pe)
{
    ImGui::TextUnformatted(I18nGet("detect.title"));
    ImGui::SameLine(0.f, ThemeSpaceXs());
    UiHelpMark(I18nGet("help.detection"));
    ImGui::Spacing();
    if (pe->detections.empty())
    {
        EmptyHint("detect.none");
        return;
    }

    DetectCategory last = DetectCatCount;
    for (int i = 0; i < (int)pe->detections.size(); i++)
    {
        const DetectionResult& r = pe->detections[i];
        if (r.category != last)
        {
            last = r.category;
            ImGui::Spacing();
            UiSection(I18nGet(DetectCatKey(r.category)));
        }

        ImGui::PushID(i);
        char title[192];
        if (r.version.empty())
            snprintf(title, sizeof(title), "%s", r.product.c_str());
        else
            snprintf(title, sizeof(title), "%s  %s", r.product.c_str(), r.version.c_str());

        bool open = ImGui::TreeNodeEx("row",
            ImGuiTreeNodeFlags_SpanAvailWidth | ImGuiTreeNodeFlags_AllowOverlap | ImGuiTreeNodeFlags_FramePadding,
            "%s", title);
        if (ImGui::IsItemClicked())
            SelectionSet("detection", r.product_key.c_str(), title, r.description.c_str(), 0, 0);
        ImVec2 after = ImGui::GetCursorScreenPos();
        ImVec2 rmin = ImGui::GetItemRectMin();
        ImVec2 rmax = ImGui::GetItemRectMax();
        float conf_w = 0.f;
        const char* ckeys[] = {
            "detect.conf.low", "detect.conf.medium", "detect.conf.high", "detect.conf.exact"
        };
        for (int ci = 0; ci < 4; ci++)
        {
            float cw = UiBadgeWidth(I18nGet(ckeys[ci]));
            if (cw > conf_w)
                conf_w = cw;
        }
        float heu_w = 0.f;
        if (r.heuristic)
            heu_w = ThemeBadgeGap() + UiBadgeWidth(I18nGet("detect.heuristic"));
        float x = rmin.x + ImGui::GetTreeNodeToLabelSpacing() + ImGui::CalcTextSize(title).x + ThemeBadgeGap();
        if (x + conf_w + heu_w > rmax.x - ThemeSpaceXs())
            x = rmax.x - ThemeSpaceXs() - conf_w - heu_w;
        float bh = UiBadgeHeight();
        float by = rmin.y + (rmax.y - rmin.y - bh) * 0.5f;
        ImGui::SetCursorScreenPos(ImVec2(x, by));
        ConfBadge("conf", r.confidence);
        if (r.heuristic)
        {
            ImGui::SameLine(0.f, ThemeBadgeGap());
            UiBadge("heu", I18nGet("detect.heuristic"), ThemeColMuted(), I18nGet("detect.heuristic"));
        }
        ImGui::SetCursorScreenPos(after);

        if (!r.evidence.empty())
        {
            char sum[240];
            if (r.evidence.size() > 1)
                snprintf(sum, sizeof(sum), "%s  (+%d)", r.evidence[0].detail.c_str(), (int)r.evidence.size() - 1);
            else
                snprintf(sum, sizeof(sum), "%s", r.evidence[0].detail.c_str());
            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
            ImGui::TextWrapped("%s", sum);
            ImGui::PopStyleColor();
        }

        if (open)
        {
            if (!r.vendor.empty())
                Field(I18nGet("detect.vendor"), r.vendor.c_str());
            Field(I18nGet("detect.source"), I18nGet(DetectSrcKey(r.source)));
            Field(I18nGet("detect.category"), I18nGet(DetectCatKey(r.category)));
            FieldLabel(I18nGet("detect.confidence"));
            ImGui::SameLine(FieldLabelCol());
            ConfBadge("det_conf", r.confidence);
            if (!r.description.empty())
                Field(I18nGet("detect.evidence"), r.description.c_str());
            if (!r.reference.empty())
                Field(I18nGet("detect.reference"), r.reference.c_str());

            ImGui::TextUnformatted(I18nGet("detect.signatures"));
            for (const DetectMatch& m : r.signatures)
                ImGui::BulletText("%s  (%s)", m.signature_id.c_str(), I18nGet(DetectSrcKey(m.source)));

            if (!WorkspaceVisible("panel.evidence"))
            {
                ImGui::TextUnformatted(I18nGet("detect.evidence"));
                for (const DetectEvidence& e : r.evidence)
                {
                    if (e.detail.empty())
                        ImGui::BulletText("%s", e.condition.c_str());
                    else
                        ImGui::BulletText("%s — %s", e.condition.c_str(), e.detail.c_str());
                }
            }
            ImGui::TreePop();
        }
        ImGui::PopID();
    }
}

const char* FindingText(const char* s)
{
    if (s && (strncmp(s, "find.", 5) == 0 || strncmp(s, "finding.", 8) == 0))
        return I18nGet(s);
    return s ? s : "";
}

static const char* FindingKindKey(PeFindingKind k)
{
    switch (k)
    {
    case PeFindHardening: return "find.cat.hardening";
    case PeFindPacking: return "find.cat.packing";
    case PeFindNetwork: return "find.cat.network";
    case PeFindExecution: return "find.cat.execution";
    case PeFindInjection: return "find.cat.injection";
    case PeFindPersistence: return "find.cat.persistence";
    case PeFindIdentity: return "find.cat.identity";
    case PeFindCrypto: return "find.cat.crypto";
    default: return "find.cat.anomaly";
    }
}

static ImU32 FindingSeverityCol(FindingSeverity sev)
{
    switch (sev)
    {
    case FindSevCritical: return ThemeColRgb(0xC96A6A);
    case FindSevHigh:     return ThemeColRgb(0xD4A45A);
    case FindSevMedium:   return ThemeColRgb(0x6A9DC2);
    case FindSevLow:      return ThemeColRgb(0x8F9AA3);
    default:              return ThemeColMuted();
    }
}

static ImU32 FindingConfidenceCol(FindingConfidence conf)
{
    switch (conf)
    {
    case FindConfExact: return ThemeColSuccess();
    case FindConfHigh: return ThemeColInfo();
    case FindConfMedium: return ThemeColFg();
    default: return ThemeColMuted();
    }
}

static void DrawFindingDetail(const PeFile* pe, const FindingItem& f)
{
    ImGui::Spacing();
    UiSection(I18nGet("finding.detail.title"));
    ImGui::TextWrapped("%s", FindingText(f.explain_key));
    ImGui::Spacing();
    ImGui::TextUnformatted(I18nGet("finding.detail.matter"));
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    ImGui::TextWrapped("%s", FindingText(f.matter_key));
    ImGui::PopStyleColor();
    ImGui::Spacing();
    ImGui::TextUnformatted(I18nGet("finding.detail.severity"));
    ImGui::SameLine(0.f, ThemeBadgeGap());
    UiBadge("sev", I18nGet(FindingSeverityKey(f.severity)), FindingSeverityCol(f.severity), nullptr);
    ImGui::SameLine(0.f, ThemeSpaceMd());
    ImGui::TextUnformatted(I18nGet("finding.detail.confidence"));
    ImGui::SameLine(0.f, ThemeBadgeGap());
    UiBadge("conf", I18nGet(FindingConfidenceKey(f.confidence)), FindingConfidenceCol(f.confidence), nullptr);
    if (f.evidence_text[0] && !WorkspaceVisible("panel.evidence"))
    {
        ImGui::Spacing();
        ImGui::TextUnformatted(I18nGet("finding.detail.evidence"));
        ImGui::TextWrapped("%s", f.evidence_text);
    }
    if (f.next_key[0])
    {
        ImGui::Spacing();
        ImGui::TextUnformatted(I18nGet("finding.detail.next"));
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
        ImGui::TextWrapped("%s", FindingText(f.next_key));
        ImGui::PopStyleColor();
    }
    if (f.tech_key[0])
    {
        ImGui::Spacing();
        if (ImGui::TreeNode(I18nGet("finding.detail.technical")))
        {
            ImGui::TextWrapped("%s", FindingText(f.tech_key));
            if (f.file_off)
                ImGui::Text("0x%X", f.file_off);
            if (f.derived)
                ImGui::TextUnformatted(I18nGet("finding.detail.derived"));
            ImGui::TreePop();
        }
    }
    if (f.file_off && UiButton(I18nGet("finding.action.open_hex")))
        GoHex(f.file_off);
    (void)pe;
}

void DrawFindings(const PeFile* pe)
{
    ImGui::TextUnformatted(I18nGet("pe.findings"));
    ImGui::SameLine(0.f, ThemeSpaceXs());
    UiHelpMark(I18nGet("help.findings"));
    ImGui::Spacing();
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    ImGui::TextWrapped("%s", I18nGet("pe.findings_hint"));
    ImGui::PopStyleColor();
    ImGui::Spacing();

    const AnalysisReport& rep = pe->report;
    if (rep.findings.empty() && pe->findings.empty())
    {
        EmptyHint("pe.findings_none");
        ImGui::Spacing();
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
        ImGui::TextWrapped("%s", I18nGet("finding.summary.disclaimer"));
        ImGui::PopStyleColor();
        return;
    }

    if (rep.summary.headline_key[0])
    {
        UiSection(I18nGet("finding.summary.title"));
        ImGui::TextWrapped("%s", I18nGet(rep.summary.headline_key));
        ImGui::Spacing();
    }

    if (rep.summary.start_here_n > 0)
    {
        UiSection(I18nGet("finding.start_here"));
        float row_h = ImGui::GetFrameHeight();
        int vis = 0;
        for (int i = 0; i < rep.summary.start_here_n; i++)
        {
            int idx = rep.summary.start_here[i];
            if (idx >= 0 && idx < (int)rep.findings.size())
                vis++;
        }
        float min_h = row_h * 2.f + ThemeSpaceXs();
        float def_h = row_h * (float)vis + ThemeSpaceXs() * 2.f;
        if (def_h < min_h)
            def_h = min_h;
        if (g_split_start_here < min_h)
            g_split_start_here = def_h;
        float rest_min = ThemePx(140.f);
        float avail = ImGui::GetContentRegionAvail().y;
        float max_h = avail - rest_min - ThemeSplitHit();
        if (max_h < min_h)
            max_h = min_h;
        if (g_split_start_here > max_h)
            g_split_start_here = max_h;

        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, ThemeSpaceXs()));
        ImGui::BeginChild("start_here", ImVec2(0.f, g_split_start_here), ImGuiChildFlags_AlwaysUseWindowPadding);
        ImGui::PopStyleVar();
        for (int i = 0; i < rep.summary.start_here_n; i++)
        {
            int idx = rep.summary.start_here[i];
            if (idx < 0 || idx >= (int)rep.findings.size())
                continue;
            const FindingItem& f = rep.findings[(size_t)idx];
            ImGui::PushID(1000 + idx);
            ImVec2 p = ImGui::GetCursorScreenPos();
            float w = ImGui::GetContentRegionAvail().x;
            bool sel = (g_find_sel == idx);
            if (ImGui::Selectable("##sh", sel, 0, ImVec2(w, row_h)))
            {
                g_find_sel = idx;
                SelectionSet("finding", f.id, FindingText(f.title_key), f.evidence_text, f.file_off, 0);
            }
            UiHandIfHovered();
            ImVec2 q = ImGui::GetItemRectMax();
            float ht = UiHoverT(ImGui::GetItemID(), ImGui::IsItemHovered() || sel);
            ImDrawList* dl = ImGui::GetWindowDrawList();
            if (sel)
                dl->AddRectFilled(p, q, ThemeColSelection());
            else if (ht > 0.02f)
                dl->AddRectFilled(p, q, ThemeWithAlpha(ThemeColHover(), ht * 0.55f));
            if (sel)
                UiAccentBar(p, q, 1.f);
            float s = IconSize(IconRoleSm);
            float gap = IconTextGap();
            char line[256];
            snprintf(line, sizeof(line), "%d. %s", i + 1, FindingText(f.title_key));
            ImVec2 ts = ImGui::CalcTextSize(line);
            float text_y = p.y + (row_h - ts.y) * 0.5f;
            float icon_y = p.y + row_h * 0.5f;
            IconDraw(IconGo, ImVec2(p.x + s, icon_y), s,
                sel ? ThemeColAccent() : ThemeColMuted(), dl);
            dl->AddText(ImVec2(p.x + s * 2.f + gap, text_y), ThemeColFg(), line);
            ImGui::PopID();
        }
        ImGui::EndChild();
        SplitH("start_here_sp", &g_split_start_here, "split.start_here", 1.f, min_h, max_h);
    }

    if (!rep.findings.empty())
    {
        const std::vector<FindingItem>& items = rep.findings;
        ImGui::BeginChild("findsplit", ImVec2(0.f, 0.f), false);
        float half = UiPersistSplitW("findings", &g_split_find, 0.48f, ThemePx(80.f), ThemePx(160.f));
        ImGui::BeginChild("findlist", ImVec2(half, 0.f), true);
        ImGui::PushStyleVar(ImGuiStyleVar_CellPadding, ImVec2(ThemeSpaceSm(), ThemePx(8.f)));
        UiTableColDef find_cols[] = {
            { "severity", I18nGet("finding.col.severity"), ImGuiTableColumnFlags_WidthFixed, 120.f },
            { "category", I18nGet("pe.find_cat"), ImGuiTableColumnFlags_WidthFixed, 168.f },
            { "title", I18nGet("pe.finding"), ImGuiTableColumnFlags_WidthStretch, 0.f },
        };
        float row_h = ImGui::GetFrameHeight();
        if (row_h < UiBadgeHeight() + ThemePx(8.f))
            row_h = UiBadgeHeight() + ThemePx(8.f);
        if (UiBeginPersistTable("findings_v2", find_cols, 3,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable |
            ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_BordersInnerV))
        {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableHeadersRow();
            ImGuiListClipper clip;
            clip.Begin((int)items.size());
            while (clip.Step())
            {
                for (int i = clip.DisplayStart; i < clip.DisplayEnd; i++)
                {
                    const FindingItem& f = items[(size_t)i];
                    ImGui::PushID(i);
                    ImGui::TableNextRow(ImGuiTableRowFlags_None, row_h);
                    ImGui::TableNextColumn();
                    bool sel = (g_find_sel == i);
                    if (ImGui::Selectable("##row", sel, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap,
                        ImVec2(0.f, row_h)))
                    {
                        g_find_sel = i;
                        SelectionSet("finding", f.id, FindingText(f.title_key), f.evidence_text, f.file_off, 0);
                    }
                    ImVec2 ra = ImGui::GetItemRectMin();
                    ImVec2 rb = ImGui::GetItemRectMax();
                    ImGui::GetWindowDrawList()->AddRectFilled(ra, ImVec2(ra.x + ThemePx(3.f), rb.y),
                        ThemeWithAlpha(FindingSeverityCol(f.severity), 0.90f));
                    ImGui::SameLine(0.f, ThemeSpaceSm());
                    UiBadge("sev", I18nGet(FindingSeverityKey(f.severity)), FindingSeverityCol(f.severity), nullptr);
                    ImGui::TableNextColumn();
                    UiBadge("cat", I18nGet(FindingCategoryKey(f.category)), ThemeColMuted(), nullptr);
                    ImGui::TableNextColumn();
                    float th = ImGui::GetTextLineHeight();
                    if (row_h > th)
                        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + floorf((row_h - th) * 0.5f));
                    ImGui::TextUnformatted(FindingText(f.title_key));
                    ImGui::PopID();
                }
            }
            UiEndPersistTable();
        }
        ImGui::PopStyleVar();
        ImGui::EndChild();
        SplitListHandle("find_sp", &g_split_find, "split.findings");
        ImGui::BeginChild("finddetail", ImVec2(0.f, 0.f), true);
        if (g_find_sel >= 0 && g_find_sel < (int)items.size())
            DrawFindingDetail(pe, items[(size_t)g_find_sel]);
        else
            EmptyHint("finding.detail.pick");
        ImGui::EndChild();
        ImGui::EndChild();
        return;
    }

    // Legacy fallback
    UiTableColDef find_legacy[] = {
        { "severity", I18nGet("pe.severity"), ImGuiTableColumnFlags_WidthFixed, 72.f },
        { "category", I18nGet("pe.find_cat"), ImGuiTableColumnFlags_WidthFixed, 110.f },
        { "title", I18nGet("pe.finding"), ImGuiTableColumnFlags_WidthStretch, 0.f },
        { "why", I18nGet("pe.why"), ImGuiTableColumnFlags_WidthStretch, 0.f },
    };
    if (!UiBeginPersistTable("findings_legacy", find_legacy, 4,
        ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable |
        ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_BordersInnerV |
        ImGuiTableFlags_Sortable))
        return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableHeadersRow();
    ImGuiListClipper clip;
    clip.Begin((int)pe->findings.size());
    while (clip.Step())
    {
        for (int i = clip.DisplayStart; i < clip.DisplayEnd; i++)
        {
            const PeFinding& f = pe->findings[i];
            ImGui::PushID(i);
            const char* sev = I18nGet("pe.sev_info");
            ImU32 col = ThemeColMuted();
            if (f.sev == PeFindingNotice)
            {
                sev = I18nGet("pe.sev_notice");
                col = ThemeColFg();
            }
            if (f.sev == PeFindingWarn)
            {
                sev = I18nGet("pe.sev_warn");
                col = ThemeColWarning();
            }
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            if (ImGui::Selectable("##row", false, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap,
                ImVec2(0.f, UiBadgeHeight())))
            {
                if (f.file_off)
                    GoHex(f.file_off);
            }
            ImGui::SameLine(0.f, 0.f);
            UiBadge("sev", sev, col, nullptr);
            ImGui::TableNextColumn();
            UiBadge("cat", I18nGet(FindingKindKey(f.kind)), ThemeColMuted(), nullptr);
            ImGui::TableSetColumnIndex(2);
            {
                float bh = UiBadgeHeight();
                float th = ImGui::GetTextLineHeight();
                if (bh > th)
                    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + floorf((bh - th) * 0.5f));
                ImGui::TextUnformatted(FindingText(f.title));
            }
            ImGui::TableSetColumnIndex(3);
            {
                float bh = UiBadgeHeight();
                float th = ImGui::GetTextLineHeight();
                if (bh > th)
                    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + floorf((bh - th) * 0.5f));
                ImGui::TextUnformatted(FindingText(f.why));
            }
            if (UiBeginPopupContextItem("fctx"))
            {
                if (ImGui::MenuItem(I18nGet("ui.copy")))
                {
                    char line[512];
                    snprintf(line, sizeof(line), "%s\t%s\t%s",
                        FindingText(f.title), FindingText(f.why), f.evidence);
                    ImGui::SetClipboardText(line);
                }
                if (f.file_off && ImGui::MenuItem(I18nGet("pe.analysis_hex")))
                    GoHex(f.file_off);
                UiEndPopup();
            }
            ImGui::PopID();
        }
    }
    UiEndPersistTable();
}

