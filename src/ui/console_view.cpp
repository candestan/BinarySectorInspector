#include "ui/console_view.h"
#include "log/log.h"
#include "ui/theme.h"
#include "ui/icons.h"
#include "ui/widgets.h"
#include "i18n/i18n.h"
#include "app/app.h"

#include "imgui.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <unordered_set>
#include <vector>

enum
{
    ExportScopeAll = 0,
    ExportScopeVisible,
    ExportScopeSelected,
};

enum
{
    ExportFmtTxt = 0,
    ExportFmtCsv,
};

static char   g_search[128];
static bool   g_pause;
static bool   g_follow_local;
static bool   g_filter_sev[LogSevCount];
static int    g_filter_source;
static bool   g_filter_plugins_only;
static int    g_cache_gen = -1;
static int    g_cache_total = -1;
static std::vector<int> g_visible;
static bool   g_filter_inited;

static std::unordered_set<uint64_t> g_sel;
static uint64_t g_anchor_seq;
static int      g_export_scope = ExportScopeVisible;
static int      g_export_fmt = ExportFmtTxt;
static bool     g_open_export;
static bool     g_do_export;
static char     g_status[256];
static double   g_status_until;

static void InitFilters()
{
    if (g_filter_inited)
        return;
    for (int i = 0; i < LogSevCount; i++)
        g_filter_sev[i] = true;
    g_filter_inited = true;
}

static ImU32 SevColor(LogSeverity sev)
{
    switch (sev)
    {
    case LogSevTrace:
    case LogSevDebug:
        return ThemeColMuted();
    case LogSevInfo:
        return ThemeColFg();
    case LogSevSuccess:
        return ThemeColLogSuccess();
    case LogSevWarning:
        return ThemeColLogWarning();
    case LogSevError:
        return ThemeColLogError();
    case LogSevCritical:
        return ThemeColLogCritical();
    default:
        return ThemeColFg();
    }
}

static ImU32 SourceColor(uint32_t source_id)
{
    switch (source_id)
    {
    case LogBuiltinCore:
        return ThemeColMuted();
    case LogBuiltinUI:
        return ThemeColRgb(0x7EB6E6);
    case LogBuiltinAnalyzer:
        return ThemeColRgb(0xA894F0);
    case LogBuiltinPeAnalyzer:
        return ThemeColRgb(0x5EC4B0);
    case LogBuiltinFile:
        return ThemeColRgb(0xC4C4C4);
    default:
        if (source_id >= LogPluginBase)
            return ThemeColRgb(0xC49BD4);
        return ThemeColFg();
    }
}

static bool StrIContains(const char* hay, const char* needle)
{
    if (!needle || !needle[0])
        return true;
    if (!hay)
        return false;
    char a[512];
    char b[128];
    snprintf(a, sizeof(a), "%s", hay);
    snprintf(b, sizeof(b), "%s", needle);
    for (char* p = a; *p; p++)
        if (*p >= 'A' && *p <= 'Z')
            *p = (char)(*p - 'A' + 'a');
    for (char* p = b; *p; p++)
        if (*p >= 'A' && *p <= 'Z')
            *p = (char)(*p - 'A' + 'a');
    return strstr(a, b) != nullptr;
}

static bool PassesRuntime(const LogEntry& e)
{
    if (!g_filter_sev[e.severity])
        return false;
    if (g_filter_source != 0 && e.source_id != (uint32_t)g_filter_source)
        return false;
    if (g_filter_plugins_only && e.source_id < LogPluginBase)
        return false;
    if (g_search[0])
    {
        if (!StrIContains(e.message, g_search) &&
            !StrIContains(e.source, g_search) &&
            !StrIContains(e.level, g_search))
            return false;
    }
    return true;
}

static void PruneSelectionLocked()
{
    if (g_sel.empty())
        return;
    std::unordered_set<uint64_t> live;
    int n = LogEntryCount();
    for (int i = 0; i < n; i++)
    {
        const LogEntry* e = LogEntryAt(i);
        if (e && g_sel.find(e->seq) != g_sel.end())
            live.insert(e->seq);
    }
    g_sel.swap(live);
    if (g_anchor_seq && g_sel.find(g_anchor_seq) == g_sel.end())
        g_anchor_seq = 0;
}

static void RebuildVisible()
{
    g_visible.clear();
    LogLockEntries();
    int n = LogEntryCount();
    for (int i = 0; i < n; i++)
    {
        const LogEntry* e = LogEntryAt(i);
        if (!e)
            continue;
        if (!LogEntryPassesSettings(*e))
            continue;
        if (!PassesRuntime(*e))
            continue;
        g_visible.push_back(i);
    }
    PruneSelectionLocked();
    LogUnlockEntries();
    g_cache_total = n;
    g_cache_gen++;
}

static void EnsureVisibleCache()
{
    LogLockEntries();
    int n = LogEntryCount();
    LogUnlockEntries();
    if (g_cache_gen < 0 || n != g_cache_total)
        RebuildVisible();
}

static void ClearSelection()
{
    g_sel.clear();
    g_anchor_seq = 0;
}

static int VisIndexOfLocked(uint64_t seq)
{
    for (int i = 0; i < (int)g_visible.size(); i++)
    {
        const LogEntry* e = LogEntryAt(g_visible[i]);
        if (e && e->seq == seq)
            return i;
    }
    return -1;
}

static void SelectAllVisible()
{
    g_sel.clear();
    g_anchor_seq = 0;
    LogLockEntries();
    for (int idx : g_visible)
    {
        const LogEntry* e = LogEntryAt(idx);
        if (!e)
            continue;
        g_sel.insert(e->seq);
        if (!g_anchor_seq)
            g_anchor_seq = e->seq;
    }
    LogUnlockEntries();
}

static void ApplyLeftClickLocked(uint64_t seq, int vis_index)
{
    ImGuiIO& io = ImGui::GetIO();
    if (io.KeyCtrl)
    {
        if (g_sel.find(seq) != g_sel.end())
            g_sel.erase(seq);
        else
        {
            g_sel.insert(seq);
            g_anchor_seq = seq;
        }
        return;
    }
    if (io.KeyShift && g_anchor_seq)
    {
        int a = VisIndexOfLocked(g_anchor_seq);
        if (a >= 0 && vis_index >= 0)
        {
            g_sel.clear();
            int lo = a < vis_index ? a : vis_index;
            int hi = a > vis_index ? a : vis_index;
            for (int i = lo; i <= hi; i++)
            {
                const LogEntry* e = LogEntryAt(g_visible[i]);
                if (e)
                    g_sel.insert(e->seq);
            }
            return;
        }
    }
    g_sel.clear();
    g_sel.insert(seq);
    g_anchor_seq = seq;
}

static void CopySelection(bool message_only)
{
    if (g_sel.empty())
        return;
    std::string out;
    out.reserve(g_sel.size() * 96);
    LogLockEntries();
    int n = LogEntryCount();
    for (int i = 0; i < n; i++)
    {
        const LogEntry* e = LogEntryAt(i);
        if (!e || g_sel.find(e->seq) == g_sel.end())
            continue;
        if (!out.empty())
            out += '\n';
        if (message_only)
            out += e->message;
        else
        {
            char line[800];
            LogFormatLine(*e, line, (int)sizeof(line));
            out += line;
        }
    }
    LogUnlockEntries();
    if (!out.empty())
        ImGui::SetClipboardText(out.c_str());
}

static void Utf8ToWide(const char* s, wchar_t* w, int cap)
{
    if (!w || cap < 1)
        return;
    w[0] = 0;
    if (!s)
        return;
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, cap);
}

static void MakeSaveFilter(wchar_t* out, int cap, const char* label, const wchar_t* glob)
{
    if (!out || cap < 8)
        return;
    out[0] = 0;
    int n = MultiByteToWideChar(CP_UTF8, 0, label ? label : "", -1, out, cap);
    if (n <= 0 || n >= cap)
    {
        out[0] = 0;
        return;
    }
    int pos = n;
    for (const wchar_t* p = glob; *p && pos < cap - 2; p++)
        out[pos++] = *p;
    if (pos < cap)
        out[pos++] = 0;
    if (pos < cap)
        out[pos] = 0;
}

static void EnsureExt(char* path, int cap, const char* ext)
{
    if (!path || cap < 8 || !ext || !ext[0])
        return;
    const char* slash = strrchr(path, '\\');
    const char* slash2 = strrchr(path, '/');
    if (slash2 && (!slash || slash2 > slash))
        slash = slash2;
    const char* name = slash ? slash + 1 : path;
    const char* dot = strrchr(name, '.');
    if (dot)
    {
        if (_stricmp(dot, ext) == 0)
            return;
        if (_stricmp(dot, ".txt") == 0 || _stricmp(dot, ".csv") == 0)
        {
            char tmp[MAX_PATH];
            int keep = (int)(dot - path);
            snprintf(tmp, sizeof(tmp), "%.*s%s", keep, path, ext);
            snprintf(path, cap, "%s", tmp);
            return;
        }
    }
    size_t n = strlen(path);
    size_t el = strlen(ext);
    if (n + el + 1 <= (size_t)cap)
        memcpy(path + n, ext, el + 1);
}

static const char* FileNameOf(const char* path)
{
    if (!path)
        return "";
    const char* slash = strrchr(path, '\\');
    const char* slash2 = strrchr(path, '/');
    if (slash2 && (!slash || slash2 > slash))
        slash = slash2;
    return slash ? slash + 1 : path;
}

static void SetStatus(const char* s)
{
    snprintf(g_status, sizeof(g_status), "%s", s ? s : "");
    g_status_until = ImGui::GetTime() + 6.0;
}

static void CsvWriteField(FILE* f, const char* s)
{
    if (!s)
        s = "";
    bool quote = false;
    for (const char* p = s; *p; p++)
    {
        unsigned char c = (unsigned char)*p;
        if (c == '"' || c == ',' || c == '\n' || c == '\r')
            quote = true;
    }
    if (quote)
        fputc('"', f);
    for (const char* p = s; *p; p++)
    {
        if (*p == '"')
        {
            fputc('"', f);
            fputc('"', f);
        }
        else
            fputc((unsigned char)*p, f);
    }
    if (quote)
        fputc('"', f);
}

static bool CollectExport(int scope, std::vector<LogEntry>& out)
{
    out.clear();
    LogLockEntries();
    if (scope == ExportScopeVisible)
    {
        out.reserve(g_visible.size());
        for (int idx : g_visible)
        {
            const LogEntry* e = LogEntryAt(idx);
            if (e)
                out.push_back(*e);
        }
    }
    else
    {
        int n = LogEntryCount();
        out.reserve(scope == ExportScopeSelected ? g_sel.size() : (size_t)n);
        for (int i = 0; i < n; i++)
        {
            const LogEntry* e = LogEntryAt(i);
            if (!e)
                continue;
            if (scope == ExportScopeSelected && g_sel.find(e->seq) == g_sel.end())
                continue;
            out.push_back(*e);
        }
    }
    LogUnlockEntries();
    return !out.empty();
}

static bool WriteTxt(FILE* f, const std::vector<LogEntry>& rows)
{
    char line[800];
    for (const LogEntry& e : rows)
    {
        LogFormatLine(e, line, (int)sizeof(line));
        if (fputs(line, f) == EOF || fputc('\n', f) == EOF)
            return false;
    }
    return true;
}

static bool WriteCsv(FILE* f, const std::vector<LogEntry>& rows)
{
    static const unsigned char bom[] = { 0xEF, 0xBB, 0xBF };
    if (fwrite(bom, 1, 3, f) != 3)
        return false;
    const char* header = "Timestamp,Severity,Source,Plugin,Module,Message\n";
    if (fputs(header, f) == EOF)
        return false;
    char plugin[96];
    char module[96];
    for (const LogEntry& e : rows)
    {
        plugin[0] = 0;
        module[0] = 0;
        LogPluginParts(e.source_id, e.module_id, plugin, (int)sizeof(plugin), module, (int)sizeof(module));
        const char* source = e.source_id >= LogPluginBase ? "Plugin" : e.source;
        CsvWriteField(f, e.stamp);
        fputc(',', f);
        CsvWriteField(f, e.level);
        fputc(',', f);
        CsvWriteField(f, source);
        fputc(',', f);
        CsvWriteField(f, plugin);
        fputc(',', f);
        CsvWriteField(f, module);
        fputc(',', f);
        CsvWriteField(f, e.message);
        if (fputc('\n', f) == EOF)
            return false;
    }
    return true;
}

static void RunExport()
{
    int scope = g_export_scope;
    if (scope == ExportScopeSelected && g_sel.empty())
        scope = ExportScopeVisible;
    std::vector<LogEntry> rows;
    CollectExport(scope, rows);

    const bool csv = g_export_fmt == ExportFmtCsv;
    wchar_t filter[256];
    wchar_t title[128];
    MakeSaveFilter(filter, 256,
        I18nGet(csv ? "log.export.filter_csv" : "log.export.filter_txt"),
        csv ? L"*.csv" : L"*.txt");
    Utf8ToWide(I18nGet("log.export.save_title"), title, 128);

    char path[MAX_PATH];
    path[0] = 0;
    if (!AppPickSaveFilter(path, MAX_PATH, filter, title, csv ? "logs.csv" : "logs.txt"))
        return;
    EnsureExt(path, MAX_PATH, csv ? ".csv" : ".txt");

    wchar_t wpath[MAX_PATH];
    Utf8ToWide(path, wpath, MAX_PATH);
    FILE* f = nullptr;
    if (_wfopen_s(&f, wpath, L"wb") != 0 || !f)
    {
        LogError(LogBuiltinUI, "Log export failed to open: %s", path);
        SetStatus(I18nGet("log.export.failed"));
        UiToastPush(UiToastError, I18nGet("toast.export.fail.title"), I18nGet("toast.export.fail.body"));
        return;
    }
    setvbuf(f, nullptr, _IOFBF, 64 * 1024);
    bool ok = csv ? WriteCsv(f, rows) : WriteTxt(f, rows);
    if (ok && fflush(f) != 0)
        ok = false;
    if (ferror(f))
        ok = false;
    fclose(f);
    if (!ok)
    {
        LogError(LogBuiltinUI, "Log export write failed: %s", path);
        SetStatus(I18nGet("log.export.failed"));
        UiToastPush(UiToastError, I18nGet("toast.export.fail.title"), I18nGet("toast.export.fail.body"));
        return;
    }
    char msg[256];
    snprintf(msg, sizeof(msg), I18nGet("log.export.success"), (int)rows.size(), FileNameOf(path));
    SetStatus(msg);
    UiToastPush(UiToastSuccess, I18nGet("toast.export.success.title"), I18nGet("toast.export.success.body"));
    LogInfo(LogBuiltinUI, "%s", msg);
}

static void RowContextMenu(const LogEntry& e)
{
    if (!UiBeginPopupContextItem("logctx"))
        return;
    int n = (int)g_sel.size();
    char copy_lab[96];
    char exp_lab[96];
    if (n > 1)
    {
        snprintf(copy_lab, sizeof(copy_lab), I18nGet("log.context.copy_n"), n);
        snprintf(exp_lab, sizeof(exp_lab), I18nGet("log.context.export_n"), n);
    }
    else
    {
        snprintf(copy_lab, sizeof(copy_lab), "%s", I18nGet("log.context.copy"));
        snprintf(exp_lab, sizeof(exp_lab), "%s", I18nGet("log.context.export"));
    }
    if (ImGui::MenuItem(copy_lab, "Ctrl+C", false, n > 0))
        CopySelection(false);
    if (ImGui::MenuItem(I18nGet("log.context.copy_message"), nullptr, false, n > 0))
        CopySelection(true);
    if (ImGui::MenuItem(I18nGet("log.context.copy_full"), nullptr, false, n > 0))
        CopySelection(false);
    ImGui::Separator();
    if (ImGui::MenuItem(I18nGet("log.context.select_all"), "Ctrl+A"))
        SelectAllVisible();
    if (ImGui::MenuItem(I18nGet("log.context.clear_sel"), nullptr, false, n > 0))
        ClearSelection();
    if (ImGui::MenuItem(exp_lab, nullptr, false, n > 0))
    {
        g_export_scope = ExportScopeSelected;
        g_open_export = true;
    }
    ImGui::Separator();
    if (ImGui::MenuItem(I18nGet("log.filter_source")))
    {
        g_filter_source = (int)e.source_id;
        RebuildVisible();
    }
    if (e.source_id >= LogPluginBase && ImGui::MenuItem(I18nGet("log.filter_plugin")))
    {
        g_filter_plugins_only = true;
        RebuildVisible();
    }
    if (ImGui::MenuItem(I18nGet("log.filter_severity")))
    {
        for (int i = 0; i < LogSevCount; i++)
            g_filter_sev[i] = false;
        g_filter_sev[e.severity] = true;
        RebuildVisible();
    }
    UiEndPopup();
}

static bool ToolbarBtn(const char* id, int icon, const char* tip, bool active)
{
    bool hit = IconButton(id, icon, nullptr);
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort))
        UiTooltip(tip);
    if (active)
    {
        ImVec2 a = ImGui::GetItemRectMin();
        ImVec2 b = ImGui::GetItemRectMax();
        ImGui::GetWindowDrawList()->AddRect(a, b, ThemeColAccent(), 0.f, 0, 1.5f);
    }
    return hit;
}

static void DrawExportPopup()
{
    if (g_open_export)
    {
        ImGui::OpenPopup("log_export");
        g_open_export = false;
    }
    if (!UiBeginPopup("log_export"))
        return;
    ImGui::TextUnformatted(I18nGet("log.export.title"));
    ImGui::Separator();
    ImGui::TextUnformatted(I18nGet("log.export.scope"));
    if (ImGui::RadioButton("##scope_all", g_export_scope == ExportScopeAll))
        g_export_scope = ExportScopeAll;
    ImGui::SameLine();
    ImGui::TextUnformatted(I18nGet("log.export.scope_all"));
    if (ImGui::RadioButton("##scope_vis", g_export_scope == ExportScopeVisible))
        g_export_scope = ExportScopeVisible;
    ImGui::SameLine();
    ImGui::TextUnformatted(I18nGet("log.export.scope_visible"));
    ImGui::BeginDisabled(g_sel.empty());
    if (ImGui::RadioButton("##scope_sel", g_export_scope == ExportScopeSelected))
        g_export_scope = ExportScopeSelected;
    ImGui::SameLine();
    ImGui::TextUnformatted(I18nGet("log.export.scope_selected"));
    ImGui::EndDisabled();
    if (g_export_scope == ExportScopeSelected && g_sel.empty())
        g_export_scope = ExportScopeVisible;
    ImGui::Spacing();
    ImGui::TextUnformatted(I18nGet("log.export.format"));
    if (ImGui::RadioButton("##fmt_txt", g_export_fmt == ExportFmtTxt))
        g_export_fmt = ExportFmtTxt;
    ImGui::SameLine();
    ImGui::TextUnformatted(I18nGet("log.export.format_txt"));
    if (ImGui::RadioButton("##fmt_csv", g_export_fmt == ExportFmtCsv))
        g_export_fmt = ExportFmtCsv;
    ImGui::SameLine();
    ImGui::TextUnformatted(I18nGet("log.export.format_csv"));
    ImGui::Spacing();
    if (UiButton(I18nGet("log.export.do"), ImVec2(0.f, 0.f), 1))
    {
        g_do_export = true;
        ImGui::CloseCurrentPopup();
    }
    UiEndPopup();
}

static void HandleConsoleKeys()
{
    ImGuiIO& io = ImGui::GetIO();
    if (io.WantTextInput)
        return;
    if (ImGui::IsPopupOpen("", ImGuiPopupFlags_AnyPopup))
        return;
    bool focused = ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows) || ImGui::IsWindowFocused(0);
    if (!focused)
        return;
    if (io.KeyCtrl && !io.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_A, false))
        SelectAllVisible();
    if (io.KeyCtrl && !io.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_C, false))
        CopySelection(false);
    if (!io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_Escape, false))
        ClearSelection();
}

void ConsoleViewDraw()
{
    InitFilters();
    if (!g_follow_local)
        g_follow_local = LogSettingsFollow();

    ImGui::PushID("console");
    ImGui::BeginChild("console_root", ImVec2(0.f, 0.f), ImGuiChildFlags_None, ImGuiWindowFlags_None);

    float tb_h = ImGui::GetFrameHeight() + ThemeSpaceXs();
    ImGui::BeginChild("log_tb", ImVec2(0.f, tb_h), ImGuiChildFlags_None,
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x * 0.36f);
    if (ImGui::InputTextWithHint("##logq", I18nGet("log.search"), g_search, (int)sizeof(g_search)))
        RebuildVisible();

    ImGui::SameLine();
    if (ToolbarBtn("follow", IconGo, I18nGet("log.follow"), g_follow_local && !g_pause))
    {
        g_follow_local = !g_follow_local;
        LogSettingsSetFollow(g_follow_local);
        LogSaveSettings();
    }
    ImGui::SameLine();
    if (ToolbarBtn("pause", IconBox, I18nGet("log.pause"), g_pause))
        g_pause = !g_pause;
    ImGui::SameLine();
    if (ToolbarBtn("clear", IconClose, I18nGet("log.clear"), false))
    {
        LogClear();
        ClearSelection();
        RebuildVisible();
    }
    ImGui::SameLine();
    if (ToolbarBtn("export", IconExport, I18nGet("log.export.tooltip"), false))
        g_open_export = true;
    ImGui::SameLine();
    if (ImGui::Button(I18nGet("log.filters")))
        ImGui::OpenPopup("log_filters");
    if (UiBeginPopup("log_filters"))
    {
        ImGui::TextUnformatted(I18nGet("log.severity"));
        for (int i = 0; i < LogSevCount; i++)
        {
            char id[16];
            snprintf(id, sizeof(id), "sv%d", i);
            bool on = g_filter_sev[i];
            if (ImGui::Checkbox(id, &on))
            {
                g_filter_sev[i] = on;
                RebuildVisible();
            }
            ImGui::SameLine();
            ImGui::TextUnformatted(LogSeverityLabel((LogSeverity)i));
        }
        ImGui::Separator();
        ImGui::TextUnformatted(I18nGet("log.source"));
        const struct { int id; const char* key; } srcs[] = {
            { 0, "log.source_all" },
            { LogBuiltinCore, "log.src.core" },
            { LogBuiltinUI, "log.src.ui" },
            { LogBuiltinAnalyzer, "log.src.analyzer" },
            { LogBuiltinPeAnalyzer, "log.src.pe_analyzer" },
            { LogBuiltinFile, "log.src.file" },
        };
        for (const auto& s : srcs)
        {
            char id[16];
            snprintf(id, sizeof(id), "so%d", s.id);
            bool sel = g_filter_source == s.id;
            if (ImGui::RadioButton(id, sel))
            {
                g_filter_source = s.id;
                RebuildVisible();
            }
            ImGui::SameLine();
            ImGui::TextUnformatted(I18nGet(s.key));
        }
        bool plug = g_filter_plugins_only;
        if (ImGui::Checkbox("plugonly", &plug))
        {
            g_filter_plugins_only = plug;
            RebuildVisible();
        }
        ImGui::SameLine();
        ImGui::TextUnformatted(I18nGet("log.plugins_only"));
        if (ImGui::Button(I18nGet("log.reset_filters")))
        {
            for (int i = 0; i < LogSevCount; i++)
                g_filter_sev[i] = true;
            g_filter_source = 0;
            g_filter_plugins_only = false;
            g_search[0] = 0;
            RebuildVisible();
        }
        UiEndPopup();
    }
    if (!g_sel.empty())
    {
        ImGui::SameLine();
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
        char nsel[64];
        snprintf(nsel, sizeof(nsel), I18nGet("log.selection.count"), (int)g_sel.size());
        ImGui::TextUnformatted(nsel);
        ImGui::PopStyleColor();
    }
    if (g_status[0] && ImGui::GetTime() < g_status_until)
    {
        ImGui::SameLine();
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
        ImGui::TextUnformatted(g_status);
        ImGui::PopStyleColor();
    }
    else if (g_status[0] && ImGui::GetTime() >= g_status_until)
        g_status[0] = 0;
    ImGui::EndChild();

    DrawExportPopup();
    EnsureVisibleCache();

    ImGuiTableFlags tf = ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_Resizable | ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_BordersInnerV;
    UiTableColDef log_cols[] = {
        { "time", I18nGet("log.col.time"), ImGuiTableColumnFlags_WidthFixed, LogSettingsShowTime() ? 64.f : 0.f },
        { "level", I18nGet("log.col.level"), ImGuiTableColumnFlags_WidthFixed, LogSettingsShowLevel() ? 52.f : 0.f },
        { "source", I18nGet("log.col.source"), ImGuiTableColumnFlags_WidthFixed, LogSettingsShowSource() ? 140.f : 0.f },
        { "message", I18nGet("log.col.message"), ImGuiTableColumnFlags_WidthStretch, 0.f },
    };
    if (!UiBeginPersistTable("console", log_cols, 4, tf))
    {
        HandleConsoleKeys();
        ImGui::EndChild();
        ImGui::PopID();
        if (g_do_export)
        {
            g_do_export = false;
            RunExport();
        }
        return;
    }

    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableHeadersRow();

    if (ImFont* mono = ThemeFontMono())
        ImGui::PushFont(mono);

    if (g_visible.empty())
    {
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::TableNextColumn();
        ImGui::TableNextColumn();
        ImGui::TableNextColumn();
        if (LogEntryCount() == 0)
            UiEmpty(I18nGet("log.empty"));
        else
            UiEmpty(I18nGet("log.no_match"));
    }
    else
    {
        bool at_bottom = ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 4.f;
        LogLockEntries();
        ImGuiListClipper clip;
        clip.Begin((int)g_visible.size());
        while (clip.Step())
        {
            for (int vi = clip.DisplayStart; vi < clip.DisplayEnd; vi++)
            {
                int idx = g_visible[vi];
                const LogEntry* e = LogEntryAt(idx);
                if (!e)
                    continue;
                const uint64_t seq = e->seq;
                const bool selected = g_sel.find(seq) != g_sel.end();
                ImGui::PushID((int)seq);
                ImGui::TableNextRow();
                ImGuiSelectableFlags sflags = ImGuiSelectableFlags_SpanAllColumns |
                    ImGuiSelectableFlags_AllowOverlap;
                ImGui::TableNextColumn();
                char sid[32];
                snprintf(sid, sizeof(sid), "##r%llu", (unsigned long long)seq);
                ImGui::Selectable(sid, selected, sflags);
                if (ImGui::IsItemClicked(ImGuiMouseButton_Left))
                    ApplyLeftClickLocked(seq, vi);
                if (ImGui::IsItemClicked(ImGuiMouseButton_Right))
                {
                    if (g_sel.find(seq) == g_sel.end())
                    {
                        g_sel.clear();
                        g_sel.insert(seq);
                        g_anchor_seq = seq;
                    }
                }
                bool hovered = ImGui::IsItemHovered();
                ImU32 bg = 0;
                if (selected && hovered)
                    bg = ThemeWithAlpha(ThemeColAccent(), 0.28f);
                else if (selected)
                    bg = ThemeWithAlpha(ThemeColAccent(), 0.16f);
                else if (hovered)
                    bg = ThemeColHoverA(0.55f);
                if (bg)
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, bg);
                if (LogSettingsShowTime())
                {
                    ImGui::SameLine(0.f, 0.f);
                    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
                    ImGui::TextUnformatted(e->time);
                    ImGui::PopStyleColor();
                }
                if (LogSettingsShowLevel())
                {
                    ImGui::TableNextColumn();
                    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(SevColor(e->severity)));
                    ImGui::TextUnformatted(e->level);
                    ImGui::PopStyleColor();
                }
                else
                    ImGui::TableNextColumn();
                if (LogSettingsShowSource())
                {
                    ImGui::TableNextColumn();
                    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(SourceColor(e->source_id)));
                    ImGui::TextUnformatted(e->source);
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("%s", e->source);
                    ImGui::PopStyleColor();
                }
                else
                    ImGui::TableNextColumn();
                ImGui::TableNextColumn();
                ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColFg()));
                if (e->repeat > 1)
                {
                    char msg[540];
                    snprintf(msg, sizeof(msg), "%s  x%u", e->message, e->repeat);
                    ImGui::TextUnformatted(msg);
                }
                else
                    ImGui::TextUnformatted(e->message);
                ImGui::PopStyleColor();
                RowContextMenu(*e);
                ImGui::PopID();
            }
        }
        LogUnlockEntries();
        if (!g_pause && g_follow_local && at_bottom)
            ImGui::SetScrollHereY(1.f);
    }

    if (ThemeFontMono())
        ImGui::PopFont();
    UiEndPersistTable();

    HandleConsoleKeys();
    ImGui::EndChild();
    ImGui::PopID();

    LogLockEntries();
    if (LogEntryCount() != g_cache_total)
        RebuildVisible();
    LogUnlockEntries();

    if (g_do_export)
    {
        g_do_export = false;
        RunExport();
    }
}
