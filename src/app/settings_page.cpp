#include "app/settings_page.h"
#include "app/app.h"
#include "ui/theme.h"
#include "ui/theme_pack.h"
#include "ui/icons.h"
#include "ui/tex.h"
#include "ui/widgets.h"
#include "i18n/i18n.h"

#include "engine/engine.h"
#include "persist/settings.h"
#include "log/log.h"
#include "detect/detect.h"
#include "plugin/plugin.h"
#include "runtime/scripting.h"
#include "pe/pe.h"

#include "imgui.h"

#include <windows.h>
#include <d3d11.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

enum
{
    SettingsTabGeneral = 0,
    SettingsTabDetection,
    SettingsTabConsole,
    SettingsTabPerformance,
    SettingsTabThemes,
    SettingsTabPlugins,
    SettingsTabScripting,
};

static void DetectReapplyOpenFile()
{
    if (PeJobBusy() || !PeJobDone())
        return;
    size_t n = 0;
    uint8_t* b = PeJobBytes(&n);
    PeFile* pe = PeJobResultMut();
    if (pe && b)
        DetectApplyToPe(pe, b, n);
}

static int g_tab = SettingsTabGeneral;

static bool NavTab(const char* id, const char* label, bool selected)
{
    float w = ImGui::GetContentRegionAvail().x;
    float h = ImGui::GetFrameHeight() + ThemeSpaceXs();
    if (h < ThemePx(32.f))
        h = ThemePx(32.f);
    ImVec2 p = ImGui::GetCursorScreenPos();
    bool hit = ImGui::InvisibleButton(id, ImVec2(w, h));
    ImVec2 q = ImGui::GetItemRectMax();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    if (selected)
        dl->AddRectFilled(p, q, ThemeColHover());
    UiHandIfHovered();
    float ht = UiHoverT(ImGui::GetItemID(), ImGui::IsItemHovered() || selected);
    UiHoverSweep(p, q, ht);
    if (selected)
    {
        static float bar_y = -1.f, bar_h = 0.f;
        if (bar_y < 0.f || !UiAnimEnabled())
        {
            bar_y = p.y;
            bar_h = h;
        }
        else
        {
            float k = 1.f - expf(-18.f * ImGui::GetIO().DeltaTime);
            bar_y += (p.y - bar_y) * k;
            bar_h += (h - bar_h) * k;
        }
        dl->AddRectFilled(ImVec2(p.x, bar_y), ImVec2(p.x + ThemePx(3.f), bar_y + bar_h), ThemeColAccent());
    }
    ImVec2 ts = ImGui::CalcTextSize(label);
    dl->AddText(ImVec2(p.x + ThemeSpaceMd(), p.y + (h - ts.y) * 0.5f), selected ? ThemeColFg() : ThemeColMuted(), label);
    return hit;
}

static void LangCombo()
{
    ImGui::TextUnformatted(I18nGet("settings.language"));
    float w = ImGui::GetContentRegionAvail().x;
    if (w > 420.f)
        w = 420.f;
    ImVec2 btn_p = ImGui::GetCursorScreenPos();
    char preview[96];
    snprintf(preview, sizeof(preview), "%s", I18nName());
    if (UiButton(preview, ImVec2(w, 0)))
        ImGui::OpenPopup("lang_combo", ImGuiPopupFlags_NoReopen);
    float cs = IconSize(IconRoleXs);
    ImVec2 chev(btn_p.x + w - ThemeSpaceMd() - cs, btn_p.y + ImGui::GetFrameHeight() * 0.5f);
    IconDraw(IconChevron, chev, cs, ThemeColMuted());

    static float open_t = 0.f;
    static bool scanned = false;
    bool want = ImGui::IsPopupOpen("lang_combo");
    float dt = ImGui::GetIO().DeltaTime;
    if (want)
    {
        if (!UiAnimEnabled())
            open_t = 1.f;
        else
        {
            open_t += dt * 12.f;
            if (open_t > 1.f)
                open_t = 1.f;
        }
        if (!scanned)
        {
            I18nRescan();
            scanned = true;
        }
    }
    else
    {
        open_t = 0.f;
        scanned = false;
    }

    float ease = UiEaseOut(open_t);
    float item_h = ImGui::GetTextLineHeightWithSpacing();
    float full_h = item_h * (float)(I18nCount() > 0 ? I18nCount() : 1) + 12.f;
    ImGui::SetNextWindowPos(ImVec2(btn_p.x, btn_p.y + ImGui::GetFrameHeight() + 4.f), ImGuiCond_Appearing);
    ImGui::SetNextWindowSize(ImVec2(w, 8.f + (full_h - 8.f) * ease));
    ImGui::SetNextWindowBgAlpha(ease);
    UiPushPopupMetrics();
    if (ImGui::BeginPopup("lang_combo"))
    {
        for (int i = 0; i < I18nCount(); i++)
        {
            bool sel = strcmp(I18nEntryFile(i), I18nFile()) == 0;
            if (ImGui::Selectable(I18nEntryName(i), sel))
                I18nLoadFile(I18nEntryFile(i));
            if (sel)
                ImGui::SetItemDefaultFocus();
        }
        ImGui::EndPopup();
    }
    UiPopPopupMetrics();
}

static void DrawGeneral()
{
    if (ImFont* title = ThemeFontTitle())
        ImGui::PushFont(title);
    ImGui::TextUnformatted(I18nGet("settings.general"));
    if (ThemeFontTitle())
        ImGui::PopFont();
    ImGui::Spacing();
    LangCombo();
    ImGui::Spacing();
    bool use_emojis = SettingsGetBool("ui.use_emojis", false);
    if (UiCheckbox("use_emojis", I18nGet("settings.general.use_emojis"), &use_emojis))
        SettingsSetBool("ui.use_emojis", use_emojis);
    if (ImFont* sm = ThemeFontSmall())
        ImGui::PushFont(sm);
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x);
    ImGui::TextUnformatted(I18nGet("settings.general.use_emojis_hint"));
    ImGui::PopTextWrapPos();
    ImGui::PopStyleColor();
    if (ThemeFontSmall())
        ImGui::PopFont();
}

static void DrawDetectionSettings()
{
    if (ImFont* title = ThemeFontTitle())
        ImGui::PushFont(title);
    ImGui::TextUnformatted(I18nGet("settings.detection"));
    if (ThemeFontTitle())
        ImGui::PopFont();
    ImGui::Spacing();

    bool packers = DetectSettingPackers();
    if (UiCheckbox("det_pack", I18nGet("settings.detection.packers"), &packers))
    {
        DetectSetPackers(packers);
        DetectReapplyOpenFile();
    }
    bool compilers = DetectSettingCompilers();
    if (UiCheckbox("det_comp", I18nGet("settings.detection.compilers"), &compilers))
    {
        DetectSetCompilers(compilers);
        DetectReapplyOpenFile();
    }
    bool dotnet = DetectSettingDotNet();
    if (UiCheckbox("det_net", I18nGet("settings.detection.dotnet"), &dotnet))
    {
        DetectSetDotNet(dotnet);
        DetectReapplyOpenFile();
    }
    bool user = DetectSettingUserSigs();
    if (UiCheckbox("det_user", I18nGet("settings.detection.user"), &user))
    {
        DetectSetUserSigs(user);
        DetectReload();
        DetectReapplyOpenFile();
    }

    ImGui::Spacing();
    UiSection(I18nGet("settings.detection.manager"));
    DetectLoadStats st = DetectStats();
    ImGui::Text("%s: %d", I18nGet("settings.detection.total"), st.total);
    ImGui::Text("%s: %d", I18nGet("settings.detection.builtin"), st.builtin);
    ImGui::Text("%s: %d", I18nGet("settings.detection.user_n"), st.user);
    ImGui::Text("%s: %d", I18nGet("settings.detection.pack_n"), st.pack);
    ImGui::Text("%s: %d", I18nGet("settings.detection.invalid"), st.invalid);
    ImGui::Text("%s: %d", I18nGet("settings.detection.collisions"), st.collisions);
    ImGui::Spacing();
    ImGui::TextWrapped("%s", DetectBuiltinDir());
    ImGui::TextWrapped("%s", DetectUserDir());
    ImGui::Spacing();
    if (UiButton(I18nGet("settings.detection.reload"), ImVec2(ThemePx(200.f), 0)))
    {
        DetectReload();
        DetectReapplyOpenFile();
    }
    ImGui::SameLine();
    if (UiButton(I18nGet("settings.detection.open_user"), ImVec2(ThemePx(220.f), 0)))
        DetectOpenUserDir();
    ImGui::SameLine();
    if (UiButton(I18nGet("settings.detection.validate"), ImVec2(ThemePx(200.f), 0)))
        DetectReload();
}

static void DrawPerformance()
{
    if (ImFont* title = ThemeFontTitle())
        ImGui::PushFont(title);
    ImGui::TextUnformatted(I18nGet("settings.performance"));
    if (ThemeFontTitle())
        ImGui::PopFont();
    ImGui::Spacing();

    bool disable_anim = !SettingsGetBool("animations", true);
    if (UiCheckbox("anim", I18nGet("settings.disable_animations"), &disable_anim))
        SettingsSetBool("animations", !disable_anim);

    bool vsync = EngineVsync();
    if (UiCheckbox("vsync", I18nGet("settings.vsync"), &vsync))
        EngineSetVsync(vsync);

    bool msaa = EngineMsaaEnabled();
    if (EngineIsSoftware())
        ImGui::BeginDisabled();
    if (UiCheckbox("msaa", I18nGet("settings.msaa"), &msaa))
    {
        SettingsSetBool("msaa", msaa);
        EngineRequestMsaa(msaa);
    }
    if (EngineIsSoftware())
        ImGui::EndDisabled();
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    ImGui::TextWrapped("%s", I18nGet("settings.msaa_hint"));
    ImGui::PopStyleColor();

    ImGui::Spacing();
    ImGui::TextUnformatted(I18nGet("settings.renderer"));
    ImGui::Spacing();
    bool hw = !EngineIsSoftware();
    if (UiButton(I18nGet("settings.renderer.hardware"), ImVec2(ThemePx(160.f), 0)))
    {
        SettingsSetString("renderer", "hardware");
        EngineRequestRenderer(false);
    }
    if (hw)
    {
        ImVec2 a = ImGui::GetItemRectMin();
        ImVec2 b = ImGui::GetItemRectMax();
        ImGui::GetWindowDrawList()->AddRect(a, b, ThemeColAccent(), 0.f, 0, 2.f);
    }
    ImGui::SameLine();
    if (UiButton(I18nGet("settings.renderer.software"), ImVec2(ThemePx(160.f), 0)))
    {
        SettingsSetString("renderer", "software");
        EngineRequestRenderer(true);
    }
    if (!hw)
    {
        ImVec2 a = ImGui::GetItemRectMin();
        ImVec2 b = ImGui::GetItemRectMax();
        ImGui::GetWindowDrawList()->AddRect(a, b, ThemeColAccent(), 0.f, 0, 2.f);
    }
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    ImGui::TextWrapped("%s", I18nGet("settings.renderer.hint"));
    ImGui::PopStyleColor();
}

static void DrawConsole()
{
    if (ImFont* title = ThemeFontTitle())
        ImGui::PushFont(title);
    ImGui::TextUnformatted(I18nGet("settings.console"));
    if (ThemeFontTitle())
        ImGui::PopFont();
    ImGui::Spacing();

    UiSection(I18nGet("log.settings.visibility"));
    const struct { LogSeverity sev; const char* key; } levels[] = {
        { LogSevTrace, "log.lvl.trace" },
        { LogSevDebug, "log.lvl.debug" },
        { LogSevInfo, "log.lvl.info" },
        { LogSevSuccess, "log.lvl.success" },
        { LogSevWarning, "log.lvl.warning" },
        { LogSevError, "log.lvl.error" },
        { LogSevCritical, "log.lvl.critical" },
    };
    for (const auto& lv : levels)
    {
        bool on = LogSettingsShowSeverity(lv.sev);
        if (UiCheckbox(lv.key, I18nGet(lv.key), &on))
        {
            LogSettingsSetShowSeverity(lv.sev, on);
            LogSaveSettings();
        }
    }

    ImGui::Spacing();
    UiSection(I18nGet("log.settings.sources"));
    const struct { LogBuiltin src; const char* key; } srcs[] = {
        { LogBuiltinCore, "log.src.core" },
        { LogBuiltinUI, "log.src.ui" },
        { LogBuiltinAnalyzer, "log.src.analyzer" },
        { LogBuiltinPeAnalyzer, "log.src.pe_analyzer" },
        { LogBuiltinFile, "log.src.file" },
    };
    for (const auto& s : srcs)
    {
        bool on = LogSettingsShowBuiltin(s.src);
        if (UiCheckbox(s.key, I18nGet(s.key), &on))
        {
            LogSettingsSetShowBuiltin(s.src, on);
            LogSaveSettings();
        }
    }
    bool plug = LogSettingsShowPlugins();
    if (UiCheckbox("plug", I18nGet("log.settings.plugins"), &plug))
    {
        LogSettingsSetShowPlugins(plug);
        LogSaveSettings();
    }

    ImGui::Spacing();
    UiSection(I18nGet("log.settings.behavior"));
    bool follow = LogSettingsFollow();
    if (UiCheckbox("follow", I18nGet("log.settings.follow"), &follow))
    {
        LogSettingsSetFollow(follow);
        LogSaveSettings();
    }
    bool st = LogSettingsShowTime();
    if (UiCheckbox("st", I18nGet("log.settings.show_time"), &st))
    {
        LogSettingsSetShowTime(st);
        LogSaveSettings();
    }
    bool sl = LogSettingsShowLevel();
    if (UiCheckbox("sl", I18nGet("log.settings.show_level"), &sl))
    {
        LogSettingsSetShowLevel(sl);
        LogSaveSettings();
    }
    bool ss = LogSettingsShowSource();
    if (UiCheckbox("ss", I18nGet("log.settings.show_source"), &ss))
    {
        LogSettingsSetShowSource(ss);
        LogSaveSettings();
    }
    bool cr = LogSettingsCollapseRepeats();
    if (UiCheckbox("cr", I18nGet("log.settings.collapse"), &cr))
    {
        LogSettingsSetCollapseRepeats(cr);
        LogSaveSettings();
    }
    int max_e = LogSettingsMaxEntries();
    if (ImGui::InputInt(I18nGet("log.settings.max_entries"), &max_e))
    {
        LogSettingsSetMaxEntries(max_e);
        LogSaveSettings();
    }
}

static void DrawThemes()
{
    if (ImFont* title = ThemeFontTitle())
        ImGui::PushFont(title);
    ImGui::TextUnformatted(I18nGet("settings.themes"));
    if (ThemeFontTitle())
        ImGui::PopFont();
    ImGui::Spacing();

    ThemePackRescan();
    ID3D11ShaderResourceView* ph = TexPlaceholder();

    float cell_w = 280.f;
    float img_h = 158.f;
    float cell_h = 292.f;
    float gap = 16.f;
    float avail = ImGui::GetContentRegionAvail().x;
    int cols = (int)((avail + gap) / (cell_w + gap));
    if (cols < 1)
        cols = 1;

    for (int i = 0; i < ThemePackCount(); i++)
    {
        const ThemeInfo* t = ThemePackGet(i);
        if (!t)
            continue;
        ImGui::PushID(t->file);
        if (i % cols != 0)
            ImGui::SameLine(0.f, gap);

        bool active = strcmp(t->file, ThemePackFile()) == 0;
        ImVec2 p0 = ImGui::GetCursorScreenPos();
        bool hit = ImGui::InvisibleButton("pick", ImVec2(cell_w, cell_h));
        ImVec2 p1 = ImGui::GetItemRectMax();
        ImDrawList* dl = ImGui::GetWindowDrawList();
        dl->AddRectFilled(p0, p1, ThemeColCard());
        dl->AddRect(p0, p1, active ? ThemeColAccent() : ThemeColBorder(), 0.f, 0, active ? 2.f : 1.f);
        UiHandIfHovered();
        UiHoverSweep(p0, p1, UiHoverT(ImGui::GetItemID(), ImGui::IsItemHovered() || active));

        ImVec2 img0(p0.x + 10.f, p0.y + 10.f);
        ImVec2 img1(p0.x + cell_w - 10.f, p0.y + 10.f + img_h);
        if (ph)
        {
            dl->AddImage(ImTextureRef((void*)ph), img0, img1);
        }
        else
            dl->AddRectFilled(img0, img1, ThemeColRgb(t->preview_card));
        if (active)
            dl->AddRect(img0, img1, ThemeColAccent(), 0.f, 0, 2.f);

        float tx = p0.x + 12.f;
        float ty = img1.y + 10.f;
        dl->AddText(ImVec2(tx, ty), ThemeColFg(), t->name);
        ty += ImGui::GetTextLineHeight() + 4.f;
        char by[96];
        snprintf(by, sizeof(by), "%s %s", I18nGet("settings.made_by"), t->author);
        dl->AddText(ImVec2(tx, ty), ThemeColMuted(), by);
        ty += ImGui::GetTextLineHeight() + 2.f;
        dl->AddText(ImVec2(tx, ty), ThemeColMuted(), ThemeKindLabel(t->kind));
        ty += ImGui::GetTextLineHeight() + 6.f;
        ImVec2 wrap(p1.x - 12.f - tx, p1.y - 12.f - ty);
        if (wrap.y > 8.f)
        {
            dl->PushClipRect(ImVec2(tx, ty), ImVec2(p1.x - 12.f, p1.y - 10.f), true);
            dl->AddText(nullptr, 0.f, ImVec2(tx, ty), ThemeColMuted(), t->description, nullptr, cell_w - 24.f);
            dl->PopClipRect();
        }

        if (hit)
            ThemePackApplyFile(t->file);
        ImGui::PopID();
    }
}

static void DrawPlugins()
{
    if (ImFont* title = ThemeFontTitle())
        ImGui::PushFont(title);
    ImGui::TextUnformatted(I18nGet("settings.plugins"));
    if (ThemeFontTitle())
        ImGui::PopFont();
    ImGui::Spacing();
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    ImGui::TextWrapped("%s", I18nGet("settings.plugins_hint"));
    ImGui::PopStyleColor();
    ImGui::Spacing();
    if (UiButton(I18nGet("plugin.rescan")))
        PluginRescan();
    ImGui::Spacing();
    int n = PluginCount();
    if (n == 0)
    {
        ImGui::TextUnformatted(I18nGet("plugin.none"));
        return;
    }
    for (int i = 0; i < n; i++)
    {
        ImGui::PushID(i);
        bool on = PluginEnabled(i);
        char lab[160];
        snprintf(lab, sizeof(lab), "%s  %s", PluginName(i), PluginVersion(i));
        if (UiCheckbox("en", lab, &on) && on != PluginEnabled(i))
            PluginSetEnabled(i, on);
        ImGui::Indent();
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
        if (PluginAuthor(i)[0])
            ImGui::Text("%s %s", I18nGet("settings.made_by"), PluginAuthor(i));
        if (PluginDescription(i)[0])
            ImGui::TextWrapped("%s", PluginDescription(i));
        ImGui::TextUnformatted(PluginId(i));
        ImGui::TextUnformatted(PluginPath(i));
        if (PluginError(i)[0])
            ImGui::TextUnformatted(PluginError(i));
        ImGui::PopStyleColor();
        if (PluginHasSettings(i))
        {
            ImGui::Spacing();
            if (ImGui::CollapsingHeader(I18nGet("settings.plugins.settings")))
                PluginDrawSettings(i);
        }
        else if (PluginEnabled(i) && !PluginInited(i))
        {
            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
            ImGui::TextWrapped("%s", I18nGet("settings.plugins.settings_off"));
            ImGui::PopStyleColor();
        }
        ImGui::Unindent();
        ImGui::Spacing();
        ImGui::PopID();
    }
}

static char g_py2_path[MAX_PATH];
static char g_py3_path[MAX_PATH];
static char g_lua_path[MAX_PATH];
static bool g_script_buf;

static void LoadScriptBufs()
{
    ScriptingPyGet(2, g_py2_path, MAX_PATH);
    ScriptingPyGet(3, g_py3_path, MAX_PATH);
    ScriptingLuaGet(g_lua_path, MAX_PATH);
    g_script_buf = true;
}

static void DrawPySlot(int family)
{
    ImGui::PushID(family);
    char* buf = family == 2 ? g_py2_path : g_py3_path;
    UiSection(I18nGet(family == 2 ? "settings.scripting.python2" : "settings.scripting.python3"));

    ScriptPyInstall cur{};
    bool probed = buf[0] && ScriptingPyProbe(buf, &cur);
    bool family_ok = probed && (cur.major == family || cur.major == 0);

    char preview[192];
    if (!buf[0])
        snprintf(preview, sizeof(preview), "%s", I18nGet("settings.scripting.none"));
    else if (probed)
        snprintf(preview, sizeof(preview), "%s", cur.label);
    else
        snprintf(preview, sizeof(preview), "%s", I18nGet("settings.scripting.custom"));

    char pop[24];
    snprintf(pop, sizeof(pop), "py%d_combo", family);
    float browse_w = ThemePx(120.f);
    float w = ImGui::GetContentRegionAvail().x - browse_w - ThemeSpaceSm();
    if (w < ThemePx(160.f))
        w = ThemePx(160.f);
    if (UiButton(preview, ImVec2(w, 0)))
        ImGui::OpenPopup(pop, ImGuiPopupFlags_NoReopen);
    ImGui::SameLine();
    if (UiButton(I18nGet("settings.scripting.browse"), ImVec2(browse_w, 0)))
    {
        char picked[MAX_PATH];
        if (AppPickOpenFilter(picked, MAX_PATH,
                L"python.exe\0python.exe\0All\0*.exe\0",
                family == 2 ? L"Python 2" : L"Python 3"))
        {
            snprintf(buf, MAX_PATH, "%s", picked);
            ScriptingPySet(family, buf);
        }
    }

    if (ImGui::BeginPopup(pop))
    {
        if (ImGui::MenuItem(I18nGet("settings.scripting.none")))
        {
            buf[0] = 0;
            ScriptingPySet(family, "");
        }
        int n = ScriptingPyCount(family);
        for (int i = 0; i < n; i++)
        {
            ScriptPyInstall inst{};
            if (!ScriptingPyAt(family, i, &inst))
                continue;
            char lab[280];
            snprintf(lab, sizeof(lab), "%s  %s", inst.label, inst.path);
            bool sel = _stricmp(buf, inst.path) == 0;
            if (ImGui::MenuItem(lab, nullptr, sel))
            {
                snprintf(buf, MAX_PATH, "%s", inst.path);
                ScriptingPySet(family, buf);
            }
        }
        ImGui::EndPopup();
    }

    ImGui::SetNextItemWidth(-1.f);
    ImGui::InputText(family == 2 ? "##py2p" : "##py3p", buf, MAX_PATH);
    if (ImGui::IsItemDeactivatedAfterEdit())
        ScriptingPySet(family, buf);

    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    if (!buf[0])
        ImGui::TextUnformatted(I18nGet("settings.scripting.none"));
    else if (!probed)
        ImGui::TextUnformatted(I18nGet("settings.scripting.missing"));
    else if (!family_ok)
        ImGui::TextUnformatted(I18nGet("settings.scripting.wrong_family"));
    else
        ImGui::TextWrapped("%s  %s", cur.label, cur.path);
    ImGui::PopStyleColor();
    ImGui::PopID();
}

static void DrawScripting()
{
    if (!g_script_buf)
        LoadScriptBufs();
    if (ImFont* title = ThemeFontTitle())
        ImGui::PushFont(title);
    ImGui::TextUnformatted(I18nGet("settings.scripting"));
    if (ThemeFontTitle())
        ImGui::PopFont();
    ImGui::Spacing();
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    ImGui::TextWrapped("%s", I18nGet("settings.scripting_hint"));
    ImGui::PopStyleColor();
    ImGui::Spacing();
    char found[160];
    snprintf(found, sizeof(found), I18nGet("settings.scripting.found"),
        ScriptingPyCount(2), ScriptingPyCount(3));
    ImGui::TextUnformatted(found);
    if (UiButton(I18nGet("settings.scripting.rescan")))
        ScriptingScan();
    ImGui::Spacing();
    DrawPySlot(2);
    ImGui::Spacing();
    DrawPySlot(3);
    ImGui::Spacing();
    UiSection(I18nGet("settings.scripting.lua"));
    ImGui::PushID("lua");
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    ImGui::TextWrapped("%s", I18nGet("settings.scripting.lua_hint"));
    ImGui::PopStyleColor();
    float browse_w = ThemePx(120.f);
    float w = ImGui::GetContentRegionAvail().x - browse_w - ThemeSpaceSm();
    if (w < ThemePx(160.f))
        w = ThemePx(160.f);
    ImGui::SetNextItemWidth(w);
    ImGui::InputText("##luap", g_lua_path, MAX_PATH);
    if (ImGui::IsItemDeactivatedAfterEdit())
        ScriptingLuaSet(g_lua_path);
    ImGui::SameLine();
    if (UiButton(I18nGet("settings.scripting.browse"), ImVec2(browse_w, 0)))
    {
        char picked[MAX_PATH];
        if (AppPickOpenFilter(picked, MAX_PATH, L"lua.exe\0lua.exe\0All\0*.exe\0", L"Lua"))
        {
            snprintf(g_lua_path, MAX_PATH, "%s", picked);
            ScriptingLuaSet(g_lua_path);
        }
    }
    ImGui::PopID();
}

void SettingsPageDraw()
{
    float enter = UiEnter(0.f, 0.32f);
    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, 0.45f + 0.55f * enter);
    if (IconButton("back", IconBack, I18nGet("settings.back")))
        AppSetPage(AppSettingsReturn());
    ImGui::SameLine();
    if (ImFont* title = ThemeFontTitle())
        ImGui::PushFont(title);
    ImGui::TextUnformatted(I18nGet("settings.title"));
    if (ThemeFontTitle())
        ImGui::PopFont();

    ImGui::Spacing();
    float body_h = ImGui::GetContentRegionAvail().y;
    const float nav_w = ThemePx(176.f);
    ImGui::BeginChild("settings_nav", ImVec2(nav_w, body_h), ImGuiChildFlags_Borders);
    if (NavTab("tab_general", I18nGet("settings.general"), g_tab == SettingsTabGeneral))
        g_tab = SettingsTabGeneral;
    if (NavTab("tab_detect", I18nGet("settings.detection"), g_tab == SettingsTabDetection))
        g_tab = SettingsTabDetection;
    if (NavTab("tab_console", I18nGet("settings.console"), g_tab == SettingsTabConsole))
        g_tab = SettingsTabConsole;
    if (NavTab("tab_perf", I18nGet("settings.performance"), g_tab == SettingsTabPerformance))
        g_tab = SettingsTabPerformance;
    if (NavTab("tab_themes", I18nGet("settings.themes"), g_tab == SettingsTabThemes))
        g_tab = SettingsTabThemes;
    if (NavTab("tab_plugins", I18nGet("settings.plugins"), g_tab == SettingsTabPlugins))
        g_tab = SettingsTabPlugins;
    if (NavTab("tab_script", I18nGet("settings.scripting"), g_tab == SettingsTabScripting))
        g_tab = SettingsTabScripting;
    ImGui::EndChild();
    ImGui::SameLine();
    ImGui::BeginChild("settings_body", ImVec2(0.f, 0.f), ImGuiChildFlags_None);
    if (g_tab == SettingsTabThemes)
        DrawThemes();
    else if (g_tab == SettingsTabPlugins)
        DrawPlugins();
    else if (g_tab == SettingsTabScripting)
        DrawScripting();
    else if (g_tab == SettingsTabConsole)
        DrawConsole();
    else if (g_tab == SettingsTabDetection)
        DrawDetectionSettings();
    else if (g_tab == SettingsTabPerformance)
        DrawPerformance();
    else
        DrawGeneral();
    ImGui::EndChild();
    ImGui::PopStyleVar();
}
