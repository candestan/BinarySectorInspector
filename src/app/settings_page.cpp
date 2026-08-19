#include "app/settings_page.h"
#include "app/app.h"
#include "app/inspector.h"
#include "ui/theme.h"
#include "ui/theme_pack.h"
#include "ui/icons.h"
#include "ui/tex.h"
#include "ui/widgets.h"
#include "ui/workspace.h"
#include "i18n/i18n.h"

#include "engine/engine.h"
#include "persist/settings.h"
#include "persist/paths.h"
#include "log/log.h"
#include "detect/detect.h"
#include "plugin/plugin.h"
#include "runtime/scripting.h"
#include "pe/pe.h"
#include "app/version.h"

#include "imgui.h"

#include <windows.h>
#include <shellapi.h>
#include <winhttp.h>
#include <d3d11.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <thread>
#include <vector>
#include <mutex>
#include <atomic>

#pragma comment(lib, "winhttp.lib")

enum
{
    SettingsTabGeneral = 0,
    SettingsTabDetection,
    SettingsTabConsole,
    SettingsTabPerformance,
    SettingsTabThemes,
    SettingsTabPlugins,
    SettingsTabScripting,
    SettingsTabAbout,
    SettingsTabLicenses,
#ifdef _DEBUG
    SettingsTabTest,
#endif
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
    if (UiBeginPopup("lang_combo"))
    {
        for (int i = 0; i < I18nCount(); i++)
        {
            bool sel = strcmp(I18nEntryFile(i), I18nFile()) == 0;
            if (ImGui::Selectable(I18nEntryName(i), sel))
                I18nLoadFile(I18nEntryFile(i));
            if (sel)
                ImGui::SetItemDefaultFocus();
        }
        UiEndPopup();
    }
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
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    ImGui::TextUnformatted(I18nGet("settings.layout.title"));
    if (ImFont* sm = ThemeFontSmall())
        ImGui::PushFont(sm);
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x);
    ImGui::TextUnformatted(I18nGet("settings.layout.hint"));
    ImGui::PopTextWrapPos();
    ImGui::PopStyleColor();
    if (ThemeFontSmall())
        ImGui::PopFont();
    ImGui::Spacing();
    if (UiButton(I18nGet("settings.layout.reset")))
        ImGui::OpenPopup("reset_layout");
    if (UiBeginPopup("reset_layout"))
    {
        ImGui::TextWrapped("%s", I18nGet("settings.layout.reset_confirm"));
        ImGui::Spacing();
        if (UiButton(I18nGet("settings.layout.reset_ok"), ImVec2(0.f, 0.f), 1))
        {
            SettingsLayoutResetWorkspace();
            WorkspaceRequestRebuild();
            InspectorReloadLayout();
            UiToastPush(UiToastInfo, I18nGet("toast.layout.reset"), nullptr);
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (UiButton(I18nGet("settings.back")))
            ImGui::CloseCurrentPopup();
        UiEndPopup();
    }
}

static void DrawEngineBrand(DetectEngineKind kind, ImDrawList* dl, ImVec2 img0, ImVec2 img1)
{
    ImVec2 c((img0.x + img1.x) * 0.5f, (img0.y + img1.y) * 0.5f);
    if (kind == DetectEngineInternal)
    {
        dl->AddRectFilled(img0, img1, ThemeColInput());
        IconDrawRole(IconImage, c, IconRoleXl, ThemeColMuted(), dl);
        return;
    }
    dl->AddRectFilledMultiColor(img0, img1,
        IM_COL32(28, 36, 58, 255), IM_COL32(40, 28, 64, 255),
        IM_COL32(52, 36, 88, 255), IM_COL32(24, 48, 72, 255));
    ImFont* font = ThemeFontTitle() ? ThemeFontTitle() : ImGui::GetFont();
    float fs = ImGui::GetFontSize() * 1.15f;
    const char* label = "KUARA";
    ImVec2 ts = font->CalcTextSizeA(fs, 1e9f, 0.f, label);
    dl->AddText(font, fs, ImVec2(c.x - ts.x * 0.5f, c.y - ts.y * 0.5f), IM_COL32(220, 220, 255, 255), label);
}

static void DrawEngineInfoRow(const char* label, const char* value)
{
    float x = ImGui::GetCursorPosX();
    float y = ImGui::GetCursorPosY();
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    ImGui::TextUnformatted(label);
    ImGui::PopStyleColor();
    ImGui::SetCursorPos(ImVec2(x + ThemePx(140.f), y));
    ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x);
    ImGui::TextUnformatted(value && value[0] ? value : "-");
    ImGui::PopTextWrapPos();
}

static bool DrawEngineOption(DetectEngineKind kind, DetectEngineKind active, float card_w, float card_h, float img_h)
{
    DetectEngineInfo info{};
    DetectEngineFillInfo(kind, &info);
    ImGui::PushID((int)kind);
    ImVec2 p0 = ImGui::GetCursorScreenPos();
    bool hit = ImGui::InvisibleButton("engine_pick", ImVec2(card_w, card_h));
    ImVec2 p1 = ImGui::GetItemRectMax();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const bool selected = active == kind;
    dl->AddRectFilled(p0, p1, ThemeColCard());
    dl->AddRect(p0, p1, selected ? ThemeColAccent() : ThemeColBorder(), 0.f, 0, selected ? 2.f : 1.f);
    UiHandIfHovered();
    UiHoverSweep(p0, p1, UiHoverT(ImGui::GetItemID(), ImGui::IsItemHovered() || selected));

    ImVec2 img0(p0.x + 10.f, p0.y + 10.f);
    ImVec2 img1(p0.x + card_w - 10.f, p0.y + 10.f + img_h);
    DrawEngineBrand(kind, dl, img0, img1);
    dl->AddRect(img0, img1, selected ? ThemeColAccent() : ThemeColBorder(), 0.f, 0, 1.f);

    float tx = p0.x + 12.f;
    float ty = img1.y + 10.f;
    dl->AddText(ImVec2(tx, ty), ThemeColFg(), I18nGet(info.name_key));
    ty += ImGui::GetTextLineHeight() + 4.f;
    dl->PushClipRect(ImVec2(tx, ty), ImVec2(p1.x - 12.f, p1.y - 10.f), true);
    dl->AddText(nullptr, 0.f, ImVec2(tx, ty), ThemeColMuted(), I18nGet(info.desc_key), nullptr, card_w - 24.f);
    dl->PopClipRect();

    if (hit && !selected)
    {
        DetectSetEngine(kind);
        DetectReapplyOpenFile();
        UiToastPush(UiToastInfo, I18nGet("toast.engine.title"), I18nGet("toast.engine.body"));
    }
    ImGui::PopID();
    return hit && !selected;
}

static void DrawDetectionEngineSettings()
{
    UiSection(I18nGet("settings.detection.engine"));
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    ImGui::TextWrapped("%s", I18nGet("settings.detection.engine.hint"));
    ImGui::PopStyleColor();
    ImGui::Spacing();

    DetectEngineKind active = DetectEngineActive();
    const float card_w = ThemePx(280.f);
    const float img_h = ThemePx(120.f);
    const float card_h = ThemePx(220.f);
    const float gap = ThemePx(16.f);
    DrawEngineOption(DetectEngineKuara, active, card_w, card_h, img_h);
    ImGui::SameLine(0.f, gap);
    DrawEngineOption(DetectEngineInternal, active, card_w, card_h, img_h);
    ImGui::Spacing();

    DetectEngineInfo info{};
    DetectEngineFillInfo(active, &info);
    UiSection(I18nGet("settings.detection.engine.info"));
    float info_w = card_w * 2.f + gap;
    if (info_w > ImGui::GetContentRegionAvail().x)
        info_w = ImGui::GetContentRegionAvail().x;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(ThemeSpaceMd(), ThemeSpaceMd()));
    ImGui::BeginChild("engine_info", ImVec2(info_w, 0.f),
        ImGuiChildFlags_Borders | ImGuiChildFlags_AlwaysUseWindowPadding | ImGuiChildFlags_AutoResizeY);
    float img = ThemePx(128.f);
    ImVec2 img0 = ImGui::GetCursorScreenPos();
    ImGui::Dummy(ImVec2(img, img));
    ImVec2 img1 = ImGui::GetItemRectMax();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    DrawEngineBrand(active, dl, img0, img1);
    dl->AddRect(img0, img1, ThemeColBorder());
    ImGui::SameLine(0.f, ThemeSpaceMd());
    ImGui::BeginGroup();
    ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x);
    if (ImFont* t = ThemeFontTitle())
        ImGui::PushFont(t);
    ImGui::TextUnformatted(I18nGet(info.name_key));
    if (ThemeFontTitle())
        ImGui::PopFont();
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    ImGui::TextWrapped("%s", I18nGet(info.desc_key));
    if (!info.brand_url || !info.brand_url[0])
        ImGui::TextWrapped("%s", I18nGet("settings.detection.engine.image_pending"));
    ImGui::PopStyleColor();
    ImGui::PopTextWrapPos();
    ImGui::EndGroup();
    ImGui::Spacing();
    DrawEngineInfoRow(I18nGet("settings.detection.engine.id"), info.id);
    DrawEngineInfoRow(I18nGet("settings.detection.engine.version"), info.version);
    DrawEngineInfoRow(I18nGet("settings.detection.engine.author"), info.author);
    DrawEngineInfoRow(I18nGet("settings.detection.engine.status"),
        I18nGet(info.ready ? "settings.detection.engine.ready" : "settings.detection.engine.not_ready"));
    ImGui::EndChild();
    ImGui::PopStyleVar();
}

static void DrawDetectionSettings()
{
    if (ImFont* title = ThemeFontTitle())
        ImGui::PushFont(title);
    ImGui::TextUnformatted(I18nGet("settings.detection"));
    if (ThemeFontTitle())
        ImGui::PopFont();
    ImGui::Spacing();

    DrawDetectionEngineSettings();
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
        DetectLoadStats after = DetectStats();
        char body[192];
        snprintf(body, sizeof(body), I18nGet("toast.sig.reload.body"),
            after.total, after.invalid, after.collisions);
        UiToastType ty = (after.invalid > 0 || after.collisions > 0) ? UiToastWarning : UiToastSuccess;
        UiToastPush(ty, I18nGet("toast.sig.reload.title"), body);
    }
    ImGui::SameLine();
    if (UiButton(I18nGet("settings.detection.open_user"), ImVec2(ThemePx(220.f), 0)))
    {
        if (DetectOpenUserDir())
            UiToastPush(UiToastSuccess, I18nGet("toast.sig.folder.ok.title"), DetectUserDir());
        else
            UiToastPush(UiToastError, I18nGet("toast.sig.folder.fail.title"),
                I18nGet("toast.sig.folder.fail.body"));
    }
    ImGui::SameLine();
    if (UiButton(I18nGet("settings.detection.validate"), ImVec2(ThemePx(200.f), 0)))
    {
        DetectReload();
        DetectReapplyOpenFile();
        DetectLoadStats after = DetectStats();
        char body[192];
        if (after.invalid == 0 && after.collisions == 0)
        {
            snprintf(body, sizeof(body), I18nGet("toast.sig.validate.ok.body"), after.total);
            UiToastPush(UiToastSuccess, I18nGet("toast.sig.validate.ok.title"), body);
        }
        else
        {
            snprintf(body, sizeof(body), I18nGet("toast.sig.validate.bad.body"),
                after.invalid, after.collisions, after.total);
            UiToastPush(after.invalid > 0 ? UiToastError : UiToastWarning,
                I18nGet("toast.sig.validate.bad.title"), body);
        }
    }
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
        {
            ThemePackApplyFile(t->file);
            UiToastPush(UiToastInfo, I18nGet("toast.theme.title"), I18nGet("toast.theme.body"));
        }
        ImGui::PopID();
    }
}

static char g_plug_q[128];
static int  g_plug_status; // 0 all, 1 enabled, 2 disabled
static char g_plug_auth[32][80];
static uint8_t g_plug_auth_on[32];
static int  g_plug_auth_n;
static char g_plug_auth_sig[512];

static void LowerAscii(char* s)
{
    for (; s && *s; s++)
    {
        if (*s >= 'A' && *s <= 'Z')
            *s = (char)(*s - 'A' + 'a');
    }
}

static bool PlugHay(const char* hay, const char* needle)
{
    if (!needle || !needle[0])
        return true;
    if (!hay)
        return false;
    char h[320];
    char n[160];
    snprintf(h, sizeof(h), "%s", hay);
    snprintf(n, sizeof(n), "%s", needle);
    LowerAscii(h);
    LowerAscii(n);
    return strstr(h, n) != nullptr;
}

static void PlugSyncAuthors()
{
    char sig[512];
    sig[0] = 0;
    int n = PluginCount();
    for (int i = 0; i < n; i++)
    {
        const char* a = PluginAuthor(i);
        if (!a[0])
            continue;
        size_t used = strlen(sig);
        if (used + 2 >= sizeof(sig))
            break;
        if (sig[0])
        {
            sig[used] = '|';
            sig[used + 1] = 0;
            used++;
        }
        snprintf(sig + used, sizeof(sig) - used, "%s", a);
    }
    if (strcmp(sig, g_plug_auth_sig) == 0)
        return;
    snprintf(g_plug_auth_sig, sizeof(g_plug_auth_sig), "%s", sig);
    g_plug_auth_n = 0;
    memset(g_plug_auth_on, 1, sizeof(g_plug_auth_on));
    for (int i = 0; i < n && g_plug_auth_n < 32; i++)
    {
        const char* a = PluginAuthor(i);
        if (!a[0])
            continue;
        int have = 0;
        for (int j = 0; j < g_plug_auth_n; j++)
        {
            if (_stricmp(g_plug_auth[j], a) == 0)
            {
                have = 1;
                break;
            }
        }
        if (have)
            continue;
        snprintf(g_plug_auth[g_plug_auth_n], sizeof(g_plug_auth[0]), "%s", a);
        g_plug_auth_on[g_plug_auth_n] = 1;
        g_plug_auth_n++;
    }
}

static bool PlugAuthorAllowed(const char* author)
{
    if (g_plug_auth_n <= 0)
        return true;
    int any_on = 0;
    int any_off = 0;
    for (int i = 0; i < g_plug_auth_n; i++)
    {
        if (g_plug_auth_on[i])
            any_on = 1;
        else
            any_off = 1;
    }
    if (!any_off)
        return true;
    if (!any_on)
        return false;
    if (!author || !author[0])
        return false;
    for (int i = 0; i < g_plug_auth_n; i++)
    {
        if (g_plug_auth_on[i] && _stricmp(g_plug_auth[i], author) == 0)
            return true;
    }
    return false;
}

static bool PlugMatches(int i)
{
    bool on = PluginEnabled(i);
    if (g_plug_status == 1 && !on)
        return false;
    if (g_plug_status == 2 && on)
        return false;
    if (!PlugAuthorAllowed(PluginAuthor(i)))
        return false;
    if (!g_plug_q[0])
        return true;
    if (PlugHay(PluginName(i), g_plug_q))
        return true;
    if (PlugHay(PluginId(i), g_plug_q))
        return true;
    if (PlugHay(PluginAuthor(i), g_plug_q))
        return true;
    return false;
}

static bool PlugFilterDirty()
{
    if (g_plug_status != 0)
        return true;
    for (int i = 0; i < g_plug_auth_n; i++)
    {
        if (!g_plug_auth_on[i])
            return true;
    }
    return false;
}

static void PlugResetFilters()
{
    g_plug_status = 0;
    for (int i = 0; i < g_plug_auth_n; i++)
        g_plug_auth_on[i] = 1;
}

static void DrawPluginFilterPopup()
{
    if (!UiBeginPopup("plugin_filter"))
        return;
    ImGui::TextUnformatted(I18nGet("plugin.filter_status"));
    if (ImGui::RadioButton(I18nGet("plugin.filter_all"), g_plug_status == 0))
        g_plug_status = 0;
    ImGui::SameLine();
    if (ImGui::RadioButton(I18nGet("plugin.filter_enabled"), g_plug_status == 1))
        g_plug_status = 1;
    ImGui::SameLine();
    if (ImGui::RadioButton(I18nGet("plugin.filter_disabled"), g_plug_status == 2))
        g_plug_status = 2;
    if (g_plug_auth_n > 0)
    {
        ImGui::Spacing();
        ImGui::TextUnformatted(I18nGet("plugin.filter_authors"));
        float h = ImGui::GetTextLineHeightWithSpacing() * (float)(g_plug_auth_n > 6 ? 6 : g_plug_auth_n) + 8.f;
        ImGui::BeginChild("authlist", ImVec2(ThemePx(280.f), h), ImGuiChildFlags_Borders);
        for (int i = 0; i < g_plug_auth_n; i++)
        {
            ImGui::PushID(i);
            bool on = g_plug_auth_on[i] != 0;
            if (UiCheckbox("a", g_plug_auth[i], &on))
                g_plug_auth_on[i] = on ? 1 : 0;
            ImGui::PopID();
        }
        ImGui::EndChild();
    }
    ImGui::Spacing();
    if (UiButton(I18nGet("plugin.filter_reset")))
        PlugResetFilters();
    UiEndPopup();
}

static void DrawPluginCard(int i, float cell_w, float cell_h, float img_h)
{
    ImGui::PushID(i);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.f, 0.f));
    ImGui::BeginChild("card", ImVec2(cell_w, cell_h), ImGuiChildFlags_None,
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    ImGui::PopStyleVar();

    ImVec2 p0 = ImGui::GetWindowPos();
    ImVec2 p1(p0.x + cell_w, p0.y + cell_h);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    bool on = PluginEnabled(i);
    dl->AddRectFilled(p0, p1, ThemeColCard());
    dl->AddRect(p0, p1, on ? ThemeColBorder() : ThemeColBorderA(0.55f), 0.f, 0, 1.f);
    UiHoverSweep(p0, p1, UiHoverT(ImGui::GetID("card"), ImGui::IsWindowHovered()));

    float pad = ThemeSpaceSm();
    ImVec2 img0(p0.x + pad, p0.y + pad);
    ImVec2 img1(p0.x + cell_w - pad, p0.y + pad + img_h);
    dl->AddRectFilled(img0, img1, ThemeColInput());
    int tw = 0, th = 0;
    void* srv = PluginCoverSrv(i, &tw, &th);
    if (!srv)
        srv = TexPlaceholder();
    if (srv)
        dl->AddImage(ImTextureRef((void*)srv), img0, img1);
    else
        IconDrawRole(IconBox, ImVec2((img0.x + img1.x) * 0.5f, (img0.y + img1.y) * 0.5f),
            IconRoleLg, ThemeColMuted());

    float tx = p0.x + pad;
    float ty = img1.y + pad;
    float foot_h = ImGui::GetFrameHeight() + pad;
    float body_bottom = p1.y - foot_h - pad;
    char head[160];
    snprintf(head, sizeof(head), "%s  %s", PluginName(i), PluginVersion(i));
    dl->AddText(ImVec2(tx, ty), ThemeColFg(), head);
    ty += ImGui::GetTextLineHeight() + 3.f;
    if (PluginAuthor(i)[0])
    {
        char by[120];
        snprintf(by, sizeof(by), "%s %s", I18nGet("settings.made_by"), PluginAuthor(i));
        dl->AddText(ImVec2(tx, ty), ThemeColMuted(), by);
        ty += ImGui::GetTextLineHeight() + 6.f;
    }
    if (PluginDescription(i)[0])
    {
        dl->PushClipRect(ImVec2(tx, ty), ImVec2(p1.x - pad, body_bottom), true);
        dl->AddText(nullptr, 0.f, ImVec2(tx, ty), ThemeColMuted(), PluginDescription(i), nullptr, cell_w - pad * 2.f);
        dl->PopClipRect();
    }
    if (PluginError(i)[0])
        dl->AddText(ImVec2(tx, body_bottom - ImGui::GetTextLineHeight()), ThemeColDanger(), PluginError(i));

    ImGui::SetCursorScreenPos(ImVec2(p0.x + pad, p1.y - foot_h));
    bool en = on;
    if (UiCheckbox("en", I18nGet("plugin.enabled"), &en) && en != on)
        PluginSetEnabled(i, en);
    char modal[160];
    snprintf(modal, sizeof(modal), "%s###pset", PluginName(i));
    if (PluginHasSettings(i))
    {
        ImGui::SameLine();
        if (UiButton(I18nGet("settings.plugins.settings")))
            ImGui::OpenPopup(modal);
    }
    else if (PluginEnabled(i) && !PluginInited(i))
    {
        ImGui::SameLine();
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
        ImGui::TextUnformatted(I18nGet("settings.plugins.settings_off"));
        ImGui::PopStyleColor();
    }

    UiPushPopupMetrics();
    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSizeConstraints(ImVec2(ThemePx(280.f), 0.f), ImVec2(ThemePx(420.f), ThemePx(520.f)));
    if (ImGui::BeginPopupModal(modal, nullptr, ImGuiWindowFlags_AlwaysAutoResize))
    {
        UiPopupFadePush();
        ImGui::SetNextItemWidth(-1.f);
        PluginDrawSettings(i);
        ImGui::Spacing();
        if (UiButton(I18nGet("settings.back"), ImVec2(-1.f, 0.f)))
            ImGui::CloseCurrentPopup();
        UiEndPopup();
    }
    else
        UiPopPopupMetrics();

    ImGui::EndChild();
    ImGui::PopID();
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
    PlugSyncAuthors();
    ImGui::Spacing();
    ImGui::SetNextItemWidth(-ThemePx(196.f));
    ImGui::InputTextWithHint("##plugq", I18nGet("plugin.search_hint"), g_plug_q, (int)sizeof(g_plug_q));
    ImGui::SameLine();
    if (UiButton(I18nGet("plugin.filter"), ImVec2(ThemePx(88.f), 0.f), PlugFilterDirty() ? 1 : 0))
        ImGui::OpenPopup("plugin_filter");
    DrawPluginFilterPopup();
    ImGui::SameLine();
    if (UiButton(I18nGet("plugin.rescan")))
        PluginRescan();
    ImGui::Spacing();

    int n = PluginCount();
    if (n == 0)
    {
        ImGui::TextUnformatted(I18nGet("plugin.none"));
        return;
    }
    int vis[32];
    int nv = 0;
    for (int i = 0; i < n && nv < 32; i++)
    {
        if (PlugMatches(i))
            vis[nv++] = i;
    }
    if (nv == 0)
    {
        ImGui::TextUnformatted(I18nGet("plugin.none_match"));
        return;
    }

    float min_w = ThemePx(260.f);
    float gap = ThemePx(16.f);
    float avail = ImGui::GetContentRegionAvail().x;
    int cols = (int)((avail + gap) / (min_w + gap));
    if (cols < 1)
        cols = 1;

    ImGui::PushStyleVar(ImGuiStyleVar_CellPadding, ImVec2(gap * 0.5f, gap * 0.5f));
    if (ImGui::BeginTable("plug_grid", cols,
            ImGuiTableFlags_SizingStretchSame | ImGuiTableFlags_NoSavedSettings | ImGuiTableFlags_NoPadOuterX))
    {
        for (int k = 0; k < nv; k++)
        {
            ImGui::TableNextColumn();
            float cell_w = ImGui::GetContentRegionAvail().x;
            float img_h = cell_w * 0.5f;
            if (img_h < ThemePx(96.f))
                img_h = ThemePx(96.f);
            if (img_h > ThemePx(180.f))
                img_h = ThemePx(180.f);
            float cell_h = img_h + ThemePx(156.f);
            DrawPluginCard(vis[k], cell_w, cell_h, img_h);
        }
        ImGui::EndTable();
    }
    ImGui::PopStyleVar();
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

    if (UiBeginPopup(pop))
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
        UiEndPopup();
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

static void OpenUrl(const char* url)
{
    if (url && url[0])
        ShellExecuteA(nullptr, "open", url, nullptr, nullptr, SW_SHOWNORMAL);
}

static bool AboutLink(const char* label, const char* url)
{
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColAccent()));
    ImGui::TextUnformatted(label);
    ImGui::PopStyleColor();
    bool hit = ImGui::IsItemClicked();
    if (ImGui::IsItemHovered())
        ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
    if (hit && url)
        OpenUrl(url);
    return hit;
}

static void AboutRow(const char* label, const char* value)
{
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    ImGui::TextUnformatted(label);
    ImGui::PopStyleColor();
    ImGui::SameLine(ThemePx(148.f));
    ImGui::TextUnformatted(value && value[0] ? value : "-");
}

static bool HttpGetHttps(const wchar_t* host, const wchar_t* path, std::vector<uint8_t>* out)
{
    if (!host || !path || !out)
        return false;
    out->clear();
    HINTERNET ses = WinHttpOpen(L"BinarySectorInspector", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ses)
        return false;
    WinHttpSetTimeouts(ses, 2500, 2500, 2500, 4000);
    HINTERNET con = WinHttpConnect(ses, host, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!con)
    {
        WinHttpCloseHandle(ses);
        return false;
    }
    HINTERNET req = WinHttpOpenRequest(con, L"GET", path, nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!req)
    {
        WinHttpCloseHandle(con);
        WinHttpCloseHandle(ses);
        return false;
    }
    BOOL ok = WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (ok)
        ok = WinHttpReceiveResponse(req, nullptr);
    DWORD status = 0;
    DWORD slen = sizeof(status);
    if (ok)
        ok = WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &slen, WINHTTP_NO_HEADER_INDEX);
    if (!ok || status != 200)
    {
        WinHttpCloseHandle(req);
        WinHttpCloseHandle(con);
        WinHttpCloseHandle(ses);
        return false;
    }
    const size_t kMax = 2 * 1024 * 1024;
    for (;;)
    {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(req, &avail))
            break;
        if (!avail)
            break;
        if (out->size() + avail > kMax)
        {
            out->clear();
            break;
        }
        size_t at = out->size();
        out->resize(at + avail);
        DWORD rd = 0;
        if (!WinHttpReadData(req, out->data() + at, avail, &rd))
        {
            out->clear();
            break;
        }
        out->resize(at + rd);
    }
    WinHttpCloseHandle(req);
    WinHttpCloseHandle(con);
    WinHttpCloseHandle(ses);
    return out->size() > 32;
}

enum
{
    AuthorIdle = 0,
    AuthorLoading,
    AuthorReady,
    AuthorFail
};

static std::atomic<int> g_author_st{ AuthorIdle };
static std::mutex g_author_mu;
static std::vector<uint8_t> g_author_bytes;
static ID3D11ShaderResourceView* g_author_srv;
static int g_author_w;
static int g_author_h;

static void AuthorKick()
{
    int expect = AuthorIdle;
    if (!g_author_st.compare_exchange_strong(expect, AuthorLoading))
        return;
    std::thread([] {
        std::vector<uint8_t> buf;
        bool ok = HttpGetHttps(L"avatars.githubusercontent.com", L"/u/74156337", &buf);
        if (ok)
        {
            std::lock_guard<std::mutex> lock(g_author_mu);
            g_author_bytes.swap(buf);
            g_author_st.store(AuthorReady);
        }
        else
            g_author_st.store(AuthorFail);
    }).detach();
}

static ID3D11ShaderResourceView* AuthorTex()
{
    AuthorKick();
    int st = g_author_st.load();
    if (st == AuthorReady && !g_author_srv)
    {
        std::vector<uint8_t> bytes;
        {
            std::lock_guard<std::mutex> lock(g_author_mu);
            bytes.swap(g_author_bytes);
        }
        if (!bytes.empty() && !TexLoadMemory(bytes.data(), bytes.size(), &g_author_srv, &g_author_w, &g_author_h))
            g_author_st.store(AuthorFail);
    }
    return g_author_srv;
}

static float LysepSpinAngle()
{
    const float pi = 3.14159265f;
    if (!UiAnimEnabled())
        return 0.f;
    const float pause = 1.85f;
    const float spin = 0.36f;
    const float cycle = pause + spin;
    double t = ImGui::GetTime();
    int n = (int)floor(t / (double)cycle);
    float phase = (float)(t - (double)n * (double)cycle);
    float base = (float)(n & 3) * (pi * 0.5f);
    if (phase <= pause)
        return base;
    float u = (phase - pause) / spin;
    if (u < 0.f)
        u = 0.f;
    if (u > 1.f)
        u = 1.f;
    u = u * u * (3.f - 2.f * u);
    return base + u * (pi * 0.5f);
}

// Mark geometry matches assets/lysep_logo.svg (inner disc + two 90deg rings + two ~33deg wedges).
static void DrawLysepMark(ImDrawList* dl, ImVec2 c, float r, float ang, ImU32 col)
{
    if (!dl || r < 4.f)
        return;
    const float pi = 3.14159265f;
    dl->AddCircleFilled(c, r * 0.303f, col, 48);
    const float mid = r * 0.825f;
    const float thick = r * 0.351f;
    const float arcs[][2] = {
        { -pi, -pi * 0.5f },
        { 0.f, pi * 0.5f },
        { 2.0785f, 2.6631f },
        { -1.0532f, -0.4663f },
    };
    for (int i = 0; i < 4; i++)
    {
        int segs = (arcs[i][1] - arcs[i][0] > 1.f) ? 20 : 12;
        dl->PathArcTo(c, mid, arcs[i][0] + ang, arcs[i][1] + ang, segs);
        dl->PathStroke(col, 0, thick);
    }
}

static void DrawLysepBrand()
{
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    ImGui::TextUnformatted(I18nGet("about.sponsor"));
    ImGui::PopStyleColor();
    ImGui::Spacing();

    const ImU32 orange = IM_COL32(0xFD, 0x70, 0x00, 255);
    float r = ThemePx(18.f);
    ImFont* title = ThemeFontTitle();
    if (title)
        ImGui::PushFont(title);
    ImFont* font = ImGui::GetFont();
    float fs = ImGui::GetFontSize();
    ImVec2 lysep = font->CalcTextSizeA(fs, 1e9f, 0.f, "LYSEP");
    ImVec2 corp = font->CalcTextSizeA(fs, 1e9f, 0.f, "CORP");
    float gap = ThemePx(10.f);
    float h = r * 2.f;
    if (h < fs)
        h = fs;
    float w = r * 2.f + gap + lysep.x + corp.x;
    ImVec2 p = ImGui::GetCursorScreenPos();
    bool hit = ImGui::InvisibleButton("lysep_brand", ImVec2(w, h));
    UiHandIfHovered();
    if (hit)
        OpenUrl("https://lysep.com/");
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 c(p.x + r, p.y + h * 0.5f);
    DrawLysepMark(dl, c, r, LysepSpinAngle(), orange);
    float tx = p.x + r * 2.f + gap;
    float ty = p.y + (h - fs) * 0.5f;
    dl->AddText(font, fs, ImVec2(tx, ty), ThemeColFg(), "LYSEP");
    dl->AddText(font, fs, ImVec2(tx + lysep.x, ty), orange, "CORP");
    if (title)
        ImGui::PopFont();
}

static void DrawAbout()
{
    if (ImFont* title = ThemeFontTitle())
        ImGui::PushFont(title);
    ImGui::TextUnformatted(I18nGet("settings.about"));
    if (ThemeFontTitle())
        ImGui::PopFont();
    ImGui::Spacing();

    ID3D11ShaderResourceView* pic = AuthorTex();
    if (pic)
    {
        float side = ThemePx(72.f);
        ImVec2 p0 = ImGui::GetCursorScreenPos();
        ImGui::Dummy(ImVec2(side, side));
        ImDrawList* dl = ImGui::GetWindowDrawList();
        ImVec2 p1(p0.x + side, p0.y + side);
        dl->AddImageRounded(ImTextureRef((void*)pic), p0, p1, ImVec2(0, 0), ImVec2(1, 1), IM_COL32_WHITE, side * 0.5f);
        ImGui::SameLine();
    }
    ImGui::BeginGroup();
    if (ImFont* t = ThemeFontTitle())
        ImGui::PushFont(t);
    ImGui::TextUnformatted("candestan");
    if (ThemeFontTitle())
        ImGui::PopFont();
    AboutLink("github.com/candestan", "https://github.com/candestan");
    AboutLink("github.com/candestan/BinarySectorInspector", "https://github.com/candestan/BinarySectorInspector");
    ImGui::EndGroup();

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    AboutRow(I18nGet("about.version"), VersionString());
    char build[64];
    snprintf(build, sizeof(build), "%d", VersionBuildNumber());
    AboutRow(I18nGet("about.build"), build);
    AboutRow(I18nGet("about.full"), VersionFull());
    AboutRow(I18nGet("about.config"), VersionConfig());
    AboutRow(I18nGet("about.commit"), VersionGitShort());
    AboutRow(I18nGet("about.commit_full"), VersionGitCommit());
    AboutRow(I18nGet("about.built"), VersionBuildTime());
    if (VersionGitDirty())
    {
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
        ImGui::TextWrapped("%s", I18nGet("about.dirty"));
        ImGui::PopStyleColor();
    }

    ImGui::Spacing();
    if (UiButton(I18nGet("about.copy")))
    {
        char clip[512];
        snprintf(clip, sizeof(clip),
            "BinarySectorInspector %s\nBuild %d (%s)\nCommit %s\n%s\nhttps://github.com/candestan/BinarySectorInspector\n",
            VersionFull(), VersionBuildNumber(), VersionConfig(), VersionGitCommit(), VersionBuildTime());
        ImGui::SetClipboardText(clip);
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    DrawLysepBrand();

    ImGui::Spacing();
    ImGui::TextUnformatted(I18nGet("about.license"));
    ImGui::SameLine();
    AboutLink(I18nGet("about.license_name"), "https://github.com/candestan/BinarySectorInspector/blob/main/LICENSE");
}

static void DrawLicenses()
{
    if (ImFont* title = ThemeFontTitle())
        ImGui::PushFont(title);
    ImGui::TextUnformatted(I18nGet("settings.third_party"));
    if (ThemeFontTitle())
        ImGui::PopFont();
    ImGui::Spacing();
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    ImGui::TextWrapped("%s", I18nGet("third_party.hint"));
    ImGui::PopStyleColor();
    ImGui::Spacing();

    struct Third
    {
        const char* name;
        const char* license;
        const char* url;
    };
    static const Third k[] = {
        { "Dear ImGui", "MIT", "https://github.com/ocornut/imgui/blob/master/LICENSE.txt" },
        { "imgui_club (memory editor)", "MIT", "https://github.com/ocornut/imgui_club/blob/master/LICENSE.txt" },
        { "FreeType", "FTL", "https://github.com/freetype/freetype/blob/master/docs/FTL.TXT" },
        { "nlohmann/json", "MIT", "https://github.com/nlohmann/json/blob/develop/LICENSE.MIT" },
    };
    if (ImGui::BeginTable("tp", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_BordersInnerV))
    {
        ImGui::TableSetupColumn(I18nGet("third_party.name"), ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn(I18nGet("third_party.license"), ImGuiTableColumnFlags_WidthFixed, ThemePx(88.f));
        ImGui::TableSetupColumn(I18nGet("third_party.link"), ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        for (const Third& t : k)
        {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(t.name);
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(t.license);
            ImGui::TableNextColumn();
            ImGui::PushID(t.name);
            AboutLink(t.url, t.url);
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    ImGui::Spacing();
    ImGui::TextWrapped("%s", I18nGet("third_party.snippets"));
}

#ifdef _DEBUG
static int g_test_toast_i = -1;
static double g_test_toast_next;

static void DrawTest()
{
    if (ImFont* title = ThemeFontTitle())
        ImGui::PushFont(title);
    ImGui::TextUnformatted(I18nGet("settings.test"));
    if (ThemeFontTitle())
        ImGui::PopFont();
    ImGui::Spacing();
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(ThemeColMuted()));
    ImGui::TextWrapped("%s", I18nGet("settings.test_hint"));
    ImGui::PopStyleColor();
    ImGui::Spacing();
    UiSection(I18nGet("settings.test.toasts"));
    if (UiButton(I18nGet("settings.test.send_all"), ImVec2(ThemePx(220.f), 0.f), 1))
    {
        g_test_toast_i = 0;
        g_test_toast_next = 0.0;
    }
}
#endif

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
    if (NavTab("tab_about", I18nGet("settings.about"), g_tab == SettingsTabAbout))
        g_tab = SettingsTabAbout;
    if (NavTab("tab_lic", I18nGet("settings.third_party"), g_tab == SettingsTabLicenses))
        g_tab = SettingsTabLicenses;
#ifdef _DEBUG
    if (NavTab("tab_test", I18nGet("settings.test"), g_tab == SettingsTabTest))
        g_tab = SettingsTabTest;
#endif
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
    else if (g_tab == SettingsTabAbout)
        DrawAbout();
    else if (g_tab == SettingsTabLicenses)
        DrawLicenses();
#ifdef _DEBUG
    else if (g_tab == SettingsTabTest)
        DrawTest();
#endif
    else
        DrawGeneral();
    ImGui::EndChild();
#ifdef _DEBUG
    if (g_test_toast_i >= 0)
    {
        double now = ImGui::GetTime();
        if (now >= g_test_toast_next)
        {
            static const struct { UiToastType type; const char* title; const char* body; } k[] = {
                { UiToastSuccess, "toast.test.success.title", "toast.test.success.body" },
                { UiToastInfo,    "toast.test.info.title",    "toast.test.info.body" },
                { UiToastWarning, "toast.test.warning.title", "toast.test.warning.body" },
                { UiToastError,   "toast.test.error.title",   "toast.test.error.body" },
            };
            const int n = (int)(sizeof(k) / sizeof(k[0]));
            if (g_test_toast_i < n)
            {
                UiToastPush(k[g_test_toast_i].type, I18nGet(k[g_test_toast_i].title), I18nGet(k[g_test_toast_i].body));
                g_test_toast_i++;
                if (g_test_toast_i >= n)
                    g_test_toast_i = -1;
                else
                    g_test_toast_next = now + 0.9;
            }
            else
                g_test_toast_i = -1;
        }
    }
#endif
    ImGui::PopStyleVar();
}
