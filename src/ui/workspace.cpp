#include "ui/workspace.h"
#include "ui/selection.h"
#include "ui/theme.h"
#include "ui/widgets.h"
#include "ui/icons.h"
#include "i18n/i18n.h"
#include "persist/settings.h"
#include "app/inspector.h"
#include "imgui.h"
#include "imgui_internal.h"

#include <float.h>
#include <stdio.h>
#include <string.h>

static const int kMaxViews = 64;

struct WsSlot
{
    WsDesc desc;
    char   id[64];
    char   title_key[64];
    char   title_lit[80];
    bool   visible;
    bool   focus;
    char   win[160];
};

static WsSlot g_slots[kMaxViews];
static int    g_n;
static bool   g_rebuild;
static bool   g_ini_loaded;
static int    g_seen_epoch = -1;

static const char* TitleOf(const WsDesc& d)
{
    if (d.title_lit && d.title_lit[0])
        return d.title_lit;
    if (d.title_key && d.title_key[0])
        return I18nGet(d.title_key);
    return d.id;
}

static void MakeWin(char* out, int cap, const WsDesc& d)
{
    snprintf(out, cap, "%s###%s", TitleOf(d), d.id);
}

static char VisKey[80];
static const char* ViewVisKey(const char* id)
{
    snprintf(VisKey, sizeof(VisKey), "ws.visible.%s", id);
    return VisKey;
}

static WsSlot* FindSlot(const char* id)
{
    if (!id || !id[0])
        return nullptr;
    for (int i = 0; i < g_n; i++)
        if (strcmp(g_slots[i].desc.id, id) == 0)
            return &g_slots[i];
    return nullptr;
}

void WorkspaceClear()
{
    g_n = 0;
    memset(g_slots, 0, sizeof(g_slots));
}

void WorkspaceRegister(const WsDesc& d)
{
    if (!d.id || !d.id[0] || !d.draw)
        return;
    WsSlot* s = FindSlot(d.id);
    if (!s)
    {
        if (g_n >= kMaxViews)
            return;
        s = &g_slots[g_n++];
        memset(s, 0, sizeof(*s));
        s->visible = SettingsLayoutGetBool(ViewVisKey(d.id), true);
    }
    s->desc = d;
    snprintf(s->id, sizeof(s->id), "%s", d.id);
    s->desc.id = s->id;
    s->title_key[0] = 0;
    s->title_lit[0] = 0;
    if (d.title_key)
    {
        snprintf(s->title_key, sizeof(s->title_key), "%s", d.title_key);
        s->desc.title_key = s->title_key;
    }
    else
        s->desc.title_key = nullptr;
    if (d.title_lit)
    {
        snprintf(s->title_lit, sizeof(s->title_lit), "%s", d.title_lit);
        s->desc.title_lit = s->title_lit;
    }
    else
        s->desc.title_lit = nullptr;
    MakeWin(s->win, (int)sizeof(s->win), s->desc);
}

void WorkspaceSetVisible(const char* id, bool vis)
{
    WsSlot* s = FindSlot(id);
    if (!s)
        return;
    s->visible = vis;
    SettingsLayoutSetBool(ViewVisKey(id), vis);
    if (vis)
        s->focus = true;
}

bool WorkspaceVisible(const char* id)
{
    WsSlot* s = FindSlot(id);
    return s && s->visible;
}

void WorkspaceFocus(const char* id)
{
    WsSlot* s = FindSlot(id);
    if (!s)
        return;
    s->visible = true;
    s->focus = true;
    SettingsLayoutSetBool(ViewVisKey(id), true);
}

const char* WorkspaceCurrentId()
{
    ImGuiWindow* w = ImGui::GetCurrentWindow();
    if (!w || !w->Name)
        return "";
    const char* p = strstr(w->Name, "###");
    return p ? p + 3 : w->Name;
}

void WorkspaceRequestRebuild()
{
    g_rebuild = true;
    g_ini_loaded = false;
    if (ImGui::GetCurrentContext())
        ImGui::ClearIniSettings();
}

void WorkspaceBindContext()
{
    g_ini_loaded = false;
    char* blob = nullptr;
    int n = SettingsLayoutGetString("imgui", nullptr, 0, nullptr);
    if (n > 1)
    {
        blob = new char[n];
        SettingsLayoutGetString("imgui", blob, n, "");
        if (blob[0])
        {
            ImGui::LoadIniSettingsFromMemory(blob, 0);
            g_ini_loaded = true;
        }
        delete[] blob;
    }
}

void WorkspaceTickSave()
{
    ImGuiIO& io = ImGui::GetIO();
    if (!io.WantSaveIniSettings)
        return;
    size_t sz = 0;
    const char* data = ImGui::SaveIniSettingsToMemory(&sz);
    if (data)
        SettingsLayoutSetString("imgui", data);
    io.WantSaveIniSettings = false;
}

static void ApplyDefaultLayout(ImGuiID dock, ImVec2 size)
{
    ImGui::DockBuilderRemoveNode(dock);
    ImGui::DockBuilderAddNode(dock, ImGuiDockNodeFlags_DockSpace);
    ImGui::DockBuilderSetNodeSize(dock, size);

    ImGuiID left = 0, right = 0, bottom = 0, center = dock;
    ImGui::DockBuilderSplitNode(center, ImGuiDir_Left, 0.22f, &left, &center);
    ImGui::DockBuilderSplitNode(center, ImGuiDir_Right, 0.26f, &right, &center);
    ImGui::DockBuilderSplitNode(center, ImGuiDir_Down, 0.28f, &bottom, &center);

    ImGuiID props = 0, evid = 0;
    ImGui::DockBuilderSplitNode(right, ImGuiDir_Down, 0.50f, &evid, &props);

    for (int i = 0; i < g_n; i++)
    {
        const WsSlot& s = g_slots[i];
        ImGuiID node = center;
        switch (s.desc.def_region)
        {
        case WsLeft:   node = left; break;
        case WsRight:  node = (strcmp(s.desc.id, "panel.evidence") == 0) ? evid : props; break;
        case WsBottom: node = bottom; break;
        case WsTop:    node = center; break;
        case WsCenter: node = center; break;
        }
        ImGui::DockBuilderDockWindow(s.win, node);
    }
    ImGui::DockBuilderFinish(dock);
}

void WorkspaceDraw(ImVec2 size)
{
    if (size.x < 1.f)
        size.x = 1.f;
    if (size.y < 1.f)
        size.y = 1.f;

    int epoch = SettingsLayoutEpoch();
    if (epoch != g_seen_epoch)
    {
        g_seen_epoch = epoch;
        for (int i = 0; i < g_n; i++)
            g_slots[i].visible = SettingsLayoutGetBool(ViewVisKey(g_slots[i].desc.id), true);
    }

    ImGuiID dock = ImGui::GetID("workspace.main");
    if (g_rebuild || (!g_ini_loaded && !ImGui::DockBuilderGetNode(dock)))
    {
        ApplyDefaultLayout(dock, size);
        g_rebuild = false;
        g_ini_loaded = true;
    }
    ImGui::DockSpace(dock, size, ImGuiDockNodeFlags_None);

    for (int i = 0; i < g_n; i++)
    {
        WsSlot& s = g_slots[i];
        if (!s.visible)
            continue;
        MakeWin(s.win, (int)sizeof(s.win), s.desc);
        if (s.focus)
        {
            ImGui::SetNextWindowFocus();
            s.focus = false;
        }
        float min_w = s.desc.utility ? ThemePx(160.f) : ThemePx(220.f);
        float min_h = s.desc.utility ? ThemePx(72.f) : ThemePx(120.f);
        ImGui::SetNextWindowSizeConstraints(ImVec2(min_w, min_h), ImVec2(FLT_MAX, FLT_MAX));
        bool open = true;
        ImGuiWindowFlags flags = ImGuiWindowFlags_None;
        if (ImGui::Begin(s.win, s.desc.closable ? &open : nullptr, flags))
        {
            if (s.desc.dirty && s.desc.dirty())
            {
                ImVec2 a = ImGui::GetWindowPos();
                ImGui::GetWindowDrawList()->AddCircleFilled(
                    ImVec2(a.x + ThemePx(8.f), a.y + ThemePx(10.f)), ThemePx(3.f), ThemeColAccent());
            }
            s.desc.draw();
        }
        ImGui::End();
        if (s.desc.closable && !open)
            WorkspaceSetVisible(s.desc.id, false);
    }
}

void WorkspaceDrawViewMenu(bool ready, bool locked)
{
    for (int i = 0; i < g_n; i++)
    {
        WsSlot& s = g_slots[i];
        bool vis = s.visible;
        if (ImGui::MenuItem(TitleOf(s.desc), nullptr, vis, ready && !locked))
            WorkspaceSetVisible(s.desc.id, !vis);
    }
    ImGui::Separator();
    if (ImGui::MenuItem(I18nGet("view.reset_workspace"), nullptr, false, !locked))
    {
        SettingsLayoutResetWorkspace();
        WorkspaceRequestRebuild();
        InspectorReloadLayout();
    }
}
