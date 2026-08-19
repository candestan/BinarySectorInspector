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
    bool   pinned;
    char   win[160];
};

static WsSlot g_slots[kMaxViews];
static int    g_n;
static bool   g_rebuild;
static bool   g_ini_loaded;
static bool   g_loaded_blob;
static bool   g_center_checked;
static int    g_seen_epoch = -1;
static ImGuiID g_node_left;
static ImGuiID g_node_right;
static ImGuiID g_node_bottom;
static ImGuiID g_node_center;

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
static char PinKey[80];
static const char* ViewVisKey(const char* id)
{
    snprintf(VisKey, sizeof(VisKey), "ws.visible.%s", id);
    return VisKey;
}

static const char* ViewPinKey(const char* id)
{
    snprintf(PinKey, sizeof(PinKey), "ws.pin.%s", id);
    return PinKey;
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

static bool CanPinSlot(const WsSlot& s)
{
    return s.desc.def_region != WsCenter;
}

static ImGuiID CentralNodeId()
{
    if (g_node_center)
        return g_node_center;
    if (!ImGui::GetCurrentContext())
        return 0;
    ImGuiID dock = ImGui::GetID("workspace.main");
    ImGuiDockNode* c = ImGui::DockBuilderGetCentralNode(dock);
    return c ? c->ID : 0;
}

static ImGuiID DefaultNodeForSlot(const WsSlot& s)
{
    switch (s.desc.def_region)
    {
    case WsLeft:   return g_node_left ? g_node_left : CentralNodeId();
    case WsRight:  return g_node_right ? g_node_right : CentralNodeId();
    case WsBottom: return g_node_bottom ? g_node_bottom : CentralNodeId();
    case WsTop:
    case WsCenter:
    default:
        return CentralNodeId();
    }
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
        s->visible = SettingsLayoutGetBool(ViewVisKey(d.id), d.default_open);
        s->pinned = SettingsLayoutGetBool(ViewPinKey(d.id), false);
    }
    s->desc = d;
    if (!CanPinSlot(*s))
        s->pinned = false;
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
    {
        s->focus = true;
        // If this window was opened after the default layout pass, dock it to its
        // default region instead of letting ImGui spawn it as a floating window.
        if (ImGui::GetCurrentContext())
        {
            ImGuiID node = DefaultNodeForSlot(*s);
            if (node)
                ImGui::DockBuilderDockWindow(s->win, node);
        }
    }
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

    // Same docking behavior as WorkspaceSetVisible(true).
    if (ImGui::GetCurrentContext())
    {
        ImGuiID node = DefaultNodeForSlot(*s);
        if (node)
            ImGui::DockBuilderDockWindow(s->win, node);
    }
}

void WorkspaceDockToCenter(const char* id)
{
    WsSlot* s = FindSlot(id);
    if (!s || !ImGui::GetCurrentContext())
        return;
    ImGuiID dock = ImGui::GetID("workspace.main");
    ImGuiDockNode* c = ImGui::DockBuilderGetCentralNode(dock);
    if (!c)
        return;
    ImGui::DockBuilderDockWindow(s->win, c->ID);
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
    g_loaded_blob = false;
    g_center_checked = false;
    for (int i = 0; i < g_n; i++)
    {
        g_slots[i].visible = g_slots[i].desc.default_open;
        SettingsLayoutSetBool(ViewVisKey(g_slots[i].desc.id), g_slots[i].visible);
    }
    if (ImGui::GetCurrentContext())
        ImGui::ClearIniSettings();
    g_node_left = g_node_right = g_node_bottom = g_node_center = 0;
}

void WorkspaceBindContext()
{
    g_ini_loaded = false;
    g_loaded_blob = false;
    g_center_checked = false;
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
            g_loaded_blob = true;
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
    ImGui::DockBuilderSplitNode(center, ImGuiDir_Left, 0.16f, &left, &center);
    ImGui::DockBuilderSplitNode(center, ImGuiDir_Right, 0.24f, &right, &center);
    ImGui::DockBuilderSplitNode(center, ImGuiDir_Down, 0.22f, &bottom, &center);

    ImGuiID props = 0, evid = 0;
    ImGui::DockBuilderSplitNode(right, ImGuiDir_Down, 0.50f, &evid, &props);
    g_node_left = left;
    g_node_right = props;
    g_node_bottom = bottom;
    g_node_center = center;

    for (int i = 0; i < g_n; i++)
    {
        const WsSlot& s = g_slots[i];
        if (!s.desc.default_open)
            continue;
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
            g_slots[i].visible = SettingsLayoutGetBool(ViewVisKey(g_slots[i].desc.id),
                g_slots[i].desc.default_open);
    }

    ImGuiID dock = ImGui::GetID("workspace.main");
    if (g_rebuild || (!g_ini_loaded && !ImGui::DockBuilderGetNode(dock)))
    {
        ApplyDefaultLayout(dock, size);
        g_rebuild = false;
        g_ini_loaded = true;
        g_loaded_blob = false;
    }
    ImGui::DockSpace(dock, size, ImGuiDockNodeFlags_None);

    if (g_loaded_blob && !g_center_checked)
    {
        ImGuiDockNode* c = ImGui::DockBuilderGetCentralNode(dock);
        if (c && c->Size.x > 8.f)
        {
            g_center_checked = true;
            if (c->Size.x < ThemePx(240.f))
            {
                for (int i = 0; i < g_n; i++)
                {
                    g_slots[i].visible = g_slots[i].desc.default_open;
                    SettingsLayoutSetBool(ViewVisKey(g_slots[i].desc.id), g_slots[i].visible);
                }
                ApplyDefaultLayout(dock, size);
            }
        }
    }

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
        if (s.pinned)
        {
            ImGuiID node = DefaultNodeForSlot(s);
            if (node)
                ImGui::DockBuilderDockWindow(s.win, node);
        }
        float min_w = s.desc.min_w > 0.f ? ThemePx(s.desc.min_w) : (s.desc.utility ? ThemePx(160.f) : ThemePx(280.f));
        float min_h = s.desc.min_h > 0.f ? ThemePx(s.desc.min_h) : (s.desc.utility ? ThemePx(96.f) : ThemePx(120.f));
        ImGui::SetNextWindowSizeConstraints(ImVec2(min_w, min_h), ImVec2(FLT_MAX, FLT_MAX));
        bool open = true;
        bool can_pin = CanPinSlot(s);
        if (!can_pin && s.pinned)
        {
            s.pinned = false;
            SettingsLayoutSetBool(ViewPinKey(s.desc.id), false);
        }
        ImGuiWindowFlags flags = ImGuiWindowFlags_None;
        if (s.pinned)
            flags |= ImGuiWindowFlags_NoMove;
        bool can_close = s.desc.closable && !s.pinned;
        if (ImGui::Begin(s.win, can_close ? &open : nullptr, flags))
        {
            if (can_pin)
            {
                ImGui::PushID(s.desc.id);
                float btn = ImGui::GetFrameHeight();
                float x = ImGui::GetCursorPosX();
                float w = ImGui::GetContentRegionAvail().x;
                ImGui::SetCursorPosX(x + w - btn);
                if (IconButton("pin", s.pinned ? IconCheck : IconPin, nullptr))
                {
                    s.pinned = !s.pinned;
                    SettingsLayoutSetBool(ViewPinKey(s.desc.id), s.pinned);
                    if (s.pinned)
                    {
                        s.visible = true;
                        SettingsLayoutSetBool(ViewVisKey(s.desc.id), true);
                        ImGuiID node = DefaultNodeForSlot(s);
                        if (node)
                            ImGui::DockBuilderDockWindow(s.win, node);
                    }
                }
                if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort))
                    UiTooltip(s.pinned ? I18nGet("view.unpin") : I18nGet("view.pin"));
                ImGui::PopID();
            }
            if (s.desc.dirty && s.desc.dirty())
            {
                ImVec2 a = ImGui::GetWindowPos();
                ImGui::GetWindowDrawList()->AddCircleFilled(
                    ImVec2(a.x + ThemePx(8.f), a.y + ThemePx(10.f)), ThemePx(3.f), ThemeColAccent());
            }
            s.desc.draw();
        }
        ImGui::End();
        if (can_close && !open)
            WorkspaceSetVisible(s.desc.id, false);
    }
}

void WorkspaceDrawViewMenu(bool ready, bool locked)
{
    const char* group_lab[2] = { "view.menu_panels", "view.menu_views" };
    const WsMenu groups[2] = { WsMenuPanel, WsMenuView };
    for (int g = 0; g < 2; g++)
    {
        if (g)
            ImGui::Separator();
        ImGui::TextDisabled("%s", I18nGet(group_lab[g]));
        for (int i = 0; i < g_n; i++)
        {
            WsSlot& s = g_slots[i];
            if (s.desc.menu != groups[g])
                continue;
            bool vis = s.visible;
            if (ImGui::MenuItem(TitleOf(s.desc), nullptr, vis, ready && !locked))
                WorkspaceSetVisible(s.desc.id, !vis);
        }
    }
    ImGui::Separator();
    if (ImGui::MenuItem(I18nGet("view.reset_workspace"), nullptr, false, !locked))
    {
        SettingsLayoutResetWorkspace();
        WorkspaceRequestRebuild();
        InspectorReloadLayout();
    }
}
