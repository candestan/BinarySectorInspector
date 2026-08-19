#pragma once

#include "imgui.h"

enum WsRegion
{
    WsLeft = 0,
    WsRight,
    WsTop,
    WsBottom,
    WsCenter
};

enum WsMenu
{
    WsMenuNone = 0,
    WsMenuPanel,
    WsMenuView
};

struct WsDesc
{
    const char* id;
    const char* title_key;
    const char* title_lit;
    int         icon;
    WsRegion    def_region;
    bool        utility;
    bool        closable;
    bool        default_open;
    WsMenu      menu;
    float       min_w;
    float       min_h;
    void      (*draw)();
    bool      (*dirty)();
};

void WorkspaceBindContext();
void WorkspaceClear();
void WorkspaceRegister(const WsDesc& d);
void WorkspaceSetVisible(const char* id, bool vis);
bool WorkspaceVisible(const char* id);
void WorkspaceFocus(const char* id);
void WorkspaceDockToCenter(const char* id);
const char* WorkspaceCurrentId();
void WorkspaceRequestRebuild();
void WorkspaceDraw(ImVec2 size);
void WorkspaceDrawViewMenu(bool ready, bool locked);
void WorkspaceTickSave();
