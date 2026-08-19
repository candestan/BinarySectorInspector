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

struct WsDesc
{
    const char* id;
    const char* title_key;
    const char* title_lit;
    int         icon;
    WsRegion    def_region;
    bool        utility;
    bool        closable;
    void      (*draw)();
    bool      (*dirty)();
};

void WorkspaceBindContext();
void WorkspaceClear();
void WorkspaceRegister(const WsDesc& d);
void WorkspaceSetVisible(const char* id, bool vis);
bool WorkspaceVisible(const char* id);
void WorkspaceFocus(const char* id);
const char* WorkspaceCurrentId();
void WorkspaceRequestRebuild();
void WorkspaceDraw(ImVec2 size);
void WorkspaceDrawViewMenu(bool ready, bool locked);
void WorkspaceTickSave();
