#pragma once

#include "imgui.h"

enum
{
    IconBack = 0,
    IconGear,
    IconFolder,
    IconFile,
    IconChevron,
    IconSave,
    IconHex,
    IconBox,
    IconCpu,
    IconShield,
    IconClose,
    IconTree,
    IconCom,
    IconImport,
    IconExport,
    IconPlay,
    IconSearch,
    IconImage,
    IconEye,
    IconGo,
    IconEdit,
    IconReplace,
};

bool IconButton(const char* id, int icon, const char* label = nullptr);
bool IconTool(const char* id, int icon, const char* label);
bool IconMenuItem(int icon, const char* label, const char* shortcut = nullptr, bool enabled = true);
bool IconBeginMenu(int icon, const char* label);
void IconDraw(int icon, ImVec2 center, float s, unsigned int col, ImDrawList* dl = nullptr);
