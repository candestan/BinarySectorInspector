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
    IconCopy,
    IconCheck,
    IconInfo,
    IconWarn,
};

enum
{
    IconRoleXs = 0, // inline status, combo chevron
    IconRoleSm,     // tree, menus, list rows
    IconRoleMd,     // labeled action buttons
    IconRoleLg,     // toolbar emphasis
    IconRoleXl,     // empty-state / feature
};

float IconSize(int role);     // half-extent passed to IconDraw
float IconSlotW(int role);    // reserved column for icon + gap
float IconTextGap();
void  IconPrefixLabel(char* dst, int cap, int role, const char* label);
void  IconDraw(int icon, ImVec2 center, float s, unsigned int col, ImDrawList* dl = nullptr);
void  IconDrawRole(int icon, ImVec2 center, int role, unsigned int col, ImDrawList* dl = nullptr);
bool  IconButton(const char* id, int icon, const char* label = nullptr);
bool  IconTool(const char* id, int icon, const char* label);
bool  IconMenuItem(int icon, const char* label, const char* shortcut = nullptr, bool enabled = true);
bool  IconBeginMenu(int icon, const char* label);
