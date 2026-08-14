#pragma once

#include "imgui.h"

enum
{
    IconBack = 0,
    IconGear,
    IconFolder,
    IconFile,
    IconChevron,
};

bool IconButton(const char* id, int icon, const char* label = nullptr);
void IconDraw(int icon, ImVec2 center, float s, unsigned int col);
