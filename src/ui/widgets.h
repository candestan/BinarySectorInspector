#pragma once

#include "imgui.h"

bool UiAnimEnabled();
float UiHoverT(unsigned int id, bool hovered);
void  UiHoverSweep(ImVec2 a, ImVec2 b, float t, float alpha_scale = 1.f);
void  UiHandIfHovered();
void  UiDecorateLastButton();
bool  UiButton(const char* label, ImVec2 size = ImVec2(0, 0));
