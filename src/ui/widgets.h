#pragma once

#include "imgui.h"

bool UiAnimEnabled();
float UiHoverT(unsigned int id, bool hovered);
void  UiHoverSweep(ImVec2 a, ImVec2 b, float t, float alpha_scale = 1.f, ImDrawList* dl = nullptr);
void  UiHandIfHovered();
void  UiDecorateLastButton();
bool  UiButton(const char* label, ImVec2 size = ImVec2(0, 0));
bool  UiCheckbox(const char* id, const char* label, bool* value);
void  UiSpinner(ImVec2 center, float radius, float progress); // progress < 0 = indeterminate
