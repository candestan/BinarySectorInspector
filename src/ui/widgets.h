#pragma once

#include "imgui.h"

bool  UiAnimEnabled();
float UiEaseOut(float t);
float UiHoverT(unsigned int id, bool hovered);
float UiAnimToward(unsigned int id, float target, float speed);
float UiReveal(unsigned int id, bool active, float speed);
void  UiAnimPageEnter();
float UiEnter(float delay, float dur);
ImU32 UiLerpCol(ImU32 a, ImU32 b, float t);
void  UiHoverSweep(ImVec2 a, ImVec2 b, float t, float alpha_scale = 1.f, ImDrawList* dl = nullptr);
void  UiAccentBar(ImVec2 a, ImVec2 b, float t, ImDrawList* dl = nullptr);
void  UiHandIfHovered();
void  UiDecorateLastButton();
bool  UiButton(const char* label, ImVec2 size = ImVec2(0, 0), int kind = 0); // 0 secondary, 1 primary
bool  UiCheckbox(const char* id, const char* label, bool* value);
void  UiSpinner(ImVec2 center, float radius, float progress); // progress < 0 = indeterminate
void  UiHelpMark(const char* text);
void  UiPopupFadePush();
void  UiPopupFadePop();
void  UiEmpty(const char* title, const char* detail = nullptr);
void  UiSection(const char* title);
void  UiTipWhenDisabled(const char* text);
