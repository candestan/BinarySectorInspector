#pragma once

#include "imgui.h"

enum
{
    ThemeClickMin   = 1,
    ThemeClickMax   = 2,
    ThemeClickClose = 4,
};

inline float ThemeFontSize() { return 20.f; }
inline float ThemeTitleBarH() { return 34.f; }
inline float ThemeChromeBtnW() { return 40.f; }

void   ThemeLoadFonts();
void   ThemeApply();
void   ThemeSetPalette(int bg, int fg, int muted, int muted_fg, int accent, int border, int input, int card, float rounding);
int    ThemeDecorateWindow(const char* title, bool maximized);
void   ThemeSetCaption(const char* caption);
const char* ThemeCaptionOr(const char* fallback);
ImFont* ThemeFontTitle();
ImFont* ThemeFontSmall();
ImFont* ThemeFontMono();
ImU32  ThemeCol(int hex, float a = 1.f);
ImU32  ThemeColFg();
ImU32  ThemeColMuted();
ImU32  ThemeColAccent();
ImU32  ThemeColBg();
ImU32  ThemeColCard();
ImU32  ThemeColBorder();
void   ThemeDrawLogo(ImVec2 center, float size);
