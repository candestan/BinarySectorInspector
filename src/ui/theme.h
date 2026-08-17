#pragma once

#include "imgui.h"

enum
{
    ThemeClickMin      = 1,
    ThemeClickMax      = 2,
    ThemeClickClose    = 4,
    ThemeClickSettings = 8,
};

float  ThemeDpi();
float  ThemePx(float logical);
float  ThemeSpaceXs();
float  ThemeSpaceSm();
float  ThemeSpaceMd();
float  ThemeSpaceLg();
float  ThemeSpaceXl();
float  ThemeFontSize();
float  ThemeTitleBarH();
float  ThemeChromeBtnW();
int    ThemeChromeButtonCount();
float  ThemeLabelW();
float  ThemeTreeMinW();
float  ThemeSplitHit();

void   ThemeLoadFonts();
void   ThemeApply();
void   ThemeSetPalette(int bg, int fg, int muted, int muted_fg, int accent, int border, int input, int card, float rounding);
int    ThemeDecorateWindow(const char* title, bool maximized);
bool   ThemeConsumeSettingsClick();
void   ThemeSetCaption(const char* caption);
const char* ThemeCaptionOr(const char* fallback);
ImFont* ThemeFontTitle();
ImFont* ThemeFontSmall();
ImFont* ThemeFontMono();
ImU32  ThemeWithAlpha(ImU32 c, float a);
ImU32  ThemeColRgb(int rgb, float a = 1.f);
ImU32  ThemeColFg();
ImU32  ThemeColFgA(float a);
ImU32  ThemeColMuted();
ImU32  ThemeColMutedA(float a);
ImU32  ThemeColAccent();
ImU32  ThemeColAccentA(float a);
ImU32  ThemeColBg();
ImU32  ThemeColBgA(float a);
ImU32  ThemeColCard();
ImU32  ThemeColCardA(float a);
ImU32  ThemeColBorder();
ImU32  ThemeColBorderA(float a);
ImU32  ThemeColHover();
ImU32  ThemeColHoverA(float a);
ImU32  ThemeColInput();
ImVec4 ThemeVec4Transparent();
int    ThemeHexBg();
int    ThemeHexFg();
int    ThemeHexMuted();
int    ThemeHexMutedFg();
int    ThemeHexAccent();
int    ThemeHexBorder();
int    ThemeHexInput();
int    ThemeHexCard();
void   ThemeDrawLogo(ImVec2 center, float size);
