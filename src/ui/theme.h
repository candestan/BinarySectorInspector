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
float  ThemeMenuPadX();
float  ThemeMenuPadY();
float  ThemeMenuBarH();
float  ThemeMenuBarPadX();
float  ThemeMenuBarPadY();
float  ThemeMenuItemPadX();
float  ThemeMenuItemPadY();
float  ThemePopupPad();
float  ThemeHitMin();
float  ThemeRowH();
float  ThemeTooltipPad();
float  ThemeToastWidth();
float  ThemeToastGap();
float  ThemeToastAccentW();
float  ThemeBadgePadX();
float  ThemeBadgePadY();
float  ThemeBadgeGap();
float  ThemeBadgeIconGap();
float  ThemeBadgeBorderW();
float  ThemeBadgeMinH();
float  ThemeBadgeRadius(float height);

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
ImU32  ThemeColDanger();
ImU32  ThemeColSuccess();
ImU32  ThemeColWarning();
ImU32  ThemeColInfo();
ImU32  ThemeColSelection();
ImU32  ThemeColLogSuccess();
ImU32  ThemeColLogWarning();
ImU32  ThemeColLogError();
ImU32  ThemeColLogCritical();
ImU32  ThemeColHexUnsaved();
ImU32  ThemeColHexSaved();
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
