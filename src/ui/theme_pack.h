#pragma once

enum ThemeKind
{
    ThemeKindDark = 0,
    ThemeKindLight,
    ThemeKindBoth,
};

struct ThemeInfo
{
    char file[64];
    char name[64];
    char author[64];
    char description[256];
    char image[260];
    ThemeKind kind;
    int preview_bg;
    int preview_card;
    int preview_accent;
};

void        ThemePackInit();
void        ThemePackRescan();
bool        ThemePackApplyFile(const char* file);
const char* ThemePackFile();
int         ThemePackCount();
const ThemeInfo* ThemePackGet(int index);
const char* ThemeKindLabel(ThemeKind k);
