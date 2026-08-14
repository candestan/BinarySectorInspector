#pragma once

#include <windows.h>

struct PlatformWindowEntry
{
    HWND  hwnd;
    DWORD pid;
    char  title[256];
    char  image_path[MAX_PATH];
};

int PlatformSnapshotWindows(PlatformWindowEntry* out, int cap);
