#pragma once

#include <windows.h>
#include <string>
#include <vector>

struct WindowProcessEntry
{
    HWND hwnd = nullptr;
    DWORD pid = 0;
    std::wstring title;
    std::wstring image_path;
};

std::vector<WindowProcessEntry> snapshot_window_processes();
