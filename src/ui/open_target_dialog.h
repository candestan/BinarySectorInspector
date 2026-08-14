#pragma once

#include <windows.h>
#include <string>
#include "platform/window_process.h"

class OpenTargetDialog
{
public:
    bool draw(HWND owner);
    const std::wstring& selected_path() const { return selected_path_; }

private:
    void refresh_processes();
    void set_path(std::wstring path);

    bool snapshot_ready_ = false;
    std::vector<WindowProcessEntry> entries_;
    int selected_row_ = -1;
    char filter_[256] = {};
    std::wstring selected_path_;
    std::string status_;
};
