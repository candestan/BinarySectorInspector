#include "platform/window_process.h"
#include "platform/unique_handle.h"

namespace {

constexpr DWORD kImagePathCapacity = 32768;

std::wstring query_process_image_path(DWORD pid)
{
    UniqueHandle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!process)
        return {};

    std::wstring path(kImagePathCapacity, L'\0');
    DWORD size = kImagePathCapacity;
    if (!QueryFullProcessImageNameW(process.get(), 0, path.data(), &size))
        return {};

    path.resize(size);
    return path;
}

BOOL CALLBACK collect_windows(HWND hwnd, LPARAM lparam)
{
    auto* entries = reinterpret_cast<std::vector<WindowProcessEntry>*>(lparam);

    if (!IsWindowVisible(hwnd))
        return TRUE;
    if (GetWindow(hwnd, GW_OWNER) != nullptr)
        return TRUE;

    wchar_t title[512];
    const int title_len = GetWindowTextW(hwnd, title, ARRAYSIZE(title));
    if (title_len <= 0)
        return TRUE;

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == 0)
        return TRUE;

    WindowProcessEntry entry;
    entry.hwnd = hwnd;
    entry.pid = pid;
    entry.title.assign(title, title + title_len);
    entry.image_path = query_process_image_path(pid);
    entries->push_back(std::move(entry));
    return TRUE;
}

} // namespace

std::vector<WindowProcessEntry> snapshot_window_processes()
{
    std::vector<WindowProcessEntry> entries;
    EnumWindows(collect_windows, reinterpret_cast<LPARAM>(&entries));
    return entries;
}
