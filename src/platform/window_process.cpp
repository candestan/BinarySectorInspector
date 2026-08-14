#include "platform/window_process.h"

#include <string.h>

struct WindowSnap
{
    PlatformWindowEntry* out;
    int cap;
    int n;
};

static BOOL CALLBACK CollectWindows(HWND hwnd, LPARAM lp)
{
    WindowSnap* snap = (WindowSnap*)lp;
    if (snap->n >= snap->cap)
        return FALSE;
    if (!IsWindowVisible(hwnd))
        return TRUE;
    if (GetWindow(hwnd, GW_OWNER) != nullptr)
        return TRUE;
    wchar_t title[512];
    int title_len = GetWindowTextW(hwnd, title, 512);
    if (title_len <= 0)
        return TRUE;
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (!pid)
        return TRUE;

    PlatformWindowEntry& e = snap->out[snap->n];
    e.hwnd = hwnd;
    e.pid = pid;
    e.title[0] = 0;
    e.image_path[0] = 0;
    WideCharToMultiByte(CP_UTF8, 0, title, title_len, e.title, (int)sizeof(e.title) - 1, nullptr, nullptr);
    e.title[sizeof(e.title) - 1] = 0;

    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (proc)
    {
        wchar_t path[32768];
        DWORD size = 32768;
        if (QueryFullProcessImageNameW(proc, 0, path, &size) && size)
            WideCharToMultiByte(CP_UTF8, 0, path, -1, e.image_path, MAX_PATH, nullptr, nullptr);
        CloseHandle(proc);
    }
    snap->n++;
    return TRUE;
}

int PlatformSnapshotWindows(PlatformWindowEntry* out, int cap)
{
    if (!out || cap <= 0)
        return 0;
    WindowSnap snap;
    snap.out = out;
    snap.cap = cap;
    snap.n = 0;
    EnumWindows(CollectWindows, (LPARAM)&snap);
    return snap.n;
}
