#include "engine/engine_p.h"
#include "ui/theme.h"
#include "persist/settings.h"

#include "imgui.h"
#include "imgui_impl_win32.h"
#include <dwmapi.h>
#include <windowsx.h>
#include <shellapi.h>

Form  g_forms[kMaxForms];
Form* g_cur;
bool  g_moving;
bool  g_quitting;

void SyncMaximized(Form* f)
{
    if (!f || !f->hwnd)
        return;
    f->maximized = IsZoomed(f->hwnd) != FALSE;
}

void CaptureGeom(Form* f)
{
    if (!f || !f->hwnd || IsIconic(f->hwnd))
        return;

    WINDOWPLACEMENT pl{};
    pl.length = sizeof(pl);
    if (!GetWindowPlacement(f->hwnd, &pl))
        return;

    RECT r = pl.rcNormalPosition; // restore rect. GetWindowRect while zoomed is the work area.
    WindowLayout w;
    w.x = r.left;
    w.y = r.top;
    w.w = r.right - r.left;
    w.h = r.bottom - r.top;
    w.maximized = (pl.showCmd == SW_SHOWMAXIMIZED) || IsZoomed(f->hwnd);
    SettingsPutWindow(f->name, w);
}

void ToggleMax(Form* f)
{
    if (!f || !f->hwnd)
        return;
    ShowWindow(f->hwnd, IsZoomed(f->hwnd) ? SW_RESTORE : SW_MAXIMIZE);
    SyncMaximized(f);
    CaptureGeom(f);
}

static int FrameX()
{
    return GetSystemMetrics(SM_CXFRAME) + GetSystemMetrics(SM_CXPADDEDBORDER);
}

static int FrameY()
{
    return GetSystemMetrics(SM_CYFRAME) + GetSystemMetrics(SM_CXPADDEDBORDER);
}

LRESULT HandleNcCalcSize(HWND hwnd, WPARAM wp, LPARAM lp)
{
    // client = full window. DefWindowProc on wParam=FALSE restores native caption.
    // credit: https://learn.microsoft.com/en-us/windows/win32/winmsg/wm-nccalcsize
    if (!wp)
        return 0;

    if (IsZoomed(hwnd))
    {
        NCCALCSIZE_PARAMS* p = (NCCALCSIZE_PARAMS*)lp;
        const int fx = FrameX();
        const int fy = FrameY();
        // inset maximized client to work area or we draw under the taskbar.
        p->rgrc[0].left += fx;
        p->rgrc[0].top += fy;
        p->rgrc[0].right -= fx;
        p->rgrc[0].bottom -= fy;
    }
    return 0;
}

LRESULT HitTest(HWND hwnd, Form* f, LPARAM lp)
{
    POINT pt = { GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
    RECT wr;
    GetWindowRect(hwnd, &wr);

    const int b = FrameX();
    const bool maxed = f && f->maximized;
    if (!maxed)
    {
        const bool left = pt.x < wr.left + b;
        const bool right = pt.x >= wr.right - b;
        const bool top = pt.y < wr.top + b;
        const bool bottom = pt.y >= wr.bottom - b;
        if (top && left) return HTTOPLEFT;
        if (top && right) return HTTOPRIGHT;
        if (bottom && left) return HTBOTTOMLEFT;
        if (bottom && right) return HTBOTTOMRIGHT;
        if (left) return HTLEFT;
        if (right) return HTRIGHT;
        if (top) return HTTOP;
        if (bottom) return HTBOTTOM;
    }

    POINT c = pt;
    ScreenToClient(hwnd, &c);
    RECT cr;
    GetClientRect(hwnd, &cr);
    const float bar = ThemeTitleBarH();
    const float btn = ThemeChromeBtnW();
    if (c.y >= 0 && c.y < (int)bar && c.x >= 0 && c.x < cr.right)
    {
        if (c.x >= cr.right - (int)(btn * 3.f))
            return HTCLIENT;
        return HTCAPTION; // Win32 drag/snap. custom mouse-move broke restore-from-max.
    }
    return HTCLIENT;
}

static void SnapIfAtTop(HWND hwnd)
{
    if (IsZoomed(hwnd))
        return;
    POINT c;
    GetCursorPos(&c);
    MONITORINFO mi{};
    mi.cbSize = sizeof(mi);
    HMONITOR mon = MonitorFromPoint(c, MONITOR_DEFAULTTONEAREST);
    if (!GetMonitorInfoW(mon, &mi))
        return;
    if (c.y <= mi.rcMonitor.top + 8)
        ShowWindow(hwnd, SW_MAXIMIZE);
}

LRESULT WINAPI HostWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    Form* f = (Form*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    if (f && f->imgui && msg != WM_NCHITTEST && msg != WM_NCCALCSIZE && msg != WM_DROPFILES)
    {
        // don't feed DROPFILES/NCHITTEST to imgui; it eats drops and steals caption hits.
        ImGui::SetCurrentContext(f->imgui);
        if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, wp, lp))
            return true;
    }

    switch (msg)
    {
    case WM_DROPFILES:
        if (wp)
        {
            HDROP drop = (HDROP)wp;
            UINT n = DragQueryFileW(drop, 0xFFFFFFFF, nullptr, 0);
            for (UINT i = 0; i < n; i++)
            {
                wchar_t wpath[MAX_PATH];
                if (!DragQueryFileW(drop, i, wpath, MAX_PATH))
                    continue;
                char path[MAX_PATH];
                if (!WideCharToMultiByte(CP_UTF8, 0, wpath, -1, path, MAX_PATH, nullptr, nullptr))
                    continue;
                EnginePushDrop(path);
            }
            DragFinish(drop);
        }
        return 0;
    case WM_NCCALCSIZE:
        return HandleNcCalcSize(hwnd, wp, lp);
    case WM_NCPAINT:
        return 0;
    case WM_NCACTIVATE:
        return TRUE;
    case WM_NCHITTEST:
        return HitTest(hwnd, f, lp);
    case WM_NCLBUTTONDBLCLK:
        if ((int)wp == HTCAPTION && f)
        {
            ToggleMax(f);
            return 0;
        }
        break;
    case WM_GETMINMAXINFO:
        if (f)
        {
            MINMAXINFO* mmi = (MINMAXINFO*)lp;
            mmi->ptMinTrackSize.x = kMinWindow;
            mmi->ptMinTrackSize.y = kMinWindow;
            return 0; // no fallthrough; used to skip WM_SIZE.
        }
        break;
    case WM_ENTERSIZEMOVE:
        g_moving = true;
        return 0;
    case WM_EXITSIZEMOVE:
        g_moving = false;
        if (f)
        {
            SnapIfAtTop(f->hwnd);
            SyncMaximized(f);
            CaptureGeom(f);
        }
        return 0;
    case WM_SIZE:
        if (f)
        {
            SyncMaximized(f);
            if (f->swap && wp != SIZE_MINIMIZED)
            {
                f->w = (UINT)LOWORD(lp);
                f->h = (UINT)HIWORD(lp);
                if (f->w == 0 || f->h == 0)
                    return 0;
                g_ctx->OMSetRenderTargets(0, nullptr, nullptr);
                NukeRTV(f);
                f->swap->ResizeBuffers(0, f->w, f->h, DXGI_FORMAT_UNKNOWN, 0);
                MakeRTV(f);
            }
        }
        return 0;
    case WM_CLOSE:
        if (f)
            KillForm(f);
        return 0;
    case WM_SYSCOMMAND:
        if ((wp & 0xfff0) == SC_CLOSE)
        {
            if (f)
                KillForm(f);
            return 0;
        }
        if (f && (wp & 0xfff0) == SC_MAXIMIZE)
        {
            if (!IsZoomed(f->hwnd))
                ShowWindow(f->hwnd, SW_MAXIMIZE);
            SyncMaximized(f);
            CaptureGeom(f);
            return 0;
        }
        if (f && (wp & 0xfff0) == SC_RESTORE && IsZoomed(f->hwnd))
        {
            ShowWindow(f->hwnd, SW_RESTORE);
            SyncMaximized(f);
            CaptureGeom(f);
            return 0;
        }
        break;
    case WM_DESTROY:
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}
