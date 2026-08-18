#include "engine/engine_p.h"
#include "ui/theme.h"
#include "persist/settings.h"

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#include <dwmapi.h>
#include <shellapi.h>
#include <stdio.h>
#include <string.h>

int g_spawn_n;

// tombstone so BeginForm doesn't respawn in the same frame.
static char g_dead[kMaxForms][96];
static int  g_dead_n;

int LiveFormCount()
{
    int n = 0;
    for (int i = 0; i < kMaxForms; i++)
        if (g_forms[i].live)
            n++;
    return n;
}

Form* FindForm(const char* name)
{
    for (int i = 0; i < kMaxForms; i++)
        if (g_forms[i].live && strcmp(g_forms[i].name, name) == 0)
            return &g_forms[i];
    return nullptr;
}

bool IsDead(const char* name)
{
    for (int i = 0; i < g_dead_n; i++)
        if (strcmp(g_dead[i], name) == 0)
            return true;
    return false;
}

void MarkDead(const char* name)
{
    if (!name || !name[0] || IsDead(name) || g_dead_n >= kMaxForms)
        return;
    snprintf(g_dead[g_dead_n++], sizeof(g_dead[0]), "%s", name);
}

void UnbindFormGpu(Form* f)
{
    if (!f)
        return;
    NukeRTV(f);
    if (f->dcomp_visual) { f->dcomp_visual->Release(); f->dcomp_visual = nullptr; }
    if (f->dcomp_target) { f->dcomp_target->Release(); f->dcomp_target = nullptr; }
    if (f->swap) { f->swap->Release(); f->swap = nullptr; }
}

bool BindFormGpu(Form* f)
{
    if (!f || !f->hwnd || !g_factory || !g_dcomp || !g_device)
        return false;
    UnbindFormGpu(f);

    DXGI_SWAP_CHAIN_DESC1 sd{};
    sd.Width = f->w ? f->w : 1;
    sd.Height = f->h ? f->h : 1;
    sd.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    sd.SampleDesc.Count = 1;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.BufferCount = 2;
    sd.SwapEffect = DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL;
    sd.AlphaMode = DXGI_ALPHA_MODE_PREMULTIPLIED; // composition swapchain, not HWND swapchain.
    sd.Scaling = DXGI_SCALING_STRETCH;

    if (FAILED(g_factory->CreateSwapChainForComposition(g_device, &sd, nullptr, &f->swap)))
        return false;

    g_dcomp->CreateTargetForHwnd(f->hwnd, TRUE, &f->dcomp_target);
    g_dcomp->CreateVisual(&f->dcomp_visual);
    f->dcomp_visual->SetContent(f->swap);
    f->dcomp_target->SetRoot(f->dcomp_visual);
    g_dcomp->Commit();
    MakeRTV(f);
    return true;
}

void KillForm(Form* f)
{
    if (!f || !f->live)
        return;

    MarkDead(f->name);
    CaptureGeom(f);
    const bool main = f->is_main;

    ImGuiContext* dying = f->imgui;
    ImGuiContext* prev = ImGui::GetCurrentContext();
    if (dying)
    {
        ImGui::SetCurrentContext(dying);
        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext(dying);
        f->imgui = nullptr;
    }
    if (prev && prev != dying)
        ImGui::SetCurrentContext(prev);
    else
        ImGui::SetCurrentContext(nullptr);

    UnbindFormGpu(f);

    HWND hwnd = f->hwnd;
    f->hwnd = nullptr;
    f->live = false;
    if (g_cur == f)
        g_cur = nullptr;
    if (hwnd)
    {
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        DestroyWindow(hwnd);
    }

    if (main && !g_quitting)
    {
        g_quitting = true;
        for (int i = 0; i < kMaxForms; i++)
            if (g_forms[i].live)
                KillForm(&g_forms[i]);
        PostQuitMessage(0);
    }
    else if (!g_quitting && LiveFormCount() == 0)
        PostQuitMessage(0);
}

Form* SpawnForm(const char* name, int w, int h)
{
    Form* f = nullptr;
    for (int i = 0; i < kMaxForms; i++)
    {
        if (!g_forms[i].live)
        {
            f = &g_forms[i];
            break;
        }
    }
    if (!f)
        return nullptr;

    memset(f, 0, sizeof(*f));
    snprintf(f->name, sizeof(f->name), "%s", name);

    int x = 80 + (g_spawn_n % 8) * 28;
    int y = 80 + (g_spawn_n % 8) * 28;
    int ww = w > 0 ? w : 360;
    int hh = h > 0 ? h : 240;
    bool start_max = false;
    WindowLayout saved;
    if (SettingsGetWindow(name, &saved))
    {
        x = saved.x;
        y = saved.y;
        if (saved.w > 0) ww = saved.w;
        if (saved.h > 0) hh = saved.h;
        start_max = saved.maximized;
        HMONITOR mon = MonitorFromPoint({ x, y }, MONITOR_DEFAULTTONEAREST);
        MONITORINFO mi{};
        mi.cbSize = sizeof(mi);
        if (GetMonitorInfoW(mon, &mi))
        {
            int mw = mi.rcWork.right - mi.rcWork.left;
            int mh = mi.rcWork.bottom - mi.rcWork.top;
            if (ww > mw) ww = mw;
            if (hh > mh) hh = mh;
            if (x < mi.rcWork.left)
                x = mi.rcWork.left;
            if (y < mi.rcWork.top)
                y = mi.rcWork.top;
            if (x + ww > mi.rcWork.right)
                x = mi.rcWork.right - ww;
            if (y + hh > mi.rcWork.bottom)
                y = mi.rcWork.bottom - hh;
            if (x < mi.rcWork.left)
                x = mi.rcWork.left;
            if (y < mi.rcWork.top)
                y = mi.rcWork.top;
        }
    }
    g_spawn_n++;
    f->w = (UINT)ww;
    f->h = (UINT)hh;
    f->min_w = kMinWindow;
    f->min_h = kMinWindow;

    // NOREDIRECTIONBITMAP + DComp. DWM redirect bitmap kills alpha.
    // credit: https://learn.microsoft.com/en-us/windows/win32/directcomp/directcomposition-portal
    // credit: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-createwindowexw (WS_EX_NOREDIRECTIONBITMAP)
    HWND hwnd = CreateWindowExW(
        WS_EX_NOREDIRECTIONBITMAP | WS_EX_APPWINDOW,
        L"BSIHost",
        nullptr,
        // keep WS_CAPTION bits for snap/max; chrome is custom.
        WS_POPUP | WS_THICKFRAME | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_MAXIMIZEBOX,
        x, y, ww, hh,
        nullptr, nullptr, g_inst, nullptr);
    if (!hwnd)
        return nullptr;

    MARGINS margins = { -1, -1, -1, -1 };
    DwmExtendFrameIntoClientArea(hwnd, &margins);
    SetWindowPos(hwnd, nullptr, 0, 0, 0, 0,
        SWP_FRAMECHANGED | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);

    BOOL freeze_trans = FALSE;
    DwmSetWindowAttribute(hwnd, DWMWA_TRANSITIONS_FORCEDISABLED, &freeze_trans, sizeof(freeze_trans));

    f->hwnd = hwnd;
    if (!BindFormGpu(f))
    {
        DestroyWindow(hwnd);
        f->hwnd = nullptr;
        return nullptr;
    }

    f->imgui = ImGui::CreateContext();
    ImGui::SetCurrentContext(f->imgui);
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = nullptr;
    ImGui_ImplWin32_Init(hwnd);
    ThemeLoadFonts();
    ThemeApply();
    ImGui_ImplDX11_Init(g_device, g_ctx);

    f->hwnd = hwnd;
    f->live = true;
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)f);
    SetWindowTextA(hwnd, name);
    ShowWindow(hwnd, start_max ? SW_SHOWMAXIMIZED : SW_SHOW);
    DragAcceptFiles(hwnd, TRUE);
    SyncMaximized(f);
    return f;
}

bool BeginForm(const char* name, bool* open, ImVec2 init_size, bool is_main)
{
    if (IsDead(name))
    {
        if (open)
            *open = false;
        return false;
    }

    Form* f = FindForm(name);
    if (!f)
    {
        f = SpawnForm(name, (int)init_size.x, (int)init_size.y);
        if (f)
            f->is_main = is_main;
    }
    if (!f)
        return false;
    if (IsIconic(f->hwnd))
        return false;

    g_cur = f;
    f->kill_me = false;
    SyncMaximized(f);
    ImGui::SetCurrentContext(f->imgui);
    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    RECT cr;
    GetClientRect(f->hwnd, &cr);
    ImVec2 client((float)(cr.right - cr.left), (float)(cr.bottom - cr.top));
    // imgui size always follows client. leftover max size re-inflated HWND on restore.
    ImGui::SetNextWindowPos(ImVec2(0.f, 0.f), ImGuiCond_Always);
    ImGui::SetNextWindowSize(client, ImGuiCond_Always);

    ImGuiWindowFlags wf = ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoBackground |
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;

    ImGui::Begin(name, nullptr, wf);
    int chrome = ThemeDecorateWindow(ThemeCaptionOr(name), f->maximized);
    if (chrome & ThemeClickMin)
        ShowWindow(f->hwnd, SW_MINIMIZE);
    if (chrome & ThemeClickMax)
        ToggleMax(f);
    if (chrome & ThemeClickClose)
    {
        f->kill_me = true;
        if (open)
            *open = false;
    }
    return true;
}

void EndForm()
{
    Form* f = g_cur;
    if (!f)
        return;

    ImGui::End();
    ImGui::Render();

    ImVec4 clear4 = ThemeVec4Transparent();
    const float clear[4] = { clear4.x, clear4.y, clear4.z, clear4.w };
    g_ctx->OMSetRenderTargets(1, &f->rtv, nullptr);
    g_ctx->ClearRenderTargetView(f->rtv, clear);
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    if (f->msaa_tex && f->bb_tex)
        g_ctx->ResolveSubresource(f->bb_tex, 0, f->msaa_tex, 0, DXGI_FORMAT_B8G8R8A8_UNORM);
    f->swap->Present(g_vsync ? 1 : 0, 0);

    g_cur = nullptr;
    if (f->kill_me)
        KillForm(f);
}
