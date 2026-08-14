#include "engine/engine.h"
#include "engine/engine_p.h"
#include "persist/settings.h"
#include "ui/tex.h"

#include "imgui.h"
#include "imgui_impl_dx11.h"

#include <dwmapi.h>
#include <stdio.h>
#include <string.h>

HINSTANCE g_inst;
bool      g_vsync;

static char g_drop[8][MAX_PATH]; // WndProc -> next frame. ImGui would swallow WM_DROPFILES.
static int  g_drop_n;
static int  g_pending_sw = -1;
static int  g_pending_msaa = -1;

ID3D11Device* EngineDevice()
{
    return g_device;
}

void EnginePushDrop(const char* path)
{
    if (!path || !path[0] || g_drop_n >= 8)
        return;
    snprintf(g_drop[g_drop_n++], MAX_PATH, "%s", path);
}

bool EngineTakeDrop(char* out, int cap)
{
    if (!out || cap < 2 || g_drop_n <= 0)
        return false;
    snprintf(out, cap, "%s", g_drop[0]);
    for (int i = 1; i < g_drop_n; i++)
        memcpy(g_drop[i - 1], g_drop[i], MAX_PATH);
    g_drop_n--;
    return true;
}

static bool RecreateDevice(bool sw)
{
    if (g_ctx)
        g_ctx->OMSetRenderTargets(0, nullptr, nullptr);
    TexShutdown();
    for (int i = 0; i < kMaxForms; i++)
    {
        Form* f = &g_forms[i];
        if (!f->live || !f->imgui)
            continue;
        ImGui::SetCurrentContext(f->imgui);
        ImGui_ImplDX11_Shutdown();
        UnbindFormGpu(f);
    }
    KillDevice();
    if (!BootDevice(sw))
    {
        if (BootDevice(!sw) && g_device)
        {
            for (int i = 0; i < kMaxForms; i++)
            {
                Form* f = &g_forms[i];
                if (!f->live || !f->imgui)
                    continue;
                BindFormGpu(f);
                ImGui::SetCurrentContext(f->imgui);
                ImGui_ImplDX11_Init(g_device, g_ctx);
            }
        }
        return false;
    }
    for (int i = 0; i < kMaxForms; i++)
    {
        Form* f = &g_forms[i];
        if (!f->live || !f->imgui)
            continue;
        BindFormGpu(f);
        ImGui::SetCurrentContext(f->imgui);
        ImGui_ImplDX11_Init(g_device, g_ctx);
    }
    return true;
}

static void ApplyMsaaNow()
{
    if (g_ctx)
        g_ctx->OMSetRenderTargets(0, nullptr, nullptr);
    PickMsaa();
    for (int i = 0; i < kMaxForms; i++)
    {
        Form* f = &g_forms[i];
        if (f->live && f->swap)
            MakeRTV(f);
    }
}

void EngineRequestRenderer(bool software)
{
    g_pending_sw = software ? 1 : 0;
}

void EngineRequestMsaa(bool enabled)
{
    g_pending_msaa = enabled ? 1 : 0;
}

void EngineSetVsync(bool on)
{
    g_vsync = on;
    SettingsSetBool("vsync", on);
}

void EngineApplyPending()
{
    if (g_pending_sw >= 0)
    {
        bool sw = g_pending_sw != 0;
        g_pending_sw = -1;
        g_pending_msaa = -1;
        if (g_sw != sw || !g_device)
            RecreateDevice(sw);
        else
            ApplyMsaaNow();
        return;
    }
    if (g_pending_msaa >= 0)
    {
        g_pending_msaa = -1;
        ApplyMsaaNow();
    }
}

bool EngineInit(HINSTANCE inst, bool force_sw)
{
    g_inst = inst;

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = HostWndProc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.lpszClassName = L"BSIHost";
    if (!RegisterClassExW(&wc))
        return false;

    SettingsLoad();
    g_vsync = SettingsGetBool("vsync", false);

    bool sw = force_sw;
    if (!sw)
    {
        char mode[32];
        SettingsGetString("renderer", mode, 32, "hardware");
        sw = _stricmp(mode, "software") == 0;
    }
    if (!BootDevice(sw))
        return false;
    return true;
}

void EngineShutdown()
{
    for (int i = 0; i < kMaxForms; i++)
        if (g_forms[i].live)
            KillForm(&g_forms[i]);
    TexShutdown();
    KillDevice();
    UnregisterClassW(L"BSIHost", g_inst);
}

bool EngineProcessEvents()
{
    MSG msg;
    while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
        if (msg.message == WM_QUIT)
            return false;
    }
    return true;
}

bool EngineShouldRender()
{
    return true;
}

void EngineEndFrame()
{
    if (!g_vsync)
        DwmFlush(); // Present(0) + one DwmFlush. Present(1)+Flush double-waits.
}

bool EngineIsSoftware()
{
    return g_sw;
}

bool EngineVsync()
{
    return g_vsync;
}

bool EngineMsaaEnabled()
{
    return SettingsGetBool("msaa", true);
}
