#include "app.h"
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#include <d3d11.h>
#include <dxgi1_2.h>
#include <dcomp.h>
#include <objbase.h>
#include <windows.h>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "dcomp.lib")

static ID3D11Device*            g_device;
static ID3D11DeviceContext*     g_ctx;
static IDXGISwapChain1*         g_swap;
static ID3D11RenderTargetView*  g_rtv;
static IDCompositionDevice*     g_dcomp;
static IDCompositionTarget*     g_dcomp_target;
static IDCompositionVisual*     g_dcomp_visual;
static UINT                     g_w;
static UINT                     g_h;
static bool                     g_sw; // true = WARP (cpu), false = gpu

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

static void MakeRTV()
{
    ID3D11Texture2D* bb = nullptr;
    g_swap->GetBuffer(0, IID_PPV_ARGS(&bb));
    g_device->CreateRenderTargetView(bb, nullptr, &g_rtv);
    bb->Release();
}

static void NukeRTV()
{
    if (g_rtv) { g_rtv->Release(); g_rtv = nullptr; }
}

static bool BootGfx(HWND hwnd, UINT w, UINT h, bool force_sw)
{
    g_w = w;
    g_h = h;
    g_sw = force_sw;

    // BGRA sart, dcomp yoksa alpha siyah cikiyor
    UINT flags = D3D11_CREATE_DEVICE_BGRA_SUPPORT;
#ifdef _DEBUG
    flags |= D3D11_CREATE_DEVICE_DEBUG;
#endif

    D3D_FEATURE_LEVEL got;
    const D3D_FEATURE_LEVEL want[] = { D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0 };
    D3D_DRIVER_TYPE type = force_sw ? D3D_DRIVER_TYPE_WARP : D3D_DRIVER_TYPE_HARDWARE;

    HRESULT hr = D3D11CreateDevice(nullptr, type, nullptr, flags,
        want, 2, D3D11_SDK_VERSION, &g_device, &got, &g_ctx);
    if (FAILED(hr) && (flags & D3D11_CREATE_DEVICE_DEBUG))
        hr = D3D11CreateDevice(nullptr, type, nullptr, D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            want, 2, D3D11_SDK_VERSION, &g_device, &got, &g_ctx);
    if (FAILED(hr) && type == D3D_DRIVER_TYPE_HARDWARE)
    {
        g_sw = true;
        hr = D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            want, 2, D3D11_SDK_VERSION, &g_device, &got, &g_ctx);
    }
    if (FAILED(hr))
        return false;

    IDXGIDevice* dxgi_dev = nullptr;
    g_device->QueryInterface(IID_PPV_ARGS(&dxgi_dev));

    IDXGIAdapter* adapter = nullptr;
    dxgi_dev->GetAdapter(&adapter);

    IDXGIFactory2* factory = nullptr;
    adapter->GetParent(IID_PPV_ARGS(&factory));

    DXGI_SWAP_CHAIN_DESC1 sd{};
    sd.Width = w;
    sd.Height = h;
    sd.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    sd.SampleDesc.Count = 1;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.BufferCount = 2;
    sd.SwapEffect = DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL;
    sd.AlphaMode = DXGI_ALPHA_MODE_PREMULTIPLIED;
    sd.Scaling = DXGI_SCALING_STRETCH;

    hr = factory->CreateSwapChainForComposition(g_device, &sd, nullptr, &g_swap);
    factory->Release();
    adapter->Release();
    if (FAILED(hr))
    {
        dxgi_dev->Release();
        return false;
    }

    if (FAILED(DCompositionCreateDevice(dxgi_dev, IID_PPV_ARGS(&g_dcomp))))
    {
        dxgi_dev->Release();
        return false;
    }
    dxgi_dev->Release();

    g_dcomp->CreateTargetForHwnd(hwnd, TRUE, &g_dcomp_target);
    g_dcomp->CreateVisual(&g_dcomp_visual);
    g_dcomp_visual->SetContent(g_swap);
    g_dcomp_target->SetRoot(g_dcomp_visual);
    g_dcomp->Commit();

    MakeRTV();
    return true;
}

static void KillGfx()
{
    NukeRTV();
    if (g_dcomp_visual) { g_dcomp_visual->Release(); g_dcomp_visual = nullptr; }
    if (g_dcomp_target) { g_dcomp_target->Release(); g_dcomp_target = nullptr; }
    if (g_dcomp) { g_dcomp->Release(); g_dcomp = nullptr; }
    if (g_swap) { g_swap->Release(); g_swap = nullptr; }
    if (g_ctx) { g_ctx->Release(); g_ctx = nullptr; }
    if (g_device) { g_device->Release(); g_device = nullptr; }
}

static LRESULT WINAPI WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, wp, lp))
        return true;

    switch (msg)
    {
    case WM_SIZE:
        if (g_swap && wp != SIZE_MINIMIZED)
        {
            g_w = (UINT)LOWORD(lp);
            g_h = (UINT)HIWORD(lp);
            NukeRTV();
            g_swap->ResizeBuffers(0, g_w, g_h, DXGI_FORMAT_UNKNOWN, 0);
            MakeRTV();
        }
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, PWSTR, int)
{
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    bool force_sw = false;
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv)
    {
        for (int i = 1; i < argc; i++)
            if (!lstrcmpiW(argv[i], L"-sw") || !lstrcmpiW(argv[i], L"--software"))
                force_sw = true;
        LocalFree(argv);
    }

    const int w = 1280;
    const int h = 720;

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.lpszClassName = L"BSIHost";
    RegisterClassExW(&wc);

    const int x = (GetSystemMetrics(SM_CXSCREEN) - w) / 2;
    const int y = (GetSystemMetrics(SM_CYSCREEN) - h) / 2;

    // NOREDIRECTIONBITMAP + dcomp = gercek per-pixel alpha, chrome yok
    HWND hwnd = CreateWindowExW(
        WS_EX_NOREDIRECTIONBITMAP,
        wc.lpszClassName,
        L"BinarySectorInspector",
        WS_POPUP,
        x, y, w, h,
        nullptr, nullptr, inst, nullptr);

    if (!hwnd || !BootGfx(hwnd, (UINT)w, (UINT)h, force_sw))
        return 1;

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = nullptr;

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_device, g_ctx);

    App app(hwnd);

    bool running = true;
    while (running)
    {
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            if (msg.message == WM_QUIT)
                running = false;
        }
        if (!running)
            break;

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        app.draw();

        ImGui::Render();

        const float clear[4] = { 0.f, 0.f, 0.f, 0.f };
        g_ctx->OMSetRenderTargets(1, &g_rtv, nullptr);
        g_ctx->ClearRenderTargetView(g_rtv, clear);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_swap->Present(1, 0);
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    KillGfx();
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, inst);
    CoUninitialize();
    return 0;
}
