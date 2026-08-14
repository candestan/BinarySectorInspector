#include "engine/engine_p.h"
#include "persist/settings.h"

#include <d3d11.h>
#include <dxgi1_2.h>
#include <dcomp.h>

ID3D11Device*        g_device;
ID3D11DeviceContext* g_ctx;
IDXGIFactory2*       g_factory;
IDCompositionDevice* g_dcomp;
bool                 g_sw;
UINT                 g_msaa = 1;

void NukeRTV(Form* f)
{
    if (f->rtv) { f->rtv->Release(); f->rtv = nullptr; }
    if (f->msaa_tex) { f->msaa_tex->Release(); f->msaa_tex = nullptr; }
    if (f->bb_tex) { f->bb_tex->Release(); f->bb_tex = nullptr; }
}

void MakeRTV(Form* f)
{
    NukeRTV(f);
    f->swap->GetBuffer(0, IID_PPV_ARGS(&f->bb_tex));
    if (g_msaa > 1)
    {
        D3D11_TEXTURE2D_DESC td{};
        f->bb_tex->GetDesc(&td);
        td.SampleDesc.Count = g_msaa;
        td.SampleDesc.Quality = 0;
        td.BindFlags = D3D11_BIND_RENDER_TARGET;
        td.MiscFlags = 0;
        if (SUCCEEDED(g_device->CreateTexture2D(&td, nullptr, &f->msaa_tex)))
        {
            // resolve into backbuffer. flip-model swapchain is not MSAA.
            g_device->CreateRenderTargetView(f->msaa_tex, nullptr, &f->rtv);
            return;
        }
    }
    g_device->CreateRenderTargetView(f->bb_tex, nullptr, &f->rtv);
}

void PickMsaa()
{
    g_msaa = 1;
    if (g_sw || !g_device || !SettingsGetBool("msaa", true))
        return;
    UINT q = 0;
    if (SUCCEEDED(g_device->CheckMultisampleQualityLevels(DXGI_FORMAT_B8G8R8A8_UNORM, 4, &q)) && q > 0)
        g_msaa = 4;
    else if (SUCCEEDED(g_device->CheckMultisampleQualityLevels(DXGI_FORMAT_B8G8R8A8_UNORM, 2, &q)) && q > 0)
        g_msaa = 2;
}

bool BootDevice(bool force_sw)
{
    g_sw = force_sw;

    // DComp wants premultiplied BGRA. debug layer missing -> retry without.
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
    adapter->GetParent(IID_PPV_ARGS(&g_factory));
    adapter->Release();

    hr = DCompositionCreateDevice(dxgi_dev, IID_PPV_ARGS(&g_dcomp));
    dxgi_dev->Release();
    if (FAILED(hr))
        return false;

    PickMsaa();
    return true;
}

void KillDevice()
{
    if (g_dcomp) { g_dcomp->Release(); g_dcomp = nullptr; }
    if (g_factory) { g_factory->Release(); g_factory = nullptr; }
    if (g_ctx) { g_ctx->Release(); g_ctx = nullptr; }
    if (g_device) { g_device->Release(); g_device = nullptr; }
}
