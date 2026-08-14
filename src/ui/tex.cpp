#include "ui/tex.h"
#include "engine/engine.h"
#include "persist/paths.h"

#include <windows.h>
#include <wincodec.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "windowscodecs.lib")

static ID3D11ShaderResourceView* g_placeholder;
static int g_ph_w, g_ph_h;
static bool g_com;

static bool EnsureCom()
{
    if (g_com)
        return true;
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE)
    {
        g_com = true;
        return true;
    }
    return false;
}

bool TexLoadFile(const char* path, ID3D11ShaderResourceView** out_srv, int* out_w, int* out_h)
{
    if (out_srv)
        *out_srv = nullptr;
    if (!path || !path[0] || !EngineDevice())
        return false;
    if (!EnsureCom())
        return false;

    wchar_t wpath[MAX_PATH];
    if (!MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, MAX_PATH))
        return false;

    IWICImagingFactory* fac = nullptr;
    if (FAILED(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&fac))))
        return false;

    IWICBitmapDecoder* dec = nullptr;
    HRESULT hr = fac->CreateDecoderFromFilename(wpath, nullptr, GENERIC_READ, WICDecodeMetadataCacheOnLoad, &dec);
    if (FAILED(hr))
    {
        fac->Release();
        return false;
    }

    IWICBitmapFrameDecode* frame = nullptr;
    dec->GetFrame(0, &frame);
    IWICFormatConverter* conv = nullptr;
    fac->CreateFormatConverter(&conv);
    bool ok = false;
    if (frame && conv && SUCCEEDED(conv->Initialize(frame, GUID_WICPixelFormat32bppRGBA, WICBitmapDitherTypeNone, nullptr, 0.f, WICBitmapPaletteTypeCustom)))
    {
        UINT w = 0, h = 0;
        conv->GetSize(&w, &h);
        if (w > 0 && h > 0 && w < 8192 && h < 8192)
        {
            UINT stride = w * 4;
            UINT bytes = stride * h;
            unsigned char* pixels = (unsigned char*)malloc(bytes);
            if (pixels && SUCCEEDED(conv->CopyPixels(nullptr, stride, bytes, pixels)))
            {
                D3D11_TEXTURE2D_DESC td{};
                td.Width = w;
                td.Height = h;
                td.MipLevels = 1;
                td.ArraySize = 1;
                td.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
                td.SampleDesc.Count = 1;
                td.Usage = D3D11_USAGE_DEFAULT;
                td.BindFlags = D3D11_BIND_SHADER_RESOURCE;
                D3D11_SUBRESOURCE_DATA sd{};
                sd.pSysMem = pixels;
                sd.SysMemPitch = stride;
                ID3D11Texture2D* tex = nullptr;
                if (SUCCEEDED(EngineDevice()->CreateTexture2D(&td, &sd, &tex)))
                {
                    ID3D11ShaderResourceView* srv = nullptr;
                    if (SUCCEEDED(EngineDevice()->CreateShaderResourceView(tex, nullptr, &srv)))
                    {
                        *out_srv = srv;
                        if (out_w) *out_w = (int)w;
                        if (out_h) *out_h = (int)h;
                        ok = true;
                    }
                    tex->Release();
                }
            }
            free(pixels);
        }
    }
    if (conv) conv->Release();
    if (frame) frame->Release();
    dec->Release();
    fac->Release();
    return ok;
}

ID3D11ShaderResourceView* TexPlaceholder()
{
    if (g_placeholder)
        return g_placeholder;
    char exe[MAX_PATH];
    char path[MAX_PATH];
    PathsExeDir(exe, MAX_PATH);
    PathsJoin(path, MAX_PATH, exe, "assets\\placeholder.png");
    TexLoadFile(path, &g_placeholder, &g_ph_w, &g_ph_h);
    return g_placeholder;
}

void TexShutdown()
{
    if (g_placeholder)
    {
        g_placeholder->Release();
        g_placeholder = nullptr;
    }
}
