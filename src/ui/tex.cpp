#include "ui/tex.h"
#include "engine/engine.h"
#include "persist/paths.h"

#include <windows.h>
#include <wincodec.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <vector>

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

static bool UploadRgba(const unsigned char* pixels, UINT w, UINT h, ID3D11ShaderResourceView** out_srv, int* out_w, int* out_h)
{
    if (!pixels || !out_srv || !EngineDevice())
        return false;
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
    sd.SysMemPitch = w * 4;
    ID3D11Texture2D* tex = nullptr;
    if (FAILED(EngineDevice()->CreateTexture2D(&td, &sd, &tex)))
        return false;
    ID3D11ShaderResourceView* srv = nullptr;
    HRESULT hr = EngineDevice()->CreateShaderResourceView(tex, nullptr, &srv);
    tex->Release();
    if (FAILED(hr))
        return false;
    *out_srv = srv;
    if (out_w) *out_w = (int)w;
    if (out_h) *out_h = (int)h;
    return true;
}

static bool DecodeFrame(IWICImagingFactory* fac, IWICBitmapDecoder* dec, ID3D11ShaderResourceView** out_srv, int* out_w, int* out_h)
{
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
                ok = UploadRgba(pixels, w, h, out_srv, out_w, out_h);
            free(pixels);
        }
    }
    if (conv) conv->Release();
    if (frame) frame->Release();
    return ok;
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
    bool ok = false;
    if (SUCCEEDED(hr) && dec)
        ok = DecodeFrame(fac, dec, out_srv, out_w, out_h);
    if (dec) dec->Release();
    fac->Release();
    return ok;
}

bool TexLoadMemory(const void* data, size_t n, ID3D11ShaderResourceView** out_srv, int* out_w, int* out_h)
{
    if (out_srv)
        *out_srv = nullptr;
    if (!data || n < 8 || !EngineDevice() || !EnsureCom())
        return false;

    IWICImagingFactory* fac = nullptr;
    if (FAILED(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&fac))))
        return false;
    IWICStream* st = nullptr;
    fac->CreateStream(&st);
    bool ok = false;
    if (st && SUCCEEDED(st->InitializeFromMemory((BYTE*)data, (DWORD)n)))
    {
        IWICBitmapDecoder* dec = nullptr;
        if (SUCCEEDED(fac->CreateDecoderFromStream(st, nullptr, WICDecodeMetadataCacheOnLoad, &dec)) && dec)
        {
            ok = DecodeFrame(fac, dec, out_srv, out_w, out_h);
            dec->Release();
        }
    }
    if (st) st->Release();
    fac->Release();
    return ok;
}

bool TexLoadPeIcon(const uint8_t* blob, uint32_t n, ID3D11ShaderResourceView** out_srv, int* out_w, int* out_h)
{
    if (!blob || n < 8)
        return false;
    if (blob[0] == 0x89 && blob[1] == 'P' && blob[2] == 'N' && blob[3] == 'G')
        return TexLoadMemory(blob, n, out_srv, out_w, out_h);

#pragma pack(push, 1)
    struct IcoDir { uint16_t reserved, type, count; };
    struct IcoEnt { uint8_t w, h, colors, reserved; uint16_t planes, bpp; uint32_t bytes, off; };
#pragma pack(pop)
    std::vector<uint8_t> ico(sizeof(IcoDir) + sizeof(IcoEnt) + n);
    IcoDir* d = (IcoDir*)ico.data();
    d->reserved = 0;
    d->type = 1;
    d->count = 1;
    IcoEnt* e = (IcoEnt*)(ico.data() + sizeof(IcoDir));
    e->w = 0;
    e->h = 0;
    e->colors = 0;
    e->reserved = 0;
    e->planes = 1;
    e->bpp = 32;
    e->bytes = n;
    e->off = sizeof(IcoDir) + sizeof(IcoEnt);
    memcpy(ico.data() + e->off, blob, n);
    return TexLoadMemory(ico.data(), ico.size(), out_srv, out_w, out_h);
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
