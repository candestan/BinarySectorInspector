#pragma once

#include "engine/engine.h"
#include <d3d11.h>
#include <dxgi1_2.h>
#include <dcomp.h>

static const int kMaxForms = 16;
static const int kMinWindow = 300; // hard min. content-based min size inflated the HWND.

struct ImNodesContext;

struct Form
{
    bool                    live;
    bool                    kill_me;
    bool                    is_main;
    HWND                    hwnd;
    IDXGISwapChain1*        swap;
    ID3D11Texture2D*        bb_tex;
    ID3D11Texture2D*        msaa_tex;
    ID3D11RenderTargetView* rtv;
    IDCompositionTarget*    dcomp_target;
    IDCompositionVisual*    dcomp_visual;
    ImGuiContext*           imgui;
    ImNodesContext*         imnodes;
    UINT                    w;
    UINT                    h;
    int                     min_w;
    int                     min_h;
    bool                    maximized;
    char                    name[96];
};

extern ID3D11Device*        g_device;
extern ID3D11DeviceContext* g_ctx;
extern IDXGIFactory2*       g_factory;
extern IDCompositionDevice* g_dcomp;
extern bool                 g_sw;
extern bool g_vsync;
extern UINT g_msaa;
extern HINSTANCE            g_inst;
extern Form                 g_forms[kMaxForms];
extern Form*                g_cur;
extern bool                 g_moving;
extern bool                 g_quitting;
extern int                  g_spawn_n;

bool BootDevice(bool force_sw);
void KillDevice();
void NukeRTV(Form* f);
void MakeRTV(Form* f);
void PickMsaa();
bool BindFormGpu(Form* f);
void UnbindFormGpu(Form* f);

Form* FindForm(const char* name);
Form* SpawnForm(const char* name, int w, int h);
void  KillForm(Form* f);
void  BindFormUi(Form* f);
int   LiveFormCount();
bool  IsDead(const char* name);
void  MarkDead(const char* name);

void    CaptureGeom(Form* f);
void    ToggleMax(Form* f);
void    SyncMaximized(Form* f);
LRESULT HitTest(HWND hwnd, Form* f, LPARAM lp);
LRESULT HandleNcCalcSize(HWND hwnd, WPARAM wp, LPARAM lp);
LRESULT WINAPI HostWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
