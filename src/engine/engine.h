#pragma once

#include "imgui.h"
#include <windows.h>

struct ID3D11Device;

bool EngineInit(HINSTANCE inst, bool force_sw);
void EngineShutdown();
bool EngineProcessEvents();
bool EngineShouldRender();
void EngineEndFrame();
bool EngineIsSoftware();
bool EngineVsync();
bool EngineMsaaEnabled();
void EngineRequestRenderer(bool software);
void EngineRequestMsaa(bool enabled);
void EngineSetVsync(bool on);
void EngineApplyPending();
ID3D11Device* EngineDevice();
bool EngineTakeDrop(char* out, int cap);
void EnginePushDrop(const char* path);

bool BeginForm(const char* name, bool* open = nullptr, ImVec2 init_size = ImVec2(0, 0), bool is_main = false);
void EndForm();
