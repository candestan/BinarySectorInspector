#pragma once

// Shared Dear ImGui compile options for the host and for plugins that
// link bsi_imgui.dll. Do not compile imgui.cpp in a plugin.
// Force-included via IMGUI_USER_CONFIG="bsi_imconfig.h".

#ifdef BSI_IMGUI_IMPL
#define IMGUI_API __declspec(dllexport)
#else
#define IMGUI_API __declspec(dllimport)
#ifndef IMGUI_IMPL_API
#define IMGUI_IMPL_API
#endif
#endif

#define IMGUI_USE_WCHAR32
#define IMGUI_ENABLE_FREETYPE
