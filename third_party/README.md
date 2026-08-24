# Third-party dependencies

All external libraries live under `third_party/`. Open-source dependencies are Git submodules pinned to an exact commit. Do not copy upstream files into `src/`. Do not edit submodule contents; first-party build glue stays outside the submodule.

## Setup

```
git clone --recursive https://github.com/candestan/BinarySectorInspector.git
```

If the clone is already present:

```
git submodule update --init --recursive
```

The default MSBuild does not download dependencies. After submodules are initialized, Debug/Release x64 builds are offline aside from the Windows SDK.

## Policy

1. Official upstream Git submodule, pinned commit or release tag.
2. Official mirror submodule only when needed.
3. Vendored source plus original license and provenance, if a submodule is impractical.
4. Proprietary SDK headers/libs/binaries only when redistribution allows it.
5. Prebuilt open-source `.lib`/`.dll` only as a documented last resort.

Generated `.lib`/`.obj`/`.dll` belong in `x64/` (gitignored). Runtime DLLs, if any, must be copied by the build. `bsi_imgui.dll` is produced next to the exe. FreeType is linked statically (`/MT`) into `bsi_imgui.dll`.

Do not bump submodule commits casually. Upgrades are deliberate.

## Inventory

| Dependency | Pin | Integration | License | Purpose |
| --- | --- | --- | --- | --- |
| Dear ImGui | `46d39d56febc2a00bdd2270dc88c8a13f2a0441a` (`v1.92.9b-20-g46d39d56f`) | Git submodule `third_party/imgui`. Shared runtime `bsi_imgui.dll` (`third_party/msvc/bsi_imgui.vcxproj`) compiles `imgui*.cpp` + `imgui_freetype.cpp`. Host and plugins dllimport it. Compile options live in `sdk/imgui/bsi_imconfig.h` (`IMGUI_USE_WCHAR32`, `IMGUI_ENABLE_FREETYPE`). Win32/DX11 backends stay in the host EXE. | MIT (`third_party/imgui/LICENSE.txt`) | UI |
| imgui_club | `a436e793fe44a2c8e827bfcbf138fcbe11940476` | Git submodule `third_party/imgui_club`. Header-only `imgui_memory_editor`. | MIT (`third_party/imgui_club/LICENSE.txt`) | Hex editor widget |
| imnodes | `eb36902c892548ef94f88f51ad7e7c9c7058a71c` | Git submodule `third_party/imnodes`. App compiles `imnodes.cpp`. Host creates a per-form `ImNodesContext` and exposes it to plugins through `BsiHost` / `BsiUi`. | MIT (`third_party/imnodes/LICENSE.md`) | Node editor widget ([Nelarius/imnodes](https://github.com/Nelarius/imnodes)) |
| nlohmann/json | `cdf52ae9bef77a0844e02e42df6d2df83a55c4b9` (`v3.11.3-474-gcdf52ae9b`) | Git submodule `third_party/nlohmann_json`. Include `single_include`. | MIT (`third_party/nlohmann_json/LICENSE.MIT`) | settings, i18n, theme JSON |
| FreeType | `42608f77f20749dd6ddc9e0536788eaad70ea4b5` (tag `VER-2-13-3`) | Git submodule `third_party/freetype` (GitHub mirror of [gitlab.freedesktop.org/freetype/freetype](https://gitlab.freedesktop.org/freetype/freetype)). Built from source by first-party `third_party/msvc/freetype.vcxproj`. Output `freetype.lib` is generated, not committed. | FTL or GPLv2 (`third_party/freetype/LICENSE.TXT`, `docs/FTL.TXT`, `docs/GPLv2.TXT`) | Color emoji / `imgui_freetype` |
| KUARA-Dynamic | submodule `third_party/kuara_dynamic` | Detection engine. BSI compiles selected sources and talks to it through `src/detect/kuara_adapter.cpp`. Do not treat KUARA as a UI plugin. | Attribution-NonSale (`third_party/kuara_dynamic/LICENSE`) | Signature matching engine |
| miniz | `77d0dce8627735138c51770d1799a1ef48f2117d` (tag `3.1.2`) | Git submodule `third_party/miniz` ([richgel999/miniz](https://github.com/richgel999/miniz)). Host compiles `miniz.c` / `miniz_tdef.c` / `miniz_tinfl.c` / `miniz_zip.c` with `MINIZ_NO_ARCHIVE_APIS` + `MINIZ_NO_STDIO`. CMake export stub is `third_party/miniz_export.h` (outside the submodule). | MIT (`third_party/miniz/LICENSE`) | zlib inflate for PyInstaller / analysis |

imgui `misc/freetype` is part of the Dear ImGui submodule, not a separate dependency.

`plugins/decompsnake` is a first-party plugin submodule (not under `third_party/`). License: Attribution-NonSale (`plugins/decompsnake/LICENSE`).
`plugins/lydis` is a plugin submodule (https://github.com/Septillioner/bsi-lydis).

## First-party build wrappers

`third_party/msvc/freetype.vcxproj` is application build integration. It compiles a minimal FreeType set (no examples, tests, docs, or tools) with the same `/MT` CRT as the app. It does not patch FreeType sources.

`third_party/miniz_export.h` is the MSVC stand-in for CMake-generated `miniz_export.h` so the miniz submodule builds without running CMake.

## Platform SDK (not in `third_party/`)

Linked from the Windows SDK: `d3d11`, `dxgi`, `dcomp`, `dwmapi`, plus Win32 (`user32`, `comdlg32`, `shell32`, …). These are OS components, not repository dependencies.

## Binaries

No third-party `.dll`, `.lib`, or `.exe` is committed. `.gitignore` excludes generated binaries and accidental `third_party/*-tmp/` extract folders.

## Local modifications

None inside submodules. App-level options:

- ImGui: `IMGUI_USE_WCHAR32`, `IMGUI_ENABLE_FREETYPE` in `BinarySectorInspector.vcxproj`.
- FreeType: compile list and `/MT` in `third_party/msvc/freetype.vcxproj`.
