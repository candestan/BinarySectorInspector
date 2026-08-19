# Getting started

[English](getting-started.md) | [Türkçe](../tr/getting-started.md)

## Requirements

- Windows 10/11 x64
- [Visual Studio 2022](https://visualstudio.microsoft.com/) with the Desktop C++ workload (toolset **v143**)
- Windows 10 SDK (the project uses `WindowsTargetPlatformVersion` 10.0)
- Git, with submodules

There is no CMake or Linux/macOS build in this repository.

## Clone

```bat
git clone --recursive https://github.com/candestan/BinarySectorInspector.git
cd BinarySectorInspector
```

Already cloned without modules:

```bat
git submodule update --init --recursive
```

You need `third_party/imgui`, `freetype`, `nlohmann_json`, `imgui_club`, `imnodes`, `kuara_dynamic`, plus `plugins/lydis` and `plugins/decompsnake`.

## Build

From a VS 2022 Developer Command Prompt, repo root:

```bat
msbuild BinarySectorInspector.sln /p:Configuration=Release /p:Platform=x64
```

Debug is the same with `Configuration=Debug`. Output: `x64\<Configuration>\BinarySectorInspector.exe`.

The host post-build step copies `languages`, `themes`, `assets`, `signatures`, analysis profiles, and plugin DLLs into that folder. `bsi_imgui.dll` is built next to the exe.

If MSBuild is not on `PATH`, use the copy under `C:\Program Files\Microsoft Visual Studio\2022\<edition>\MSBuild\Current\Bin\MSBuild.exe`.

More failure modes: [Building](building.md).

## First PE

1. Start `BinarySectorInspector.exe`.
2. Welcome screen: **Open file...**, or drop a file on the window (`WM_DROPFILES`). In the inspector, **File → Open file...** (`Ctrl+O`). Dialog title is `Open PE`.
3. **File → From window...** attaches to a running process image when the picker can read it.
4. **File → Open Recent** lists paths from settings.

The navigator on the left is the PE tree. Center starts on Overview and Hex. Detection and Findings are separate views in **View**.

A **PE** is a Windows Portable Executable (`.exe`, `.dll`, …). After the loader maps it, addresses in the file are often discussed as **RVA** (relative virtual address): offset from the image base in memory, not the raw file offset. Hex in this app is still **file offset** unless a plugin converts via `rva_to_off`.
