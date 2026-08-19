# Plugins

[English](plugins.md) | [Türkçe](../tr/plugins.md)

The host loads `*.dll` from `{exe}\plugins\` and one folder level below. A plugin is a Windows x64 DLL exporting `BsiPluginGetInfo`, `BsiPluginInit`, and `BsiPluginShutdown`. ABI **2** (`sdk/plugin/bsi_plugin.h`).

The inspector exe does not link plugin `.lib` files. Bundled plugins are MSBuild ProjectReferences so they build and copy into `{OutDir}plugins\`.

How to write a DLL, host function table, and ImGui pin: [`sdk/plugin/README.md`](../../sdk/plugin/README.md). ImGui runtime: [`sdk/imgui/README.md`](../../sdk/imgui/README.md).

`bsi_imgui.dll` must sit **next to the exe**. Level-2 plugins (Lydis) import it; Windows looks in the application directory.

## Shipped with this tree

**Lydis** (`com.septillioner.bsi.lydis`) — [bsi-lydis](https://github.com/Septillioner/bsi-lydis). Zydis listing of x86/x64 executable sections, function list, xrefs, Tools to start at entry or hex cursor. Decoder internals live in that repo.

**DecompSnake** (`com.candestan.binarysectorinspector.decompsnake`) — [BSI-Decompsnake](https://github.com/candestan/BSI-Decompsnake). **Tools → DecompSnake → Export .py** from host bytecode artifacts. No docked view. `decompsnake.exe` in `x64\<Config>\` is a CLI project, not the inspector plugin.

Enable/disable and settings cards: Settings → Plugins. Config keys are stored per plugin id.

## Job lifecycle

`BsiPluginOnJob(1)` after a PE is ready, `(0)` when it closes. Plugins should drop image caches on 0.
