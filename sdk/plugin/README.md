# BinarySectorInspector Plugin SDK

Plugins are ordinary Windows x64 DLLs. Core never lists plugin ids in source. Putting a DLL in the host `plugins` folder is enough.

```
{BinarySectorInspector.exe}
  bsi_imgui.dll               # host ImGui runtime; Level 2 plugins import this
  plugins\
    myplugin.dll              # loaded
    other\
      other.dll               # loaded (one folder level)
    data\
      com.example.myplugin\   # writable dir from host->path(..., "data")
```

Third-party plugins need no project reference, no `#include` of plugin code, and no rebuild of the inspector. Bundled plugins (`plugins/lydis`, `plugins/decompsnake`) are host ProjectReferences so building the inspector also builds those DLLs and copies them into `{OutDir}plugins\`. The EXE still does not link plugin `.lib`s.

## Ship a plugin

1. Copy `bsi_plugin.h` into the plugin repo. Do not include BSI `src/`.
2. Export `BsiPluginGetInfo`, `BsiPluginInit`, `BsiPluginShutdown`.
3. Build a DLL. Level 1 UI does not need ImGui. Level 2 UI links `bsi_imgui.dll` (import `sdk/imgui/bsi_imgui.props`) and draws with `ImGui::` in view/settings callbacks. Do not compile `imgui.cpp`. Do not link the inspector EXE.
4. Copy the DLL to `{exe}/plugins/` (or a one-level subfolder).
5. Start BinarySectorInspector. Settings → Plugins shows a card per DLL (search/filter by name, package id, author). Optional icon/cover paths come from `BsiPluginVisuals`, `plugin.json` / `tool.json`, or `icon.png` / `cover.png` next to the DLL.

`sdk/plugin/skeleton.c` is a minimal compilable example.

## ABI

| Macro | Meaning |
| --- | --- |
| `BSI_PLUGIN_ABI_MIN` | Oldest host ABI a plugin may accept |
| `BSI_PLUGIN_ABI_VERSION` | ABI this header was written for |

Structs grow only at the **end**. `abi_version` stays **2** until a breaking change. Then MIN/VERSION bump.

```c
if (!BsiHostCompatible(host))
    return 1;   // Init failed
if (BSI_HOST_HAS(host, hex_goto))
    host->hex_goto(host->ctx, off);
```

The host loads a plugin when `BSI_PLUGIN_ABI_MIN <= info->abi_version <= BSI_PLUGIN_ABI_VERSION`.

## Exports

| Export | Required | Role |
| --- | --- | --- |
| `BsiPluginGetInfo` | yes | Identity; `abi_version` = `BSI_PLUGIN_ABI_VERSION` |
| `BsiPluginInit` | yes | Receive `BsiHost*`; return 0 on success |
| `BsiPluginShutdown` | yes | Drop host pointer |
| `BsiPluginToolCount/Info/Run` | no | Tools menu, grouped by `parent` |
| `BsiPluginViewCount/Info/Draw` | no | Inspector tree views |
| `BsiPluginHasSettings` / `DrawSettings` | no | Settings → Plugins |
| `BsiPluginOnJob` | no | `ready=1` after a PE parses, `0` when closed or failed |
| `BsiPluginVisuals` | no | Local `icon` / `cover` paths for the Settings card |

Draw callbacks run on the UI thread.

Level 1: use `BsiUi` widgets. No ImGui needed.

Level 2: link the host `bsi_imgui.dll` and call `ImGui::` directly. Native plugins are trusted in-process code, not a sandbox. Do not compile `imgui.cpp` in the plugin.

```cpp
#include "bsi_plugin.h"
#include "imgui.h"

BSI_PLUGIN_EXPORT int BsiPluginViewDraw(int index, const BsiUi* ui)
{
    if (index != 0 || !ui)
        return 0;
    if (BSI_UI_HAS(ui, imgui) && ui->imgui)
        ImGui::SetCurrentContext((ImGuiContext*)ui->imgui);
    ImGui::TextUnformatted("hello");
    return 1;
}
```

Import `sdk/imgui/bsi_imgui.props` so include paths, `IMGUI_USER_CONFIG`, and `bsi_imgui.lib` match the host. `bsi_imgui.dll` already sits next to the exe; Windows resolves it when the plugin loads.

`SetCurrentContext` is optional during a host draw callback (the form context is already current inside `bsi_imgui.dll`) but keep it. Do not `CreateContext` / `NewFrame` / `Render`. Do not compile Win32/DX backends. Do not keep `ImGuiContext*` after the callback returns. Do not call ImGui from worker threads.

Compile flags are in `sdk/imgui/bsi_imconfig.h` (`IMGUI_USE_WCHAR32`, `IMGUI_ENABLE_FREETYPE`). Probe `host->imgui_compile_flags` / `host->imgui_version` if you need to assert the pin.

imnodes is still compiled into the host EXE. A plugin that wants `ImNodes::` compiles the host-pinned `imnodes.cpp` and binds `ui->imnodes`:

```c
if (BSI_UI_HAS(ui, imnodes) && ui->imnodes)
    ImNodes::SetCurrentContext((ImNodesContext*)ui->imnodes);
```

`sdk/plugin/skeleton.c` is Level 1. `sdk/plugin/skeleton_imgui.cpp` is Level 2.

`BsiHost` is the current HostContext. New services are appended to `BsiHost` / `BsiUi` (size/version probe). Nested service tables (`BsiBinaryApi`, `BsiPatchApi`, …) are planned; they are not a breaking ABI yet. Do not freeze a DLL ABI until static providers have used the same contracts.

## Host paths (`host->path`)

| Key | Result |
| --- | --- |
| `exe` | Directory of the host exe |
| `plugins` | `{exe}/plugins` |
| `themes` / `languages` / `assets` | Packed host folders |
| `settings` | `settings.json` |
| `python2` / `python3` / `lua` | Paths from Settings → Scripting (may be empty) |
| `self` | Full path of this DLL |
| `data` | `{exe}/plugins/data/<plugin-id>\` (created on demand) |

## Job and image

`job_ready` is true when a PE is open and idle. `image` is the mapped file bytes (read-only view). `has_product` uses detection `product_key` (for example `py2exe`). `has_media` / `artifact_*` walk analysis artifacts by media string (for example `python.bytecode`). `has_rsrc_name` matches a resource leaf name.

Additive queries: `detection_*`, `rsrc_*`, `section_*`, `hex_goto` / `hex_select`, `open_job`.

Additive mutation (probe with `BSI_HOST_HAS`): `patch_bytes(file_off, data, n)` applies through the host patch journal (undoable). `job_save(skip_backup)` writes the mapped image to the open job path. Do not cast away `const` on `image()` to poke bytes.

PE layout (probe with `BSI_HOST_HAS`): `pe_machine` (`IMAGE_FILE_MACHINE_*`), `image_base`, `entry_rva`, `rva_to_off` / `off_to_rva`. `hex_cursor` returns the hex view selection (`file_off`, `size`); 0 if none.

## Card visuals

Settings → Plugins draws one card per loaded DLL. Art is optional and **local only** (no HTTP).

Resolution order for `icon` and `cover`:

1. `BsiPluginVisuals()` (`icon` / `cover`, relative to the DLL folder or absolute)
2. `plugin.json` or `tool.json` next to the DLL (`"icon"`, `"cover"`)
3. `icon.png` / `icon.jpg` / `cover.png` / `cover.jpg` next to the DLL

`..` and `http(s):` paths are rejected. Missing art uses the host placeholder.

```c
BSI_PLUGIN_EXPORT const struct BsiVisuals* BsiPluginVisuals(void)
{
    static const struct BsiVisuals v = {
        (uint32_t)sizeof(struct BsiVisuals),
        "icon.png",
        "cover.png"
    };
    return &v;
}
```

## Settings and JSON

Plugin keys are stored as `plugin.cfg.<id>.<key>` in `settings.json`. JSON handles are per-process; free them. Paths are JSON pointers (`/a/b/0`) or dotted (`a.b.0`).

## Rules

- Stable `id` (reverse-DNS). Changing it orphans settings.
- Log through `host->log`. Do not call `MessageBox`.
- Do not parse PE / walk resources yourself if a host query already exists.
- Save dialogs last; cancel is not an error.
- Optional UI strings may use `i18n_get` with host keys. Plugin-owned labels may stay English.
- New host fields: append only, then document here. Never reorder `BsiHost` / `BsiUi`.
