# BinarySectorInspector Plugin SDK

Plugins are ordinary Windows x64 DLLs. Core never lists plugin ids in source. Putting a DLL in the host `plugins` folder is enough.

```
{BinarySectorInspector.exe}
  plugins\
    myplugin.dll              # loaded
    other\
      other.dll               # loaded (one folder level)
    data\
      com.example.myplugin\   # writable dir from host->path(..., "data")
```

No project reference, no `#include` of plugin code, no rebuild of the inspector.

## Ship a plugin

1. Copy `bsi_plugin.h` into the plugin repo. Do not include BSI `src/`.
2. Export `BsiPluginGetInfo`, `BsiPluginInit`, `BsiPluginShutdown`.
3. Build a DLL. Level 1 UI does not need ImGui. Level 2 UI compiles the host-pinned `imgui.cpp` / `imnodes.cpp` and binds the host contexts (see below). Do not link the inspector EXE.
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

Level 1: use `BsiUi` widgets. Do not call ImGui from the plugin.

Level 2: bind the host ImGui / imnodes contexts, then call ImGui and ImNodes as usual. Native plugins are trusted in-process code, not a sandbox.

```c
if (BSI_UI_HAS(ui, imgui) && ui->imgui)
{
    ImGuiMemAllocFunc alloc_fn = 0;
    ImGuiMemFreeFunc free_fn = 0;
    void* user = 0;
    if (BSI_HOST_HAS(host, imgui_get_allocators))
        host->imgui_get_allocators(host->ctx, (void**)&alloc_fn, (void**)&free_fn, &user);
    if (alloc_fn && free_fn)
        ImGui::SetAllocatorFunctions(alloc_fn, free_fn, user);
    ImGui::SetCurrentContext((ImGuiContext*)ui->imgui);
    if (BSI_UI_HAS(ui, imnodes) && ui->imnodes)
        ImNodes::SetCurrentContext((ImNodesContext*)ui->imnodes);
}
```

Compile flags must match the host (`host->imgui_compile_flags`): currently `IMGUI_USE_WCHAR32` and `IMGUI_ENABLE_FREETYPE`. Use the same Dear ImGui and imnodes commits as `third_party/imgui` and `third_party/imnodes`. Do not Begin/End host windows. Do not keep `ImGuiContext*` after the callback returns. Do not call ImGui or ImNodes from worker threads.

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

`job_ready` is true when a PE is open and idle. `image` is the mapped file bytes. `has_product` uses detection `product_key` (for example `py2exe`). `has_media` / `artifact_*` walk analysis artifacts by media string (for example `python.bytecode`). `has_rsrc_name` matches a resource leaf name.

Additive queries: `detection_*`, `rsrc_*`, `section_*`, `hex_goto` / `hex_select`, `open_job`.

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
