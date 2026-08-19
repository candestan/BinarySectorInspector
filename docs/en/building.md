# Building

[English](building.md) | [Türkçe](../tr/building.md)

Solution: `BinarySectorInspector.sln`. Configurations: **Debug|x64**, **Release|x64** only. Platform toolset v143. CRT: `/MT` (Release) / `/MTd` (Debug) on the host; plugins follow their vcxproj.

```bat
msbuild BinarySectorInspector.sln /p:Configuration=Release /p:Platform=x64
```

Projects in the sln: host, freetype (static lib), `bsi_imgui`, Lydis, DecompSnake DLL, DecompSnake CLI.

## Output next to the exe

Needed to run:

- `BinarySectorInspector.exe`
- `bsi_imgui.dll`
- `languages\`, `themes\`, `assets\`
- `signatures\builtin\` (and empty `user` / `packs` dirs as created)
- `plugins\lydis.dll`, `plugins\decompsnake.dll`

Generated `.pdb` / `.lib` / `obj\` are for developers, not a release zip. `settings.json` is created at runtime next to the exe.

## Common failures

**Submodules empty.** ImGui/FreeType/json missing include paths. Run `git submodule update --init --recursive`.

**`bsi_imgui.lib` missing while linking Lydis.** Lydis waits on the `bsi_imgui` project. A parallel build of Lydis alone, before `bsi_imgui`, fails with LNK1104. Build the sln, or build `bsi_imgui` first.

**Plugin DLL locked.** Copy to `{OutDir}plugins\` fails if the inspector still has the DLL loaded. Close the app.

**Win32 / x86.** Not a solution platform. Do not pass `Platform=Win32`.

## Third-party

Pins and licenses: [`third_party/README.md`](../../third_party/README.md). Do not edit submodule working trees for app glue; wrappers live in `third_party/msvc/`.
