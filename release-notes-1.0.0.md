# BinarySectorInspector 1.0.0

Windows x64 PE inspector. First numbered release.

## Download

`BinarySectorInspector-1.0.0-win-x64.zip` — unpack and run `BinarySectorInspector.exe`. No installer.

## Highlights

- PE inspector: headers, sections, imports/exports, resources, icons, version info, findings
- Hex view with search, range select, and a patch journal (undo/redo, backup)
- JSON signature detection (packers, protectors, compilers, toolchains, .NET obfuscators)
- Specialized analyzers (py2exe, AutoIt, AutoHotkey, Go)
- Drop-in plugin host: put a DLL in `{exe}/plugins/` (or one subfolder). Core does not list plugin ids. SDK in `sdk/plugin/`
- Plugin cards in Settings, with search and filter dialogs (name, package id, author). Optional local icon/cover
- Settings → Scripting: separate Python 2 / Python 3 paths, Lua path stored for later
- Settings → About: version, build, git commit, GitHub avatar, LYSEP CORP lockup, license
- Settings → Third-party: ImGui, imgui_club, FreeType (FTL), nlohmann/json

## Optional plugin

The zip includes `plugins\decompsnake.dll` ([DecompSnake 0.2.1](https://github.com/candestan/BSI-Decompsnake)). Tools → DecompSnake → Export .py decompiles py2exe / Python bytecode to source-like text. You can remove the DLL if you do not want it.

## License

Attribution-NonSale (see `LICENSE`). Third-party libraries keep their own licenses.

Sponsored by [LYSEP CORP](https://lysep.com/).
