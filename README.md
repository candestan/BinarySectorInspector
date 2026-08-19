# BinarySectorInspector

[English](README.md) | [Türkçe](README.tr.md)

Windows PE inspector. Open an executable, look at its structure, detections, resources, and bytes in one docked workspace, then patch in memory and save.

Requires **Windows x64**. UI is Dear ImGui on Win32 + Direct3D 11.

## What it does

**Executable inspection.** PE headers, sections, imports, exports, relocations, TLS, debug directories, resources, overlay, strings, entropy.

**Detection and findings.** JSON signatures (packers, protectors, compilers, toolchains, .NET obfuscators) matched through [KUARA-Dynamic](https://github.com/candestan/KUARA-Dynamic). Separate findings collect structural and string-based notes. Specialized analyzers unpack a few known containers (py2exe marshal, Go buildinfo/pclntab, AutoIt, AutoHotkey).

**Binary editing.** Hex editor over the mapped file (AOB / ASCII / regex search). Version-resource edits where the existing slot has room. Save writes the PE and tries a sibling backup first.

**Workspace.** Dockable views (navigator, overview, hex, detection, …). English and Turkish UI. Themes as JSON next to the exe.

**Plugins.** Drop-in x64 DLLs (`sdk/plugin`). The tree ships [Lydis](https://github.com/Septillioner/bsi-lydis) (x86/x64 listing) and [DecompSnake](https://github.com/candestan/BSI-Decompsnake) (Python bytecode → `.py`-like text).

## Build and run

Visual Studio 2022 (toolset v143), Windows 10 SDK, x64.

```bat
git clone --recursive https://github.com/candestan/BinarySectorInspector.git
cd BinarySectorInspector
msbuild BinarySectorInspector.sln /p:Configuration=Release /p:Platform=x64
```

Run `x64\Release\BinarySectorInspector.exe`. Keep `bsi_imgui.dll`, `languages\`, `themes\`, `assets\`, `signatures\`, and `plugins\` next to the exe.

If you cloned without `--recursive`:

```bat
git submodule update --init --recursive
```

Details: [Getting started](docs/en/getting-started.md) · [Building](docs/en/building.md)

## Documentation

- [Getting started](docs/en/getting-started.md)
- [Usage](docs/en/usage.md)
- [Analysis](docs/en/analysis.md)
- [Plugins](docs/en/plugins.md)
- [Architecture](docs/en/architecture.md)
- Signature authoring: [`signatures/README.md`](signatures/README.md)
- Dependencies: [`third_party/README.md`](third_party/README.md)
- Plugin ABI: [`sdk/plugin/README.md`](sdk/plugin/README.md)

Index: [docs/README.md](docs/README.md)

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md)

## License

See [LICENSE](LICENSE) (Attribution-NonSale). Third-party code keeps its own licenses.
