# BinarySectorInspector

[English](README.md) | [Türkçe](README.tr.md)

Windows PE inspector. Bir PE açıp structure, detection, resource ve byte'lara aynı workspace içinde bakarsınız; memory'de patch atıp Save ile yazarsınız.

**Windows x64** gerekir. UI: Dear ImGui, Win32 + Direct3D 11.

## Ne işe yarar

**PE inspection.** Header, section, import, export, relocation, TLS, debug directory, resource, overlay, string, entropy.

**Detection ve Findings.** JSON signature'lar (packer, protector, compiler, toolchain, .NET obfuscator) [KUARA-Dynamic](https://github.com/candestan/KUARA-Dynamic) matcher'ı ile eşlenir. Findings ayrı bir listedir. Birkaç bilinen container için specialized analyzer vardır (py2exe marshal, Go buildinfo/pclntab, AutoIt, AutoHotkey).

**Hex editing.** Map edilmiş file üzerinde hex editor (AOB / ASCII / regex). Version resource, slot'ta yer varsa düzenlenir. Save PE'yi yazar; önce yanına backup kopyalamayı dener.

**Workspace.** Dock edilebilir view'lar. UI İngilizce ve Türkçe. Theme'ler exe yanındaki JSON.

**Plugin.** x64 DLL (`sdk/plugin`). Ağaçta [Lydis](https://github.com/Septillioner/bsi-lydis) (x86/x64 listing) ve [DecompSnake](https://github.com/candestan/BSI-Decompsnake) (Python bytecode → `.py`-benzeri text) gelir.

## Build ve çalıştırma

Visual Studio 2022 (v143), Windows 10 SDK, x64.

```bat
git clone --recursive https://github.com/candestan/BinarySectorInspector.git
cd BinarySectorInspector
msbuild BinarySectorInspector.sln /p:Configuration=Release /p:Platform=x64
```

`x64\Release\BinarySectorInspector.exe` çalıştırın. Yanında `bsi_imgui.dll`, `languages\`, `themes\`, `assets\`, `signatures\` ve `plugins\` durmalı.

`--recursive` olmadan clone aldıysanız:

```bat
git submodule update --init --recursive
```

Ayrıntı: [Başlangıç](docs/tr/getting-started.md) · [Build](docs/tr/building.md)

## Dokümantasyon

- [Başlangıç](docs/tr/getting-started.md)
- [Kullanım](docs/tr/usage.md)
- [Analiz](docs/tr/analysis.md)
- [Plugin](docs/tr/plugins.md)
- [Mimari](docs/tr/architecture.md)
- Signature yazımı: [`signatures/README.md`](signatures/README.md) (İngilizce şema)
- Dependency'ler: [`third_party/README.md`](third_party/README.md)
- Plugin ABI: [`sdk/plugin/README.md`](sdk/plugin/README.md)

Index: [docs/README.md](docs/README.md)

## Katkı

[CONTRIBUTING.tr.md](CONTRIBUTING.tr.md)

## Lisans

[LICENSE](LICENSE) (Attribution-NonSale). Third-party kod kendi lisansındadır.
