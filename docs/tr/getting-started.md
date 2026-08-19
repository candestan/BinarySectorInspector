# Başlangıç

[English](../en/getting-started.md) | [Türkçe](getting-started.md)

## Gereksinimler

- Windows 10/11 x64
- Desktop C++ workload ile [Visual Studio 2022](https://visualstudio.microsoft.com/) (toolset **v143**)
- Windows 10 SDK (`WindowsTargetPlatformVersion` 10.0)
- Git ve submodule'ler

Bu repository'de CMake veya Linux/macOS build yok.

## Clone

```bat
git clone --recursive https://github.com/candestan/BinarySectorInspector.git
cd BinarySectorInspector
```

Submodule'süz clone aldıysanız:

```bat
git submodule update --init --recursive
```

Gerekli: `third_party/imgui`, `freetype`, `nlohmann_json`, `imgui_club`, `imnodes`, `kuara_dynamic`, `plugins/lydis`, `plugins/decompsnake`.

## Build

VS 2022 Developer Command Prompt, repo kökü:

```bat
msbuild BinarySectorInspector.sln /p:Configuration=Release /p:Platform=x64
```

Debug için `Configuration=Debug`. Çıktı: `x64\<Configuration>\BinarySectorInspector.exe`.

Host post-build `languages`, `themes`, `assets`, `signatures`, analysis profile'ları ve plugin DLL'lerini bu klasöre kopyalar. `bsi_imgui.dll` exe'nin yanında üretilir.

MSBuild `PATH`'te değilse: `C:\Program Files\Microsoft Visual Studio\2022\<edition>\MSBuild\Current\Bin\MSBuild.exe`.

Daha fazla hata: [Build](building.md).

## İlk PE

1. `BinarySectorInspector.exe` başlatın.
2. Welcome: **Dosya aç...**, veya pencereye dosya bırakın. Inspector'da **File → Open file...** (`Ctrl+O`). Dialog başlığı `Open PE`.
3. **File → From window...** çalışan process image'ına (okunabiliyorsa) bağlanır.
4. **File → Open Recent** settings'teki son path'leri listeler.

Solda navigator PE tree'sidir. Ortada Overview ve Hex açılır. Detection ve Findings **View** altındadır. TR UI'da Detection "Tespit", Findings "Bulgular" diye görünür; view id'leri aynıdır.

**PE** (Portable Executable): Windows `.exe` / `.dll` formatı. Loader map ettikten sonra adresler çoğu zaman **RVA** (relative virtual address) ile konuşulur: memory'deki image base'e göre offset, raw file offset değil. Bu uygulamada Hex yine **file offset** kullanır; plugin `rva_to_off` ile çevirir.
