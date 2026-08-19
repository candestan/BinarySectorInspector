# Başlangıç

[English](../en/getting-started.md) | [Türkçe](getting-started.md)

## Gereksinimler

- Windows 10/11 x64
- Masaüstü C++ iş yüküyle [Visual Studio 2022](https://visualstudio.microsoft.com/) (toolset **v143**)
- Windows 10 SDK (`WindowsTargetPlatformVersion` 10.0)
- Git, altmodüllerle

Bu depoda CMake veya Linux/macOS derlemesi yok.

## Klon

```bat
git clone --recursive https://github.com/candestan/BinarySectorInspector.git
cd BinarySectorInspector
```

Modülsüz klonladıysanız:

```bat
git submodule update --init --recursive
```

Gerekli: `third_party/imgui`, `freetype`, `nlohmann_json`, `imgui_club`, `imnodes`, `kuara_dynamic`, `plugins/lydis`, `plugins/decompsnake`.

## Derleme

VS 2022 Developer Command Prompt, depo kökü:

```bat
msbuild BinarySectorInspector.sln /p:Configuration=Release /p:Platform=x64
```

Debug için `Configuration=Debug`. Çıktı: `x64\<Configuration>\BinarySectorInspector.exe`.

Host post-build `languages`, `themes`, `assets`, `signatures`, analiz profilleri ve eklenti DLL’lerini bu klasöre kopyalar. `bsi_imgui.dll` exe’nin yanında üretilir.

MSBuild `PATH`’te değilse: `C:\Program Files\Microsoft Visual Studio\2022\<edition>\MSBuild\Current\Bin\MSBuild.exe`.

Daha fazla hata: [Derleme](building.md).

## İlk PE

1. `BinarySectorInspector.exe` başlatın.
2. Karşılama: **Dosya aç...**, veya pencereye dosya bırakın. Inspector’da **File → Open file...** (`Ctrl+O`). Diyalog başlığı `Open PE`.
3. **File → From window...** çalışan süreç imajına (okunabiliyorsa) bağlanır.
4. **File → Open Recent** ayarlardaki son yolları listeler.

Solda navigator PE ağacıdır. Ortada Overview ve Hex açılır. Detection ve Findings **View** altındadır.

**PE**, Windows Portable Executable (`.exe`, `.dll`, …). Yükleyici eşledikten sonra adresler çoğu zaman **RVA** (relative virtual address) ile konuşulur: bellek image base’ine göre ofset, ham dosya ofseti değil. Bu uygulamada Hex yine **dosya ofsetidir**; eklenti `rva_to_off` ile çevirir.
