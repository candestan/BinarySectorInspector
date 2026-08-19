# BinarySectorInspector

[English](README.md) | [Türkçe](README.tr.md)

Windows PE inceleme aracı. Çalıştırılabilir dosyayı açıp yapıyı, tespitleri, kaynakları ve baytları aynı yerleşimde görürsünüz; bellekte yama yapıp kaydedersiniz.

**Windows x64** gerekir. Arayüz Dear ImGui, Win32 + Direct3D 11.

## Ne işe yarar

**Yürütülebilir inceleme.** PE başlıkları, bölümler, import/export, relocation, TLS, debug dizinleri, kaynaklar, overlay, stringler, entropi.

**Tespit ve bulgular.** JSON imzalar (packer, protector, derleyici, toolchain, .NET obfuscator) [KUARA-Dynamic](https://github.com/candestan/KUARA-Dynamic) ile eşlenir. Findings ayrı bir listedir. Birkaç bilinen kapsayıcı için özel analiz vardır (py2exe marshal, Go buildinfo/pclntab, AutoIt, AutoHotkey).

**Bayt düzenleme.** Eşlenen dosya üzerinde hex (AOB / ASCII / regex). Sürüm kaynağı, yuvada yer varsa düzenlenir. Save PE’yi yazar; önce yanına yedek kopyalamayı dener.

**Çalışma alanı.** Yerleşebilir paneller. Arayüz İngilizce ve Türkçe. Temalar exe yanındaki JSON.

**Eklentiler.** x64 DLL (`sdk/plugin`). Ağaçta [Lydis](https://github.com/Septillioner/bsi-lydis) (x86/x64 listing) ve [DecompSnake](https://github.com/candestan/BSI-Decompsnake) (Python baytkodu → `.py`-benzeri metin) gelir.

## Derleme ve çalıştırma

Visual Studio 2022 (v143), Windows 10 SDK, x64.

```bat
git clone --recursive https://github.com/candestan/BinarySectorInspector.git
cd BinarySectorInspector
msbuild BinarySectorInspector.sln /p:Configuration=Release /p:Platform=x64
```

`x64\Release\BinarySectorInspector.exe` çalıştırın. Yanında `bsi_imgui.dll`, `languages\`, `themes\`, `assets\`, `signatures\` ve `plugins\` durmalı.

`--recursive` olmadan klonladıysanız:

```bat
git submodule update --init --recursive
```

Ayrıntı: [Başlangıç](docs/tr/getting-started.md) · [Derleme](docs/tr/building.md)

## Belgeler

- [Başlangıç](docs/tr/getting-started.md)
- [Kullanım](docs/tr/usage.md)
- [Analiz](docs/tr/analysis.md)
- [Eklentiler](docs/tr/plugins.md)
- [Mimari](docs/tr/architecture.md)
- İmza yazımı: [`signatures/README.md`](signatures/README.md) (İngilizce şema)
- Bağımlılıklar: [`third_party/README.md`](third_party/README.md)
- Eklenti ABI: [`sdk/plugin/README.md`](sdk/plugin/README.md)

Dizin: [docs/README.md](docs/README.md)

## Katkı

[CONTRIBUTING.tr.md](CONTRIBUTING.tr.md)

## Lisans

[LICENSE](LICENSE) (Attribution-NonSale). Üçüncü taraf kod kendi lisansındadır.
