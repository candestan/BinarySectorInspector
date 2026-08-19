# Build

[English](../en/building.md) | [Türkçe](building.md)

Solution: `BinarySectorInspector.sln`. Yalnız **Debug|x64** ve **Release|x64**. Toolset v143. CRT: host'ta Release `/MT`, Debug `/MTd`.

```bat
msbuild BinarySectorInspector.sln /p:Configuration=Release /p:Platform=x64
```

Sln içindeki project'ler: host, freetype (static lib), `bsi_imgui`, Lydis, DecompSnake DLL, DecompSnake CLI.

## Exe yanında çalışmak için

- `BinarySectorInspector.exe`
- `bsi_imgui.dll`
- `languages\`, `themes\`, `assets\`
- `signatures\builtin\`
- `plugins\lydis.dll`, `plugins\decompsnake.dll`

`.pdb` / `.lib` / `obj\` developer çıktısıdır. `settings.json` runtime'da exe yanında oluşur.

## Sık hatalar

**Boş submodule.** Include path kırılır. `git submodule update --init --recursive`.

**Lydis link'inde `bsi_imgui.lib` yok.** Lydis `bsi_imgui` project'ini bekler. Yalnız Lydis'i `bsi_imgui`'den önce `/m` ile build etmek LNK1104 verir. Sln build edin veya önce `bsi_imgui`.

**Kilitli DLL.** Inspector açıkken `{OutDir}plugins\` kopyası fail olur. Uygulamayı kapatın.

**Win32 / x86.** Solution platform'u değil. `Platform=Win32` kullanmayın.

## Third-party

Pin ve lisans: [`third_party/README.md`](../../third_party/README.md). App glue `third_party/msvc/` altındadır; submodule tree'sini bunun için değiştirmeyin.
