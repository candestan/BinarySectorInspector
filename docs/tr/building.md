# Derleme

[English](../en/building.md) | [Türkçe](building.md)

Çözüm: `BinarySectorInspector.sln`. Yalnız **Debug|x64** ve **Release|x64**. Toolset v143. CRT: host’ta Release `/MT`, Debug `/MTd`.

```bat
msbuild BinarySectorInspector.sln /p:Configuration=Release /p:Platform=x64
```

Sln içindeki projeler: host, freetype (statik lib), `bsi_imgui`, Lydis, DecompSnake DLL, DecompSnake CLI.

## Exe yanında çalışmak için

- `BinarySectorInspector.exe`
- `bsi_imgui.dll`
- `languages\`, `themes\`, `assets\`
- `signatures\builtin\`
- `plugins\lydis.dll`, `plugins\decompsnake.dll`

`.pdb` / `.lib` / `obj\` geliştirici çıktısıdır. `settings.json` çalışma anında exe yanında oluşur.

## Sık hatalar

**Boş altmodül.** Include yolu kırılır. `git submodule update --init --recursive`.

**Lydis linkinde `bsi_imgui.lib` yok.** Lydis `bsi_imgui` projesini bekler. Yalnız Lydis’i `bsi_imgui`’den önce `/m` ile derlemek LNK1104 verir. Sln derleyin veya önce `bsi_imgui`.

**Kilitli DLL.** Inspector açıkken `{OutDir}plugins\` kopyası başarısız olur. Uygulamayı kapatın.

**Win32 / x86.** Çözüm platformu değil. `Platform=Win32` kullanmayın.

## Üçüncü taraf

Pin ve lisans: [`third_party/README.md`](../../third_party/README.md). Uygulama tutkalı `third_party/msvc/` altındadır; altmodül ağacını bunun için değiştirmeyin.
