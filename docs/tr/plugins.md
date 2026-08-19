# Plugin

[English](../en/plugins.md) | [Türkçe](plugins.md)

Host `{exe}\plugins\` ve bir alt klasördeki `*.dll` dosyalarını yükler. Plugin, `BsiPluginGetInfo`, `BsiPluginInit`, `BsiPluginShutdown` export eden x64 DLL'dir. ABI **2** (`sdk/plugin/bsi_plugin.h`).

Inspector exe plugin `.lib` dosyalarını link etmez. Bundled plugin'ler ProjectReference ile build edilir ve `{OutDir}plugins\` altına kopyalanır.

DLL yazımı, host table, ImGui pin: [`sdk/plugin/README.md`](../../sdk/plugin/README.md). ImGui runtime: [`sdk/imgui/README.md`](../../sdk/imgui/README.md).

`bsi_imgui.dll` **exe'nin yanında** durmalı. Level-2 plugin'ler (Lydis) bunu import eder; Windows application directory'de arar.

## Bu tree'de gelenler

**Lydis** (`com.septillioner.bsi.lydis`) — [bsi-lydis](https://github.com/Septillioner/bsi-lydis). x86/x64 executable section listing'i, function list, xref, Tools ile entry point veya hex cursor'dan start. Decoder ayrıntısı o repository'de.

**DecompSnake** (`com.candestan.binarysectorinspector.decompsnake`) — [BSI-Decompsnake](https://github.com/candestan/BSI-Decompsnake). **Tools → DecompSnake → Export .py**, host bytecode artifact'larından. Docked view yok. `x64\<Config>\decompsnake.exe` CLI projesidir, inspector plugin'i değil.

Enable ve settings card'ları: Settings → Plugins. Key'ler plugin id'sine göre saklanır.

## Job

PE hazır olunca `BsiPluginOnJob(1)`, kapanınca `(0)`. `0`'da image cache bırakılmalı.
