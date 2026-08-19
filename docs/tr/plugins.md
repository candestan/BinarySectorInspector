# Eklentiler

[English](../en/plugins.md) | [Türkçe](plugins.md)

Host `{exe}\plugins\` ve bir alt klasördeki `*.dll` dosyalarını yükler. Eklenti, `BsiPluginGetInfo`, `BsiPluginInit`, `BsiPluginShutdown` dışa aktaran x64 DLL’dir. ABI **2** (`sdk/plugin/bsi_plugin.h`).

Inspector exe eklenti `.lib` dosyalarını bağlamaz. Birlikte gelen eklentiler ProjectReference ile derlenir ve `{OutDir}plugins\` altına kopyalanır.

DLL yazımı, host tablo, ImGui pin: [`sdk/plugin/README.md`](../../sdk/plugin/README.md). ImGui çalışma zamanı: [`sdk/imgui/README.md`](../../sdk/imgui/README.md).

`bsi_imgui.dll` **exe’nin yanında** durmalı. Level-2 eklentiler (Lydis) bunu içe aktarır; Windows uygulama dizinine bakar.

## Bu ağaçta gelenler

**Lydis** (`com.septillioner.bsi.lydis`) — [bsi-lydis](https://github.com/Septillioner/bsi-lydis). x86/x64 yürütülebilir bölüm listing’i, fonksiyon listesi, xref, Tools ile entry veya hex imlecinden başlama. Çözücü ayrıntısı o depoda.

**DecompSnake** (`com.candestan.binarysectorinspector.decompsnake`) — [BSI-Decompsnake](https://github.com/candestan/BSI-Decompsnake). **Tools → DecompSnake → Export .py**, host baytkodu artifaktlarından. Yerleşik görünüm yok. `x64\<Config>\decompsnake.exe` CLI projesidir, inspector eklentisi değil.

Aç/kapa ve ayar kartları: Settings → Plugins. Anahtarlar eklenti id’sine göre saklanır.

## Job

PE hazır olunca `BsiPluginOnJob(1)`, kapanınca `(0)`. `0`’da görüntü önbelleği bırakılmalı.
