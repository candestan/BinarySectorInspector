# Katkı

[English](CONTRIBUTING.md) | [Türkçe](CONTRIBUTING.tr.md)

Clone için `--recursive` ([Başlangıç](docs/tr/getting-started.md)). Third-party submodule'de kalır; app glue `src/` ve `third_party/msvc/`.

Mevcut C++ stiline uyun. User-visible string hem `languages/en.json` hem `languages/tr.json` içinde olur.

Detection bilgisi bir leaf ile anlatılabiliyorsa `signatures/` JSON. Schema: [`signatures/README.md`](signatures/README.md). Bu repo'ya live malware sample koymayın.

Plugin'ler yalnızca `sdk/plugin/bsi_plugin.h` kullanır. Host `src/` include edilmez.

User-facing davranış değişince `docs/` altındaki EN ve TR sayfalarını güncelleyin. Ürün davranışını değiştirmeyen refactor'da doc şart değil.

Türkçe dokümantasyonda reverse engineering ve software development terimleri zorla çevrilmez. Sektörde İngilizce kullanılan terimler (PE, section, plugin, overlay, signature, …) İngilizce bırakılır; cümle Türkçe kalır. Suffix tutarlı olsun: `plugin'in`, `section'lar`.

Göndermeden `BinarySectorInspector.sln` `Release|x64` build edin.

`x64/`, `settings.json`, üretilmiş `.dll`/`.pdb` commitlenmez.
