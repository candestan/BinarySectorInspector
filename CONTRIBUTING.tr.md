# Katkı

[English](CONTRIBUTING.md) | [Türkçe](CONTRIBUTING.tr.md)

Klon için `--recursive` ([Başlangıç](docs/tr/getting-started.md)). Üçüncü taraf altmodülde kalır; uygulama tutkalı `src/` ve `third_party/msvc/`.

Mevcut C++ stiline uyun. Kullanıcıya görünen metin hem `languages/en.json` hem `languages/tr.json` içinde olur.

Tespit bilgisi bir yaprakla anlatılabiliyorsa `signatures/` JSON. Şema: [`signatures/README.md`](signatures/README.md). Bu depoya canlı zararlı örnek koymayın.

Eklentiler yalnızca `sdk/plugin/bsi_plugin.h` kullanır. Host `src/` include edilmez.

Kullanıcıya yansıyan davranış `docs/` altındaki EN ve TR sayfalarını güncellemeyi gerektirir. Ürün davranışını değiştirmeyen refaktörlerde belge şart değil.

Göndermeden `BinarySectorInspector.sln` `Release|x64` derleyin.

`x64/`, `settings.json`, üretilmiş `.dll`/`.pdb` commitlenmez.
