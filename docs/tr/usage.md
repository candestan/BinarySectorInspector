# Kullanım

[English](../en/usage.md) | [Türkçe](usage.md)

Tipik tur:

1. PE açın veya bırakın ([Başlangıç](getting-started.md)).
2. **Overview** (hash, makine, giriş, packer/derleyici özeti).
3. **Detection** — imza ve kanıt.
4. Navigator: başlıklar, bölümler, import/export, kaynaklar, overlay.
5. Aralığı **Hex**’te açın.
6. **Findings** — host notları (import, string, başlık anormallikleri).
7. Hex veya sürüm düzeni diske gidecekse **File → Save** / **Save as...**.

## Çalışma alanı

Görünümler sol / orta / sağ / alt yerleşme. **View** panelleri ve belge pencerelerini listeler. **Reset Workspace Layout** varsayılanı getirir.

Eklenti pencereleri (Lydis Disassembly, Symbols, …) DLL yüklendiyse aynı menüdedir.

## Hex

Eşlenen görüntünün tamamı. Sürükleyerek seçin. Kaydedilmemiş baytlar bu oturumda farklı çizilir. **Ctrl+F**: AOB (`??`), ASCII veya regex.

Düzen Save’e kadar RAM’dedir. Genel Undo yok (`menu.undo_none`).

## Kayıt ve yedek

Save PE’yi yazar. Hedef zaten varsa önce yanına yedek kopyalanır. Kopya başarısızsa yedeksiz kaydı onaylayabilirsiniz.

## Go

**Go to entry point** ve **Go to overlay**, varsa Hex’i o dosya ofsetlerine alır.

## Tools

Host araçları ve eklenti araçları (Lydis entry/hex, DecompSnake **Export .py**) **Tools** altındadır.

## Ayarlar

Tema, dil, tespit motoru (KUARA veya dahili eşleştirici), imza yenileme, eklenti aç/kapa, betik yolları (Python 2/3, Lua).
