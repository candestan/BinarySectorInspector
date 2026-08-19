# Kullanım

[English](../en/usage.md) | [Türkçe](usage.md)

Tipik tur:

1. PE açın veya drop edin ([Başlangıç](getting-started.md)).
2. **Overview** — hash, machine, entry point, packer/compiler özeti.
3. **Detection** — hangi signature'ın tuttuğu ve evidence.
4. Navigator: header, section, import/export, resource, overlay.
5. Range'i **Hex**'te açın.
6. **Findings** — host notları (import, string, header anormallikleri).
7. Hex veya version edit diske gidecekse **File → Save** / **Save as...**.

## Workspace

View'lar left / center / right / bottom dock edilir. **View** menüsü panel ve document window'ları listeler. **Reset Workspace Layout** default layout'u getirir.

Plugin window'ları (Lydis Disassembly, Symbols, …) DLL yüklendiyse aynı menüdedir.

## Hex

Map edilmiş image'ın tamamı. Sürükleyerek select. Unsaved byte'lar bu session'da farklı çizilir. **Ctrl+F**: AOB (`??` wildcard), ASCII veya regex.

Edit'ler Save'e kadar RAM'dedir. Genel Undo yok (`menu.undo_none`).

## Save ve backup

Save PE'yi yazar. Hedef zaten varsa önce sibling backup kopyalanır. Kopya fail olursa backup'sız kaydı onaylayabilirsiniz.

## Go

**Go to entry point** — PE çalışınca CPU'nun normalde ilk gittiği adresin file offset'i. **Go to overlay** — image'ın normal raw sonundan sonraki ekstra data. İkisi de Hex'i o file offset'e alır (varsa).

## Tools

Host tool'ları ve plugin tool'ları (Lydis entry/hex, DecompSnake **Export .py**) **Tools** altındadır.

## Settings

Theme, dil, detection engine (KUARA veya internal matcher), signature reload, plugin enable, script path'leri (Python 2/3, Lua).
