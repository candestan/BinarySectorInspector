# BinarySectorInspector

Win32 + DX11 + DirectComposition + Dear ImGui host. Static PE analysis of on-disk files. Process targeting resolves the image path; it does not dump memory.

## Layout

- `src/main.cpp` — window, gfx, message loop. Frame body is `App::draw()` only.
- `src/app.cpp` — Open-target vs inspector session.
- `src/platform/` — file picker (`IFileOpenDialog`), window→PID→`QueryFullProcessImageNameW`, UTF-8, HANDLE RAII.
- `src/pe/` — no ImGui. `PeFile` bounds-checked IO; `pe_headers` DOS/NT/sections; `pe_address` RVA/VA/file offset; `pe_directories` import/delay/export/reloc/TLS/resource/debug; `pe_analysis` entropy/strings/findings; `PeImage::load` facade.
- `src/ui/` — `OpenTargetDialog`, tabbed inspector.

## Intake

Two paths, one dialog: browse PE file, or pick a visible unowned top-level window and use that process's on-disk image. `PROCESS_QUERY_LIMITED_INFORMATION` only. No debug privilege.

## PE notes

PE32 and PE32+. Untrusted input: every offset/size checked. Partial parse: directory failures do not drop headers. Findings describe interesting traits, not malware verdicts. Address conversion uses section VirtualAddress/VirtualSize for RVA and PointerToRawData/SizeOfRawData for file mapping.

## Limits

256 MiB files. Caps on sections, imports, exports, relocs, resources, strings. Overlay is file bytes past the last section raw end.
