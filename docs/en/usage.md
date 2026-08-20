# Usage

[English](usage.md) | [Türkçe](../tr/usage.md)

Typical pass:

1. Open or drop a PE ([Getting started](getting-started.md)).
2. Skim **Overview** (hashes, machine, entry, packer/compiler summary).
3. Open **Detection** for signature hits and evidence.
4. Use the navigator for headers, sections, imports/exports, resources, overlay.
5. Select a range and inspect it in **Hex**.
6. Check **Findings** for host notes (imports, strings, header oddities).
7. **File → Save** / **Save as...** when hex or version edits should hit disk.

## Workspace

Views dock left / center / right / bottom. **View** lists panels and document views. **Reset Workspace Layout** restores defaults.

Plugin windows (Lydis Disassembly, Symbols, …) appear in the same menu once the DLL loaded.

## Hex

The editor covers the whole mapped image. Drag to select. Unsaved bytes are drawn differently from saved ones this session. **Ctrl+F**: AOB (`??` wildcards), ASCII, or regex.

Edits stay in RAM until Save. There is no general Undo; the menu says so (`menu.undo_none`).

## Save and backup

Save writes the PE. If the destination already exists, the app copies a sibling backup first. If that copy fails, you can confirm saving without backup.

## Go

**Go to entry point** and **Go to overlay** jump Hex to those file offsets when they exist.

## Tools

Host tools plus plugin tools (Lydis disassemble at entry/hex, DecompSnake **Export .py**) live under **Tools**. DecompSnake also registers a docked view for editing PYTHONSCRIPT.

## Settings

Themes, language, detection engine (KUARA vs internal matcher), signature reload, plugin enable, scripting interpreter paths (Python 2/3, Lua) if a plugin needs them.
