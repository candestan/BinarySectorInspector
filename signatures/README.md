# Detection signatures

Declarative JSON rules for packers, protectors, compilers/toolchains, and .NET obfuscators.

The application loads these at startup and can reload them without a rebuild. Do not put detection knowledge in C++ if a signature can express it.

## Directories

```
signatures/
  builtin/                 shipped with the app (this repository)
    packers/
    protectors/
    compilers/
    toolchains/
    dotnet_obfuscators/
  user/                    local analyst rules (not overwritten)
  packs/                   future community / plugin packs
  README.md
```

On disk next to the executable the same layout is copied. User rules live in `signatures/user/` beside the exe (the same place as `settings.json`). Do not edit `builtin/` to add personal rules.

Load order:

1. built-in
2. `signatures/packs/` and plugin-registered pack directories
3. user (if enabled in Settings)

Duplicate `id` values are rejected. The first loaded rule wins. Collisions are logged to **Analyzer > Signature Engine**.

## Schema

`schema_version` must be `1`. Future versions are rejected rather than guessed.

Required:

* `id` — stable identity, `[a-z0-9._-]`, 3–80 chars. Not the display name.
  Examples: `packer.upx.generic`, `protector.vmprotect.generic`, `compiler.msvc.ucrt`, `dotnet.confuserex.generic`
* `name` — product label shown in the UI (not translated)
* `category` — `packer` | `protector` | `compiler` | `toolchain` | `dotnet_obfuscator`
* `conditions` — declarative tree (`all` / `any` / `not` / leaf)

Optional:

* `vendor`, `version`, `description`, `author`, `reference`, `license`, `notes`
* `created`, `updated`, `min_app_version`
* `product_key` — grouping key; multiple rules with the same key become one UI row
* `confidence` — cap: `low` | `medium` | `high` | `exact` (default `high`)
* `heuristic` — `true` for generic evidence that is not a product id
* `architecture` — `any` | `x86` | `x64` | `arm64` (string or array)
* `format` — `pe` (only format implemented)
* `requires_clr` — skip native images (implied for `dotnet_obfuscator`)
* `native_only` — skip CLR images
* `weight` on a leaf — 1–100, overrides the default for that condition type

## Conditions

Logical:

```json
{ "all": [ ... ] }
{ "any": [ ... ] }
{ "not": { ... } }
```

Leaves (only types the current PE/.NET fact model can evaluate):

| Key | Meaning |
|---|---|
| `section_name` | PE section name. `match`: `exact` (default), `contains`, `prefix` |
| `section_count` | number or `{min,max,eq}` |
| `section_chars` | characteristics mask, or `{mask,name}` |
| `section_entropy` | `{min, name?}` Shannon entropy 0–8 |
| `entry_point_bytes` | wildcard pattern at AddressOfEntryPoint |
| `byte_pattern` | pattern; `where`: `entry` (default), `file`, `overlay` |
| `imported_dll` | import DLL name |
| `imported_function` | function; optional `dll` |
| `exported_symbol` | export name |
| `pe_chars` / `dll_chars` | header flag mask |
| `rich_present` | Microsoft Rich header |
| `rich_prod` / `rich_build` | Rich entry |
| `overlay` | `true` or `{min_size}` |
| `tls` / `tls_callbacks` | TLS directory / callbacks |
| `debug_type` | debug directory type name |
| `version_string` | string or `{key,contains}` |
| `resource_type` / `resource_name` | resource directory |
| `string_contains` | extracted ASCII/UTF-16 strings (min 4 chars) |
| `has_com` | CLR directory present |
| `clr_stream` | metadata stream name (`#~`, `#Strings`, …) |
| `assembly_ref` | AssemblyRef name |
| `type_name` / `namespace` | TypeDef |
| `linker_major` / `linker_minor` | optional header linker version |
| `import_dll_count` | `{min,max,eq}` |
| `writable_executable_section` | W+X section |

Byte patterns use space-separated hex bytes. `??` is a wildcard byte.

```
60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ??
```

Patterns are compiled when the signature loads, not during every file analysis. Whole-file scans are capped.

There is no scripting, no file I/O, no network, and no expression language beyond `all` / `any` / `not`.

## Specialized analysis

Identity belongs in JSON. Deep procedural parsing (embedded archives, marshal walks, reconstructed containers) lives in statically registered analyzer providers under `src/analyze/`. Those providers emit generic `AnalysisArtifact` trees. The Inspector Specialized Analysis pane renders artifacts without product-specific UI branches.

A product may have:

* a signature only (`DetectionResult`)
* a signature plus an analyzer (`AnalysisArtifact`)

Shipped procedural analyzers (static `AnalyzerProvider`, no DLL ABI):

* py2exe — `PYTHONSCRIPT` marshal reconstruction
* Go — buildinfo + pclntab (1.16+ function tables; older pclntab is detected, not fully walked)
* AutoIt — SCRIPT / overlay container inventory (compiled payload, not original source)

Do not add a C++ condition such as `is_confuserex`. Extend `DetectFacts` only when a new leaf is useful to many products.

## Confidence

Each matched leaf contributes a weight. The sum (capped at 100) maps to:

* 0–24 low
* 25–49 medium
* 50–79 high
* 80–100 exact

The signature `confidence` field is a **ceiling**. A weak match cannot be advertised as exact.

Generic packing (high entropy + few imports) is a separate heuristic with `heuristic: true`. It is **not** UPX.

Conflicting products in the same category are all shown, with their own confidence.

## Example

```json
{
  "schema_version": 1,
  "id": "packer.upx.generic",
  "name": "UPX",
  "category": "packer",
  "vendor": "UPX",
  "product_key": "upx",
  "confidence": "high",
  "reference": "https://github.com/upx/upx",
  "conditions": {
    "all": [
      { "section_name": "UPX0", "match": "contains" },
      { "section_name": "UPX1", "match": "contains" }
    ]
  }
}
```

Copy a file into `signatures/user/`, then Settings → Detection → Reload Signatures.

## Contribution rules

* Every `id` is stable. Do not reuse an id for a different product.
* Cite a public reference when you can (`reference`).
* Do not claim a product from a single weak heuristic.
* Do not add rules that need live malware in this repository. Test with mock facts or harmless fixtures.
* Invalid JSON, unknown condition types, bad patterns, and duplicate ids are rejected and logged. They must not crash the analyzer.

## Packs (future)

A community pack is a folder under `signatures/packs/<id>/`:

```json
{
  "id": "community.example",
  "name": "Example pack",
  "author": "…",
  "version": "1.0.0",
  "license": "…",
  "schema_version": 1,
  "description": "…"
}
```

`pack.json` is metadata. Signature `.json` files beside it (or in subfolders) are loaded as pack-sourced rules. Plugins may also call `DetectAddPackDirectory` and then reload. Plugins must not mutate built-in files.
