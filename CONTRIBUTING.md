# Contributing

[English](CONTRIBUTING.md) | [Türkçe](CONTRIBUTING.tr.md)

Clone with `--recursive` (see [Getting started](docs/en/getting-started.md)). Keep third-party code in submodules; app glue stays in `src/` and `third_party/msvc/`.

Match surrounding C++. User-visible strings go in both `languages/en.json` and `languages/tr.json`.

Detection knowledge belongs in `signatures/` JSON when a leaf can express it. Schema: [`signatures/README.md`](signatures/README.md). Do not add live-malware samples to this repo.

Plugins use `sdk/plugin/bsi_plugin.h` only. Do not `#include` host `src/` from a plugin.

User-facing behavior changes should update English and Turkish pages under `docs/` when those pages describe the behavior. Skip doc edits for refactors that do not change product behavior.

Build `BinarySectorInspector.sln` `Release|x64` (and Debug if you touched debug-only paths) before sending a change.

Do not commit `x64/`, `settings.json`, or generated `.dll`/`.pdb`.
