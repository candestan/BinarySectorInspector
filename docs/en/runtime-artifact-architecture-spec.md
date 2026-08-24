# BinarySectorInspector — Runtime & Artifact Analysis Architecture

**Status:** Implementation master specification (no production code in this document)  
**Option selected:** Phase 1 first — foundational architecture + PyInstaller  
**Repository:** local `BinarySectorInspector` (Windows x64 host)  
**Date:** 2026-08-24  

Labels used throughout:

| Label | Meaning |
|-------|---------|
| **VERIFIED** | Confirmed in this repository’s source |
| **PROPOSED** | New design; not present today |
| **INFERRED** | Reasonable reading of source without an explicit comment |
| **UNKNOWN** | Needs validation before implementation |
| **UPSTREAM** | Fact from PyInstaller / other upstream sources |

---

## 1. Repository Analysis

### 1.1 Actual analysis data flow (VERIFIED)

```text
AppOpenPath / CLI path
  -> PeJobStart (worker thread)
       -> read file bytes
       -> PeParse (src/pe/pe.cpp)
            -> sections, overlay, rsrc, strings, CLR basics
            -> AnalyzeEngineRun (src/analyze/analyze_engine.cpp)
                 [1] DetectApplyToPe   (signatures / KUARA)
                 [2] AnalyzeRun        (AnalyzerProvider*)
                 [3] FindingsEngineRun (structural / import / string / artifact scan)
  -> UI: view.detection | view.analysis | view.findings
  -> Plugins: BsiPluginOnJob + host->image / artifact_*
```

**Not present today (VERIFIED):** recursive nested `PeParse`, structural probe registry separate from `AnalyzerApply`, SHA-256 artifact graph, zlib decompressor, PyInstaller signatures.

### 1.2 Key subsystems (verified ownership)

| Subsystem | Paths | Role |
|-----------|-------|------|
| PE | `src/pe/pe.{h,cpp}` | Parse + `PeJob*` async open |
| Detect | `src/detect/*`, `signatures/` | JSON schema 1 + KUARA |
| Analyze | `src/analyze/*` | `AnalyzerProvider` + `AnalysisArtifact` |
| Findings | `src/findings/*` | `AnalysisReport` / `FindingItem` |
| UI Analysis | `src/app/inspector_analysis.cpp` | Renders `pe->analysis` |
| Plugin ABI | `sdk/plugin/bsi_plugin.h` | ABI 2; image + artifacts |
| Profiles | `analysis/profiles/default.json`, `src/analyze/profile.*` | Stages + budgets |
| DecompSnake | `plugins/decompsnake/` | `python.bytecode` media via host |
| Lydis | `plugins/lydis/` | Disasm from `host->image` |

---

## 2. Current Architecture

### 2.1 Analyzer registration (VERIFIED)

```text
AnalyzerSelfRegister ctor
  -> AnalyzeRegister(provider)   // analyze.cpp; dedupe by id
AnalyzeRun(pe, data, n)
  -> pe->analysis.clear()
  -> for each AnalyzerProvider:
       if Applicable(pe, apply): provider->analyze(...)
```

`AnalyzerApply` (`analyze.h`): `needs_pe`, `needs_clr`, `resource_type`, `product_key`, `section_name`.

`Applicable` (VERIFIED logic in `analyze.cpp`):

- If no resource/key/section gate → **always true**
- Else OR of: resource type match / `pe->detections[].product_key` / section name

**Implication:** An analyzer with all gates null already runs on every PE. Current shipped analyzers all set at least one gate.

### 2.2 Shipped analyzers (VERIFIED)

| Provider id | Gates | Emits |
|-------------|-------|-------|
| `…analyzer.py2exe` | `PYTHONSCRIPT` **or** `product_key=py2exe` | Payload + marshal + script children; media `python.bytecode` |
| `…analyzer.go` | `product_key=go` **or** `.gopclntab` | Runtime + tables |
| `…analyzer.autoit` | `SCRIPT` **or** `autoit` | Container + files |
| `…analyzer.autohotkey` | `autohotkey` only | Overlay/RCDATA inventory |
| `…analyzer.labview` | `labview` only | RSRC inventory |

### 2.3 Artifact model today (VERIFIED)

`AnalysisArtifact` (`analyze.h`): `id`, `kind`, `label`, `provider_id`, `group`, `media`, `file_off`, `size`, `rva`, `extra`, `extra2`, `flag_main`, `props`, `names`, `strings`, `exports`, `tables`, **`children`** (one level used heavily; deeper nesting possible in type but UI is root→child).

**No** fields for: `parent_id`, `sha256`, `compression`, `logical_path`, owned buffers, lazy decompressors.

Export: user save dialog → `AnalyzeExport` (raw slice of **original image** or provider text dump).

### 2.4 Detection vs analysis (VERIFIED)

- Detection: `DetectApplyToPe` → `pe->detections` (`product_key`, confidence, evidence).
- Analysis: structural inventory on `pe->analysis`.
- Boundary documented in `signatures/README.md` and `docs/en/analysis.md`.

### 2.5 Budgets (VERIFIED present, partially unused)

`AnalysisBudgets` in `profile.h` / `default.json`:

| Field | Default | Consumer today |
|-------|---------|----------------|
| `max_artifacts` | 64 | **UNKNOWN** whether enforced in analyzers |
| `max_findings` | 120 | findings engine |
| `max_nested_depth` | 2 | **VERIFIED unused** outside profile load |
| `max_scan_bytes` | 64 MiB | profile only / limited use |
| `max_analyzer_passes` | 1 | profile only |

### 2.6 Plugins & bytecode (VERIFIED)

DecompSnake: `artifact_count(ctx, "python.bytecode")` + `image` slice; **not** path-primary.  
Lydis: `image` + executable sections.  
ABI must stay compatible (additive only).

### 2.7 Platform / tests / session (VERIFIED)

- Windows x64 GUI only (`wWinMain`, D3D11).
- No first-party test suite; only `Detect*ForTest` hooks.
- No analysis session serialization; only `settings.json`.
- No zlib/miniz in tree (**PROPOSED** dependency for PyInstaller).

---

## 3. Problems / Limitations

1. **Selection coupled to detection for AHK/LabVIEW** — without `product_key`, analyzer never runs; violates “probe independently” requirement for those products.
2. **No structural probe API** — only `Applicable` gates + full `analyze`.
3. **No recursive PE** — embedded EXE/DLL/PYD never re-enter `PeParse`.
4. **`max_nested_depth` unused** — budgets not wired to recursion.
5. **`max_artifacts` = 64** — too low for PyInstaller TOC/PYZ (often 100–1000+ entries).
6. **Artifact content = parent image ranges only** — compressed members cannot be exported without decompress-to-owned-buffer (**PROPOSED**).
7. **`AnalyzeAddFinding` wiped** — `FindingsEngineRun` clears `pe->findings`; identity notices from analyzers are lost unless mirrored into `AnalysisReport` (**VERIFIED** `findings_engine.cpp`).
8. **UI is flat-ish** — `DrawAnalysis` handles root + direct children; deep trees need UX extension (**INFERRED** from `inspector_analysis.cpp` patterns).
9. **No PyInstaller / Electron / Nuitka signatures** today (**VERIFIED** grep).
10. **Hostile parse helpers** — no shared checked binary reader; each analyzer rolls its own.

---

## 4. Proposed Architecture

### 4.1 Guiding principle

Keep **Detection** (JSON/KUARA: “what is this?”) separate from **Analyzers** (native parsers: “what is inside?”). Analyzers **must** be able to validate formats without a detection hit.

### 4.2 Additive layers (PROPOSED)

```text
PeParse
  -> DetectApplyToPe                    [UNCHANGED]
  -> AnalyzeRun
       -> for each AnalyzerProvider:
            Applicable? (existing OR + optional PROPOSED probe)
            analyze() -> AnalysisArtifact tree
            (PROPOSED) enqueue recursive jobs for Embedded PE children
  -> (PROPOSED) AnalyzeRecurseDrain(budgets)
  -> FindingsEngineRun                  [extend ScanArtifacts]
```

### 4.3 Minimal change vs new framework

**Prefer extending** `AnalyzerProvider` / `AnalysisArtifact` / budgets over a parallel “Runtime Engine”.

**PROPOSED SYMBOL** additions (additive, ABI-stable for plugins initially):

```text
// analyze.h
struct AnalyzerApply {
  ... existing ...
  // PROPOSED: optional cheap structural probe; nullptr = skip
  bool (*probe)(PeFile* pe, const uint8_t* data, size_t n, int* out_score_0_100);
};

struct AnalysisArtifact {
  ... existing ...
  // PROPOSED optional metadata (default zero / empty = old behavior)
  char     logical_path[260];
  char     sha256_hex[65];   // empty if not computed
  uint32_t compressed_size;  // 0 = unknown / same as size
  uint8_t  compression;      // 0 none, 1 zlib, ...
  uint8_t  flags;            // extractable, owned_buf, ...
  // PROPOSED: owned payload when not a slice of pe image
  std::vector<uint8_t> owned; // empty = use file_off/size on image
};
```

**Plugin ABI:** do **not** require ABI bump for Phase 1 if DecompSnake still sees `python.bytecode` media on artifacts pointing into **reconstructed .pyc owned buffers** exposed via existing `artifact_at` + a host that can return owned ranges (**PROPOSED host extension** or keep writing temp .pyc for DecompSnake — prefer extending `artifact_at` semantics carefully).

**Safer Phase 1 for DecompSnake:** write reconstructed `.pyc` into plugin data dir or expose via existing `patch`/`path("data")` only on user action; keep `python.bytecode` media on children with `owned` filled and teach host `artifact_at` to prefer owned when present (**PROPOSED**, host-side, still ABI field-compatible if `file_off` becomes sentinel).

### 4.4 Detection remains JSON-first

Add `signatures/builtin/packers/pyinstaller.generic.json` (**PROPOSED**) with strong leaves (`byte_pattern` MEI cookie, `_MEIPASS`, etc.) — **supporting** Overview identity only. Analyzer does not require it.

---

## 5. Files to Create

| Path | Status | Responsibility |
|------|--------|----------------|
| `src/analyze/binread.h` | **NEW** | Checked span reader (u8/u16be/u32be, bounds) |
| `src/analyze/binread.cpp` | **NEW** | Implementation |
| `src/analyze/artifact_util.h/.cpp` | **NEW** | SHA-256 (Windows BCrypt), path sanitize, budget helpers |
| `src/analyze/recurse.h/.cpp` | **NEW** | Nested PE job queue + budgets |
| `src/analyze/pyinstaller_analyzer.cpp` | **NEW** | Probe + CArchive + PYZ + artifacts |
| `signatures/builtin/packers/pyinstaller.generic.json` | **NEW** | Detection identity |
| `signatures/builtin/compilers/pyinstaller.generic.json` | **NEW** optional | Or packer-only; avoid duplicate product_key noise — **prefer packer only** |
| `docs/en/runtime-artifact-architecture-spec.md` | **NEW** | This document |

---

## 6. Files to Modify

| Path | Status | Changes |
|------|--------|---------|
| `src/analyze/analyze.h` | EXISTING | Optional artifact fields; optional `probe` on `AnalyzerApply` |
| `src/analyze/analyze.cpp` | EXISTING | Call `probe` if set; wire recurse drain; enforce `max_artifacts` |
| `src/analyze/analyze_engine.cpp` | EXISTING | After `AnalyzeRun`, call recurse; optionally re-run findings |
| `src/analyze/profile.h` + `default.json` | EXISTING | Raise `max_artifacts`; add budgets: `max_decompress_bytes`, `max_decompress_ratio`, `max_artifact_bytes` |
| `BinarySectorInspector.vcxproj` (+filters) | EXISTING | Compile new units; link `bcrypt` / miniz |
| `src/app/inspector_analysis.cpp` | EXISTING | Deep tree navigation; export owned buffers; PyInstaller props |
| `src/findings/findings_engine.cpp` | EXISTING | Richer `ScanArtifacts`; stop wiping analyzer identity or re-emit from artifacts |
| `src/plugin/plugin.cpp` | EXISTING | `artifact_at` serve owned buffers when flagged |
| `languages/en.json` / `tr.json` | EXISTING | Analysis/export/runtime strings |
| `docs/en/analysis.md` / `tr` | EXISTING | Document PyInstaller analyzer |
| `signatures/README.md` | EXISTING | List PyInstaller; note probe independence |
| `third_party/README.md` | EXISTING | If miniz added |

**Compatibility:** signature schema stays 1; plugin ABI prefer no bump; session format N/A.

---

## 7. Public Interfaces

**Must remain stable (VERIFIED consumers):**

- `BsiHost` / plugin exports (ABI 2)
- Signature JSON schema 1
- `DetectionResult.product_key`
- `AnalysisArtifact.media` string `"python.bytecode"` for DecompSnake
- Workspace view ids (`view.analysis`, …)

**PROPOSED public (host-internal C++ only initially):**

- `AnalyzeRecurseEnqueueEmbeddedPe(...)` — not for plugins in Phase 1
- Budget getters from `AnalyzeProfileActive()`

Do **not** expose probe API to plugins in Phase 1.

---

## 8. Internal Interfaces

```text
PROPOSED BinReader
  -> read from (data,n) with checked offsets

PROPOSED ArtifactBudget
  -> TryAddArtifact(pe) -> bool
  -> TryDecompress(in_n, out_n) -> bool

PROPOSED PyInstallerProbe(data,n) -> score 0..100

PROPOSED PyInstallerAnalyze(pe,data,n) -> bool
  -> uses BinReader, ArtifactBudget, zlib/miniz

PROPOSED RecurseQueue
  -> Push(image_bytes or owned)
  -> Drain with depth/hash limits
```

---

## 9. Data Models

### 9.1 Extend `AnalysisArtifact` (PROPOSED)

| Field | Required | Lazy | Serialized | Notes |
|-------|----------|------|------------|-------|
| existing fields | yes | no | N/A (in-memory) | Keep |
| `logical_path` | no | no | N/A | TOC name |
| `sha256_hex` | no | yes | N/A | Compute on export / recurse |
| `compressed_size` | no | no | N/A | TOC length |
| `compression` | no | no | N/A | flag |
| `owned` | no | yes | N/A | Decompressed / reconstructed .pyc |

### 9.2 Kinds / media (reuse enums)

- Prefer existing `AnalysisKindPayload|Archive|Script|Runtime|Metadata`
- Media strings: `python.bytecode`, `bytes.raw`, **PROPOSED** `archive.pyz`, `pe.embedded`, `lib.python`

### 9.3 Do not invent malware verdict enum

Keep capability findings in `FindingItem` wording; never “Malware detected”.

---

## 10. Analyzer Lifecycle

```text
input accepted (PeJob)
 -> PeParse
 -> Facts (DetectFillFacts inside DetectApplyToPe)
 -> detection (KUARA/internal)
 -> AnalyzeRun
      for provider:
        Applicable (gates)
        if probe: score < threshold => skip
        analyze() => artifacts (+ enqueue recurse)
 -> AnalyzeRecurseDrain   [PROPOSED]
 -> FindingsEngineRun
 -> UI refresh / BsiPluginOnJob
```

- **Ownership:** `PeFile` owns `analysis` tree; owned buffers live on artifacts.
- **Ordering:** detection before analyze (unchanged); recurse after primary analyzers.
- **Failure isolation:** one analyzer/`catch`/bool false; continue others (already true).
- **Cancellation:** Phase 1 = cooperative checks against `PeJob` busy/cancel if exists; else budget only (**UNKNOWN** cancel API — verify `PeJob` cancel before implementing).
- **Concurrency:** keep analysis on existing worker thread; no UI-thread decompress.

---

## 11. Probe / Confidence Logic

### 11.1 Structural score (PROPOSED, separate from detection confidence)

PyInstaller probe weights (sum capped 100):

| Observation | Points |
|-------------|--------|
| Valid MEI cookie + unpack | 35 |
| `pkg_start`/`pkg_end` in file | 20 |
| TOC range valid + ≥1 entry | 20 |
| ≥3 TOC entries with in-range blobs | 15 |
| PYZ magic at a `z` entry | 5 |
| Supporting: `_MEIPASS` / `pyi_` strings | 5 |

Thresholds:

- **analyze:** score ≥ 55  
- **probable finding:** ≥ 70  
- **strong:** ≥ 85  

String-only evidence **cannot** reach 55.

Detection confidence (JSON) remains independent.

### 11.2 Registration pattern (PROPOSED)

```text
AnalyzerApply apply = {
  true, false,
  nullptr,           // no resource gate required
  "pyinstaller",     // OR detection (optional boost)
  nullptr,
  PyInstallerProbe   // PROPOSED
};
// Applicable: keyed OR probe-driven:
// PROPOSED change: if probe && !keyed && !typed && !sect => call probe
// OR: leave gates empty and probe inside analyze() for zero Applicable change.
```

**Phase 1 recommendation:** avoid `Applicable` signature change; use **empty gates** + early `probe` inside `analyze()` returning false → no artifacts. Matches existing “always true if no gates” path without API churn.

---

## 12. Artifact Hierarchy

```text
sample.exe
└── pyinstaller.carchive          [Runtime/Archive]
    ├── python311.dll             [Payload] file_off in pkg
    ├── base_library.zip
    ├── PYZ-00.pyz                [Archive] media archive.pyz
    │   ├── os.pyc                [Script] owned reconstructed
    │   └── ...
    ├── main                      [Script] typecode entry
    └── ...
```

Parent/child via existing `children` vector; set `logical_path` for TOC names.

**UI:** extend tree to recurse children (**PROPOSED** `DrawAnalysis` walk).

---

## 13. Recursive Analysis

### 13.1 Triggers (PROPOSED)

Enqueue when TOC/typecode indicates Windows PE/DLL/PYD (MZ header at blob after decompress) or Electron `.node` (Phase 2).

### 13.2 Budgets (PROPOSED — wire real fields)

| Budget | Suggested default | On exceed |
|--------|-------------------|-----------|
| `max_nested_depth` | 2 (already in profile) | warn prop; stop branch |
| `max_artifacts` | **4096** (raise from 64) | stop adding; warning artifact |
| max cumulative decompress | 256 MiB | stop branch |
| max single artifact | 64 MiB | skip entry |
| max ratio out/in | 100:1 | skip |
| SHA-256 duplicate | suppress recurse | link prop `dup_of` |
| ancestor hash cycle | abort branch | warning |

### 13.3 Nested PE (PROPOSED)

```text
owned_or_slice -> PeParse into temporary PeFile
  -> merge detections/findings as child AnalysisArtifact subtree
  -> DO NOT replace root PeFile
```

Lydis: user selects embedded PE artifact → **PROPOSED** “Open as job” or secondary listing; Phase 1 may only export + hex. Full Lydis on child = Phase 1.5.

---

## 14. UI Integration

Reuse `view.analysis` (`DrawAnalysis`).

**PROPOSED UX additions:**

- Root runtime summary props: `runtime=PyInstaller`, `python=3.11`, `toc_entries=N`, `probe_score`
- Recursive tree
- Actions by media: Hex (image or owned), Strings, Export, Decompile (if `python.bytecode`), Open nested (Phase 1.5)

No new top-level popup workflow.

Decompress/enumerate stays on `PeJob` worker — UI already waits on job.

---

## 15. PyInstaller Parser Specification

### 15.1 Upstream evidence (UPSTREAM)

| Format claim | Upstream | Version | Source | Verified behavior | Design implication |
|--------------|----------|---------|--------|-------------------|--------------------|
| Cookie magic `MEI\x0c\x0b\x0a\x0b\x0e` | PyInstaller | v6.11.1 / bootloader | `PyInstaller/archive/readers.py`, `bootloader/src/pyi_archive.h` | 8-byte magic | Search file for pattern |
| Cookie layout `!8sIIII64s` (80 bytes) | same | same | `readers.py` `_COOKIE_FORMAT` | BE u32 fields + pylib name | Network endian |
| `pkg_start = cookie_end - pkg_length` | same | same | `readers.py` / `pyi_archive.c` | Archive may be overlay-appended | Overlay is normal |
| TOC entry `!IIIIBc` + name padded to 16 | same | same | `readers.py` | Variable-length entries | Bounds-check entry_length |
| Compression zlib per entry flag | same | writers.py level 9 | zlib | Need zlib inflate | |
| PYZ magic `PYZ\0` + pymagic + TOC offset | v6.11.1 | `pyimod01_archive.py` | marshal TOC dict | Marshal parse in C++ or defer PYZ detail | |
| PYZ entry types 0/1/3 module/pkg/nspkg | same | `PYZ_ITEM_*` | zlib then marshal code | Reconstruct .pyc header for tools | |

**Historical cookies:** older PyInstaller used shorter cookies (**UNKNOWN** exact pre-3.x layouts in this pass — implement current 80-byte first; add versioned parsers after fixture matrix).

**Encrypted PYZ:** historical; if detected, report unsupported — **do not invent decryption**.

### 15.2 Typecodes (UPSTREAM / document unknowns)

Bootloader `ARCHIVE_ITEM_*` — implement known extractable codes from `pyi_archive.h` in chosen tag; unknown codes → artifact with prop `typecode=?` and skip decompress if unsafe.

### 15.3 .pyc reconstruction (UPSTREAM + PROPOSED)

PYZ stores zlib-compressed marshal of **code object**, not full `.pyc` file. For DecompSnake:

- Prepend Python magic (from PYZ header pymagic) + flags/header appropriate to version (**verify** against DecompSnake supported headers)
- Mark uncertainty if magic unknown

### 15.4 Malformed behavior

Partial TOC recovery; skip bad entries; never crash; record `parse_warnings` props on root.

### 15.5 Pseudocode (selected)

#### Analyzer registration

```text
static AnalyzerProvider kPi = {
  "com.binarysectorinspector.analyzer.pyinstaller",
  "pyinstaller",
  { true, false, nullptr, nullptr, nullptr }, // empty gates
  AnalyzePyInstaller,
  ExportPyInstaller
};
static AnalyzerSelfRegister g_pi(&kPi);
```

#### Probe

```text
score = 0
off = FindMeI(data, n)
if off < 0: return 0
cookie = ReadCookieBE(data+off)
if !InRange(pkg): return score
score += 35
if TocValid: score += 20
if EntriesOk: score += 15..35
return min(100, score)
```

#### Package start

```text
cookie_end = cookie_off + 80
pkg_start = cookie_end - pkg_length
pkg_end = cookie_end
require 0 <= pkg_start < pkg_end <= n
```

#### Decompression guard

```text
if uncompressed_length > max_artifact: skip
if uncompressed_length > compressed_length * max_ratio: skip
if total_out + uncompressed > max_decompress: stop
out = zlib_inflate(in)
if out.size != uncompressed_length: warn; still keep if partial policy says so
```

#### DecompSnake routing

```text
child.media = "python.bytecode"
child.owned = reconstructed_pyc
// host artifact_at returns owned pointer when flags.owned
```

*(Full list of 25 pseudocode items is summarized above; implementers expand in-code comments mirroring this section.)*

---

## 16. Security Constraints

- Treat all inputs hostile.
- Checked add/mul for offset+length.
- Cap allocations; no unbounded TOC loops (`entry_length == 0` → break).
- Decompression bombs: ratio + absolute caps.
- Export path sanitization: reject `..`, absolute paths, reserved Win names, control chars.
- Never execute scripts/bytecode/PE.
- Analyzer exceptions → log + false; siblings kept.

**PROPOSED** `BinReader` in `src/analyze/binread.*`.

---

## 17. Error Handling

| Failure | Behavior |
|---------|----------|
| No cookie | probe 0; analyzer no-op |
| Truncated cookie/TOC | warning props; partial |
| zlib fail | skip entry; continue |
| Marshal/PYZ fail | PYZ child with status unsupported |
| Budget hit | `budget_exceeded` prop; stop branch |
| Nested PeParse fail | child status fail; continue |
| DecompSnake fail | UI only; extraction remains |

---

## 18. Cross-Platform Concerns

Host is **Windows-only** today (**VERIFIED**). Parsers in `src/analyze` should stay CRT-portable (no Win32 in PyInstaller parser except optional BCrypt SHA-256 behind `#ifdef _WIN32`).

Do not add unconditional WinHTTP into analyzers.

---

## 19. Tests

**VERIFIED:** no app test framework. **PROPOSED Phase 1:**

1. Add minimal console test project `tests/analyze_pyinstaller` **or** Catch2 — prefer tiny custom runner to avoid new framework dependency (**PROPOSED decision:** custom `tests/host_tests.exe` linking analyze objs).
2. Fixtures: onefile 3.10/3.11/3.12; truncated; fake `_MEIPASS` PE; bomb ratio.
3. Unit: cookie find, TOC walk, inflate limits, path sanitize, probe scores.
4. Integration: PeParse → artifacts → `python.bytecode` present.
5. Fuzz: cookie/TOC parsers (libFuzzer later; Phase 1 = assert no crash on random 4KiB).

User rule historically avoids unsolicited tests — this spec **requires** tests for the feature; implement when coding Phase 1.

---

## 20. Migration / Backwards Compatibility

| Surface | Policy |
|---------|--------|
| Signature schema | Stay at 1; new files only |
| Existing signatures | Untouched |
| Plugin ABI | Prefer no bump; owned artifacts via host implementation detail |
| `AnalysisArtifact` layout | Additive fields at end; old code ignores |
| Profile JSON | Additive budget keys with defaults if missing |
| UI | Additive; existing roots still render |
| CLI | Unchanged (`-sw` + paths) |

---

## 21. Implementation Phases

### Phase 1 — **SELECTED (birinci opsiyon)**

Reviewable PR units:

1. `BinReader` + budget helpers + profile budget bumps  
2. Artifact owned-buffer + export + host `artifact_at` owned serve  
3. PyInstaller probe + CArchive TOC enumerate (no PYZ yet)  
4. zlib/miniz + entry extract + hierarchy UI  
5. PYZ enumerate + .pyc reconstruct + DecompSnake media  
6. Recurse embedded PE (depth 1) + SHA suppress  
7. Signature JSON + findings wiring fix (`AnalyzeAddFinding` vs clear)  
8. Tests/fixtures  

**Out of Phase 1:** Electron, .NET deep metadata, cx_Freeze, Nuitka deep, PowerShell, Java, games, installers.

### Phase 2–4

As in requirements roadmap (cx_Freeze, .NET, Electron, pkg, PS2EXE, …). Reuse BinReader/budgets/recurse.

---

## 22. Acceptance Criteria

Phase 1 done when:

- [ ] Existing PE/detect/plugins still work  
- [ ] PyInstaller recognized structurally without requiring detection string  
- [ ] CArchive TOC enumerated under budgets  
- [ ] PYZ modules become `python.bytecode` artifacts where format verified  
- [ ] Export path-safe; no auto-exec  
- [ ] DecompSnake optional; failure isolated  
- [ ] Nested PE cannot recurse forever  
- [ ] Decompression bounded  
- [ ] Malformed samples do not crash  
- [ ] Detection ≠ extraction conceptually  
- [ ] No “malware detected” verdict introduced  
- [ ] Windows x64 build green  

---

# Appendices

## A. Repository evidence table

```text
Claim: AnalyzeRun clears pe->analysis then runs Applicable providers.
Source path: src/analyze/analyze.cpp
Symbol: AnalyzeRun, Applicable
Evidence: pe->analysis.clear(); for Providers() if Applicable then analyze
Implication: Analyzers must re-emit full tree each job; no incremental cache.

Claim: product_key OR resource OR section gates Applicable.
Source path: src/analyze/analyze.cpp
Symbol: Applicable
Evidence: OR of HasResourceType / HasProductKey / HasSectionName; empty => true
Implication: Empty gates enable independent probing.

Claim: Detection precedes AnalyzeRun.
Source path: src/analyze/analyze_engine.cpp
Symbol: AnalyzeEngineRun
Evidence: DetectApplyToPe then AnalyzeRun then FindingsEngineRun
Implication: product_key available but must not be sole PyInstaller trigger.

Claim: max_nested_depth unused.
Source path: src/analyze/profile.cpp / grep consumers
Symbol: AnalysisBudgets::max_nested_depth
Evidence: Loaded from JSON; no analyze recurse reader
Implication: Must wire in PROPOSED recurse module.

Claim: DecompSnake uses python.bytecode media + image.
Source path: plugins/decompsnake/src/plugin_export.cpp
Symbol: artifact_count / image
Evidence: ReloadFromJob picks bytecode artifacts
Implication: PyInstaller must emit that media.

Claim: FindingsEngineRun clears pe->findings.
Source path: src/findings/findings_engine.cpp
Symbol: FindingsEngineRun
Evidence: pe->findings.clear() at start
Implication: Analyzer AnalyzeAddFinding notices are lost; fix in Phase 1.

Claim: default max_artifacts is 64.
Source path: analysis/profiles/default.json
Symbol: budgets.max_artifacts
Evidence: "max_artifacts": 64
Implication: Must raise for PyInstaller.
```

## B. Upstream-source evidence table

See §15.1. Primary sources: PyInstaller `v6.11.1` `archive/readers.py`, `bootloader/src/pyi_archive.h`, `loader/pyimod01_archive.py`, docs `advanced-topics.rst`.

## C. Dependency evaluation

```text
Dependency: miniz (or zlib)
Purpose: inflate CArchive/PYZ entries
Why existing code insufficient: no zlib in tree
License: miniz MIT / zlib zlib-license
Size: small (single .c)
Windows/Linux/macOS: portable C
Maintenance: low
Can it be avoided: Win32 Cabinet API incomplete for raw zlib streams; avoid
Recommendation: vendor miniz.c/.h under third_party/miniz
```

```text
Dependency: BCrypt (Windows)
Purpose: SHA-256 for duplicate suppression
Recommendation: use existing Windows libs; no NuGet
```

## D. Format-support matrix (Phase 1)

| Format | Detect JSON | Probe | Enumerate | Extract | Recurse | Decompile |
|--------|-------------|-------|-----------|---------|---------|-----------|
| PyInstaller CArchive | PROPOSED | PROPOSED | PROPOSED | PROPOSED | PE/DLL | n/a |
| PYZ | via parent | part of analyze | PROPOSED | PROPOSED | no | DecompSnake |
| py2exe | VERIFIED | VERIFIED | VERIFIED | VERIFIED | no | DecompSnake |
| AHK/AutoIt/Go/LV | VERIFIED | gated | VERIFIED | limited | no | n/a |

## E. Test sample matrix (PROPOSED)

| Sample | Expect |
|--------|--------|
| onefile py3.11 hello | cookie+TOC+PYZ+main |
| onefile py3.8 | older magic |
| onedir launcher only | weak/no full archive |
| PE with `_MEIPASS` string only | probe &lt; 55 |
| truncated after cookie | partial/fail safe |
| crafted ratio bomb entry | skip entry |

## F. Unresolved questions / verified unknowns

1. Exact pre-PyInstaller-3 cookie layouts — defer.  
2. DecompSnake exact `.pyc` header versions supported — read plugin before reconstruct.  
3. Whether `PeJob` supports cancel mid-analyze — grep before UI cancel.  
4. Historical encrypted PYZ key material — treat unsupported.  
5. Electron adjacent-directory open — Phase 2; single-PE only for now.  
6. Nuitka onefile container variants — Phase 2 research.  

---

## Quality gate (author checklist)

- [x] Real repo inspected  
- [x] Symbols verified (AnalyzerProvider, Applicable, PeParse, …)  
- [x] No invented “existing” RuntimeEngine class  
- [x] Detection vs extraction separated  
- [x] Independent probe path defined  
- [x] Hierarchical artifacts via existing `children` + extensions  
- [x] Recursion budgets explicit  
- [x] PyInstaller from upstream readers/headers  
- [x] PYZ ≠ source recovery stated  
- [x] DecompSnake optional  
- [x] Lydis reuse not duplicated in Phase 1 core  
- [x] Findings ≠ malware verdict  
- [x] Export path-safe requirements  
- [x] Platforms preserved  
- [x] Phase 1 independently shippable  

**Design principle:** evolve BSI from “this is PyInstaller” into “here is the CArchive/PYZ/bytecode tree,” without breaking signatures, plugins, or the existing analyze pipeline.
