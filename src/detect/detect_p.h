#pragma once

#include "detect/detect.h"

#include <string>
#include <vector>

enum CondKind : uint8_t
{
    CondAll = 0,
    CondAny,
    CondNot,
    CondSectionName,
    CondSectionCount,
    CondSectionChars,
    CondSectionEntropy,
    CondEntryBytes,
    CondBytePattern,
    CondImportedDll,
    CondImportedFn,
    CondExported,
    CondPeChars,
    CondDllChars,
    CondRichPresent,
    CondRichProd,
    CondRichBuild,
    CondOverlay,
    CondTls,
    CondTlsCallbacks,
    CondDebugType,
    CondVersionString,
    CondResourceType,
    CondResourceName,
    CondStringContains,
    CondHasCom,
    CondClrStream,
    CondAsmRef,
    CondTypeName,
    CondNamespace,
    CondLinkerMajor,
    CondLinkerMinor,
    CondImportDllCount,
    CondWxSection,
    CondSectionRawSize,
    CondOddSectionNames,
    CondVirtualOnlyBeforeEntry,
    CondEntrySectionChars,
    CondEntrySectionRawSize,
    CondEntrySectionEntropy
};

enum MatchMode : uint8_t
{
    MatchExact = 0,
    MatchContains,
    MatchPrefix
};

enum ScanWhere : uint8_t
{
    ScanEntry = 0,
    ScanFile,
    ScanOverlay
};

struct BytePat
{
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> mask;
};

struct Cond
{
    CondKind          kind = CondAll;
    MatchMode         mode = MatchExact;
    ScanWhere         where = ScanEntry;
    int               weight = 0;
    int               i0 = 0;
    int               i1 = 0;
    double            f0 = 0.0;
    bool              b0 = false;
    std::string       a;
    std::string       b;
    BytePat           pat;
    std::vector<Cond> kids;
};

enum ArchMask : uint32_t
{
    ArchAny  = 1u,
    ArchX86  = 2u,
    ArchX64  = 4u,
    ArchArm64 = 8u
};

struct CompiledSig
{
    int               schema_version = 1;
    DetectCategory    category = DetectCatPacker;
    DetectConfidence  cap = DetectConfHigh;
    DetectSource      source = DetectSrcBuiltin;
    uint32_t          arch = ArchAny;
    bool              requires_clr = false;
    bool              native_only = false;
    bool              heuristic = false;
    std::string       id;
    std::string       name;
    std::string       vendor;
    std::string       version;
    std::string       product_key;
    std::string       description;
    std::string       author;
    std::string       reference;
    std::string       origin;
    Cond              root;
};

struct LoadDiag
{
    std::string path;
    std::string message;
};

bool DetectParseBytePattern(const char* text, BytePat* out, std::string* err);
bool DetectParseSignatureJson(const char* json, const char* origin, DetectSource src, CompiledSig* out, std::string* err);
bool DetectEvalCond(const DetectFacts& facts, const Cond& c, std::vector<DetectEvidence>* ev);
bool DetectSigApplies(const DetectFacts& facts, const CompiledSig& sig);
DetectConfidence DetectScoreToConfidence(int score, DetectConfidence cap);

void DetectLogSig(int sev, const char* fmt, ...);
void DetectLogPe(int sev, const char* fmt, ...);
