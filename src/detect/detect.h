#pragma once

#include <stdint.h>
#include <stddef.h>
#include <string>
#include <vector>

struct PeFile;

enum DetectCategory : uint8_t
{
    DetectCatPacker = 0,
    DetectCatProtector,
    DetectCatCompiler,
    DetectCatToolchain,
    DetectCatDotNetObfuscator,
    DetectCatCount
};

enum DetectConfidence : uint8_t
{
    DetectConfLow = 0,
    DetectConfMedium,
    DetectConfHigh,
    DetectConfExact,
    DetectConfCount
};

enum DetectSource : uint8_t
{
    DetectSrcBuiltin = 0,
    DetectSrcPack,
    DetectSrcUser
};

struct DetectEvidence
{
    std::string condition;
    std::string detail;
    int         weight = 0;
};

struct DetectMatch
{
    std::string                  signature_id;
    DetectSource                 source = DetectSrcBuiltin;
    std::vector<DetectEvidence>  evidence;
};

struct DetectionResult
{
    DetectCategory               category = DetectCatPacker;
    DetectConfidence             confidence = DetectConfLow;
    int                          score = 0;
    bool                         heuristic = false;
    DetectSource                 source = DetectSrcBuiltin;
    std::string                  product_key;
    std::string                  product;
    std::string                  vendor;
    std::string                  version;
    std::string                  description;
    std::string                  reference;
    std::vector<DetectMatch>     signatures;
    std::vector<DetectEvidence>  evidence;
};

struct DetectSectionFact
{
    char     name[9];
    uint32_t chars;
    uint32_t vsize;
    uint32_t vaddr;
    uint32_t rawsize;
    uint32_t rawptr;
    double   entropy;
};

struct DetectFacts
{
    bool     is_pe = false;
    bool     pe32plus = false;
    bool     has_com = false;
    bool     overlay = false;
    bool     tls = false;
    bool     tls_callbacks = false;
    uint16_t machine = 0;
    uint16_t chars = 0;
    uint16_t dllchars = 0;
    uint16_t linker_major = 0;
    uint16_t linker_minor = 0;
    uint32_t entry_rva = 0;
    uint64_t entry_off = 0;
    uint64_t overlay_off = 0;
    uint64_t overlay_size = 0;
    uint16_t clr_major = 0;
    uint16_t clr_minor = 0;
    uint32_t clr_flags = 0;
    int      section_n = 0;
    int      import_dll_n = 0;

    std::vector<DetectSectionFact> sections;
    std::vector<uint16_t>          rich_prod;
    std::vector<uint16_t>          rich_build;
    std::vector<std::string>       import_dlls;
    std::vector<std::string>       import_fns;
    std::vector<std::string>       exports;
    std::vector<std::string>       debug_types;
    std::vector<std::string>       version_kv;
    std::vector<std::string>       resource_types;
    std::vector<std::string>       resource_names;
    std::vector<std::string>       strings;
    std::vector<std::string>       clr_streams;
    std::vector<std::string>       clr_asm_refs;
    std::vector<std::string>       clr_types;
    std::vector<std::string>       clr_namespaces;

    const uint8_t* bytes = nullptr;
    size_t         byte_n = 0;
};

struct DetectLoadStats
{
    int builtin = 0;
    int pack = 0;
    int user = 0;
    int invalid = 0;
    int collisions = 0;
    int total = 0;
};

void DetectInit();
void DetectShutdown();
bool DetectReload();
void DetectAddPackDirectory(const char* path);

DetectLoadStats DetectStats();
const char*     DetectBuiltinDir();
const char*     DetectUserDir();
const char*     DetectPacksDir();
bool            DetectOpenUserDir();
void            DetectEnsureUserDir();

void DetectFillFacts(const PeFile* pe, const uint8_t* bytes, size_t n, DetectFacts* out);
void DetectRun(const DetectFacts& facts, std::vector<DetectionResult>* out);
void DetectApplyToPe(PeFile* pe, const uint8_t* bytes, size_t n);

bool DetectSettingPackers();
bool DetectSettingCompilers();
bool DetectSettingDotNet();
bool DetectSettingUserSigs();
void DetectSetPackers(bool on);
void DetectSetCompilers(bool on);
void DetectSetDotNet(bool on);
void DetectSetUserSigs(bool on);

const char* DetectCategoryId(DetectCategory cat);
const char* DetectConfidenceId(DetectConfidence conf);

// Test / tooling. Not used by the UI.
void DetectResetForTest();
bool DetectLoadJsonForTest(const char* json, DetectSource src, const char* origin, char* err, int err_cap);
int  DetectSignatureCount();
bool DetectParseBytePatternForTest(const char* text, int* byte_n, int* wild_n, char* err, int err_cap);
