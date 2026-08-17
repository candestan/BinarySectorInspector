#pragma once

#include <stdint.h>
#include <stddef.h>
#include <vector>
#include <string>

struct PeFile;

enum AnalysisKind : uint8_t
{
    AnalysisKindUnknown = 0,
    AnalysisKindPayload,
    AnalysisKindArchive,
    AnalysisKindScript,
    AnalysisKindRuntime,
    AnalysisKindMetadata,
    AnalysisKindAssembly
};

enum AnalysisExportKind : uint8_t
{
    AnalysisExportRaw = 0,
    AnalysisExportText,
    AnalysisExportProvider
};

enum
{
    AnalysisTableMaxCols = 6,
    AnalysisTableCell    = 160
};

struct AnalysisProp
{
    char key[48];
    char value[256];
};

struct AnalysisExport
{
    char               id[32];
    char               i18n_key[48];
    char               suggest[160];
    AnalysisExportKind kind;
    uint32_t           file_off;
    uint32_t           size;
    uint32_t           extra;
    uint32_t           extra2;
};

struct AnalysisTableRow
{
    char     cells[AnalysisTableMaxCols][AnalysisTableCell];
    uint32_t rva;
    uint32_t file_off;
};

struct AnalysisTable
{
    char id[32];
    char title_i18n[48];
    char col_i18n[AnalysisTableMaxCols][48];
    int  col_n;
    std::vector<AnalysisTableRow> rows;
};

struct AnalysisArtifact
{
    char     id[80];
    AnalysisKind kind;
    char     label[160];
    char     provider_id[64];
    char     group[48];
    char     status_i18n[48];
    uint32_t file_off;
    uint32_t size;
    uint32_t rva;
    bool     flag_main;
    std::vector<AnalysisProp>     props;
    std::vector<std::string>      names;
    std::vector<std::string>      strings;
    std::vector<AnalysisExport>   exports;
    std::vector<AnalysisTable>    tables;
    std::vector<AnalysisArtifact> children;
};

struct AnalyzerApply
{
    bool        needs_pe;
    bool        needs_clr;
    const char* resource_type;
    const char* product_key;
    const char* section_name;
};

struct AnalyzerProvider
{
    const char*   id;
    const char*   name;
    AnalyzerApply apply;
    bool (*analyze)(PeFile* pe, const uint8_t* data, size_t n);
    bool (*export_bytes)(const PeFile* pe, const uint8_t* data, size_t n,
        const AnalysisArtifact* art, const AnalysisExport* ex, const char* path);
};

void AnalyzeRegister(const AnalyzerProvider* provider);
void AnalyzeRegisterPy2Exe();
void AnalyzeRegisterGo();
void AnalyzeRegisterAutoIt();
void AnalyzeInit();
void AnalyzeRun(PeFile* pe, const uint8_t* data, size_t n);
bool AnalyzeExport(const PeFile* pe, const uint8_t* data, size_t n,
    const AnalysisArtifact* art, const AnalysisExport* ex, const char* path);
const AnalysisArtifact* AnalyzeFindByOff(const PeFile* pe, uint32_t file_off);
const AnalyzerProvider* AnalyzeFindProvider(const char* id);
void AnalyzeStamp(AnalysisArtifact* art, const char* provider_id, const char* group);
void AnalyzeAddProp(AnalysisArtifact* art, const char* key, const char* value);
void AnalyzeAddFinding(PeFile* pe, int sev, const char* title, const char* why);
void AnalyzeTableInit(AnalysisTable* t, const char* id, const char* title_i18n);
void AnalyzeTableAddCol(AnalysisTable* t, const char* col_i18n);
void AnalyzeTableAddRow(AnalysisTable* t, uint32_t rva, uint32_t file_off,
    const char* c0, const char* c1 = nullptr, const char* c2 = nullptr,
    const char* c3 = nullptr, const char* c4 = nullptr, const char* c5 = nullptr);
void AnalyzeAddRawExport(AnalysisArtifact* art, const char* id, const char* i18n_key,
    const char* suggest, uint32_t file_off, uint32_t size);
void AnalyzeAddProviderExport(AnalysisArtifact* art, const char* id, const char* i18n_key,
    const char* suggest);
