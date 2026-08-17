#include "analyze/analyze.h"
#include "pe/pe.h"
#include "log/log.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <vector>

static std::vector<const AnalyzerProvider*> g_providers;
static bool g_inited;

void AnalyzeRegister(const AnalyzerProvider* provider)
{
    if (!provider || !provider->id || !provider->analyze)
        return;
    for (const AnalyzerProvider* p : g_providers)
    {
        if (p && _stricmp(p->id, provider->id) == 0)
            return;
    }
    g_providers.push_back(provider);
}

void AnalyzeInit()
{
    if (g_inited)
        return;
    g_inited = true;
    AnalyzeRegisterPy2Exe();
    AnalyzeRegisterGo();
    AnalyzeRegisterAutoIt();
    AnalyzeRegisterAhk();
}

void AnalyzeStamp(AnalysisArtifact* art, const char* provider_id, const char* group)
{
    if (!art)
        return;
    snprintf(art->provider_id, sizeof(art->provider_id), "%s", provider_id ? provider_id : "");
    snprintf(art->group, sizeof(art->group), "%s", group ? group : "");
}

void AnalyzeAddProp(AnalysisArtifact* art, const char* key, const char* value)
{
    if (!art || !key || !key[0])
        return;
    AnalysisProp p{};
    snprintf(p.key, sizeof(p.key), "%s", key);
    snprintf(p.value, sizeof(p.value), "%s", value ? value : "");
    art->props.push_back(p);
}

void AnalyzeAddFinding(PeFile* pe, int sev, const char* title, const char* why)
{
    if (!pe)
        return;
    PeFinding f{};
    f.sev = (PeFindingSev)sev;
    f.kind = PeFindIdentity;
    snprintf(f.title, sizeof(f.title), "%s", title ? title : "");
    snprintf(f.why, sizeof(f.why), "%s", why ? why : "");
    pe->findings.push_back(f);
}

void AnalyzeTableInit(AnalysisTable* t, const char* id, const char* title_i18n)
{
    if (!t)
        return;
    *t = AnalysisTable{};
    snprintf(t->id, sizeof(t->id), "%s", id ? id : "table");
    snprintf(t->title_i18n, sizeof(t->title_i18n), "%s", title_i18n ? title_i18n : "");
}

void AnalyzeTableAddCol(AnalysisTable* t, const char* col_i18n)
{
    if (!t || !col_i18n || t->col_n >= AnalysisTableMaxCols)
        return;
    snprintf(t->col_i18n[t->col_n], sizeof(t->col_i18n[0]), "%s", col_i18n);
    t->col_n++;
}

static void CopyCell(char* dst, int cap, const char* s)
{
    if (!dst || cap <= 0)
        return;
    snprintf(dst, cap, "%s", s ? s : "");
}

void AnalyzeTableAddRow(AnalysisTable* t, uint32_t rva, uint32_t file_off,
    const char* c0, const char* c1, const char* c2,
    const char* c3, const char* c4, const char* c5)
{
    if (!t || t->col_n <= 0)
        return;
    if (t->rows.size() >= 20000)
        return;
    AnalysisTableRow r{};
    r.rva = rva;
    r.file_off = file_off;
    CopyCell(r.cells[0], AnalysisTableCell, c0);
    CopyCell(r.cells[1], AnalysisTableCell, c1);
    CopyCell(r.cells[2], AnalysisTableCell, c2);
    CopyCell(r.cells[3], AnalysisTableCell, c3);
    CopyCell(r.cells[4], AnalysisTableCell, c4);
    CopyCell(r.cells[5], AnalysisTableCell, c5);
    t->rows.push_back(r);
}

void AnalyzeAddRawExport(AnalysisArtifact* art, const char* id, const char* i18n_key,
    const char* suggest, uint32_t file_off, uint32_t size)
{
    if (!art)
        return;
    AnalysisExport ex{};
    snprintf(ex.id, sizeof(ex.id), "%s", id ? id : "raw");
    snprintf(ex.i18n_key, sizeof(ex.i18n_key), "%s", i18n_key ? i18n_key : "pe.analysis_dump_raw");
    snprintf(ex.suggest, sizeof(ex.suggest), "%s", suggest ? suggest : "dump.bin");
    ex.kind = AnalysisExportRaw;
    ex.file_off = file_off;
    ex.size = size;
    art->exports.push_back(ex);
}

void AnalyzeAddProviderExport(AnalysisArtifact* art, const char* id, const char* i18n_key,
    const char* suggest)
{
    if (!art)
        return;
    AnalysisExport ex{};
    snprintf(ex.id, sizeof(ex.id), "%s", id ? id : "listing");
    snprintf(ex.i18n_key, sizeof(ex.i18n_key), "%s", i18n_key ? i18n_key : "pe.analysis_dump_listing");
    snprintf(ex.suggest, sizeof(ex.suggest), "%s", suggest ? suggest : "listing.txt");
    ex.kind = AnalysisExportProvider;
    art->exports.push_back(ex);
}

static bool HasResourceType(const PeFile* pe, const char* type)
{
    if (!pe || !type || !type[0])
        return false;
    for (const PeRsrcLeaf& L : pe->rsrc)
    {
        if (_stricmp(L.type_name, type) == 0)
            return true;
        if (_stricmp(L.name, type) == 0)
            return true;
    }
    return false;
}

static bool HasProductKey(const PeFile* pe, const char* key)
{
    if (!pe || !key || !key[0])
        return false;
    for (const DetectionResult& r : pe->detections)
    {
        if (_stricmp(r.product_key.c_str(), key) == 0)
            return true;
    }
    return false;
}

static bool HasSectionName(const PeFile* pe, const char* name)
{
    if (!pe || !name || !name[0])
        return false;
    for (int i = 0; i < pe->section_n; i++)
    {
        if (_stricmp(pe->sections[i].name, name) == 0)
            return true;
        if (strstr(pe->sections[i].name, name))
            return true;
    }
    return false;
}

static bool Applicable(const PeFile* pe, const AnalyzerApply& a)
{
    if (!pe || !pe->ok)
        return false;
    if (a.needs_clr && (!pe->has_com || !pe->clr_off))
        return false;
    bool typed = a.resource_type && a.resource_type[0];
    bool keyed = a.product_key && a.product_key[0];
    bool sect = a.section_name && a.section_name[0];
    if (!typed && !keyed && !sect)
        return true;
    if (typed && HasResourceType(pe, a.resource_type))
        return true;
    if (keyed && HasProductKey(pe, a.product_key))
        return true;
    if (sect && HasSectionName(pe, a.section_name))
        return true;
    return false;
}

const AnalyzerProvider* AnalyzeFindProvider(const char* id)
{
    if (!id || !id[0])
        return nullptr;
    for (const AnalyzerProvider* p : g_providers)
    {
        if (p && _stricmp(p->id, id) == 0)
            return p;
    }
    return nullptr;
}

static bool WriteBytes(const char* path, const void* data, DWORD n)
{
    wchar_t wpath[MAX_PATH];
    if (!path || !MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, MAX_PATH))
        return false;
    HANDLE h = CreateFileW(wpath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    DWORD wr = 0;
    BOOL ok = WriteFile(h, data, n, &wr, nullptr);
    CloseHandle(h);
    return ok && wr == n;
}

static bool DumpTablesText(const AnalysisArtifact* art, const char* path)
{
    std::string t;
    char line[512];
    for (const AnalysisProp& p : art->props)
    {
        snprintf(line, sizeof(line), "%s=%s\n", p.key, p.value);
        t.append(line);
    }
    if (!art->tables.empty())
        t.push_back('\n');
    for (const AnalysisTable& tb : art->tables)
    {
        snprintf(line, sizeof(line), "# %s\n", tb.id);
        t.append(line);
        for (int c = 0; c < tb.col_n; c++)
        {
            if (c)
                t.push_back('\t');
            t.append(tb.col_i18n[c]);
        }
        t.push_back('\n');
        for (const AnalysisTableRow& r : tb.rows)
        {
            for (int c = 0; c < tb.col_n; c++)
            {
                if (c)
                    t.push_back('\t');
                t.append(r.cells[c]);
            }
            t.push_back('\n');
        }
        t.push_back('\n');
    }
    for (size_t i = 0; i < art->strings.size(); i++)
    {
        t.append(art->strings[i]);
        t.push_back('\n');
    }
    return WriteBytes(path, t.data(), (DWORD)t.size());
}

void AnalyzeRun(PeFile* pe, const uint8_t* data, size_t n)
{
    AnalyzeInit();
    if (!pe)
        return;
    pe->analysis.clear();
    if (!pe->ok || !data)
        return;
    for (const AnalyzerProvider* p : g_providers)
    {
        if (!p || !Applicable(pe, p->apply))
            continue;
        auto log = LogFor(LogBuiltinPeAnalyzer).Module(p->name ? p->name : p->id);
        log.Info("Running analyzer");
        if (!p->analyze(pe, data, n))
            log.Warning("Analyzer returned no artifacts");
    }
}

bool AnalyzeExport(const PeFile* pe, const uint8_t* data, size_t n,
    const AnalysisArtifact* art, const AnalysisExport* ex, const char* path)
{
    if (!pe || !art || !ex || !path || !path[0])
        return false;
    if (ex->kind == AnalysisExportRaw)
    {
        if (!data || !ex->size || (uint64_t)ex->file_off + ex->size > n)
            return false;
        return WriteBytes(path, data + ex->file_off, ex->size);
    }
    if (ex->kind == AnalysisExportText)
        return DumpTablesText(art, path);
    const AnalyzerProvider* p = AnalyzeFindProvider(art->provider_id);
    if (!p || !p->export_bytes)
        return false;
    return p->export_bytes(pe, data, n, art, ex, path);
}

const AnalysisArtifact* AnalyzeFindByOff(const PeFile* pe, uint32_t file_off)
{
    if (!pe || !file_off)
        return nullptr;
    for (const AnalysisArtifact& a : pe->analysis)
    {
        if (a.file_off == file_off)
            return &a;
        for (const AnalysisArtifact& c : a.children)
        {
            if (c.file_off == file_off)
                return &c;
        }
    }
    return nullptr;
}
