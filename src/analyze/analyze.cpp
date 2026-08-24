#include "analyze/analyze.h"
#include "analyze/profile.h"
#include "pe/pe.h"
#include "log/log.h"

#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <ctype.h>

#pragma comment(lib, "bcrypt.lib")

#define MINIZ_NO_ARCHIVE_APIS
#define MINIZ_NO_STDIO
#include "miniz.h"

static std::vector<const AnalyzerProvider*>& Providers()
{
    static std::vector<const AnalyzerProvider*> v;
    return v;
}

static uint64_t g_decompress_used;

void AnalyzeRegister(const AnalyzerProvider* provider)
{
    if (!provider || !provider->id || !provider->analyze)
        return;
    std::vector<const AnalyzerProvider*>& g_providers = Providers();
    for (const AnalyzerProvider* p : g_providers)
    {
        if (p && _stricmp(p->id, provider->id) == 0)
            return;
    }
    g_providers.push_back(provider);
}

void AnalyzeInit()
{
}

void AnalyzeStamp(AnalysisArtifact* art, const char* provider_id, const char* group)
{
    if (!art)
        return;
    snprintf(art->provider_id, sizeof(art->provider_id), "%s", provider_id ? provider_id : "");
    snprintf(art->group, sizeof(art->group), "%s", group ? group : "");
}

void AnalyzeSetMedia(AnalysisArtifact* art, const char* media)
{
    if (!art)
        return;
    snprintf(art->media, sizeof(art->media), "%s", media ? media : "");
}

bool AnalyzeLooksText(const uint8_t* p, uint32_t n)
{
    if (!p || n < 8)
        return false;
    uint32_t chk = n > 2048 ? 2048 : n;
    uint32_t ok = 0;
    uint32_t zeros = 0;
    for (uint32_t i = 0; i < chk; i++)
    {
        uint8_t c = p[i];
        if (c == 0)
            zeros++;
        if (c == '\t' || c == '\n' || c == '\r' || (c >= 32 && c < 127))
            ok++;
    }
    if (zeros * 3 >= chk && zeros * 2 <= chk)
        return ok * 2 >= chk;
    return ok * 10 >= chk * 8;
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

void AnalyzeAddOwnedExport(AnalysisArtifact* art, const char* id, const char* i18n_key,
    const char* suggest)
{
    if (!art || art->owned.empty())
        return;
    AnalysisExport ex{};
    snprintf(ex.id, sizeof(ex.id), "%s", id ? id : "owned");
    snprintf(ex.i18n_key, sizeof(ex.i18n_key), "%s", i18n_key ? i18n_key : "pe.analysis_dump_raw");
    snprintf(ex.suggest, sizeof(ex.suggest), "%s", suggest ? suggest : "dump.bin");
    ex.kind = AnalysisExportRaw;
    ex.file_off = 0;
    ex.size = (uint32_t)art->owned.size();
    ex.extra = 1; // owned buffer
    art->exports.push_back(ex);
}

static uint32_t CountArtTree(const AnalysisArtifact& a)
{
    uint32_t n = 1;
    for (const AnalysisArtifact& ch : a.children)
        n += CountArtTree(ch);
    return n;
}

uint32_t AnalyzeCountArtifacts(const PeFile* pe)
{
    if (!pe)
        return 0;
    uint32_t n = 0;
    for (const AnalysisArtifact& a : pe->analysis)
        n += CountArtTree(a);
    return n;
}

bool AnalyzeBudgetCanAdd(const PeFile* pe, uint32_t add)
{
    const AnalysisProfile* prof = AnalyzeProfileActive();
    if (!prof || !pe)
        return false;
    uint64_t have = AnalyzeCountArtifacts(pe);
    return have + add <= (uint64_t)prof->budgets.max_artifacts;
}

bool AnalyzeBudgetCanDecompress(uint64_t compressed_n, uint64_t uncompressed_n, uint64_t* total_out)
{
    const AnalysisProfile* prof = AnalyzeProfileActive();
    if (!prof)
        return false;
    if (uncompressed_n == 0 || uncompressed_n > prof->budgets.max_artifact_bytes)
        return false;
    if (compressed_n && uncompressed_n > compressed_n * (uint64_t)prof->budgets.max_inflate_ratio)
        return false;
    if (g_decompress_used > UINT64_MAX - uncompressed_n)
        return false;
    uint64_t next = g_decompress_used + uncompressed_n;
    if (next > prof->budgets.max_decompress_bytes)
        return false;
    if (total_out)
        *total_out = next;
    return true;
}

bool AnalyzeZlibInflate(const uint8_t* src, size_t src_n, size_t expect_n, std::vector<uint8_t>* out)
{
    if (!src || !src_n || !out || !expect_n)
        return false;
    if (!AnalyzeBudgetCanDecompress(src_n, expect_n, nullptr))
        return false;
    out->resize(expect_n);
    mz_ulong dest_len = (mz_ulong)expect_n;
    int rc = mz_uncompress(out->data(), &dest_len, src, (mz_ulong)src_n);
    if (rc != MZ_OK)
    {
        out->clear();
        return false;
    }
    out->resize((size_t)dest_len);
    g_decompress_used += (uint64_t)dest_len;
    return true;
}

bool AnalyzeZlibInflateAuto(const uint8_t* src, size_t src_n, std::vector<uint8_t>* out)
{
    if (!src || !src_n || !out)
        return false;
    size_t out_len = 0;
    void* p = tinfl_decompress_mem_to_heap(src, src_n, &out_len, TINFL_FLAG_PARSE_ZLIB_HEADER);
    if (!p || !out_len)
    {
        if (p)
            mz_free(p);
        return false;
    }
    if (!AnalyzeBudgetCanDecompress(src_n, out_len, nullptr))
    {
        mz_free(p);
        return false;
    }
    out->assign((const uint8_t*)p, (const uint8_t*)p + out_len);
    mz_free(p);
    g_decompress_used += (uint64_t)out_len;
    return true;
}

void AnalyzeStampSha256(AnalysisArtifact* art)
{
    if (!art)
        return;
    art->sha256_hex[0] = 0;
    const uint8_t* p = nullptr;
    size_t n = 0;
    if (!art->owned.empty())
    {
        p = art->owned.data();
        n = art->owned.size();
    }
    if (!p || !n)
        return;
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD hash_len = 0, cb = 0;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
        return;
    if (BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&hash_len, sizeof(hash_len), &cb, 0) != 0 ||
        hash_len != 32)
    {
        BCryptCloseAlgorithmProvider(alg, 0);
        return;
    }
    std::vector<uint8_t> dig(hash_len);
    if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) != 0)
    {
        BCryptCloseAlgorithmProvider(alg, 0);
        return;
    }
    BCryptHashData(hash, (PUCHAR)p, (ULONG)n, 0);
    BCryptFinishHash(hash, dig.data(), hash_len, 0);
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    for (DWORD i = 0; i < hash_len; i++)
        snprintf(art->sha256_hex + i * 2, 3, "%02x", dig[i]);
    art->sha256_hex[64] = 0;
}

void AnalyzeSetLogicalPath(AnalysisArtifact* art, const char* path)
{
    if (!art)
        return;
    snprintf(art->logical_path, sizeof(art->logical_path), "%s", path ? path : "");
}

bool AnalyzeSanitizeExportName(const char* in, char* out, int out_cap)
{
    if (!out || out_cap < 2)
        return false;
    out[0] = 0;
    if (!in || !in[0])
        return false;
    // Reject absolute / traversal / reserved devices.
    if (strstr(in, "..") || strchr(in, ':') || in[0] == '/' || in[0] == '\\')
        return false;
    char tmp[260];
    int j = 0;
    for (int i = 0; in[i] && j < (int)sizeof(tmp) - 1; i++)
    {
        unsigned char c = (unsigned char)in[i];
        if (c < 32 || c == '<' || c == '>' || c == '"' || c == '|' || c == '?' || c == '*')
            tmp[j++] = '_';
        else if (c == '/' || c == '\\')
            tmp[j++] = '_';
        else
            tmp[j++] = (char)c;
    }
    tmp[j] = 0;
    if (!tmp[0])
        return false;
    // Strip trailing dots/spaces (Win reserved).
    while (j > 0 && (tmp[j - 1] == '.' || tmp[j - 1] == ' '))
        tmp[--j] = 0;
    if (!tmp[0])
        return false;
    const char* base = tmp;
    static const char* kBad[] = {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        nullptr
    };
    for (int i = 0; kBad[i]; i++)
    {
        if (_stricmp(base, kBad[i]) == 0)
            return false;
    }
    snprintf(out, out_cap, "%s", tmp);
    return out[0] != 0;
}

const uint8_t* AnalyzeArtifactBytes(const AnalysisArtifact* art, const uint8_t* image, size_t image_n,
    size_t* out_n)
{
    if (out_n)
        *out_n = 0;
    if (!art)
        return nullptr;
    if (!art->owned.empty())
    {
        if (out_n)
            *out_n = art->owned.size();
        return art->owned.data();
    }
    if (!image || !art->size)
        return nullptr;
    if ((uint64_t)art->file_off + art->size > image_n)
        return nullptr;
    if (out_n)
        *out_n = art->size;
    return image + art->file_off;
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
    for (const AnalyzerProvider* p : Providers())
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
    g_decompress_used = 0;
    if (!pe)
        return;
    pe->analysis.clear();
    if (!pe->ok || !data)
        return;
    for (const AnalyzerProvider* p : Providers())
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
        if (ex->extra == 1 || (!art->owned.empty() && ex->file_off == 0 &&
            ex->size && ex->size <= art->owned.size()))
        {
            size_t take = ex->size ? ex->size : art->owned.size();
            if (take > art->owned.size())
                return false;
            return WriteBytes(path, art->owned.data(), (DWORD)take);
        }
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
