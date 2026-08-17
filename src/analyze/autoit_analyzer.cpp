#include "analyze/analyze.h"
#include "pe/pe.h"
#include "log/log.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <vector>
#include <string>

// AutoIt compiled container recovery. Identity is JSON.
// Format constants: MyAutToExe / autoit-ripper README (public).
// credit: https://github.com/nazywam/AutoIt-Ripper
// Does not detokenize bytecode into claimed original source.

static const char* kAnalyzerId = "com.binarysectorinspector.analyzer.autoit";

static const uint8_t kEa05Guid[20] = {
    0xA3, 0x48, 0x4B, 0xBE, 0x98, 0x6C, 0x4A, 0xA9, 0x99, 0x4C,
    0x53, 0x0A, 0x86, 0xD6, 0x48, 0x7D, 0x41, 0x55, 0x33, 0x21
};

static const int kMaxRecords = 256;
static const uint32_t kMaxBlob = 16u * 1024u * 1024u;

static uint32_t LameStep(uint32_t key)
{
    uint32_t lo = (key & 0xFFFFu) * 0x13AE9u;
    uint32_t hi = (key >> 16) * 0x13AE9u;
    hi += (lo >> 16);
    return (hi << 16) | (lo & 0xFFFFu);
}

static void LameXor(uint8_t* p, uint32_t n, uint32_t seed)
{
    uint32_t k = seed;
    for (uint32_t i = 0; i < n; i++)
    {
        k = LameStep(k);
        p[i] ^= (uint8_t)((k >> 8) & 0xFF);
    }
}

static bool MemFind(const uint8_t* b, size_t n, const uint8_t* needle, size_t k, size_t* out)
{
    if (!b || !needle || k == 0 || n < k)
        return false;
    size_t lim = n - k;
    if (lim > 64u * 1024u * 1024u)
        lim = 64u * 1024u * 1024u;
    for (size_t i = 0; i <= lim; i++)
    {
        if (memcmp(b + i, needle, k) == 0)
        {
            *out = i;
            return true;
        }
    }
    return false;
}

static const PeRsrcLeaf* FindNamedResource(const PeFile* pe, const char* type, const char* name)
{
    const PeRsrcLeaf* best = nullptr;
    for (const PeRsrcLeaf& L : pe->rsrc)
    {
        bool t = !type || !type[0] || _stricmp(L.type_name, type) == 0;
        bool nm = !name || !name[0] || _stricmp(L.name, name) == 0;
        if (t && nm && (!best || L.size > best->size))
            best = &L;
    }
    return best;
}

static uint32_t Rd32le(const uint8_t* p)
{
    uint32_t x;
    memcpy(&x, p, 4);
    return x;
}

static bool RdUtf16z(const uint8_t* p, uint32_t n, char* out, int cap)
{
    if (!out || cap < 2)
        return false;
    out[0] = 0;
    int o = 0;
    for (uint32_t i = 0; i + 1 < n && o < cap - 1; i += 2)
    {
        uint16_t c = (uint16_t)(p[i] | (p[i + 1] << 8));
        if (!c)
            break;
        if (c < 32 || c > 126)
        {
            if (c != '\t' && c != '\r' && c != '\n')
                out[o++] = '?';
            else
                out[o++] = (char)c;
        }
        else
            out[o++] = (char)c;
    }
    out[o] = 0;
    return o > 0;
}

struct AuRec
{
    char     kind[80];
    char     name[160];
    bool     compressed;
    uint32_t data_off;
    uint32_t data_size;
    uint32_t uncomp_size;
};

static bool WalkEa06(const uint8_t* body, uint32_t n, std::vector<AuRec>* recs)
{
    auto log = LogFor(LogBuiltinPeAnalyzer).Module("container");
    if (n < 24)
        return false;
    uint32_t i = 0;
    if (n >= 16)
        i = 16;
    int count = 0;
    while (i + 8 < n && count < kMaxRecords)
    {
        if (i + 4 > n)
            break;
        uint8_t tag[4];
        memcpy(tag, body + i, 4);
        LameXor(tag, 4, 0x18EE);
        if (memcmp(tag, "FILE", 4) != 0)
            break;
        i += 4;
        if (i + 4 > n)
            break;
        uint32_t flag = Rd32le(body + i) ^ 0xADBCu;
        i += 4;
        uint32_t slen = flag;
        if (slen > 0x10000)
            break;
        uint32_t sbytes = slen * 2;
        if (i + sbytes > n)
            break;
        std::vector<uint8_t> st(body + i, body + i + sbytes);
        LameXor(st.data(), sbytes, 0xB33F + flag);
        char kind[80];
        RdUtf16z(st.data(), sbytes, kind, (int)sizeof(kind));
        i += sbytes;

        if (i + 4 > n)
            break;
        uint32_t plen = Rd32le(body + i) ^ 0xF820u;
        i += 4;
        if (plen > 0x4000)
            break;
        uint32_t pbytes = plen * 2;
        if (i + pbytes > n)
            break;
        std::vector<uint8_t> pt(body + i, body + i + pbytes);
        LameXor(pt.data(), pbytes, 0xF479 + plen);
        char path[160];
        RdUtf16z(pt.data(), pbytes, path, (int)sizeof(path));
        i += pbytes;

        if (i + 1 + 12 > n)
            break;
        uint8_t compressed = body[i++];
        uint32_t csize = Rd32le(body + i) ^ 0x87BCu; i += 4;
        uint32_t usize = Rd32le(body + i) ^ 0x87BCu; i += 4;
        i += 4;
        i += 16;
        if (csize > kMaxBlob || (uint64_t)i + csize > n)
        {
            log.Warning("AutoIt record '%s' payload is truncated", kind[0] ? kind : path);
            break;
        }
        AuRec r{};
        snprintf(r.kind, sizeof(r.kind), "%s", kind);
        snprintf(r.name, sizeof(r.name), "%s", path[0] ? path : kind);
        r.compressed = compressed != 0;
        r.data_off = i;
        r.data_size = csize;
        r.uncomp_size = usize;
        recs->push_back(r);
        i += csize;
        count++;
    }
    return count > 0;
}

static bool AnalyzeAutoIt(PeFile* pe, const uint8_t* data, size_t n)
{
    if (!pe || !data)
        return false;
    auto log = LogFor(LogBuiltinPeAnalyzer).Module("autoit");

    const PeRsrcLeaf* script = FindNamedResource(pe, "RCDATA", "SCRIPT");
    if (!script)
        script = FindNamedResource(pe, nullptr, "SCRIPT");

    size_t magic_off = (size_t)-1;
    const char* magic_name = nullptr;
    if (pe->overlay_size && pe->overlay_off < n)
    {
        size_t on = (size_t)pe->overlay_size;
        if ((uint64_t)pe->overlay_off + on > n)
            on = n - pe->overlay_off;
        size_t rel = 0;
        if (MemFind(data + pe->overlay_off, on, (const uint8_t*)"AU3!EA06", 8, &rel))
        {
            magic_off = (size_t)pe->overlay_off + rel;
            magic_name = "AU3!EA06";
        }
        else if (MemFind(data + pe->overlay_off, on, (const uint8_t*)"AU3!EA05", 8, &rel))
        {
            magic_off = (size_t)pe->overlay_off + rel;
            magic_name = "AU3!EA05";
        }
        else if (MemFind(data + pe->overlay_off, on, kEa05Guid, 20, &rel))
        {
            magic_off = (size_t)pe->overlay_off + rel;
            magic_name = "EA05-GUID";
        }
    }
    if (magic_off == (size_t)-1)
    {
        size_t rel = 0;
        size_t scan = n;
        if (scan > 32u * 1024u * 1024u)
            scan = 32u * 1024u * 1024u;
        if (MemFind(data, scan, (const uint8_t*)"AU3!EA06", 8, &rel))
        {
            magic_off = rel;
            magic_name = "AU3!EA06";
        }
        else if (MemFind(data, scan, kEa05Guid, 20, &rel))
        {
            magic_off = rel;
            magic_name = "EA05-GUID";
        }
    }

    if (!script && magic_off == (size_t)-1)
    {
        log.Info("No SCRIPT resource or AutoIt overlay magic");
        return false;
    }

    AnalysisArtifact root{};
    snprintf(root.id, sizeof(root.id), "autoit.container");
    root.kind = AnalysisKindPayload;
    snprintf(root.label, sizeof(root.label), "AutoIt");
    AnalyzeStamp(&root, kAnalyzerId, "AutoIt");
    if (magic_name)
        AnalyzeAddProp(&root, "magic", magic_name);
    if (magic_off != (size_t)-1)
    {
        root.file_off = (uint32_t)magic_off;
        char offb[16];
        snprintf(offb, sizeof(offb), "0x%X", (unsigned)magic_off);
        AnalyzeAddProp(&root, "magic_off", offb);
    }
    if (script)
    {
        char sz[16];
        snprintf(sz, sizeof(sz), "%u", script->size);
        AnalyzeAddProp(&root, "script_resource", sz);
        AnalyzeAddRawExport(&root, "script_rsrc", "pe.analysis_dump_raw", "autoit_script.bin",
            script->file_off, script->size);
        if (!root.file_off)
        {
            root.file_off = script->file_off;
            root.size = script->size;
        }
    }
    if (pe->overlay_size)
    {
        AnalyzeAddRawExport(&root, "overlay", "pe.analysis_dump_raw", "autoit_overlay.bin",
            pe->overlay_off, pe->overlay_size > kMaxBlob ? kMaxBlob : (uint32_t)pe->overlay_size);
        AnalyzeAddProp(&root, "overlay", "present");
    }

    std::vector<AuRec> recs;
    const uint8_t* body = nullptr;
    uint32_t body_n = 0;
    uint32_t body_file_off = 0;
    if (script && script->size > 0x28 && (uint64_t)script->file_off + script->size <= n)
    {
        body = data + script->file_off + 0x18;
        body_n = script->size - 0x18;
        body_file_off = script->file_off + 0x18;
    }
    else if (magic_off != (size_t)-1 && magic_name && strcmp(magic_name, "AU3!EA06") == 0)
    {
        uint32_t start = (uint32_t)magic_off + 8;
        if (start < n)
        {
            body = data + start;
            body_n = (uint32_t)(n - start);
            if (body_n > kMaxBlob)
                body_n = kMaxBlob;
            body_file_off = start;
        }
    }
    else if (magic_off != (size_t)-1 && magic_name && strcmp(magic_name, "EA05-GUID") == 0)
    {
        uint32_t start = (uint32_t)magic_off + 20;
        if (start + 4 < n)
        {
            char tag[5] = {};
            memcpy(tag, data + start, 4);
            AnalyzeAddProp(&root, "stream", tag);
            snprintf(root.status_i18n, sizeof(root.status_i18n), "pe.analysis_unsupported");
            log.Warning("EA05 stream is not fully walked");
        }
    }

    if (body && WalkEa06(body, body_n, &recs))
        log.Info("EA06 container: %zu records", recs.size());
    else if (body)
        log.Info("EA06 FILE records were not recovered (wrong layout or LAME mismatch)");

    AnalysisArtifact files{};
    snprintf(files.id, sizeof(files.id), "autoit.files");
    files.kind = AnalysisKindArchive;
    snprintf(files.label, sizeof(files.label), "Embedded files");
    AnalyzeStamp(&files, kAnalyzerId, "AutoIt");
    AnalysisTable tb{};
    AnalyzeTableInit(&tb, "files", "pe.analysis_col.files");
    AnalyzeTableAddCol(&tb, "pe.analysis_col.name");
    AnalyzeTableAddCol(&tb, "pe.analysis_col.kind");
    AnalyzeTableAddCol(&tb, "pe.analysis_col.size");
    AnalyzeTableAddCol(&tb, "pe.analysis_col.compressed");

    for (int i = 0; i < (int)recs.size(); i++)
    {
        const AuRec& r = recs[i];
        char sz[16];
        snprintf(sz, sizeof(sz), "%u", r.data_size);
        AnalyzeTableAddRow(&tb, 0, body_file_off + r.data_off, r.name, r.kind, sz,
            r.compressed ? "yes" : "no");

        AnalysisArtifact ch{};
        snprintf(ch.id, sizeof(ch.id), "autoit.file.%d", i);
        bool is_script = strstr(r.kind, "SCRIPT") != nullptr;
        ch.kind = is_script ? AnalysisKindScript : AnalysisKindPayload;
        snprintf(ch.label, sizeof(ch.label), "%s", r.name[0] ? r.name : r.kind);
        AnalyzeStamp(&ch, kAnalyzerId, "AutoIt");
        AnalyzeAddProp(&ch, "kind", r.kind);
        AnalyzeAddProp(&ch, "compressed", r.compressed ? "yes" : "no");
        ch.file_off = body_file_off + r.data_off;
        ch.size = r.data_size;
        if (is_script)
        {
            AnalyzeAddProp(&ch, "note", "tokenized_or_encrypted");
            snprintf(ch.status_i18n, sizeof(ch.status_i18n), "pe.analysis_not_source");
        }
        bool text = ch.size && (uint64_t)ch.file_off + ch.size <= n &&
            !r.compressed && AnalyzeLooksText(data + ch.file_off, ch.size);
        if (text)
        {
            AnalyzeSetMedia(&ch, "script.text");
            char sug[160];
            snprintf(sug, sizeof(sug), "%s", r.name[0] ? r.name : "script");
            if (!strchr(sug, '.'))
                strncat_s(sug, ".au3", _TRUNCATE);
            AnalyzeAddRawExport(&ch, "script", "pe.analysis_dump_script", sug, ch.file_off, ch.size);
        }
        else
            AnalyzeSetMedia(&ch, "bytes.raw");
        char sug[160];
        snprintf(sug, sizeof(sug), "autoit_%d.bin", i);
        AnalyzeAddRawExport(&ch, "payload", "pe.analysis_dump_raw", sug, ch.file_off, ch.size);
        if (is_script || i < 12)
            files.children.push_back(std::move(ch));
    }
    if (!tb.rows.empty())
        files.tables.push_back(std::move(tb));

    if (recs.empty() && !script && magic_off == (size_t)-1)
        return false;
    if (recs.empty())
        snprintf(root.status_i18n, sizeof(root.status_i18n), "pe.analysis_partial");

    AnalyzeAddProviderExport(&root, "listing", "pe.analysis_dump_listing", "autoit_listing.txt");
    if (!files.tables.empty() || !files.children.empty())
        root.children.push_back(std::move(files));

    AnalyzeAddFinding(pe, PeFindingNotice, "AutoIt container",
        "Compiled AutoIt markers were found. Extracted blobs may be encrypted or tokenized.");
    pe->analysis.push_back(std::move(root));
    log.Info("AutoIt analysis: magic=%s script_rsrc=%s records=%zu",
        magic_name ? magic_name : "none",
        script ? "yes" : "no",
        recs.size());
    return true;
}

static void DumpArtifactListing(const AnalysisArtifact& a, std::string* t, char* line, int line_cap, int depth)
{
    if (!t || depth > 8)
        return;
    for (const AnalysisTable& tb : a.tables)
    {
        snprintf(line, line_cap, "# %s\n", tb.id);
        t->append(line);
        for (const AnalysisTableRow& r : tb.rows)
        {
            for (int c = 0; c < tb.col_n; c++)
            {
                if (c)
                    t->push_back('\t');
                t->append(r.cells[c]);
            }
            t->push_back('\n');
        }
    }
    for (const AnalysisArtifact& ch : a.children)
        DumpArtifactListing(ch, t, line, line_cap, depth + 1);
}

static bool ExportAutoIt(const PeFile* pe, const uint8_t* data, size_t n,
    const AnalysisArtifact* art, const AnalysisExport* ex, const char* path)
{
    (void)data;
    (void)n;
    if (!pe || !art || !ex || !path)
        return false;
    if (strcmp(ex->id, "listing") != 0)
        return false;
    std::string t;
    char line[512];
    snprintf(line, sizeof(line), "AutoIt analysis\n");
    t.append(line);
    for (const AnalysisProp& p : art->props)
    {
        snprintf(line, sizeof(line), "%s=%s\n", p.key, p.value);
        t.append(line);
    }
    t.push_back('\n');
    DumpArtifactListing(*art, &t, line, (int)sizeof(line), 0);
    wchar_t wpath[MAX_PATH];
    if (!MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, MAX_PATH))
        return false;
    HANDLE h = CreateFileW(wpath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    DWORD wr = 0;
    BOOL ok = WriteFile(h, t.data(), (DWORD)t.size(), &wr, nullptr);
    CloseHandle(h);
    return ok && wr == (DWORD)t.size();
}

static const AnalyzerProvider kAutoItProvider = {
    kAnalyzerId,
    "autoit",
    { true, false, "SCRIPT", "autoit", nullptr },
    AnalyzeAutoIt,
    ExportAutoIt
};

void AnalyzeRegisterAutoIt()
{
    AnalyzeRegister(&kAutoItProvider);
}
