#include "analyze/analyze.h"
#include "pe/pe.h"
#include "log/log.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <vector>
#include <string>

// Native Go PE recovery (buildinfo + pclntab). Identity is JSON.
// credit: https://go.dev/src/debug/buildinfo/buildinfo.go
// credit: https://go.dev/src/debug/gosym/pclntab.go
// credit: https://go.dev/src/runtime/symtab.go

static const char* kAnalyzerId = "com.binarysectorinspector.analyzer.go";
static const char kBuildInfoMagic[16] = "\xff Go buildinf:";

static const uint32_t kPcln12  = 0xFFFFFFFBu;
static const uint32_t kPcln116 = 0xFFFFFFFAu;
static const uint32_t kPcln118 = 0xFFFFFFF0u;
static const uint32_t kPcln120 = 0xFFFFFFF1u;

static const int kMaxFuncs = 16384;
static const int kMaxFiles = 4096;
static const int kMaxPkgs  = 2048;
static const int kMaxName  = 256;
static const int kMaxMod   = 4096;
static const int kMaxDeps  = 512;

struct GoView
{
    const uint8_t* b;
    size_t         n;
    bool           le;
    int            ptr;
};

static bool InRange(const GoView& v, uint64_t off, uint64_t need)
{
    return need <= v.n && off <= (uint64_t)v.n - need;
}

static uint8_t Rd8(const GoView& v, uint64_t off, bool* ok)
{
    if (!InRange(v, off, 1))
    {
        *ok = false;
        return 0;
    }
    return v.b[off];
}

static uint32_t Rd32(const GoView& v, uint64_t off, bool* ok)
{
    if (!InRange(v, off, 4))
    {
        *ok = false;
        return 0;
    }
    uint32_t x;
    memcpy(&x, v.b + off, 4);
    return x;
}

static uint64_t Rd64(const GoView& v, uint64_t off, bool* ok)
{
    if (!InRange(v, off, 8))
    {
        *ok = false;
        return 0;
    }
    uint64_t x;
    memcpy(&x, v.b + off, 8);
    return x;
}

static uint64_t RdPtr(const GoView& v, uint64_t off, bool* ok)
{
    if (v.ptr == 8)
        return Rd64(v, off, ok);
    return Rd32(v, off, ok);
}

static bool RdZ(const GoView& v, uint64_t off, char* out, int cap, int max_scan)
{
    if (!out || cap < 2)
        return false;
    out[0] = 0;
    if (!InRange(v, off, 1))
        return false;
    int n = 0;
    int lim = max_scan;
    if (lim > cap - 1)
        lim = cap - 1;
    while (n < lim && InRange(v, off + (uint64_t)n, 1))
    {
        unsigned char c = v.b[off + (uint64_t)n];
        if (!c)
            break;
        if (c < 32 || c > 126)
        {
            if (c != '\t')
                break;
        }
        out[n++] = (char)c;
    }
    out[n] = 0;
    return n > 0;
}

static uint64_t Uvarint(const uint8_t* p, size_t n, size_t* used, bool* ok)
{
    uint64_t x = 0;
    size_t s = 0;
    for (size_t i = 0; i < n && i < 10; i++)
    {
        uint8_t b = p[i];
        if (b < 0x80)
        {
            x |= (uint64_t)b << s;
            *used = i + 1;
            *ok = true;
            return x;
        }
        x |= (uint64_t)(b & 0x7F) << s;
        s += 7;
    }
    *ok = false;
    *used = 0;
    return 0;
}

static bool FindInSection(const PeFile* pe, const uint8_t* data, size_t n,
    const char* want_name, const uint8_t* needle, size_t needle_n,
    uint32_t* off_out, uint32_t* size_out)
{
    for (int i = 0; i < pe->section_n; i++)
    {
        const PeSection& s = pe->sections[i];
        if (want_name && want_name[0] && _stricmp(s.name, want_name) != 0)
            continue;
        if (!s.rawsize || (uint64_t)s.rawptr + s.rawsize > n)
            continue;
        uint32_t scan = s.rawsize;
        if (scan > 32u * 1024u * 1024u)
            scan = 32u * 1024u * 1024u;
        if (needle_n == 0)
        {
            *off_out = s.rawptr;
            *size_out = s.rawsize;
            return true;
        }
        if (scan < needle_n)
            continue;
        const uint8_t* p = data + s.rawptr;
        for (uint32_t k = 0; k + needle_n <= scan; k++)
        {
            if (memcmp(p + k, needle, needle_n) == 0)
            {
                *off_out = s.rawptr + k;
                *size_out = s.rawsize - k;
                return true;
            }
        }
    }
    return false;
}

static bool FindBuildInfo(const PeFile* pe, const uint8_t* data, size_t n, uint32_t* off, uint32_t* sz)
{
    if (FindInSection(pe, data, n, ".go.buildinfo", (const uint8_t*)kBuildInfoMagic, 14, off, sz))
        return true;
    const char* names[] = { ".rdata", ".data", ".noptrdata", nullptr };
    for (int i = 0; names[i]; i++)
    {
        if (FindInSection(pe, data, n, names[i], (const uint8_t*)kBuildInfoMagic, 14, off, sz))
            return true;
    }
    return false;
}

static bool FindPclntab(const PeFile* pe, const uint8_t* data, size_t n, uint32_t* off, uint32_t* sz, uint32_t* magic)
{
    auto try_sec = [&](const char* name) -> bool
    {
        uint32_t o = 0, s = 0;
        if (!FindInSection(pe, data, n, name, nullptr, 0, &o, &s))
            return false;
        if (s < 16 || (uint64_t)o + 16 > n)
            return false;
        uint32_t m = 0;
        memcpy(&m, data + o, 4);
        if (m == kPcln12 || m == kPcln116 || m == kPcln118 || m == kPcln120)
        {
            *off = o;
            *sz = s;
            *magic = m;
            return true;
        }
        uint32_t scan = s;
        if (scan > 8u * 1024u * 1024u)
            scan = 8u * 1024u * 1024u;
        for (uint32_t k = 0; k + 16 <= scan; k += 4)
        {
            memcpy(&m, data + o + k, 4);
            if (m == kPcln116 || m == kPcln118 || m == kPcln120 || m == kPcln12)
            {
                *off = o + k;
                *sz = s - k;
                *magic = m;
                return true;
            }
        }
        return false;
    };
    if (try_sec(".gopclntab"))
        return true;
    if (try_sec(".rdata"))
        return true;
    if (try_sec(".text"))
        return true;
    if (try_sec(".noptrdata"))
        return true;
    return false;
}

static void TwoTok(const char* line, char* a, int a_cap, char* b, int b_cap)
{
    if (a && a_cap > 0)
        a[0] = 0;
    if (b && b_cap > 0)
        b[0] = 0;
    if (!line)
        return;
    while (*line == ' ' || *line == '\t')
        line++;
    int i = 0;
    while (*line && *line != ' ' && *line != '\t' && *line != '\n' && i < a_cap - 1)
        a[i++] = *line++;
    if (a)
        a[i] = 0;
    while (*line == ' ' || *line == '\t')
        line++;
    i = 0;
    while (*line && *line != ' ' && *line != '\t' && *line != '\n' && i < b_cap - 1)
        b[i++] = *line++;
    if (b)
        b[i] = 0;
}

static void ParseModInfo(const char* mod, AnalysisArtifact* mod_art, AnalysisTable* deps)
{
    if (!mod || !mod[0] || !mod_art)
        return;
    const char* p = mod;
    if (strncmp(p, "path\t", 5) == 0)
    {
        p += 5;
        char path[256];
        int i = 0;
        while (*p && *p != '\n' && i < (int)sizeof(path) - 1)
            path[i++] = *p++;
        path[i] = 0;
        AnalyzeAddProp(mod_art, "path", path);
        if (*p == '\n')
            p++;
    }
    if (strncmp(p, "mod\t", 4) == 0)
    {
        p += 4;
        char line[320];
        int i = 0;
        while (*p && *p != '\n' && i < (int)sizeof(line) - 1)
            line[i++] = *p++;
        line[i] = 0;
        char mpath[160] = {}, ver[64] = {};
        TwoTok(line, mpath, (int)sizeof(mpath), ver, (int)sizeof(ver));
        if (mpath[0])
            AnalyzeAddProp(mod_art, "module", mpath);
        if (ver[0])
            AnalyzeAddProp(mod_art, "version", ver);
        if (*p == '\n')
            p++;
    }
    int nd = 0;
    while (*p && nd < kMaxDeps)
    {
        if (strncmp(p, "end", 3) == 0)
            break;
        if (strncmp(p, "dep\t", 4) != 0)
        {
            while (*p && *p != '\n')
                p++;
            if (*p == '\n')
                p++;
            continue;
        }
        p += 4;
        char line[320];
        int i = 0;
        while (*p && *p != '\n' && i < (int)sizeof(line) - 1)
            line[i++] = *p++;
        line[i] = 0;
        char dpath[160] = {}, dver[64] = {};
        TwoTok(line, dpath, (int)sizeof(dpath), dver, (int)sizeof(dver));
        if (dpath[0] && deps)
            AnalyzeTableAddRow(deps, 0, 0, dpath, dver[0] ? dver : "");
        nd++;
        if (*p == '\n')
            p++;
    }
}

static bool ParseBuildInfo(GoView v, uint32_t off, char* vers, int vers_cap, char* mod, int mod_cap)
{
    vers[0] = 0;
    mod[0] = 0;
    auto log = LogFor(LogBuiltinPeAnalyzer).Module("buildinfo");
    if (!InRange(v, off, 16))
        return false;
    if (memcmp(v.b + off, kBuildInfoMagic, 14) != 0)
        return false;
    uint8_t ptr = v.b[off + 14];
    uint8_t flags = v.b[off + 15];
    if (ptr != 4 && ptr != 8)
    {
        log.Warning("buildinfo pointer size %u is not 4 or 8", ptr);
        return false;
    }
    v.ptr = ptr;
    if (flags & 2)
    {
        size_t used = 0;
        bool ok = false;
        uint64_t ln = Uvarint(v.b + off + 16, (size_t)(v.n - (off + 16)), &used, &ok);
        if (!ok || ln == 0 || ln > 128 || !InRange(v, off + 16 + used, ln))
        {
            log.Warning("buildinfo version string is truncated");
            return false;
        }
        size_t ncopy = (size_t)ln;
        if (ncopy >= (size_t)vers_cap)
            ncopy = (size_t)vers_cap - 1;
        memcpy(vers, v.b + off + 16 + used, ncopy);
        vers[ncopy] = 0;
        size_t rest = off + 16 + used + (size_t)ln;
        ok = false;
        uint64_t mln = Uvarint(v.b + rest, (size_t)(v.n - rest), &used, &ok);
        if (ok && mln && mln < (uint64_t)mod_cap && InRange(v, rest + used, mln))
        {
            memcpy(mod, v.b + rest + used, (size_t)mln);
            mod[mln] = 0;
        }
        return vers[0] != 0;
    }
    bool ok = true;
    uint64_t vaddr = RdPtr(v, off + 16, &ok);
    uint64_t maddr = RdPtr(v, off + 16 + (uint64_t)ptr, &ok);
    if (!ok)
        return false;
    log.Info("buildinfo uses pointer format (pre-1.18)");
    (void)vaddr;
    (void)maddr;
    return false;
}

static void SplitGoSym(const char* full, char* pkg, int pkg_cap, char* name, int name_cap)
{
    pkg[0] = 0;
    name[0] = 0;
    if (!full || !full[0])
        return;
    const char* dot = nullptr;
    for (const char* p = full; *p; p++)
    {
        if (*p == '.' && p > full && p[1] && p[-1] != '.')
            dot = p;
    }
    if (!dot)
    {
        snprintf(name, name_cap, "%s", full);
        return;
    }
    int pn = (int)(dot - full);
    if (pn >= pkg_cap)
        pn = pkg_cap - 1;
    memcpy(pkg, full, (size_t)pn);
    pkg[pn] = 0;
    snprintf(name, name_cap, "%s", dot + 1);
}

static bool ParsePclntab(GoView v, uint32_t off, uint32_t size, uint32_t magic,
    const PeFile* pe, AnalysisArtifact* fn_art, AnalysisArtifact* pkg_art,
    AnalysisArtifact* file_art, char* runtime_note, int note_cap)
{
    auto log = LogFor(LogBuiltinPeAnalyzer).Module("pclntab");
    if (size < 32 || !InRange(v, off, 16))
        return false;
    bool ok = true;
    uint8_t minLC = Rd8(v, off + 6, &ok);
    uint8_t ptr = Rd8(v, off + 7, &ok);
    if (!ok || (ptr != 4 && ptr != 8) || (minLC != 1 && minLC != 2 && minLC != 4))
    {
        log.Warning("pclntab header fields are not plausible (ptr=%u minLC=%u)", ptr, minLC);
        snprintf(runtime_note, note_cap, "pe.analysis_unsupported");
        return false;
    }
    v.ptr = ptr;
    if (magic == kPcln12)
    {
        log.Warning("pclntab 1.2–1.15 layout is not walked; buildinfo may still be present");
        snprintf(runtime_note, note_cap, "pe.analysis_unsupported");
        AnalyzeAddProp(fn_art, "pclntab", "go1.2-1.15");
        return true;
    }
    uint64_t nfunc = RdPtr(v, off + 8, &ok);
    uint64_t nfiles = RdPtr(v, off + 8 + (uint64_t)ptr, &ok);
    if (!ok || nfunc == 0 || nfunc > (uint64_t)kMaxFuncs)
    {
        log.Warning("pclntab nfunc %llu is out of range", (unsigned long long)nfunc);
        snprintf(runtime_note, note_cap, "pe.analysis_partial");
        return false;
    }
    uint64_t cursor = off + 8 + (uint64_t)ptr * 2;
    uint64_t textStart = RdPtr(v, cursor, &ok); cursor += ptr;
    uint64_t funcnameOff = RdPtr(v, cursor, &ok); cursor += ptr;
    uint64_t cuOff = RdPtr(v, cursor, &ok); cursor += ptr;
    uint64_t filetabOff = RdPtr(v, cursor, &ok); cursor += ptr;
    uint64_t pctabOff = RdPtr(v, cursor, &ok); cursor += ptr;
    uint64_t pclnOff = RdPtr(v, cursor, &ok);
    (void)pctabOff;
    (void)cuOff;
    if (!ok)
    {
        snprintf(runtime_note, note_cap, "pe.analysis_partial");
        return false;
    }

    uint32_t text_rva = 0;
    if (textStart >= pe->image_base)
        text_rva = (uint32_t)(textStart - pe->image_base);
    else
        text_rva = (uint32_t)textStart;

    uint64_t nametab = (uint64_t)off + funcnameOff;
    uint64_t functab = (uint64_t)off + pclnOff;
    bool wide_pc = (magic == kPcln116);
    uint32_t ent_sz = wide_pc ? (uint32_t)ptr * 2u : 8u;
    if (nfunc > (uint64_t)kMaxFuncs)
        nfunc = kMaxFuncs;

    AnalysisTable fns{};
    AnalyzeTableInit(&fns, "functions", "pe.analysis_col.functions");
    AnalyzeTableAddCol(&fns, "pe.analysis_col.rva");
    AnalyzeTableAddCol(&fns, "pe.analysis_col.function");
    AnalyzeTableAddCol(&fns, "pe.analysis_col.package");

    AnalysisTable pkgs{};
    AnalyzeTableInit(&pkgs, "packages", "pe.analysis_col.packages");
    AnalyzeTableAddCol(&pkgs, "pe.analysis_col.package");
    AnalyzeTableAddCol(&pkgs, "pe.analysis_col.count");

    std::vector<int> pkg_count;
    std::vector<std::string> pkg_names;
    pkg_names.reserve(256);

    auto pkg_index = [&](const char* pkg) -> int
    {
        for (int i = 0; i < (int)pkg_names.size(); i++)
        {
            if (pkg_names[i] == pkg)
                return i;
        }
        if ((int)pkg_names.size() >= kMaxPkgs)
            return -1;
        pkg_names.push_back(pkg);
        pkg_count.push_back(0);
        return (int)pkg_names.size() - 1;
    };

    int recovered = 0;
    for (uint64_t i = 0; i < nfunc; i++)
    {
        uint64_t eoff = functab + i * ent_sz;
        uint32_t pc_off = 0;
        uint32_t funcoff = 0;
        if (wide_pc)
        {
            uint64_t pc = RdPtr(v, eoff, &ok);
            uint64_t fo = RdPtr(v, eoff + (uint64_t)ptr, &ok);
            if (!ok)
                break;
            pc_off = (uint32_t)pc;
            funcoff = (uint32_t)fo;
        }
        else
        {
            pc_off = Rd32(v, eoff, &ok);
            funcoff = Rd32(v, eoff + 4, &ok);
            if (!ok)
                break;
        }
        uint64_t func_base = (magic == kPcln116) ? (uint64_t)off + funcoff : functab + funcoff;
        if (!InRange(v, func_base + 8, 4))
            continue;
        uint32_t name_off = Rd32(v, func_base + 4, &ok);
        if (!ok)
            continue;
        char full[kMaxName];
        if (!RdZ(v, nametab + name_off, full, (int)sizeof(full), kMaxName - 1))
            continue;
        char pkg[160], fn[160];
        SplitGoSym(full, pkg, (int)sizeof(pkg), fn, (int)sizeof(fn));
        uint32_t rva = text_rva + pc_off;
        uint32_t foff = PeImageRvaToOff(pe, rva);
        char rvas[16];
        snprintf(rvas, sizeof(rvas), "%08X", rva);
        AnalyzeTableAddRow(&fns, rva, foff, rvas, full, pkg[0] ? pkg : "");
        int pi = pkg_index(pkg[0] ? pkg : "(none)");
        if (pi >= 0)
            pkg_count[pi]++;
        recovered++;
    }

    for (int i = 0; i < (int)pkg_names.size(); i++)
    {
        char nbuf[16];
        snprintf(nbuf, sizeof(nbuf), "%d", pkg_count[i]);
        AnalyzeTableAddRow(&pkgs, 0, 0, pkg_names[i].c_str(), nbuf);
    }

    if (nfiles && nfiles <= (uint64_t)kMaxFiles && filetabOff)
    {
        AnalysisTable files{};
        AnalyzeTableInit(&files, "files", "pe.analysis_col.files");
        AnalyzeTableAddCol(&files, "pe.analysis_col.file");
        uint64_t ft = (uint64_t)off + filetabOff;
        int got = 0;
        for (uint64_t i = 0; i < nfiles && got < kMaxFiles; i++)
        {
            uint32_t so = Rd32(v, ft + i * 4, &ok);
            if (!ok)
                break;
            char path[260];
            uint64_t base = (uint64_t)off + cuOff;
            if (!RdZ(v, base + so, path, (int)sizeof(path), 259))
            {
                if (!RdZ(v, (uint64_t)off + so, path, (int)sizeof(path), 259))
                    continue;
            }
            if (!strstr(path, ".go") && !strchr(path, '/') && !strchr(path, '\\'))
                continue;
            AnalyzeTableAddRow(&files, 0, 0, path);
            got++;
        }
        if (got && file_art)
            file_art->tables.push_back(std::move(files));
    }

    char nbuf[16];
    snprintf(nbuf, sizeof(nbuf), "%d", recovered);
    AnalyzeAddProp(fn_art, "functions", nbuf);
    snprintf(nbuf, sizeof(nbuf), "%d", (int)pkg_names.size());
    AnalyzeAddProp(pkg_art, "packages", nbuf);
    if (magic == kPcln120)
        AnalyzeAddProp(fn_art, "pclntab", "go1.20+");
    else if (magic == kPcln118)
        AnalyzeAddProp(fn_art, "pclntab", "go1.18-1.19");
    else
        AnalyzeAddProp(fn_art, "pclntab", "go1.16-1.17");

    fn_art->tables.push_back(std::move(fns));
    pkg_art->tables.push_back(std::move(pkgs));
    log.Info("pclntab magic 0x%08X, %d functions, %d packages", magic, recovered, (int)pkg_names.size());
    return recovered > 0;
}

static bool ExportGo(const PeFile* pe, const uint8_t* data, size_t n,
    const AnalysisArtifact* art, const AnalysisExport* ex, const char* path)
{
    (void)pe;
    (void)data;
    (void)n;
    if (!art || !ex || !path)
        return false;
    if (strcmp(ex->id, "listing") != 0 && strcmp(ex->id, "functions") != 0)
        return false;
    std::string t;
    char line[512];
    snprintf(line, sizeof(line), "Go analysis\n");
    t.append(line);
    for (const AnalysisProp& p : art->props)
    {
        snprintf(line, sizeof(line), "%s=%s\n", p.key, p.value);
        t.append(line);
    }
    t.push_back('\n');
    auto dump_table = [&](const AnalysisTable& tb)
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
    };
    for (const AnalysisTable& tb : art->tables)
        dump_table(tb);
    for (const AnalysisArtifact& ch : art->children)
        for (const AnalysisTable& tb : ch.tables)
            dump_table(tb);

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

static bool AnalyzeGo(PeFile* pe, const uint8_t* data, size_t n)
{
    if (!pe || !data)
        return false;
    auto log = LogFor(LogBuiltinPeAnalyzer).Module("go");
    GoView v{};
    v.b = data;
    v.n = n;
    v.le = true;
    v.ptr = pe->pe32plus ? 8 : 4;

    uint32_t bioff = 0, bisz = 0;
    bool have_bi = FindBuildInfo(pe, data, n, &bioff, &bisz);
    uint32_t pcoff = 0, pcsz = 0, magic = 0;
    bool have_pc = FindPclntab(pe, data, n, &pcoff, &pcsz, &magic);
    if (!have_bi && !have_pc)
    {
        log.Info("No Go buildinfo or pclntab found");
        return false;
    }

    AnalysisArtifact root{};
    snprintf(root.id, sizeof(root.id), "go.runtime");
    root.kind = AnalysisKindRuntime;
    snprintf(root.label, sizeof(root.label), "Go");
    AnalyzeStamp(&root, kAnalyzerId, "Go");
    if (have_pc)
    {
        root.file_off = pcoff;
        root.size = pcsz;
        root.rva = 0;
        for (int i = 0; i < pe->section_n; i++)
        {
            if (_stricmp(pe->sections[i].name, ".gopclntab") == 0)
            {
                root.rva = pe->sections[i].vaddr;
                break;
            }
        }
    }
    else if (have_bi)
    {
        root.file_off = bioff;
        root.size = bisz;
    }

    char vers[96] = {};
    char mod[kMaxMod] = {};
    if (have_bi)
    {
        if (ParseBuildInfo(v, bioff, vers, (int)sizeof(vers), mod, (int)sizeof(mod)))
        {
            AnalyzeAddProp(&root, "go", vers);
            AnalyzeAddRawExport(&root, "buildinfo", "pe.analysis_dump_raw", "go_buildinfo.bin", bioff, bisz < 4096 ? bisz : 4096);
        }
        else
            AnalyzeAddProp(&root, "buildinfo", "present");
    }

    AnalysisArtifact mod_art{};
    snprintf(mod_art.id, sizeof(mod_art.id), "go.module");
    mod_art.kind = AnalysisKindMetadata;
    snprintf(mod_art.label, sizeof(mod_art.label), "Module");
    AnalyzeStamp(&mod_art, kAnalyzerId, "Go");
    AnalysisTable deps{};
    AnalyzeTableInit(&deps, "deps", "pe.analysis_col.deps");
    AnalyzeTableAddCol(&deps, "pe.analysis_col.module");
    AnalyzeTableAddCol(&deps, "pe.analysis_col.version");
    if (mod[0])
        ParseModInfo(mod, &mod_art, &deps);
    if (!deps.rows.empty())
        mod_art.tables.push_back(std::move(deps));

    AnalysisArtifact pkg_art{};
    snprintf(pkg_art.id, sizeof(pkg_art.id), "go.packages");
    pkg_art.kind = AnalysisKindMetadata;
    snprintf(pkg_art.label, sizeof(pkg_art.label), "Packages");
    AnalyzeStamp(&pkg_art, kAnalyzerId, "Go");

    AnalysisArtifact fn_art{};
    snprintf(fn_art.id, sizeof(fn_art.id), "go.functions");
    fn_art.kind = AnalysisKindMetadata;
    snprintf(fn_art.label, sizeof(fn_art.label), "Functions");
    AnalyzeStamp(&fn_art, kAnalyzerId, "Go");

    AnalysisArtifact file_art{};
    snprintf(file_art.id, sizeof(file_art.id), "go.files");
    file_art.kind = AnalysisKindMetadata;
    snprintf(file_art.label, sizeof(file_art.label), "Files");
    AnalyzeStamp(&file_art, kAnalyzerId, "Go");

    char note[48] = {};
    bool walked = false;
    if (have_pc)
    {
        walked = ParsePclntab(v, pcoff, pcsz, magic, pe, &fn_art, &pkg_art, &file_art, note, (int)sizeof(note));
        AnalyzeAddRawExport(&root, "pclntab", "pe.analysis_dump_raw", "gopclntab.bin", pcoff, pcsz > 1u << 20 ? 1u << 20 : pcsz);
    }
    if (note[0])
        snprintf(root.status_i18n, sizeof(root.status_i18n), "%s", note);

    bool stripped = walked && fn_art.tables.empty();
    AnalyzeAddProp(&root, "symbols", stripped ? "stripped/unavailable" : (walked ? "pclntab" : "none"));
    AnalyzeAddProviderExport(&root, "listing", "pe.analysis_dump_listing", "go_listing.txt");

    if (!mod_art.props.empty() || !mod_art.tables.empty())
        root.children.push_back(std::move(mod_art));
    if (!pkg_art.tables.empty())
        root.children.push_back(std::move(pkg_art));
    if (!fn_art.tables.empty())
    {
        AnalyzeAddProviderExport(&fn_art, "functions", "pe.analysis_dump_listing", "go_functions.txt");
        root.children.push_back(std::move(fn_art));
    }
    if (!file_art.tables.empty())
        root.children.push_back(std::move(file_art));

    AnalyzeAddFinding(pe, PeFindingNotice, "Go runtime metadata",
        "Go buildinfo and/or pclntab structures were recovered from the image.");
    pe->analysis.push_back(std::move(root));
    return true;
}

static const AnalyzerProvider kGoProvider = {
    kAnalyzerId,
    "go",
    { true, false, nullptr, "go", ".gopclntab" },
    AnalyzeGo,
    ExportGo
};

static AnalyzerSelfRegister g_go_reg(&kGoProvider);
