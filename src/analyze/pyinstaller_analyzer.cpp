#include "analyze/analyze.h"
#include "analyze/binread.h"
#include "analyze/profile.h"
#include "pe/pe.h"
#include "log/log.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <ctype.h>

// PyInstaller CArchive / PYZ inventory. Empty gates + structural MEI probe.
// DecompSnake sees python.bytecode via owned buffers (host artifact_bytes).

static const char* kAnalyzerId = "com.binarysectorinspector.analyzer.pyinstaller";
static const uint8_t kCookieMagic[8] = { 'M', 'E', 'I', 0x0C, 0x0B, 0x0A, 0x0B, 0x0E };
// struct.calcsize('!8sIIII64s') == 88
static const size_t kCookieLen = 88;
static const int kProbeThreshold = 55;

struct PiCookie
{
    uint32_t pkg_length;
    uint32_t toc_offset;
    uint32_t toc_length;
    uint32_t python_version;
    char     python_libname[65];
    size_t   cookie_off;
    size_t   pkg_start;
    size_t   pkg_end;
};

struct TocEntry
{
    uint32_t entry_length;
    uint32_t offset;
    uint32_t length;
    uint32_t uncompressed_length;
    uint8_t  compression_flag;
    char     typecode;
    char     name[240];
};

static int ProbeScore(const uint8_t* data, size_t n, PiCookie* ck)
{
    if (!data || n < kCookieLen)
        return 0;
    size_t off = BinFind(data, n, 0, kCookieMagic, 8);
    if (off == (size_t)-1)
        return 0;
    // Prefer the last cookie (appended PKG).
    size_t last = off;
    for (;;)
    {
        size_t nxt = BinFind(data, n, last + 1, kCookieMagic, 8);
        if (nxt == (size_t)-1)
            break;
        last = nxt;
    }
    off = last;
    if (off + kCookieLen > n)
        return 0;

    BinReader r = BinReaderMake(data + off, kCookieLen);
    uint8_t mag[8];
    if (!BinBytes(&r, mag, 8))
        return 0;
    PiCookie c{};
    c.cookie_off = off;
    if (!BinBe32(&r, &c.pkg_length) || !BinBe32(&r, &c.toc_offset) ||
        !BinBe32(&r, &c.toc_length) || !BinBe32(&r, &c.python_version))
        return 0;
    char lib[64];
    if (!BinBytes(&r, lib, 64))
        return 0;
    memcpy(c.python_libname, lib, 64);
    c.python_libname[64] = 0;
    for (int i = 0; i < 64; i++)
    {
        if (c.python_libname[i] < 32 || (unsigned char)c.python_libname[i] > 126)
        {
            c.python_libname[i] = 0;
            break;
        }
    }

    size_t cookie_end = off + kCookieLen;
    if (c.pkg_length == 0 || c.pkg_length > cookie_end)
        return 10;
    c.pkg_end = cookie_end;
    c.pkg_start = cookie_end - c.pkg_length;
    if (c.pkg_start >= c.pkg_end || c.pkg_end > n)
        return 10;

    int score = 35;
    if ((uint64_t)c.pkg_start + c.toc_offset + c.toc_length <= c.pkg_end && c.toc_length >= 18)
        score += 20;
    else
    {
        if (ck)
            *ck = c;
        return score;
    }

    // Spot-check first TOC entry.
    BinReader t = BinReaderMake(data + c.pkg_start + c.toc_offset, c.toc_length);
    uint32_t el = 0, eoff = 0, elen = 0, eulen = 0;
    uint8_t flag = 0;
    char tc = 0;
    if (BinBe32(&t, &el) && el >= 18 && el <= c.toc_length &&
        BinBe32(&t, &eoff) && BinBe32(&t, &elen) && BinBe32(&t, &eulen) &&
        BinU8(&t, &flag) && BinBytes(&t, &tc, 1))
    {
        if ((uint64_t)c.pkg_start + eoff + elen <= c.pkg_end)
            score += 15;
    }

    // Supporting strings near cookie / overlay.
    auto has = [&](const char* s) -> bool {
        size_t sn = strlen(s);
        return BinFind(data, n, c.pkg_start > 4096 ? c.pkg_start - 4096 : 0,
            (const uint8_t*)s, sn) != (size_t)-1;
    };
    if (has("_MEIPASS") || has("pyi_rth_") || has("PyInstaller"))
        score += 5;

    if (ck)
        *ck = c;
    if (score > 100)
        score = 100;
    return score;
}

static bool ParseToc(const uint8_t* data, size_t n, const PiCookie& ck, std::vector<TocEntry>* out)
{
    if (!data || !out || ck.toc_length == 0)
        return false;
    if ((uint64_t)ck.pkg_start + ck.toc_offset + ck.toc_length > n)
        return false;
    BinReader r = BinReaderMake(data + ck.pkg_start + ck.toc_offset, ck.toc_length);
    out->clear();
    while (BinLeft(&r) >= 18)
    {
        size_t entry_begin = r.i;
        TocEntry e{};
        if (!BinBe32(&r, &e.entry_length) || e.entry_length < 18 || e.entry_length > BinLeft(&r) + 4)
            break;
        // entry_length includes the 4-byte length field itself.
        size_t body = e.entry_length - 4;
        if (body > BinLeft(&r))
            break;
        if (!BinBe32(&r, &e.offset) || !BinBe32(&r, &e.length) ||
            !BinBe32(&r, &e.uncompressed_length) || !BinU8(&r, &e.compression_flag) ||
            !BinBytes(&r, &e.typecode, 1))
            break;
        size_t name_max = e.entry_length - 18;
        size_t name_have = BinLeft(&r);
        if (name_max > name_have)
            name_max = name_have;
        char namebuf[240];
        size_t take = name_max < sizeof(namebuf) - 1 ? name_max : sizeof(namebuf) - 1;
        if (!BinBytes(&r, namebuf, take))
            break;
        namebuf[take] = 0;
        // Name is null-terminated inside the padded field.
        for (size_t i = 0; i < take; i++)
        {
            if (namebuf[i] == 0)
            {
                namebuf[i] = 0;
                break;
            }
            if ((unsigned char)namebuf[i] < 32)
                namebuf[i] = '_';
        }
        snprintf(e.name, sizeof(e.name), "%s", namebuf);

        // Advance to next entry boundary.
        size_t consumed = r.i - entry_begin;
        if (consumed < e.entry_length)
        {
            if (!BinSkip(&r, e.entry_length - consumed))
                break;
        }
        else if (consumed > e.entry_length)
            break;

        if ((uint64_t)ck.pkg_start + e.offset + e.length > ck.pkg_end)
            continue;
        out->push_back(e);
        if (out->size() >= 10000)
            break;
    }
    return !out->empty();
}

static bool Materialize(const uint8_t* data, size_t n, const PiCookie& ck, const TocEntry& e,
    std::vector<uint8_t>* out)
{
    if (!out)
        return false;
    out->clear();
    const uint8_t* src = nullptr;
    BinReader img = BinReaderMake(data, n);
    if (!BinSlice(&img, ck.pkg_start + e.offset, e.length, &src) || !src)
        return false;
    if (!e.compression_flag)
    {
        if (e.length > 32u * 1024u * 1024u)
            return false;
        out->assign(src, src + e.length);
        return true;
    }
    if (e.uncompressed_length)
        return AnalyzeZlibInflate(src, e.length, e.uncompressed_length, out);
    return AnalyzeZlibInflateAuto(src, e.length, out);
}

// Minimal marshal reader for PYZ TOC: dict[str] -> (typecode_int, pos, length).
struct MarR
{
    const uint8_t* p;
    size_t n;
    size_t i;
    bool fail;
    std::vector<std::string> refs;
};

static bool MarNeed(MarR* r, size_t k)
{
    if (!r || r->fail || r->i + k > r->n)
    {
        if (r)
            r->fail = true;
        return false;
    }
    return true;
}

static uint8_t MarU8(MarR* r)
{
    if (!MarNeed(r, 1))
        return 0;
    return r->p[r->i++];
}

static int32_t MarI32(MarR* r)
{
    if (!MarNeed(r, 4))
        return 0;
    int32_t v = (int32_t)(r->p[r->i] | (r->p[r->i + 1] << 8) | (r->p[r->i + 2] << 16) | (r->p[r->i + 3] << 24));
    r->i += 4;
    return v;
}

static bool MarStr(MarR* r, std::string* out)
{
    if (!out)
        return false;
    out->clear();
    uint8_t t = MarU8(r);
    if (r->fail)
        return false;
    if (t == 'r')
    {
        int32_t idx = MarI32(r);
        if (idx < 0 || (size_t)idx >= r->refs.size())
        {
            r->fail = true;
            return false;
        }
        *out = r->refs[(size_t)idx];
        return true;
    }
    size_t len = 0;
    if (t == 'z' || t == 'Z' || t == 'a' || t == 'A')
    {
        if (!MarNeed(r, 1))
            return false;
        len = r->p[r->i++];
    }
    else if (t == 'u' || t == 's' || t == 't')
    {
        int32_t L = MarI32(r);
        if (L < 0)
        {
            r->fail = true;
            return false;
        }
        len = (size_t)L;
    }
    else
    {
        r->fail = true;
        return false;
    }
    if (!MarNeed(r, len))
        return false;
    out->assign((const char*)r->p + r->i, (const char*)r->p + r->i + len);
    r->i += len;
    if (t == 'Z' || t == 'A' || t == 't')
        r->refs.push_back(*out);
    return true;
}

static bool MarSkip(MarR* r);

static bool MarTuple3Ints(MarR* r, int32_t* a, int32_t* b, int32_t* c)
{
    uint8_t t = MarU8(r);
    if (r->fail)
        return false;
    int n = 0;
    if (t == ')')
    {
        if (!MarNeed(r, 1))
            return false;
        n = r->p[r->i++];
    }
    else if (t == '(')
    {
        n = MarI32(r);
    }
    else
    {
        r->fail = true;
        return false;
    }
    if (n != 3)
    {
        for (int i = 0; i < n && !r->fail; i++)
            MarSkip(r);
        return false;
    }
    auto one = [&](int32_t* o) -> bool {
        uint8_t tt = MarU8(r);
        if (r->fail)
            return false;
        if (tt == 'i')
        {
            *o = MarI32(r);
            return !r->fail;
        }
        if (tt == 'I')
        {
            // long — take low 32
            *o = MarI32(r);
            return !r->fail;
        }
        r->fail = true;
        return false;
    };
    return one(a) && one(b) && one(c);
}

static bool MarSkip(MarR* r)
{
    uint8_t t = MarU8(r);
    if (r->fail)
        return false;
    switch (t)
    {
    case 'N': case 'T': case 'F': case 'S':
        return true;
    case 'i': case 'I': case 'l': case 'f': case 'g':
        return MarNeed(r, 4) && (r->i += 4, true);
    case 'r':
        MarI32(r);
        return !r->fail;
    case 'z': case 'Z': case 'a': case 'A':
    {
        if (!MarNeed(r, 1))
            return false;
        size_t len = r->p[r->i++];
        return MarNeed(r, len) && (r->i += len, true);
    }
    case 'u': case 's': case 't':
    {
        int32_t L = MarI32(r);
        if (L < 0)
            return false;
        return MarNeed(r, (size_t)L) && (r->i += (size_t)L, true);
    }
    case ')':
    {
        if (!MarNeed(r, 1))
            return false;
        int n = r->p[r->i++];
        for (int i = 0; i < n; i++)
            if (!MarSkip(r))
                return false;
        return true;
    }
    case '(':
    {
        int n = MarI32(r);
        for (int i = 0; i < n; i++)
            if (!MarSkip(r))
                return false;
        return true;
    }
    case '{':
        for (;;)
        {
            if (r->i >= r->n)
            {
                r->fail = true;
                return false;
            }
            if (r->p[r->i] == '0')
            {
                r->i++;
                return true;
            }
            if (!MarSkip(r) || !MarSkip(r))
                return false;
        }
    default:
        r->fail = true;
        return false;
    }
}

struct PyzMod
{
    std::string name;
    int32_t ispkg;
    uint32_t pos;
    uint32_t length;
};

static bool ParsePyzToc(const uint8_t* pyz, size_t n, std::vector<PyzMod>* mods, uint32_t* pymagic)
{
    if (!pyz || n < 12 || !mods)
        return false;
    if (memcmp(pyz, "PYZ\0", 4) != 0)
        return false;
    uint32_t magic = (uint32_t)pyz[4] | ((uint32_t)pyz[5] << 8) |
        ((uint32_t)pyz[6] << 16) | ((uint32_t)pyz[7] << 24);
    if (pymagic)
        *pymagic = magic;
    int32_t toc_off = (int32_t)(((uint32_t)pyz[8] << 24) | ((uint32_t)pyz[9] << 16) |
        ((uint32_t)pyz[10] << 8) | (uint32_t)pyz[11]);
    if (toc_off < 12 || (size_t)toc_off >= n)
        return false;
    MarR r{ pyz + (size_t)toc_off, n - (size_t)toc_off, 0, false, {} };
    uint8_t t = MarU8(&r);
    if (t != '{')
        return false;
    mods->clear();
    while (!r.fail && r.i < r.n)
    {
        if (r.p[r.i] == '0')
        {
            r.i++;
            break;
        }
        std::string name;
        if (!MarStr(&r, &name))
            break;
        int32_t ispkg = 0, pos = 0, len = 0;
        if (!MarTuple3Ints(&r, &ispkg, &pos, &len))
            break;
        if (pos >= 0 && len > 0 && (uint64_t)pos + (uint32_t)len <= n)
        {
            PyzMod m;
            m.name = name;
            m.ispkg = ispkg;
            m.pos = (uint32_t)pos;
            m.length = (uint32_t)len;
            mods->push_back(std::move(m));
        }
        if (mods->size() >= 8000)
            break;
    }
    return !mods->empty();
}

static uint32_t PycMagicForVersion(uint32_t pyver)
{
    int maj = 0, min = 0;
    if (pyver >= 100)
    {
        maj = (int)(pyver / 100);
        min = (int)(pyver % 100);
    }
    else
    {
        maj = (int)(pyver / 10);
        min = (int)(pyver % 10);
    }
    // Common CPython .pyc magics (little-endian uint32 as stored on disk).
    struct Row { int maj, min; uint32_t magic; };
    static const Row k[] = {
        { 3, 8, 0x0A0D0D55 },  // 3413
        { 3, 9, 0x0A0D0D61 },  // 3425
        { 3, 10, 0x0A0D0D6F }, // 3439
        { 3, 11, 0x0A0D0DA7 }, // 3495
        { 3, 12, 0x0A0D0DCB }, // 3531
        { 3, 13, 0x0A0D0DF3 }, // 3571
        { 3, 14, 0x0A0D0E2B }, // 3627
        { 0, 0, 0 }
    };
    for (int i = 0; k[i].maj; i++)
    {
        if (k[i].maj == maj && k[i].min == min)
            return k[i].magic;
    }
    return 0;
}

static uint32_t VersionExtra2(uint32_t pyver)
{
    int maj = 0, min = 0;
    if (pyver >= 100)
    {
        maj = (int)(pyver / 100);
        min = (int)(pyver % 100);
    }
    else
    {
        maj = (int)(pyver / 10);
        min = (int)(pyver % 10);
    }
    return ((uint32_t)maj << 8) | (uint32_t)(min & 0xff);
}

static const char* TypeLabel(char tc)
{
    switch (tc)
    {
    case 'z': case 'Z': return "PYZ";
    case 's': return "script";
    case 'm': case 'M': return "module";
    case 'b': return "binary";
    case 'd': return "dependency";
    case 'o': return "option";
    case 'x': return "data";
    case 'p': return "package";
    case 'D': return "pkg-resource";
    default: return "entry";
    }
}

static bool IsCodeType(char tc)
{
    return tc == 's' || tc == 'm' || tc == 'M';
}

static bool AnalyzePyInstaller(PeFile* pe, const uint8_t* data, size_t n)
{
    PiCookie ck{};
    int score = ProbeScore(data, n, &ck);
    if (score < kProbeThreshold)
        return false;
    if (!AnalyzeBudgetCanAdd(pe, 1))
        return false;

    std::vector<TocEntry> toc;
    if (!ParseToc(data, n, ck, &toc))
    {
        AnalyzeAddFinding(pe, PeFindingNotice, "PyInstaller cookie",
            "MEI cookie found but TOC parse failed");
        return false;
    }

    AnalysisArtifact root{};
    snprintf(root.id, sizeof(root.id), "pyinstaller.carchive");
    root.kind = AnalysisKindArchive;
    snprintf(root.label, sizeof(root.label), "PyInstaller CArchive");
    AnalyzeStamp(&root, kAnalyzerId, "PyInstaller");
    AnalyzeSetMedia(&root, "archive.pyinstaller");
    root.file_off = (uint32_t)ck.pkg_start;
    root.size = (uint32_t)(ck.pkg_end - ck.pkg_start);
    root.flag_main = true;

    char buf[96];
    snprintf(buf, sizeof(buf), "%d", score);
    AnalyzeAddProp(&root, "probe_score", buf);
    snprintf(buf, sizeof(buf), "%u", ck.python_version);
    AnalyzeAddProp(&root, "python_version", buf);
    AnalyzeAddProp(&root, "python_lib", ck.python_libname);
    snprintf(buf, sizeof(buf), "%zu", toc.size());
    AnalyzeAddProp(&root, "toc_entries", buf);
    snprintf(buf, sizeof(buf), "0x%X", (unsigned)ck.cookie_off);
    AnalyzeAddProp(&root, "cookie_off", buf);

    AnalysisTable tb{};
    AnalyzeTableInit(&tb, "toc", "pe.analysis_col.blocks");
    AnalyzeTableAddCol(&tb, "pe.analysis_col.name");
    AnalyzeTableAddCol(&tb, "pe.analysis_col.kind");
    AnalyzeTableAddCol(&tb, "pe.analysis_col.size");
    AnalyzeTableAddCol(&tb, "pe.analysis_col.compressed");

    int code_n = 0;
    int pyz_n = 0;
    int pe_n = 0;
    uint32_t art_budget_left = 0;
    {
        const AnalysisProfile* prof = AnalyzeProfileActive();
        uint32_t have = AnalyzeCountArtifacts(pe);
        uint32_t max = prof ? prof->budgets.max_artifacts : 2048;
        art_budget_left = max > have + 1 ? max - have - 1 : 0;
    }

    for (size_t ti = 0; ti < toc.size(); ti++)
    {
        const TocEntry& e = toc[ti];
        char sz[32], csz[32];
        snprintf(sz, sizeof(sz), "%u", e.uncompressed_length ? e.uncompressed_length : e.length);
        snprintf(csz, sizeof(csz), "%u%s", e.length, e.compression_flag ? " z" : "");
        char tcs[8];
        snprintf(tcs, sizeof(tcs), "%c", e.typecode ? e.typecode : '?');
        AnalyzeTableAddRow(&tb, 0, (uint32_t)(ck.pkg_start + e.offset),
            e.name[0] ? e.name : "(unnamed)", tcs, sz, csz);

        if (art_budget_left == 0)
            continue;

        AnalysisArtifact ch{};
        snprintf(ch.id, sizeof(ch.id), "pyi.toc.%u", (unsigned)ti);
        snprintf(ch.label, sizeof(ch.label), "%s", e.name[0] ? e.name : TypeLabel(e.typecode));
        AnalyzeStamp(&ch, kAnalyzerId, "PyInstaller");
        AnalyzeSetLogicalPath(&ch, e.name);
        ch.file_off = (uint32_t)(ck.pkg_start + e.offset);
        ch.size = e.length;
        ch.compressed_size = e.length;
        ch.compression = e.compression_flag ? 1 : 0;
        ch.extra = (uint32_t)(unsigned char)e.typecode;
        AnalyzeAddProp(&ch, "typecode", tcs);
        AnalyzeAddProp(&ch, "role", TypeLabel(e.typecode));

        std::vector<uint8_t> body;
        bool have_body = Materialize(data, n, ck, e, &body);

        if (e.typecode == 'z' || e.typecode == 'Z')
        {
            ch.kind = AnalysisKindArchive;
            AnalyzeSetMedia(&ch, "archive.pyz");
            if (have_body)
            {
                ch.owned = std::move(body);
                ch.size = (uint32_t)ch.owned.size();
                AnalyzeStampSha256(&ch);
                AnalyzeAddOwnedExport(&ch, "pyz", "pe.analysis_dump_raw", "PYZ-00.pyz");

                std::vector<PyzMod> mods;
                uint32_t pymagic = 0;
                if (ParsePyzToc(ch.owned.data(), ch.owned.size(), &mods, &pymagic))
                {
                    snprintf(buf, sizeof(buf), "%zu", mods.size());
                    AnalyzeAddProp(&ch, "pyz_modules", buf);
                    snprintf(buf, sizeof(buf), "%08X", pymagic);
                    AnalyzeAddProp(&ch, "pymagic", buf);
                    const size_t max_mods = 256;
                    for (size_t mi = 0; mi < mods.size() && mi < max_mods && art_budget_left > 0; mi++)
                    {
                        const PyzMod& m = mods[mi];
                        std::vector<uint8_t> mod;
                        if (!AnalyzeZlibInflateAuto(ch.owned.data() + m.pos, m.length, &mod) || mod.empty())
                            continue;
                        AnalysisArtifact mod_art{};
                        snprintf(mod_art.id, sizeof(mod_art.id), "pyi.pyz.%u.%u", (unsigned)ti, (unsigned)mi);
                        snprintf(mod_art.label, sizeof(mod_art.label), "%s", m.name.c_str());
                        AnalyzeStamp(&mod_art, kAnalyzerId, "PyInstaller");
                        AnalyzeSetLogicalPath(&mod_art, m.name.c_str());
                        AnalyzeSetMedia(&mod_art, "python.bytecode");
                        mod_art.kind = AnalysisKindScript;
                        mod_art.owned = std::move(mod);
                        mod_art.size = (uint32_t)mod_art.owned.size();
                        mod_art.extra = pymagic ? pymagic : PycMagicForVersion(ck.python_version);
                        mod_art.extra2 = VersionExtra2(ck.python_version);
                        if (m.ispkg)
                            AnalyzeAddProp(&mod_art, "package", "1");
                        AnalyzeAddOwnedExport(&mod_art, "marshal", "pe.analysis_dump_raw", "module.pyc");
                        AnalyzeStampSha256(&mod_art);
                        ch.children.push_back(std::move(mod_art));
                        art_budget_left--;
                        code_n++;
                    }
                    pyz_n++;
                }
                else
                    AnalyzeAddProp(&ch, "pyz_status", "toc_unsupported_or_encrypted");
            }
        }
        else if (IsCodeType(e.typecode))
        {
            ch.kind = AnalysisKindScript;
            AnalyzeSetMedia(&ch, "python.bytecode");
            if (have_body)
            {
                ch.owned = std::move(body);
                ch.size = (uint32_t)ch.owned.size();
                ch.extra = PycMagicForVersion(ck.python_version);
                ch.extra2 = VersionExtra2(ck.python_version);
                AnalyzeStampSha256(&ch);
                AnalyzeAddOwnedExport(&ch, "marshal", "pe.analysis_dump_raw", "script.pyc");
                if (_stricmp(e.name, "struct") != 0 && strstr(e.name, "pyiboot") == nullptr)
                {
                    // Prefer entry script as main when named like main / __main__
                    if (strstr(e.name, "main") || e.typecode == 's')
                        ch.flag_main = (code_n == 0);
                }
                code_n++;
            }
        }
        else
        {
            ch.kind = AnalysisKindPayload;
            if (have_body)
            {
                ch.owned = std::move(body);
                ch.size = (uint32_t)ch.owned.size();
                AnalyzeStampSha256(&ch);
                char sug[160];
                if (!AnalyzeSanitizeExportName(e.name, sug, (int)sizeof(sug)))
                    snprintf(sug, sizeof(sug), "entry_%u.bin", (unsigned)ti);
                AnalyzeAddOwnedExport(&ch, "raw", "pe.analysis_dump_raw", sug);
                if (ch.owned.size() >= 2 && ch.owned[0] == 'M' && ch.owned[1] == 'Z')
                {
                    AnalyzeSetMedia(&ch, "pe.image");
                    AnalyzeAddProp(&ch, "pe_candidate", "1");
                    pe_n++;
                }
            }
            else if (!e.compression_flag)
            {
                AnalyzeAddRawExport(&ch, "raw", "pe.analysis_dump_raw",
                    e.name[0] ? e.name : "entry.bin", ch.file_off, ch.size);
            }
        }

        root.children.push_back(std::move(ch));
        art_budget_left--;
    }

    root.tables.push_back(std::move(tb));
    AnalyzeAddRawExport(&root, "pkg", "pe.analysis_dump_raw", "pyinstaller.pkg",
        root.file_off, root.size);
    AnalyzeAddProviderExport(&root, "listing", "pe.analysis_dump_listing", "pyinstaller_toc.txt");

    snprintf(buf, sizeof(buf), "%d", code_n);
    AnalyzeAddProp(&root, "bytecode_artifacts", buf);
    snprintf(buf, sizeof(buf), "%d", pyz_n);
    AnalyzeAddProp(&root, "pyz_archives", buf);
    snprintf(buf, sizeof(buf), "%d", pe_n);
    AnalyzeAddProp(&root, "pe_candidates", buf);

    pe->analysis.push_back(std::move(root));

    char why[192];
    snprintf(why, sizeof(why), "CArchive TOC %zu entries; python %u; probe %d",
        toc.size(), ck.python_version, score);
    AnalyzeAddFinding(pe, PeFindingNotice, "PyInstaller CArchive", why);
    return true;
}

static bool ExportPyInstaller(const PeFile* pe, const uint8_t* data, size_t n,
    const AnalysisArtifact* art, const AnalysisExport* ex, const char* path)
{
    (void)pe;
    (void)data;
    (void)n;
    if (!art || !ex || !path)
        return false;
    // Text listing from tables/props via AnalyzeExport Text path — provider only for custom.
    if (_stricmp(ex->id, "listing") == 0)
    {
        // Fall through handled by AnalyzeExportText when kind is Text; provider export uses this.
        std::string t;
        char line[512];
        for (const AnalysisProp& p : art->props)
        {
            snprintf(line, sizeof(line), "%s=%s\n", p.key, p.value);
            t.append(line);
        }
        for (const AnalysisTable& tb : art->tables)
        {
            snprintf(line, sizeof(line), "\n# %s\n", tb.id);
            t.append(line);
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
        }
        HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE)
        {
            // UTF-8 path
            wchar_t wpath[MAX_PATH];
            if (!MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, MAX_PATH))
                return false;
            h = CreateFileW(wpath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (h == INVALID_HANDLE_VALUE)
                return false;
        }
        DWORD wr = 0;
        BOOL ok = WriteFile(h, t.data(), (DWORD)t.size(), &wr, nullptr);
        CloseHandle(h);
        return ok && wr == (DWORD)t.size();
    }
    return false;
}

static const AnalyzerProvider kProvider = {
    kAnalyzerId,
    "pyinstaller",
    { true, false, nullptr, nullptr, nullptr },
    AnalyzePyInstaller,
    ExportPyInstaller
};

static AnalyzerSelfRegister g_reg(&kProvider);
