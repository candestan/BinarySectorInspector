#include "pe/pe.h"
#include "log/log.h"
#include "analyze/analyze.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <string>
#include <vector>

// Specialized PYTHONSCRIPT marshal walk. Identity is the JSON signature;
// this file only reconstructs code objects. Host sees AnalysisArtifact.
// credit: py2exe start.c / runtime.py (MIT) — magic 0x78563412, then zippath, then marshal.

static const char* kAnalyzerId = "com.binarysectorinspector.analyzer.py2exe";

struct PyCode
{
    char     filename[260];
    char     name[128];
    int      firstlineno;
    uint32_t marshal_off;
    uint32_t marshal_size;
    bool     is_module;
    bool     is_main;
    std::vector<std::string> names;
    std::vector<std::string> strings;
};

struct PyBundle
{
    bool     present;
    bool     header_ok;
    bool     marshal_ok;
    uint32_t rsrc_off;
    uint32_t rsrc_size;
    uint32_t magic;
    int      optimize;
    int      unbuffered;
    uint32_t data_bytes;
    char     archive[260];
    uint32_t marshal_off;
    uint32_t marshal_size;
    int      py_major;
    int      py_minor;
    uint32_t pyc_magic;
    int      main_index;
    std::vector<PyCode> codes;
};

static const uint32_t kPy2ExeMagic = 0x78563412u;
static const uint32_t kPy2ExeMagicSwap = 0x12345678u;
static const int kMaxMarshalDepth = 48;
static const int kMaxMarshalOps = 250000;
static const int kMaxCodes = 256;
static const int kMaxStrPerCode = 256;
static const int kMaxNamesPerCode = 256;
static const int kMaxStrChars = 4096;
static const int kMaxSeq = 100000;

enum
{
    LayoutPy20 = 0,
    LayoutPy21,
    LayoutPy27,
    LayoutPy3,
    LayoutPy38,
    LayoutPy311
};

enum
{
    TypeNull = '0',
    TypeNone = 'N',
    TypeFalse = 'F',
    TypeTrue = 'T',
    TypeStopIter = 'S',
    TypeEllipsis = '.',
    TypeInt = 'i',
    TypeInt64 = 'I',
    TypeFloat = 'f',
    TypeBinFloat = 'g',
    TypeComplex = 'x',
    TypeBinComplex = 'y',
    TypeLong = 'l',
    TypeString = 's',
    TypeInterned = 't',
    TypeRef = 'r',
    TypeTuple = '(',
    TypeList = '[',
    TypeDict = '{',
    TypeCode = 'c',
    TypeUnicode = 'u',
    TypeUnknown = '?',
    TypeSet = '<',
    TypeFrozenSet = '>',
    TypeAscii = 'a',
    TypeAsciiInterned = 'A',
    TypeSmallTuple = ')',
    TypeShortAscii = 'z',
    TypeShortAsciiInterned = 'Z',
    TypeStringRef = 'R',
    FlagRef = 0x80
};

struct Mar
{
    const uint8_t* b;
    size_t         n;
    size_t         i;
    uint32_t       file_base;
    int            depth;
    int            ops;
    int            layout;
    bool           py3;
    int            inside_code;
    std::vector<std::string> intern;
    std::vector<std::string> refs;
    PyBundle*      out;
};

static void CopyZ(char* dst, int cap, const std::string& s)
{
    if (!dst || cap <= 0)
        return;
    size_t n = s.size();
    if (n >= (size_t)cap)
        n = (size_t)cap - 1;
    memcpy(dst, s.data(), n);
    dst[n] = 0;
}

static bool PrintableRatio(const uint8_t* p, int n, float* ratio)
{
    if (n <= 0)
        return false;
    int ok = 0;
    int letters = 0;
    for (int i = 0; i < n; i++)
    {
        unsigned char c = p[i];
        if (c == '\t' || c == '\n' || c == '\r' || (c >= 32 && c < 127))
            ok++;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
            letters++;
    }
    *ratio = (float)ok / (float)n;
    return letters > 0;
}

static std::string BytesAsText(const uint8_t* p, int n)
{
    std::string s;
    s.reserve((size_t)n);
    bool utf8 = true;
    int expect = 0;
    for (int i = 0; i < n; i++)
    {
        unsigned char c = p[i];
        if (expect)
        {
            if ((c & 0xC0) != 0x80)
            {
                utf8 = false;
                break;
            }
            expect--;
            continue;
        }
        if (c < 0x80)
            continue;
        if ((c & 0xE0) == 0xC0)
            expect = 1;
        else if ((c & 0xF0) == 0xE0)
            expect = 2;
        else if ((c & 0xF8) == 0xF0)
            expect = 3;
        else
        {
            utf8 = false;
            break;
        }
    }
    if (expect)
        utf8 = false;
    if (utf8)
    {
        s.assign((const char*)p, (size_t)n);
        return s;
    }
    for (int i = 0; i < n; i++)
    {
        unsigned char c = p[i];
        if (c < 0x80)
            s.push_back((char)c);
        else
        {
            s.push_back((char)(0xC0 | (c >> 6)));
            s.push_back((char)(0x80 | (c & 0x3F)));
        }
    }
    return s;
}

static bool MarNeed(Mar& m, size_t k)
{
    return m.i + k <= m.n;
}

static bool MarByte(Mar& m, uint8_t* v)
{
    if (!MarNeed(m, 1))
        return false;
    *v = m.b[m.i++];
    return true;
}

static bool MarI32(Mar& m, int32_t* v)
{
    if (!MarNeed(m, 4))
        return false;
    memcpy(v, m.b + m.i, 4);
    m.i += 4;
    return true;
}

static bool MarI16(Mar& m, int32_t* v)
{
    if (!MarNeed(m, 2))
        return false;
    int16_t s = 0;
    memcpy(&s, m.b + m.i, 2);
    m.i += 2;
    *v = s;
    return true;
}

static bool MarU32(Mar& m, uint32_t* v)
{
    int32_t s = 0;
    if (!MarI32(m, &s))
        return false;
    *v = (uint32_t)s;
    return true;
}

static bool MarSkip(Mar& m, size_t k)
{
    if (!MarNeed(m, k))
        return false;
    m.i += k;
    return true;
}

static bool MarBytes(Mar& m, int n, std::string* out)
{
    if (n < 0 || n > kMaxStrChars * 4)
        return false;
    if (!MarNeed(m, (size_t)n))
        return false;
    if (out)
    {
        int keep = n;
        if (keep > kMaxStrChars)
            keep = kMaxStrChars;
        *out = BytesAsText(m.b + m.i, keep);
    }
    m.i += (size_t)n;
    return true;
}

static void PushStr(PyCode* code, int kind, const std::string& s)
{
    if (!code || s.empty())
        return;
    if (kind == 1)
    {
        if ((int)code->strings.size() >= kMaxStrPerCode)
            return;
        code->strings.push_back(s);
    }
    else if (kind == 2)
    {
        if ((int)code->names.size() >= kMaxNamesPerCode)
            return;
        code->names.push_back(s);
    }
}

static bool WalkObj(Mar& m, std::string* got, PyCode* harvest, int harvest_kind);
static bool ParsePyDllName(const char* s, int* maj, int* min);

static uint32_t PycMagicFor(int maj, int min)
{
    if (maj == 2)
    {
        switch (min)
        {
        case 0:  return 0x0A0DC687u;
        case 1:  return 0x0A0DEB2Au;
        case 2:  return 0x0A0DED2Du;
        case 3:  return 0x0A0DF23Bu;
        case 4:  return 0x0A0DF26Du;
        case 5:  return 0x0A0DF2B3u;
        case 6:  return 0x0A0DF2D1u;
        default: return 0x0A0DF303u;
        }
    }
    if (maj == 3)
    {
        switch (min)
        {
        case 4:  return 0x0A0D0CEEu;
        case 5:  return 0x0A0D0D16u;
        case 6:  return 0x0A0D0D33u;
        case 7:  return 0x0A0D0D42u;
        case 8:  return 0x0A0D0D55u;
        case 9:  return 0x0A0D0D61u;
        case 10: return 0x0A0D0D6Fu;
        case 11: return 0x0A0D0DA7u;
        case 12: return 0x0A0D0DCBu;
        case 13: return 0x0A0D0DF3u;
        default: break;
        }
    }
    return 0;
}

static int ProbeCodeHeaderWidth(const uint8_t* p, uint32_t n)
{
    size_t i = 0;
    if (!p || n < 10)
        return 32;
    if (p[0] == TypeList || p[0] == TypeTuple)
    {
        if (n < 6)
            return 32;
        i = 5;
    }
    else if (p[0] == TypeSmallTuple)
        i = 2;
    if (i >= n || (p[i] & 0x7F) != TypeCode)
        return 32;
    if (i + 17 < n)
    {
        uint8_t t = p[i + 17] & 0x7F;
        if (t == TypeString || t == TypeInterned)
            return 32;
    }
    if (i + 9 < n)
    {
        uint8_t t = p[i + 9] & 0x7F;
        if (t == TypeString || t == TypeInterned)
            return 16;
    }
    return 32;
}

static void InferVerFromCodes(PyBundle* py)
{
    if (!py)
        return;
    for (const PyCode& c : py->codes)
    {
        int maj = 0, min = 0;
        if (ParsePyDllName(c.filename, &maj, &min))
        {
            py->py_major = maj;
            py->py_minor = min;
            return;
        }
    }
}

static bool ReadCode(Mar& m)
{
    PyCode code{};
    size_t start = m.i ? m.i - 1 : 0;
    code.marshal_off = m.file_base + (uint32_t)start;

    int nlong = 4;
    int skip_after_names = 3;
    bool py311 = false;
    bool use_short = false;
    if (m.layout == LayoutPy20)
    {
        skip_after_names = 1;
        use_short = true;
    }
    else if (m.layout == LayoutPy21)
        use_short = true;
    else if (m.layout == LayoutPy3)
        nlong = 5;
    else if (m.layout == LayoutPy38)
        nlong = 6;
    else if (m.layout == LayoutPy311)
    {
        nlong = 5;
        skip_after_names = 0;
        py311 = true;
    }

    for (int i = 0; i < nlong; i++)
    {
        int32_t dummy = 0;
        if (use_short)
        {
            if (!MarI16(m, &dummy))
                return false;
        }
        else if (!MarI32(m, &dummy))
            return false;
    }

    if (!WalkObj(m, nullptr, nullptr, 0))
        return false;

    if (!WalkObj(m, nullptr, &code, 1))
        return false;
    if (!WalkObj(m, nullptr, &code, 2))
        return false;

    for (int i = 0; i < skip_after_names; i++)
    {
        if (!WalkObj(m, nullptr, nullptr, 0))
            return false;
    }

    if (py311)
    {
        if (!WalkObj(m, nullptr, nullptr, 0))
            return false;
        if (!WalkObj(m, nullptr, nullptr, 0))
            return false;
    }

    std::string filename;
    std::string name;
    if (!WalkObj(m, &filename, nullptr, 0))
        return false;
    if (!WalkObj(m, &name, nullptr, 0))
        return false;
    CopyZ(code.filename, (int)sizeof(code.filename), filename);
    CopyZ(code.name, (int)sizeof(code.name), name);

    if (py311)
    {
        if (!WalkObj(m, nullptr, nullptr, 0))
            return false;
    }

    int32_t lineno = 0;
    if (use_short)
    {
        if (!MarI16(m, &lineno))
            return false;
    }
    else if (!MarI32(m, &lineno))
        return false;
    code.firstlineno = lineno;

    if (!WalkObj(m, nullptr, nullptr, 0))
        return false;
    if (py311)
    {
        if (!WalkObj(m, nullptr, nullptr, 0))
            return false;
    }

    code.marshal_size = (uint32_t)(m.i - start);
    code.is_module = (m.inside_code == 1);
    if (m.out && (int)m.out->codes.size() < kMaxCodes)
        m.out->codes.push_back(std::move(code));
    return true;
}

static bool WalkObj(Mar& m, std::string* got, PyCode* harvest, int harvest_kind)
{
    if (++m.ops > kMaxMarshalOps)
        return false;
    if (m.depth >= kMaxMarshalDepth)
        return false;
    m.depth++;

    uint8_t raw = 0;
    if (!MarByte(m, &raw))
    {
        m.depth--;
        return false;
    }
    bool flag_ref = m.py3 && (raw & FlagRef) != 0;
    int type = raw & 0x7F;
    int ref_i = -1;
    if (flag_ref)
    {
        ref_i = (int)m.refs.size();
        m.refs.push_back(std::string());
    }

    bool ok = true;
    std::string str;
    bool has_str = false;

    switch (type)
    {
    case TypeNull:
    case TypeNone:
    case TypeFalse:
    case TypeTrue:
    case TypeStopIter:
    case TypeEllipsis:
        break;
    case TypeInt:
    {
        int32_t v = 0;
        ok = MarI32(m, &v);
        break;
    }
    case TypeInt64:
        ok = MarSkip(m, 8);
        break;
    case TypeBinFloat:
        ok = MarSkip(m, 8);
        break;
    case TypeBinComplex:
        ok = MarSkip(m, 16);
        break;
    case TypeFloat:
    case TypeComplex:
    {
        uint8_t ln = 0;
        ok = MarByte(m, &ln) && MarSkip(m, ln);
        if (ok && type == TypeComplex)
        {
            uint8_t ln2 = 0;
            ok = MarByte(m, &ln2) && MarSkip(m, ln2);
        }
        break;
    }
    case TypeLong:
    {
        int32_t nd = 0;
        ok = MarI32(m, &nd);
        if (ok)
        {
            if (nd < 0)
                nd = -nd;
            if (nd > kMaxSeq)
                ok = false;
            else
                ok = MarSkip(m, (size_t)nd * 2);
        }
        break;
    }
    case TypeString:
    case TypeInterned:
    case TypeUnicode:
    case TypeAscii:
    case TypeAsciiInterned:
    {
        int32_t ln = 0;
        ok = MarI32(m, &ln) && ln >= 0 && MarBytes(m, ln, &str);
        if (ok)
        {
            has_str = true;
            if (type == TypeInterned)
                m.intern.push_back(str);
        }
        break;
    }
    case TypeShortAscii:
    case TypeShortAsciiInterned:
    {
        uint8_t ln = 0;
        ok = MarByte(m, &ln) && MarBytes(m, ln, &str);
        if (ok)
            has_str = true;
        break;
    }
    case TypeStringRef:
    {
        int32_t idx = 0;
        ok = MarI32(m, &idx);
        if (ok && idx >= 0 && idx < (int)m.intern.size())
        {
            str = m.intern[(size_t)idx];
            has_str = true;
        }
        break;
    }
    case TypeRef:
    {
        int32_t idx = 0;
        ok = MarI32(m, &idx);
        if (ok && idx >= 0 && idx < (int)m.refs.size())
        {
            str = m.refs[(size_t)idx];
            has_str = !str.empty();
        }
        break;
    }
    case TypeTuple:
    case TypeList:
    case TypeSet:
    case TypeFrozenSet:
    {
        int32_t cnt = 0;
        ok = MarI32(m, &cnt);
        if (!ok || cnt < 0 || cnt > kMaxSeq)
            ok = false;
        else
        {
            for (int32_t i = 0; i < cnt && ok; i++)
                ok = WalkObj(m, nullptr, harvest, harvest_kind);
        }
        break;
    }
    case TypeSmallTuple:
    {
        uint8_t cnt = 0;
        ok = MarByte(m, &cnt);
        for (uint8_t i = 0; i < cnt && ok; i++)
            ok = WalkObj(m, nullptr, harvest, harvest_kind);
        break;
    }
    case TypeDict:
        while (ok)
        {
            if (!MarNeed(m, 1))
            {
                ok = false;
                break;
            }
            if ((m.b[m.i] & 0x7F) == TypeNull)
            {
                m.i++;
                break;
            }
            ok = WalkObj(m, nullptr, harvest, harvest_kind) &&
                 WalkObj(m, nullptr, harvest, harvest_kind);
        }
        break;
    case TypeCode:
    {
        m.inside_code++;
        ok = ReadCode(m);
        m.inside_code--;
        break;
    }
    default:
        ok = false;
        break;
    }

    if (ok && has_str)
    {
        if (got)
            *got = str;
        PushStr(harvest, harvest_kind, str);
        if (ref_i >= 0)
            m.refs[(size_t)ref_i] = str;
    }

    m.depth--;
    return ok;
}

static bool IsPy2ExeMagic(uint32_t t)
{
    return t == kPy2ExeMagic || t == kPy2ExeMagicSwap;
}

static bool ParsePyDllName(const char* s, int* maj, int* min)
{
    if (!s || !s[0])
        return false;
    char buf[64];
    snprintf(buf, sizeof(buf), "%s", s);
    for (char* p = buf; *p; p++)
        *p = (char)tolower((unsigned char)*p);
    const char* p = strstr(buf, "python");
    if (!p)
        return false;
    p += 6;
    if (!isdigit((unsigned char)*p))
        return false;
    if (p[0] == '2' && p[1] && isdigit((unsigned char)p[1]) && !isdigit((unsigned char)p[2]))
    {
        *maj = 2;
        *min = p[1] - '0';
        return true;
    }
    if (p[0] == '3')
    {
        *maj = 3;
        if (!isdigit((unsigned char)p[1]))
        {
            *min = 0;
            return true;
        }
        *min = atoi(p + 1);
        return true;
    }
    return false;
}

static void GuessPythonVer(const PeFile* pe, int* maj, int* min)
{
    *maj = 0;
    *min = 0;
    for (const PeImportDll& d : pe->imports)
    {
        if (ParsePyDllName(d.name.c_str(), maj, min))
            return;
    }
    for (const PeRsrcLeaf& L : pe->rsrc)
    {
        if (ParsePyDllName(L.type_name, maj, min))
            return;
        if (ParsePyDllName(L.name, maj, min))
            return;
    }
}

static bool IsPythonScriptLeaf(const PeRsrcLeaf& L)
{
    return _stricmp(L.type_name, "PYTHONSCRIPT") == 0 ||
           _stricmp(L.name, "PYTHONSCRIPT") == 0;
}

static const PeRsrcLeaf* FindPythonScript(const PeFile* pe)
{
    const PeRsrcLeaf* best = nullptr;
    for (const PeRsrcLeaf& L : pe->rsrc)
    {
        if (!IsPythonScriptLeaf(L))
            continue;
        if (!best || L.size > best->size)
            best = &L;
    }
    return best;
}

static void LooseHarvest(const uint8_t* p, uint32_t n, uint32_t file_off, PyBundle* out)
{
    PyCode blob{};
    snprintf(blob.name, sizeof(blob.name), "<marshal>");
    blob.marshal_off = file_off;
    blob.marshal_size = n;
    blob.is_module = true;
    for (uint32_t i = 0; i + 5 < n && (int)blob.strings.size() < kMaxStrPerCode;)
    {
        uint8_t t = p[i] & 0x7F;
        if (t == TypeString || t == TypeInterned || t == TypeUnicode || t == TypeAscii || t == TypeAsciiInterned)
        {
            int32_t len = 0;
            memcpy(&len, p + i + 1, 4);
            if (len >= 4 && len <= kMaxStrChars && i + 5 + (uint32_t)len <= n)
            {
                float ratio = 0.f;
                if (PrintableRatio(p + i + 5, len, &ratio) && ratio >= 0.85f)
                {
                    blob.strings.push_back(BytesAsText(p + i + 5, len));
                    i += 5 + (uint32_t)len;
                    continue;
                }
            }
        }
        if (t == TypeShortAscii || t == TypeShortAsciiInterned)
        {
            int len = p[i + 1];
            if (len >= 4 && i + 2 + (uint32_t)len <= n)
            {
                float ratio = 0.f;
                if (PrintableRatio(p + i + 2, len, &ratio) && ratio >= 0.85f)
                {
                    blob.strings.push_back(BytesAsText(p + i + 2, len));
                    i += 2 + (uint32_t)len;
                    continue;
                }
            }
        }
        i++;
    }
    if (!blob.strings.empty() && out->codes.empty())
        out->codes.push_back(std::move(blob));
}

static int NamedCodeCount(const PyBundle& py)
{
    int n = 0;
    for (const PyCode& c : py.codes)
    {
        if (c.filename[0] || c.name[0])
            n++;
    }
    return n;
}

static bool WalkMarshal(const uint8_t* p, uint32_t n, uint32_t file_off, int layout, bool py3, PyBundle* out)
{
    out->codes.clear();
    Mar m{};
    m.b = p;
    m.n = n;
    m.i = 0;
    m.file_base = file_off;
    m.layout = layout;
    m.py3 = py3;
    m.out = out;
    if (!WalkObj(m, nullptr, nullptr, 0))
        return false;
    if (out->codes.empty())
        return false;
    return NamedCodeCount(*out) > 0 || m.i + 8 >= n;
}

static void MarkMain(PyBundle* out)
{
    out->main_index = -1;
    int last_mod = -1;
    for (int i = 0; i < (int)out->codes.size(); i++)
    {
        out->codes[i].is_main = false;
        if (out->codes[i].is_module)
            last_mod = i;
    }
    if (last_mod >= 0)
    {
        out->codes[last_mod].is_main = true;
        out->main_index = last_mod;
    }
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

static void Push32(std::vector<uint8_t>* o, uint32_t v)
{
    o->push_back((uint8_t)v);
    o->push_back((uint8_t)(v >> 8));
    o->push_back((uint8_t)(v >> 16));
    o->push_back((uint8_t)(v >> 24));
}

static void AppendEscaped(std::string* o, const std::string& s)
{
    for (unsigned char c : s)
    {
        if (c == '\n')
            o->append("\\n");
        else if (c == '\r')
            o->append("\\r");
        else if (c == '\t')
            o->append("\\t");
        else if (c < 32)
        {
            char b[8];
            snprintf(b, sizeof(b), "\\x%02X", c);
            o->append(b);
        }
        else
            o->push_back((char)c);
    }
}

static void ArtLabelFromCode(const PyCode& c, char* lab, int cap)
{
    const char* fn = c.filename[0] ? c.filename : c.name;
    const char* base = fn;
    if (fn && fn[0])
    {
        const char* sl = strrchr(fn, '\\');
        if (sl && sl[1])
            base = sl + 1;
        sl = strrchr(base, '/');
        if (sl && sl[1])
            base = sl + 1;
    }
    const char* nm = c.name[0] ? c.name : "";
    if (base && base[0] && nm[0] && strcmp(base, nm) != 0)
        snprintf(lab, cap, "%s  %s", base, nm);
    else if (base && base[0])
        snprintf(lab, cap, "%s", base);
    else if (nm[0])
        snprintf(lab, cap, "%s", nm);
    else
        snprintf(lab, cap, "code");
}

static void PublishBundle(PeFile* pe, const PyBundle& py)
{
    AnalysisArtifact root{};
    snprintf(root.id, sizeof(root.id), "payload.pythonscript");
    root.kind = AnalysisKindPayload;
    snprintf(root.label, sizeof(root.label), "PYTHONSCRIPT");
    AnalyzeStamp(&root, kAnalyzerId, "py2exe");
    root.file_off = py.rsrc_off;
    root.size = py.rsrc_size;

    char ver[24];
    if (py.py_major == 3 && py.py_minor == 0)
        snprintf(ver, sizeof(ver), "3");
    else if (py.py_major)
        snprintf(ver, sizeof(ver), "%d.%d", py.py_major, py.py_minor);
    else
        snprintf(ver, sizeof(ver), "?");
    AnalyzeAddProp(&root, "python", ver);
    char mag[16];
    snprintf(mag, sizeof(mag), "0x%08X", py.magic);
    AnalyzeAddProp(&root, "magic", mag);
    char opt[12];
    snprintf(opt, sizeof(opt), "%d", py.optimize);
    AnalyzeAddProp(&root, "optimize", opt);
    AnalyzeAddProp(&root, "archive", py.archive[0] ? py.archive : "(self)");
    AnalyzeAddProp(&root, "header", py.header_ok ? "ok" : "mismatch");
    char ncodes[12];
    snprintf(ncodes, sizeof(ncodes), "%zu", py.codes.size());
    AnalyzeAddProp(&root, "code_objects", ncodes);

    AnalysisExport raw{};
    snprintf(raw.id, sizeof(raw.id), "resource");
    snprintf(raw.i18n_key, sizeof(raw.i18n_key), "pe.analysis_dump_raw");
    snprintf(raw.suggest, sizeof(raw.suggest), "pythonscript.bin");
    raw.kind = AnalysisExportRaw;
    raw.file_off = py.rsrc_off;
    raw.size = py.rsrc_size;
    root.exports.push_back(raw);

    AnalysisExport listing{};
    snprintf(listing.id, sizeof(listing.id), "listing");
    snprintf(listing.i18n_key, sizeof(listing.i18n_key), "pe.analysis_dump_listing");
    snprintf(listing.suggest, sizeof(listing.suggest), "listing.txt");
    listing.kind = AnalysisExportProvider;
    root.exports.push_back(listing);

    if (py.marshal_size)
    {
        AnalysisArtifact dump{};
        snprintf(dump.id, sizeof(dump.id), "marshal");
        dump.kind = AnalysisKindPayload;
        snprintf(dump.label, sizeof(dump.label), "<marshal>");
        AnalyzeStamp(&dump, kAnalyzerId, "py2exe");
        dump.file_off = py.marshal_off;
        dump.size = py.marshal_size;
        dump.extra = py.pyc_magic;
        dump.extra2 = ((uint32_t)py.py_major << 8) | (uint32_t)(py.py_minor & 0xff);
        AnalyzeSetMedia(&dump, "python.bytecode");
        root.children.push_back(std::move(dump));
    }

    for (int i = 0; i < (int)py.codes.size(); i++)
    {
        const PyCode& c = py.codes[i];
        AnalysisArtifact ch{};
        snprintf(ch.id, sizeof(ch.id), "script.%d", i);
        ch.kind = AnalysisKindScript;
        ArtLabelFromCode(c, ch.label, (int)sizeof(ch.label));
        AnalyzeStamp(&ch, kAnalyzerId, "py2exe");
        ch.file_off = c.marshal_off;
        ch.size = c.marshal_size;
        ch.flag_main = c.is_main;
        ch.extra = py.pyc_magic;
        ch.extra2 = ((uint32_t)py.py_major << 8) | (uint32_t)(py.py_minor & 0xff);
        AnalyzeSetMedia(&ch, "python.bytecode");
        if (c.filename[0])
            AnalyzeAddProp(&ch, "filename", c.filename);
        if (c.name[0])
            AnalyzeAddProp(&ch, "name", c.name);
        if (c.firstlineno)
        {
            char ln[16];
            snprintf(ln, sizeof(ln), "%d", c.firstlineno);
            AnalyzeAddProp(&ch, "firstlineno", ln);
        }
        ch.names = c.names;
        ch.strings = c.strings;

        AnalysisExport pyc{};
        snprintf(pyc.id, sizeof(pyc.id), "bytecode");
        snprintf(pyc.i18n_key, sizeof(pyc.i18n_key), "pe.analysis_dump_bytecode");
        const char* fn = c.filename[0] ? c.filename : (c.name[0] ? c.name : "script");
        const char* base = fn;
        const char* sl = strrchr(fn, '\\');
        if (sl && sl[1])
            base = sl + 1;
        sl = strrchr(base, '/');
        if (sl && sl[1])
            base = sl + 1;
        char sug[160];
        snprintf(sug, sizeof(sug), "%s", base);
        for (char* p = sug; *p; p++)
        {
            if ((unsigned char)*p < 32 || strchr("<>:\"|?*", *p))
                *p = '_';
        }
        size_t slen = strlen(sug);
        if (slen > 3 && _stricmp(sug + slen - 3, ".py") == 0)
            snprintf(pyc.suggest, sizeof(pyc.suggest), "%.*s.pyc", (int)(slen - 3), sug);
        else if (sug[0])
            snprintf(pyc.suggest, sizeof(pyc.suggest), "%s.pyc", sug);
        else
            snprintf(pyc.suggest, sizeof(pyc.suggest), "code_%d.pyc", i);
        pyc.kind = AnalysisExportProvider;
        pyc.file_off = c.marshal_off;
        pyc.size = c.marshal_size;
        pyc.extra = py.pyc_magic;
        pyc.extra2 = ((uint32_t)py.py_major << 8) | (uint32_t)(py.py_minor & 0xff);
        ch.exports.push_back(pyc);
        root.children.push_back(std::move(ch));
    }

    pe->analysis.push_back(std::move(root));
    AnalyzeAddFinding(pe, PeFindingNotice, "PYTHONSCRIPT resource",
        "Marshalled Python code objects are stored in a named resource.");
    if (!py.header_ok)
        AnalyzeAddFinding(pe, PeFindingNotice, "PYTHONSCRIPT header",
            "Resource magic does not match 0x78563412.");
}

static bool AnalyzePy2Exe(PeFile* pe, const uint8_t* data, size_t n)
{
    if (!pe)
        return false;
    const PeRsrcLeaf* leaf = FindPythonScript(pe);
    if (!leaf || !data)
        return false;

    PyBundle py{};
    py.present = true;
    py.rsrc_off = leaf->file_off;
    py.rsrc_size = leaf->size;
    py.main_index = -1;

    auto log = LogFor(LogBuiltinPeAnalyzer).Module("marshal");
    if (!leaf->size || (uint64_t)leaf->file_off + leaf->size > n)
    {
        log.Warning("PYTHONSCRIPT resource is truncated");
        PublishBundle(pe, py);
        return true;
    }

    const uint8_t* r = data + leaf->file_off;
    uint32_t rn = leaf->size;
    if (rn < 20)
    {
        log.Warning("PYTHONSCRIPT resource is too small (%u bytes)", rn);
        PublishBundle(pe, py);
        return true;
    }

    uint32_t tag = 0, opt = 0, unbuf = 0, nbytes = 0;
    memcpy(&tag, r, 4);
    memcpy(&opt, r + 4, 4);
    memcpy(&unbuf, r + 8, 4);
    memcpy(&nbytes, r + 12, 4);
    py.magic = tag;
    py.optimize = (int)opt;
    py.unbuffered = (int)unbuf;
    py.data_bytes = nbytes;
    py.header_ok = IsPy2ExeMagic(tag);

    uint32_t z = 16;
    while (z < rn && r[z] != 0 && (z - 16) < 259)
        z++;
    if (z >= rn)
    {
        log.Warning("PYTHONSCRIPT zippath is not NUL-terminated");
        PublishBundle(pe, py);
        return true;
    }
    uint32_t zlen = z - 16;
    memcpy(py.archive, r + 16, zlen);
    py.archive[zlen] = 0;
    uint32_t moff = z + 1;
    uint32_t msize = nbytes;
    if (moff > rn)
    {
        PublishBundle(pe, py);
        return true;
    }
    if (!msize || moff + msize > rn)
        msize = rn - moff;
    py.marshal_off = leaf->file_off + moff;
    py.marshal_size = msize;

    GuessPythonVer(pe, &py.py_major, &py.py_minor);
    const uint8_t* mp = r + moff;
    bool py3 = false;
    if (msize)
        py3 = (mp[0] & FlagRef) != 0 || mp[0] == TypeAscii || mp[0] == TypeAsciiInterned ||
              mp[0] == TypeShortAscii || mp[0] == TypeShortAsciiInterned || mp[0] == TypeSmallTuple;
    if (py3 && py.py_major == 2)
        py.py_major = 3;
    else if (!py3 && py.py_major == 3)
        py.py_major = 2;
    if (!py.py_major)
        py.py_major = py3 ? 3 : 2;

    int layouts[8];
    int nlay = 0;
    auto add_layout = [&](int L)
    {
        for (int i = 0; i < nlay; i++)
        {
            if (layouts[i] == L)
                return;
        }
        if (nlay < 8)
            layouts[nlay++] = L;
    };
    int width = ProbeCodeHeaderWidth(mp, msize);
    if (py.py_major == 2)
    {
        if (width == 16)
        {
            add_layout(LayoutPy20);
            add_layout(LayoutPy21);
            add_layout(LayoutPy27);
        }
        else
        {
            add_layout(LayoutPy27);
            add_layout(LayoutPy21);
            add_layout(LayoutPy20);
        }
    }
    else if (py.py_minor >= 11)
        add_layout(LayoutPy311);
    else if (py.py_minor >= 8)
        add_layout(LayoutPy38);
    else if (py.py_major == 3)
        add_layout(LayoutPy3);
    add_layout(LayoutPy27);
    add_layout(LayoutPy38);
    add_layout(LayoutPy3);
    add_layout(LayoutPy311);

    bool walked = false;
    PyBundle best = py;
    int best_n = -1;
    for (int i = 0; i < nlay; i++)
    {
        PyBundle trial = py;
        if (!WalkMarshal(mp, msize, py.marshal_off, layouts[i], py3, &trial))
            continue;
        int score = NamedCodeCount(trial);
        if (score > best_n)
        {
            best = trial;
            best_n = score;
            walked = true;
        }
    }
    if (walked)
        py = std::move(best);

    if (py.codes.empty())
        LooseHarvest(mp, msize, py.marshal_off, &py);

    MarkMain(&py);
    InferVerFromCodes(&py);
    if (py.py_major == 2 && py.py_minor == 0 && width == 32)
        py.py_minor = 7;
    py.marshal_ok = !py.codes.empty();
    py.pyc_magic = PycMagicFor(py.py_major, py.py_minor);

    if (!py.header_ok)
        log.Warning("PYTHONSCRIPT magic 0x%08X (expected 0x78563412)", tag);
    log.Info("PYTHONSCRIPT %u bytes, python %d.%d, %zu code objects%s",
        rn, py.py_major, py.py_minor, py.codes.size(),
        py.archive[0] ? "" : ", archive=self");

    PublishBundle(pe, py);
    return true;
}

static bool ExportPy2Exe(const PeFile* pe, const uint8_t* data, size_t n,
    const AnalysisArtifact* art, const AnalysisExport* ex, const char* path)
{
    if (!pe || !art || !ex || !path)
        return false;
    if (strcmp(ex->id, "listing") == 0)
    {
        std::string t;
        char line[512];
        snprintf(line, sizeof(line), "PYTHONSCRIPT\n");
        t.append(line);
        for (const AnalysisProp& p : art->props)
        {
            snprintf(line, sizeof(line), "%s=%s\n", p.key, p.value);
            t.append(line);
        }
        t.push_back('\n');
        for (int i = 0; i < (int)art->children.size(); i++)
        {
            const AnalysisArtifact& c = art->children[i];
            snprintf(line, sizeof(line), "--- [%d]%s %s ---\n",
                i, c.flag_main ? " main" : "", c.label);
            t.append(line);
            if (!c.names.empty())
            {
                t.append("names: ");
                for (size_t k = 0; k < c.names.size(); k++)
                {
                    if (k)
                        t.append(", ");
                    AppendEscaped(&t, c.names[k]);
                }
                t.push_back('\n');
            }
            for (size_t k = 0; k < c.strings.size(); k++)
            {
                t.append("  ");
                AppendEscaped(&t, c.strings[k]);
                t.push_back('\n');
            }
            t.push_back('\n');
        }
        return WriteBytes(path, t.data(), (DWORD)t.size());
    }
    if (strcmp(ex->id, "bytecode") == 0)
    {
        if (!data || !ex->size || (uint64_t)ex->file_off + ex->size > n)
            return false;
        std::vector<uint8_t> out;
        uint32_t magic = ex->extra;
        int maj = (int)(ex->extra2 >> 8);
        int min = (int)(ex->extra2 & 0xff);
        if (magic)
        {
            Push32(&out, magic);
            if (maj == 2)
                Push32(&out, 0);
            else if (maj == 3 && min >= 7)
            {
                Push32(&out, 0);
                Push32(&out, 0);
                Push32(&out, 0);
            }
            else if (maj == 3 && min >= 3)
            {
                Push32(&out, 0);
                Push32(&out, 0);
            }
            else
                Push32(&out, 0);
        }
        size_t body = out.size();
        out.insert(out.end(), data + ex->file_off, data + ex->file_off + ex->size);
        if (body < out.size() && (out[body] & 0x80))
            out[body] = (uint8_t)(out[body] & 0x7F);
        return WriteBytes(path, out.data(), (DWORD)out.size());
    }
    return false;
}

static const AnalyzerProvider kPy2ExeProvider = {
    kAnalyzerId,
    "py2exe",
    { true, false, "PYTHONSCRIPT", "py2exe", nullptr },
    AnalyzePy2Exe,
    ExportPy2Exe
};

static AnalyzerSelfRegister g_py2exe_reg(&kPy2ExeProvider);
