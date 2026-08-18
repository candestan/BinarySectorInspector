#include "detect/detect_p.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <algorithm>

static const char* IStrStr(const char* hay, const char* needle)
{
    if (!hay || !needle || !needle[0])
        return nullptr;
    size_t n = strlen(needle);
    for (const char* p = hay; *p; p++)
    {
        if (_strnicmp(p, needle, (int)n) == 0)
            return p;
    }
    return nullptr;
}

static void LowerInPlace(std::string& s)
{
    for (char& c : s)
        c = (char)tolower((unsigned char)c);
}

static std::string LowerCopy(const std::string& s)
{
    std::string o = s;
    LowerInPlace(o);
    return o;
}

static bool StrMatch(MatchMode mode, const char* have, const char* want)
{
    if (!have || !want || !want[0])
        return false;
    if (mode == MatchExact)
        return _stricmp(have, want) == 0;
    if (mode == MatchPrefix)
        return _strnicmp(have, want, (int)strlen(want)) == 0;
    return IStrStr(have, want) != nullptr;
}

static bool VecStrMatch(MatchMode mode, const std::vector<std::string>& v, const std::string& want)
{
    for (const std::string& s : v)
    {
        if (StrMatch(mode, s.c_str(), want.c_str()))
            return true;
    }
    return false;
}

static int EntrySectionIndex(const DetectFacts& facts)
{
    if (!facts.entry_rva)
        return -1;
    for (int i = 0; i < (int)facts.sections.size(); i++)
    {
        const DetectSectionFact& s = facts.sections[i];
        if (facts.entry_rva >= s.vaddr && facts.entry_rva < s.vaddr + s.vsize)
            return i;
    }
    return -1;
}

static bool PatAt(const BytePat& pat, const uint8_t* b, size_t n, size_t off)
{
    if (pat.bytes.empty() || off + pat.bytes.size() > n)
        return false;
    for (size_t i = 0; i < pat.bytes.size(); i++)
    {
        if (pat.mask[i] && b[off + i] != pat.bytes[i])
            return false;
    }
    return true;
}

static bool PatScan(const BytePat& pat, const uint8_t* b, size_t n, size_t from, size_t to)
{
    if (!b || pat.bytes.empty() || to > n)
        return false;
    if (to < from + pat.bytes.size())
        return false;
    size_t last = to - pat.bytes.size();
    const size_t kCap = 8 * 1024 * 1024;
    if (last - from > kCap)
        last = from + kCap;
    for (size_t i = from; i <= last; i++)
    {
        if (PatAt(pat, b, n, i))
            return true;
    }
    return false;
}

static bool MatchPattern(const DetectFacts& facts, const Cond& c)
{
    if (!facts.bytes || facts.byte_n == 0)
        return false;
    if (c.where == ScanEntry || c.kind == CondEntryBytes)
        return PatAt(c.pat, facts.bytes, facts.byte_n, (size_t)facts.entry_off);
    if (c.where == ScanOverlay)
    {
        if (!facts.overlay)
            return false;
        return PatScan(c.pat, facts.bytes, facts.byte_n, (size_t)facts.overlay_off,
            (size_t)(facts.overlay_off + facts.overlay_size));
    }
    if (PatScan(c.pat, facts.bytes, facts.byte_n, 0, facts.byte_n))
        return true;
    if (facts.byte_n > 64 * 1024)
    {
        size_t tail = facts.byte_n - 64 * 1024;
        if (PatScan(c.pat, facts.bytes, facts.byte_n, tail, facts.byte_n))
            return true;
    }
    if (facts.overlay && facts.overlay_size)
    {
        if (PatScan(c.pat, facts.bytes, facts.byte_n, (size_t)facts.overlay_off,
            (size_t)(facts.overlay_off + facts.overlay_size)))
            return true;
    }
    return false;
}

static void PushEv(std::vector<DetectEvidence>* ev, const char* cond, const char* detail, int weight)
{
    if (!ev)
        return;
    DetectEvidence e;
    e.condition = cond ? cond : "";
    e.detail = detail ? detail : "";
    e.weight = weight;
    ev->push_back(std::move(e));
}

static bool EvalLeaf(const DetectFacts& facts, const Cond& c, std::vector<DetectEvidence>* ev)
{
    char det[192];
    det[0] = 0;

    switch (c.kind)
    {
    case CondSectionName:
        for (const DetectSectionFact& s : facts.sections)
        {
            if (StrMatch(c.mode, s.name, c.a.c_str()))
            {
                snprintf(det, sizeof(det), "section %s", s.name);
                PushEv(ev, "section_name", det, c.weight);
                return true;
            }
        }
        return false;
    case CondSectionCount:
        if (facts.section_n >= c.i0 && facts.section_n <= c.i1)
        {
            snprintf(det, sizeof(det), "%d sections", facts.section_n);
            PushEv(ev, "section_count", det, c.weight);
            return true;
        }
        return false;
    case CondSectionChars:
        for (const DetectSectionFact& s : facts.sections)
        {
            if (!c.a.empty() && !StrMatch(MatchExact, s.name, c.a.c_str()))
                continue;
            if ((s.chars & (uint32_t)c.i0) == (uint32_t)c.i0)
            {
                snprintf(det, sizeof(det), "%s chars 0x%08X", s.name[0] ? s.name : "(unnamed)", s.chars);
                PushEv(ev, "section_chars", det, c.weight);
                return true;
            }
        }
        return false;
    case CondSectionEntropy:
        for (const DetectSectionFact& s : facts.sections)
        {
            if (!c.a.empty() && !StrMatch(c.mode == MatchExact ? MatchExact : MatchContains, s.name, c.a.c_str()))
                continue;
            if (s.entropy >= c.f0)
            {
                snprintf(det, sizeof(det), "%s entropy %.2f", s.name[0] ? s.name : "(unnamed)", s.entropy);
                PushEv(ev, "section_entropy", det, c.weight);
                return true;
            }
        }
        return false;
    case CondEntryBytes:
    case CondBytePattern:
        if (MatchPattern(facts, c))
        {
            snprintf(det, sizeof(det), "%s pattern (%zu bytes)",
                c.where == ScanOverlay ? "overlay" : (c.kind == CondEntryBytes || c.where == ScanEntry) ? "entry" : "file",
                c.pat.bytes.size());
            PushEv(ev, c.kind == CondEntryBytes ? "entry_point_bytes" : "byte_pattern", det, c.weight);
            return true;
        }
        return false;
    case CondImportedDll:
        if (VecStrMatch(c.mode, facts.import_dlls, c.a))
        {
            snprintf(det, sizeof(det), "imports %s", c.a.c_str());
            PushEv(ev, "imported_dll", det, c.weight);
            return true;
        }
        return false;
    case CondImportedFn:
        for (const std::string& fn : facts.import_fns)
        {
            if (!c.b.empty())
            {
                std::string want = LowerCopy(c.b) + "!" + LowerCopy(c.a);
                if (_stricmp(fn.c_str(), want.c_str()) == 0)
                {
                    snprintf(det, sizeof(det), "%s", fn.c_str());
                    PushEv(ev, "imported_function", det, c.weight);
                    return true;
                }
            }
            else
            {
                const char* bang = strchr(fn.c_str(), '!');
                const char* name = bang ? bang + 1 : fn.c_str();
                if (_stricmp(name, c.a.c_str()) == 0)
                {
                    snprintf(det, sizeof(det), "%s", fn.c_str());
                    PushEv(ev, "imported_function", det, c.weight);
                    return true;
                }
            }
        }
        return false;
    case CondExported:
        if (VecStrMatch(c.mode, facts.exports, c.a))
        {
            snprintf(det, sizeof(det), "export %s", c.a.c_str());
            PushEv(ev, "exported_symbol", det, c.weight);
            return true;
        }
        return false;
    case CondPeChars:
        if ((facts.chars & (uint16_t)c.i0) == (uint16_t)c.i0)
        {
            snprintf(det, sizeof(det), "Characteristics 0x%04X", facts.chars);
            PushEv(ev, "pe_chars", det, c.weight);
            return true;
        }
        return false;
    case CondDllChars:
        if ((facts.dllchars & (uint16_t)c.i0) == (uint16_t)c.i0)
        {
            snprintf(det, sizeof(det), "DllCharacteristics 0x%04X", facts.dllchars);
            PushEv(ev, "dll_chars", det, c.weight);
            return true;
        }
        return false;
    case CondRichPresent:
        if ((!facts.rich_prod.empty()) == c.b0)
        {
            PushEv(ev, "rich_present", c.b0 ? "Rich header present" : "no Rich header", c.weight);
            return true;
        }
        return false;
    case CondRichProd:
        for (uint16_t p : facts.rich_prod)
        {
            if (p == (uint16_t)c.i0)
            {
                snprintf(det, sizeof(det), "Rich prod %u", p);
                PushEv(ev, "rich_prod", det, c.weight);
                return true;
            }
        }
        return false;
    case CondRichBuild:
        for (uint16_t b : facts.rich_build)
        {
            if (b == (uint16_t)c.i0)
            {
                snprintf(det, sizeof(det), "Rich build %u", b);
                PushEv(ev, "rich_build", det, c.weight);
                return true;
            }
        }
        return false;
    case CondOverlay:
        if (c.b0)
        {
            if (facts.overlay && facts.overlay_size >= (uint64_t)c.i0)
            {
                snprintf(det, sizeof(det), "overlay %llu bytes", (unsigned long long)facts.overlay_size);
                PushEv(ev, "overlay", det, c.weight);
                return true;
            }
            return false;
        }
        if (!facts.overlay)
        {
            PushEv(ev, "overlay", "no overlay", c.weight);
            return true;
        }
        return false;
    case CondTls:
        if (facts.tls == c.b0)
        {
            PushEv(ev, "tls", facts.tls ? "TLS directory present" : "no TLS", c.weight);
            return true;
        }
        return false;
    case CondTlsCallbacks:
        if (facts.tls_callbacks == c.b0)
        {
            PushEv(ev, "tls_callbacks", facts.tls_callbacks ? "TLS callbacks present" : "no TLS callbacks", c.weight);
            return true;
        }
        return false;
    case CondDebugType:
        if (VecStrMatch(MatchContains, facts.debug_types, c.a))
        {
            snprintf(det, sizeof(det), "debug %s", c.a.c_str());
            PushEv(ev, "debug_type", det, c.weight);
            return true;
        }
        return false;
    case CondVersionString:
        for (const std::string& kv : facts.version_kv)
        {
            bool key_ok = c.a.empty() || IStrStr(kv.c_str(), c.a.c_str()) != nullptr;
            bool val_ok = c.b.empty() || IStrStr(kv.c_str(), c.b.c_str()) != nullptr;
            if (key_ok && val_ok)
            {
                snprintf(det, sizeof(det), "%s", kv.c_str());
                PushEv(ev, "version_string", det, c.weight);
                return true;
            }
        }
        return false;
    case CondResourceType:
        if (VecStrMatch(c.mode, facts.resource_types, c.a))
        {
            snprintf(det, sizeof(det), "resource type %s", c.a.c_str());
            PushEv(ev, "resource_type", det, c.weight);
            return true;
        }
        return false;
    case CondResourceName:
        if (VecStrMatch(c.mode, facts.resource_names, c.a))
        {
            snprintf(det, sizeof(det), "resource %s", c.a.c_str());
            PushEv(ev, "resource_name", det, c.weight);
            return true;
        }
        return false;
    case CondStringContains:
        if (VecStrMatch(MatchContains, facts.strings, c.a))
        {
            snprintf(det, sizeof(det), "string contains \"%s\"", c.a.c_str());
            PushEv(ev, "string_contains", det, c.weight);
            return true;
        }
        return false;
    case CondHasCom:
        if (facts.has_com == c.b0)
        {
            PushEv(ev, "has_com", facts.has_com ? "CLR directory present" : "native (no CLR)", c.weight);
            return true;
        }
        return false;
    case CondClrStream:
        if (VecStrMatch(MatchExact, facts.clr_streams, c.a) || VecStrMatch(MatchContains, facts.clr_streams, c.a))
        {
            snprintf(det, sizeof(det), "metadata stream %s", c.a.c_str());
            PushEv(ev, "clr_stream", det, c.weight);
            return true;
        }
        return false;
    case CondAsmRef:
        if (VecStrMatch(c.mode, facts.clr_asm_refs, c.a))
        {
            snprintf(det, sizeof(det), "assembly ref %s", c.a.c_str());
            PushEv(ev, "assembly_ref", det, c.weight);
            return true;
        }
        return false;
    case CondTypeName:
        if (VecStrMatch(c.mode, facts.clr_types, c.a))
        {
            snprintf(det, sizeof(det), "type %s", c.a.c_str());
            PushEv(ev, "type_name", det, c.weight);
            return true;
        }
        return false;
    case CondNamespace:
        if (VecStrMatch(c.mode, facts.clr_namespaces, c.a))
        {
            snprintf(det, sizeof(det), "namespace %s", c.a.c_str());
            PushEv(ev, "namespace", det, c.weight);
            return true;
        }
        return false;
    case CondLinkerMajor:
        if (facts.linker_major == (uint16_t)c.i0)
        {
            snprintf(det, sizeof(det), "linker %u.%u", facts.linker_major, facts.linker_minor);
            PushEv(ev, "linker_major", det, c.weight);
            return true;
        }
        return false;
    case CondLinkerMinor:
        if (facts.linker_minor == (uint16_t)c.i0)
        {
            snprintf(det, sizeof(det), "linker minor %u", facts.linker_minor);
            PushEv(ev, "linker_minor", det, c.weight);
            return true;
        }
        return false;
    case CondImportDllCount:
        if (facts.import_dll_n >= c.i0 && facts.import_dll_n <= c.i1)
        {
            snprintf(det, sizeof(det), "%d import DLLs", facts.import_dll_n);
            PushEv(ev, "import_dll_count", det, c.weight);
            return true;
        }
        return false;
    case CondWxSection:
    {
        bool wx = false;
        for (const DetectSectionFact& s : facts.sections)
        {
            if ((s.chars & IMAGE_SCN_MEM_EXECUTE) && (s.chars & IMAGE_SCN_MEM_WRITE))
            {
                wx = true;
                snprintf(det, sizeof(det), "W+X section %s", s.name);
                break;
            }
        }
        if (wx == c.b0)
        {
            PushEv(ev, "writable_executable_section", det[0] ? det : "no W+X section", c.weight);
            return true;
        }
        return false;
    }
    case CondSectionRawSize:
        for (const DetectSectionFact& s : facts.sections)
        {
            if (!c.a.empty() && !StrMatch(MatchExact, s.name, c.a.c_str()))
                continue;
            if ((int)s.rawsize >= c.i0 && (int)s.rawsize <= c.i1)
            {
                snprintf(det, sizeof(det), "%s raw %u", s.name[0] ? s.name : "(unnamed)", s.rawsize);
                PushEv(ev, "section_raw_size", det, c.weight);
                return true;
            }
        }
        return false;
    case CondOddSectionNames:
    {
        int n = 0;
        for (const DetectSectionFact& s : facts.sections)
        {
            const char* name = s.name;
            if (!name || name[0] != '.')
                continue;
            size_t len = strlen(name);
            if (len < 2 || len > 4)
                continue;
            bool odd = false;
            for (size_t i = 1; i < len; i++)
            {
                unsigned char ch = (unsigned char)name[i];
                if (!isalnum(ch) && ch != '_')
                {
                    odd = true;
                    break;
                }
            }
            if (odd)
                n++;
        }
        if (n >= c.i0)
        {
            snprintf(det, sizeof(det), "%d mutated short section names", n);
            PushEv(ev, "odd_section_names", det, c.weight);
            return true;
        }
        return false;
    }
    // Layout fact used by several protectors: original sections left mapped but empty
    // before the on-disk entry stub. credit: https://github.com/notsnakesilent/VMPStatic/blob/main/main.go
    case CondVirtualOnlyBeforeEntry:
    {
        int ep = EntrySectionIndex(facts);
        if (ep < 1)
            return false;
        int packed = 0;
        for (int i = 0; i < ep; i++)
        {
            const DetectSectionFact& s = facts.sections[(size_t)i];
            if (s.rawsize == 0 && s.rawptr == 0 &&
                (s.chars & IMAGE_SCN_CNT_UNINITIALIZED_DATA) == 0)
                packed++;
        }
        if (packed < c.i0)
            return false;
        snprintf(det, sizeof(det), "%d virtual-only sections before entry", packed);
        PushEv(ev, "virtual_only_before_entry", det, c.weight);
        return true;
    }
    case CondEntrySectionChars:
    {
        int ep = EntrySectionIndex(facts);
        if (ep < 0)
            return false;
        const DetectSectionFact& stub = facts.sections[(size_t)ep];
        if ((stub.chars & (uint32_t)c.i0) != (uint32_t)c.i0)
            return false;
        snprintf(det, sizeof(det), "entry %s chars 0x%08X", stub.name[0] ? stub.name : "(unnamed)", stub.chars);
        PushEv(ev, "entry_section_chars", det, c.weight);
        return true;
    }
    case CondEntrySectionRawSize:
    {
        int ep = EntrySectionIndex(facts);
        if (ep < 0)
            return false;
        const DetectSectionFact& stub = facts.sections[(size_t)ep];
        if ((int)stub.rawsize < c.i0 || (int)stub.rawsize > c.i1)
            return false;
        snprintf(det, sizeof(det), "entry %s raw %u", stub.name[0] ? stub.name : "(unnamed)", stub.rawsize);
        PushEv(ev, "entry_section_raw_size", det, c.weight);
        return true;
    }
    case CondEntrySectionEntropy:
    {
        int ep = EntrySectionIndex(facts);
        if (ep < 0)
            return false;
        const DetectSectionFact& stub = facts.sections[(size_t)ep];
        if (stub.entropy < c.f0)
            return false;
        snprintf(det, sizeof(det), "entry %s entropy %.2f", stub.name[0] ? stub.name : "(unnamed)", stub.entropy);
        PushEv(ev, "entry_section_entropy", det, c.weight);
        return true;
    }
    default:
        return false;
    }
}

bool DetectEvalCond(const DetectFacts& facts, const Cond& c, std::vector<DetectEvidence>* ev)
{
    if (c.kind == CondAll)
    {
        std::vector<DetectEvidence> acc;
        for (const Cond& k : c.kids)
        {
            if (!DetectEvalCond(facts, k, &acc))
                return false;
        }
        if (ev)
            ev->insert(ev->end(), acc.begin(), acc.end());
        return true;
    }
    if (c.kind == CondAny)
    {
        std::vector<DetectEvidence> acc;
        bool ok = false;
        for (const Cond& k : c.kids)
        {
            if (DetectEvalCond(facts, k, &acc))
                ok = true;
        }
        if (ok && ev)
            ev->insert(ev->end(), acc.begin(), acc.end());
        return ok;
    }
    if (c.kind == CondNot)
    {
        if (c.kids.empty())
            return false;
        std::vector<DetectEvidence> ignore;
        if (DetectEvalCond(facts, c.kids[0], &ignore))
            return false;
        PushEv(ev, "not", "negative condition held", 0);
        return true;
    }
    return EvalLeaf(facts, c, ev);
}

bool DetectSigApplies(const DetectFacts& facts, const CompiledSig& sig)
{
    if (!facts.is_pe)
        return false;
    if (sig.requires_clr && !facts.has_com)
        return false;
    if (sig.native_only && facts.has_com)
        return false;
    if (sig.arch & ArchAny)
        return true;
    if ((sig.arch & ArchX86) && facts.machine == IMAGE_FILE_MACHINE_I386)
        return true;
    if ((sig.arch & ArchX64) && facts.machine == IMAGE_FILE_MACHINE_AMD64)
        return true;
#ifdef IMAGE_FILE_MACHINE_ARM64
    if ((sig.arch & ArchArm64) && facts.machine == IMAGE_FILE_MACHINE_ARM64)
        return true;
#endif
    return false;
}

DetectConfidence DetectScoreToConfidence(int score, DetectConfidence cap)
{
    DetectConfidence c = DetectConfLow;
    if (score >= 80)
        c = DetectConfExact;
    else if (score >= 50)
        c = DetectConfHigh;
    else if (score >= 25)
        c = DetectConfMedium;
    if (c > cap)
        c = cap;
    return c;
}
