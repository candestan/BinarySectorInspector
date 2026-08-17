#include "detect/detect.h"
#include "pe/pe.h"

#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <algorithm>

static uint32_t FactRvaOff(const PeFile* pe, uint32_t rva, size_t n)
{
    if (!pe || rva == 0)
        return 0;
    for (int i = 0; i < pe->section_n; i++)
    {
        const PeSection& s = pe->sections[i];
        uint32_t span = s.vsize ? s.vsize : s.rawsize;
        if (span == 0)
            continue;
        if (rva >= s.vaddr && rva < s.vaddr + span)
        {
            uint32_t delta = rva - s.vaddr;
            if (!s.rawptr || delta >= s.rawsize)
                return 0;
            uint32_t off = s.rawptr + delta;
            if (off >= n)
                return 0;
            return off;
        }
    }
    return 0;
}

static const uint8_t* At(const uint8_t* b, size_t n, uint32_t off, size_t need)
{
    if (!b || (uint64_t)off + need > n)
        return nullptr;
    return b + off;
}

static uint32_t Rd32(const uint8_t* p) { return *(const uint32_t*)p; }
static uint16_t Rd16(const uint8_t* p) { return *(const uint16_t*)p; }

static std::string HeapStr(const uint8_t* heap, size_t heap_n, uint32_t idx, bool idx4)
{
    if (!heap || idx == 0)
        return {};
    if (idx4)
    {
        if (idx >= heap_n)
            return {};
    }
    else if (idx >= heap_n)
        return {};
    size_t i = idx;
    std::string s;
    while (i < heap_n && heap[i] && s.size() < 256)
    {
        s.push_back((char)heap[i]);
        i++;
    }
    return s;
}

static uint32_t ReadIndex(const uint8_t*& p, const uint8_t* end, bool wide)
{
    if (wide)
    {
        if (p + 4 > end)
            return 0;
        uint32_t v = Rd32(p);
        p += 4;
        return v;
    }
    if (p + 2 > end)
        return 0;
    uint32_t v = Rd16(p);
    p += 2;
    return v;
}

static int CodedSize(uint64_t rows_max, int tag_bits)
{
    // coded index is 2 bytes unless max rows of any target >= 2^(16-tag_bits)
    uint32_t cap = 1u << (16 - tag_bits);
    return rows_max >= cap ? 4 : 2;
}

static void ParseClrMeta(const PeFile* pe, const uint8_t* b, size_t n, DetectFacts* out)
{
    if (!pe->has_com || !pe->clr_off)
        return;
    const uint8_t* h = At(b, n, pe->clr_off, 16);
    if (!h)
        return;
    uint32_t meta_rva = Rd32(h + 8);
    uint32_t meta_sz = Rd32(h + 12);
    if (!meta_rva || meta_sz < 20 || meta_sz > 16 * 1024 * 1024)
        return;
    uint32_t meta_off = FactRvaOff(pe, meta_rva, n);
    const uint8_t* meta = At(b, n, meta_off, meta_sz);
    if (!meta)
        return;
    if (Rd32(meta) != 0x424A5342)
        return;

    uint32_t ver_len = Rd32(meta + 12);
    if (ver_len > 256 || 16 + ver_len + 4 > meta_sz)
        return;
    uint32_t after_ver = 16 + ((ver_len + 3) & ~3u);
    if (after_ver + 4 > meta_sz)
        return;
    uint16_t nstreams = Rd16(meta + after_ver + 2);
    if (nstreams == 0 || nstreams > 8)
        return;

    struct Stream
    {
        char     name[16];
        uint32_t off;
        uint32_t size;
    } streams[8]{};
    int ns = 0;
    uint32_t cur = after_ver + 4;
    for (uint16_t i = 0; i < nstreams && ns < 8; i++)
    {
        if (cur + 8 >= meta_sz)
            break;
        Stream s{};
        s.off = Rd32(meta + cur);
        s.size = Rd32(meta + cur + 4);
        cur += 8;
        int k = 0;
        while (cur < meta_sz && meta[cur] && k < 15)
        {
            s.name[k++] = (char)meta[cur];
            cur++;
        }
        s.name[k] = 0;
        cur++;
        cur = (cur + 3) & ~3u;
        if (s.off >= meta_sz || s.size > meta_sz - s.off)
            continue;
        streams[ns++] = s;
        out->clr_streams.push_back(s.name);
    }

    const Stream* pound = nullptr;
    const Stream* strings = nullptr;
    for (int i = 0; i < ns; i++)
    {
        if (strcmp(streams[i].name, "#~") == 0 || strcmp(streams[i].name, "#-") == 0)
            pound = &streams[i];
        if (strcmp(streams[i].name, "#Strings") == 0)
            strings = &streams[i];
    }
    if (!pound || pound->size < 24)
        return;

    const uint8_t* t = meta + pound->off;
    const uint8_t* tend = t + pound->size;
    uint8_t heap_sizes = t[6];
    bool str4 = (heap_sizes & 1) != 0;
    bool guid4 = (heap_sizes & 2) != 0;
    bool blob4 = (heap_sizes & 4) != 0;
    uint64_t valid = *(const uint64_t*)(t + 8);
    const uint8_t* rows_p = t + 24;
    uint32_t rows[64]{};
    int present = 0;
    for (int i = 0; i < 64; i++)
    {
        if ((valid >> i) & 1ull)
        {
            if (rows_p + 4 > tend)
                return;
            rows[i] = Rd32(rows_p);
            rows_p += 4;
            present++;
            if (present > 48)
                return;
            if (rows[i] > 200000)
                rows[i] = 0;
        }
    }

    const uint8_t* str_heap = nullptr;
    size_t str_n = 0;
    if (strings)
    {
        str_heap = meta + strings->off;
        str_n = strings->size;
    }

    int str_w = str4 ? 4 : 2;
    int guid_w = guid4 ? 4 : 2;
    int blob_w = blob4 ? 4 : 2;
    auto simple = [&](int table) { return rows[table] > 65535 ? 4 : 2; };
    int type_def_or_ref = CodedSize((std::max)({ rows[2], rows[1], rows[27] }), 2);
    int has_constant = CodedSize((std::max)({ rows[4], rows[8], rows[23] }), 2);
    int has_ca = CodedSize((std::max)({ rows[0], rows[1], rows[2], rows[4], rows[6], rows[8],
        rows[9], rows[10], rows[17], rows[20], rows[23], rows[26], rows[27], rows[32],
        rows[35], rows[38], rows[39], rows[40] }), 5);
    int has_field_marshal = CodedSize((std::max)(rows[4], rows[8]), 1);
    int has_decl_sec = CodedSize((std::max)({ rows[2], rows[6], rows[32] }), 2);
    int member_ref_parent = CodedSize((std::max)({ rows[1], rows[2], rows[6], rows[26], rows[27] }), 3);
    int has_semantics = CodedSize((std::max)(rows[20], rows[23]), 1);
    int method_def_or_ref = CodedSize((std::max)(rows[6], rows[10]), 1);
    int member_forwarded = CodedSize((std::max)(rows[4], rows[6]), 1);
    int implementation = CodedSize((std::max)({ rows[38], rows[35], rows[39] }), 2);
    int ca_type = CodedSize((std::max)(rows[6], rows[10]), 3);
    int res_scope = CodedSize((std::max)({ rows[0], rows[26], rows[35], rows[1] }), 2);
    int type_or_method = CodedSize((std::max)(rows[2], rows[6]), 1);

    int row_sz[64]{};
    row_sz[0] = 2 + str_w + guid_w * 3;
    row_sz[1] = res_scope + str_w + str_w;
    row_sz[2] = 4 + str_w + str_w + type_def_or_ref + simple(4) + simple(6);
    row_sz[3] = simple(4);
    row_sz[4] = 2 + str_w + blob_w;
    row_sz[5] = simple(6);
    row_sz[6] = 4 + 2 + 2 + str_w + blob_w + simple(8);
    row_sz[7] = simple(8);
    row_sz[8] = 2 + 2 + str_w;
    row_sz[9] = simple(2) + type_def_or_ref;
    row_sz[10] = member_ref_parent + str_w + blob_w;
    row_sz[11] = 2 + has_constant + blob_w;
    row_sz[12] = has_ca + ca_type + blob_w;
    row_sz[13] = has_field_marshal + blob_w;
    row_sz[14] = 2 + has_decl_sec + blob_w;
    row_sz[15] = 2 + 4 + simple(2);
    row_sz[16] = 4 + simple(4);
    row_sz[17] = blob_w;
    row_sz[18] = simple(2) + simple(20);
    row_sz[19] = simple(20);
    row_sz[20] = 2 + str_w + type_def_or_ref;
    row_sz[21] = simple(2) + simple(23);
    row_sz[22] = simple(23);
    row_sz[23] = 2 + str_w + blob_w;
    row_sz[24] = 2 + simple(6) + has_semantics;
    row_sz[25] = simple(2) + method_def_or_ref + method_def_or_ref;
    row_sz[26] = str_w;
    row_sz[27] = blob_w;
    row_sz[28] = 2 + member_forwarded + str_w + simple(26);
    row_sz[29] = 4 + simple(4);
    row_sz[32] = 4 + 8 + 4 + blob_w + str_w + str_w;
    row_sz[33] = 4;
    row_sz[34] = 12;
    row_sz[35] = 8 + 4 + blob_w + str_w + str_w + blob_w;
    row_sz[36] = 4 + simple(35);
    row_sz[37] = 12 + simple(35);
    row_sz[38] = 4 + str_w + blob_w;
    row_sz[39] = 4 + 4 + str_w + str_w + implementation;
    row_sz[40] = 4 + 4 + str_w + implementation;
    row_sz[41] = simple(2) + simple(2);
    row_sz[42] = 2 + 2 + type_or_method + str_w;
    row_sz[43] = method_def_or_ref + blob_w;
    row_sz[44] = simple(42) + type_def_or_ref;

    const uint8_t* row = rows_p;
    const int kMaxTypes = 512;
    const int kMaxRefs = 64;

    for (int ti = 0; ti < 64 && row < tend; ti++)
    {
        if (((valid >> ti) & 1ull) == 0)
            continue;
        uint32_t count = rows[ti];
        int sz = row_sz[ti];
        if (count == 0)
            continue;
        if (sz <= 0)
            return;
        if ((uint64_t)count * (uint64_t)sz > (uint64_t)(tend - row))
            return;

        if (ti == 2)
        {
            for (uint32_t r = 0; r < count && (int)out->clr_types.size() < kMaxTypes; r++)
            {
                const uint8_t* p = row + (size_t)r * (size_t)sz + 4;
                const uint8_t* e = row + (size_t)(r + 1) * (size_t)sz;
                if (e > tend)
                    break;
                uint32_t ni = ReadIndex(p, e, str4);
                uint32_t nsi = ReadIndex(p, e, str4);
                std::string name = HeapStr(str_heap, str_n, ni, str4);
                std::string ns = HeapStr(str_heap, str_n, nsi, str4);
                if (!name.empty())
                    out->clr_types.push_back(name);
                if (!ns.empty() && (int)out->clr_namespaces.size() < 128)
                {
                    bool seen = false;
                    for (const std::string& x : out->clr_namespaces)
                    {
                        if (_stricmp(x.c_str(), ns.c_str()) == 0)
                        {
                            seen = true;
                            break;
                        }
                    }
                    if (!seen)
                        out->clr_namespaces.push_back(ns);
                }
            }
        }
        else if (ti == 35)
        {
            for (uint32_t r = 0; r < count && (int)out->clr_asm_refs.size() < kMaxRefs; r++)
            {
                const uint8_t* p = row + (size_t)r * (size_t)sz + 12;
                const uint8_t* e = row + (size_t)(r + 1) * (size_t)sz;
                if (e > tend)
                    break;
                ReadIndex(p, e, blob4);
                uint32_t ni = ReadIndex(p, e, str4);
                std::string name = HeapStr(str_heap, str_n, ni, str4);
                if (!name.empty())
                    out->clr_asm_refs.push_back(name);
            }
        }
        row += (size_t)count * (size_t)sz;
    }
}

void DetectFillFacts(const PeFile* pe, const uint8_t* bytes, size_t n, DetectFacts* out)
{
    if (!out)
        return;
    *out = DetectFacts{};
    if (!pe || !pe->ok)
        return;
    out->is_pe = true;
    out->pe32plus = pe->pe32plus;
    out->has_com = pe->has_com != 0 && pe->clr_off != 0;
    out->overlay = pe->overlay_size != 0;
    out->tls = pe->tls.present;
    out->tls_callbacks = pe->tls.present && !pe->tls.callback_rvas.empty();
    out->machine = pe->machine;
    out->chars = pe->chars;
    out->dllchars = pe->dllchars;
    out->linker_major = pe->linker_major;
    out->linker_minor = pe->linker_minor;
    out->entry_rva = pe->entry_rva;
    out->overlay_off = pe->overlay_off;
    out->overlay_size = pe->overlay_size;
    out->clr_major = pe->clr_major;
    out->clr_minor = pe->clr_minor;
    out->clr_flags = pe->clr_flags;
    out->section_n = pe->section_n;
    out->bytes = bytes;
    out->byte_n = n;

    PeAddr ep{};
    if (PeAddrFromRva(pe, pe->entry_rva, &ep) && ep.valid)
        out->entry_off = ep.file_off;

    out->sections.reserve((size_t)pe->section_n);
    for (int i = 0; i < pe->section_n; i++)
    {
        DetectSectionFact s{};
        memcpy(s.name, pe->sections[i].name, 9);
        s.chars = pe->sections[i].chars;
        s.vsize = pe->sections[i].vsize;
        s.rawsize = pe->sections[i].rawsize;
        s.rawptr = pe->sections[i].rawptr;
        s.entropy = 0.0;
        for (const PeEntropyRange& e : pe->entropy)
        {
            if (_stricmp(e.label, s.name) == 0)
            {
                s.entropy = e.entropy;
                break;
            }
        }
        out->sections.push_back(s);
    }

    out->rich_prod.reserve(pe->rich.size());
    out->rich_build.reserve(pe->rich.size());
    for (const PeRichEntry& r : pe->rich)
    {
        out->rich_prod.push_back(r.prod);
        out->rich_build.push_back(r.build);
    }

    out->import_dll_n = (int)pe->imports.size();
    for (const PeImportDll& d : pe->imports)
    {
        out->import_dlls.push_back(d.name);
        for (const PeImportFn& fn : d.fns)
        {
            if (fn.name.empty())
                continue;
            std::string q = d.name + "!" + fn.name;
            out->import_fns.push_back(std::move(q));
        }
    }
    for (const PeExportFn& e : pe->exports)
    {
        if (!e.name.empty())
            out->exports.push_back(e.name);
    }
    for (const PeDebugEntry& d : pe->debug)
        out->debug_types.push_back(d.type_name);
    for (const PeVerInfo& v : pe->versions)
    {
        for (const PeVerString& s : v.strings)
        {
            std::string kv = std::string(s.key) + "=" + s.value;
            out->version_kv.push_back(std::move(kv));
        }
    }
    for (const PeRsrcType& t : pe->rsrc_types)
        out->resource_types.push_back(t.name);
    for (const PeRsrcLeaf& L : pe->rsrc)
    {
        if (L.name[0])
            out->resource_names.push_back(L.name);
        if (L.type_name[0])
            out->resource_types.push_back(L.type_name);
    }
    const int kMaxStr = 8000;
    out->strings.reserve((size_t)kMaxStr);
    if (pe->overlay_size)
    {
        for (const PeStringEntry& s : pe->strings)
        {
            if (s.file_off >= pe->overlay_off)
            {
                out->strings.push_back(s.text);
                if ((int)out->strings.size() >= kMaxStr)
                    break;
            }
        }
    }
    for (size_t i = 0; i < pe->strings.size() && (int)out->strings.size() < kMaxStr; i++)
    {
        if (pe->overlay_size && pe->strings[i].file_off >= pe->overlay_off)
            continue;
        out->strings.push_back(pe->strings[i].text);
    }

    if (bytes && n && out->has_com)
        ParseClrMeta(pe, bytes, n, out);
}
