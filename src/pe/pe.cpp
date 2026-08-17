#include "pe/pe.h"
#include "pe/patch.h"
#include "log/log.h"
#include "detect/detect.h"
#include "analyze/analyze.h"

#include <windows.h>
#include <delayimp.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <thread>
#include <mutex>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

// PE layout: Microsoft PE/COFF spec
// credit: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

static const size_t kMaxFile = 512ull * 1024ull * 1024ull;
static const uint32_t kMaxImportDescriptors = 4096;
static const uint32_t kMaxRelocBlocks = 65536;
static const uint32_t kMaxRelocEntriesPerBlock = 16384;
static const uint32_t kMaxTlsCallbacks = 1024;
static const uint32_t kMaxDebugEntries = 256;
static const uint32_t kMinExtractedStringLength = 4;
static const uint32_t kMaxExtractedStrings = 20000;
static const uint32_t kMaxExtractedStringChars = 512;

#ifndef IMAGE_DLLCHARACTERISTICS_GUARD_CF
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF 0x4000
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
#define IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA 0x0020
#endif

template <typename T>
static const T* At(const uint8_t* b, size_t n, size_t off)
{
    if (off + sizeof(T) > n)
        return nullptr;
    return reinterpret_cast<const T*>(b + off);
}

static uint32_t RvaToOff(const PeFile* pe, uint32_t rva)
{
    if (rva < pe->size_of_headers)
        return rva;
    for (int i = 0; i < pe->section_n; i++)
    {
        uint32_t va = pe->sections[i].vaddr;
        uint32_t span = pe->sections[i].vsize;
        if (pe->sections[i].rawsize > span)
            span = pe->sections[i].rawsize;
        if (rva >= va && rva < va + span)
            return pe->sections[i].rawptr + (rva - va);
    }
    return 0;
}

static bool ReadAscii(const uint8_t* b, size_t n, uint32_t off, char* out, int cap)
{
    if (!out || cap < 2)
        return false;
    out[0] = 0;
    if (off >= n)
        return false;
    int i = 0;
    while (i < cap - 1 && off + (size_t)i < n)
    {
        char c = (char)b[off + i];
        if (!c)
            break;
        if (c < 32 || c > 126)
            break;
        out[i++] = c;
    }
    out[i] = 0;
    return i > 0;
}

static void MachineName(uint16_t m, char* out, int cap)
{
    const char* s = "unknown";
    switch (m)
    {
    case 0x014c: s = "x86"; break;
    case 0x8664: s = "x64"; break;
    case 0xAA64: s = "ARM64"; break;
    case 0x01c0: s = "ARM"; break;
    case 0x01c4: s = "ARMv7"; break;
    case 0x0162: s = "MIPS"; break;
    case 0x01f0: s = "PowerPC"; break;
    case 0x0ebc: s = "EFI"; break;
    }
    snprintf(out, cap, "%s", s);
}

static void SubsystemName(uint16_t m, char* out, int cap)
{
    const char* s = "unknown";
    switch (m)
    {
    case 1: s = "Native"; break;
    case 2: s = "Windows GUI"; break;
    case 3: s = "Windows CUI"; break;
    case 7: s = "POSIX CUI"; break;
    case 9: s = "Windows CE"; break;
    case 10: s = "EFI app"; break;
    case 11: s = "EFI boot"; break;
    case 12: s = "EFI runtime"; break;
    case 13: s = "EFI ROM"; break;
    case 14: s = "Xbox"; break;
    case 16: s = "Windows boot"; break;
    }
    snprintf(out, cap, "%s", s);
}

static bool HashHex(LPCWSTR alg_id, const uint8_t* data, size_t n, char* out, int cap,
    std::atomic<float>* progress, float p0, float p1)
{
    out[0] = 0;
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD obj_len = 0, cb = 0, hash_len = 0;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, alg_id, nullptr, 0)))
        return false;
    BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&obj_len, sizeof(obj_len), &cb, 0);
    BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&hash_len, sizeof(hash_len), &cb, 0);
    if (hash_len * 2 + 1 > (DWORD)cap)
    {
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }
    std::vector<uint8_t> obj(obj_len);
    std::vector<uint8_t> dig(hash_len);
    if (!BCRYPT_SUCCESS(BCryptCreateHash(alg, &hash, obj.data(), obj_len, nullptr, 0, 0)))
    {
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }
    const size_t chunk = 1024 * 1024;
    size_t off = 0;
    while (off < n)
    {
        size_t take = n - off;
        if (take > chunk)
            take = chunk;
        BCryptHashData(hash, (PUCHAR)(data + off), (ULONG)take, 0);
        off += take;
        if (progress && n)
            progress->store(p0 + (p1 - p0) * (float)off / (float)n);
    }
    BCryptFinishHash(hash, dig.data(), hash_len, 0);
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    for (DWORD i = 0; i < hash_len; i++)
        snprintf(out + i * 2, 3, "%02x", dig[i]);
    out[hash_len * 2] = 0;
    return true;
}

static void HashFile(const uint8_t* data, size_t n, PeFile* out, std::atomic<float>* progress)
{
    HashHex(BCRYPT_MD5_ALGORITHM, data, n, out->md5, (int)sizeof(out->md5), progress, 0.08f, 0.12f);
    HashHex(BCRYPT_SHA1_ALGORITHM, data, n, out->sha1, (int)sizeof(out->sha1), progress, 0.12f, 0.16f);
    HashHex(BCRYPT_SHA256_ALGORITHM, data, n, out->sha256, (int)sizeof(out->sha256), progress, 0.16f, 0.22f);
    HashHex(BCRYPT_SHA512_ALGORITHM, data, n, out->sha512, (int)sizeof(out->sha512), progress, 0.22f, 0.28f);
}

static void DllStem(const char* dll, char* out, int cap)
{
    out[0] = 0;
    if (!dll || cap < 2)
        return;
    const char* slash = strrchr(dll, '\\');
    const char* fwd = strrchr(dll, '/');
    if (fwd && (!slash || fwd > slash))
        slash = fwd;
    const char* p = slash ? slash + 1 : dll;
    int i = 0;
    while (p[i] && i < cap - 1)
    {
        out[i] = (char)tolower((unsigned char)p[i]);
        i++;
    }
    out[i] = 0;
    char* dot = strrchr(out, '.');
    if (dot && (strcmp(dot, ".dll") == 0 || strcmp(dot, ".ocx") == 0 ||
        strcmp(dot, ".sys") == 0 || strcmp(dot, ".drv") == 0))
        *dot = 0;
}

static void ImpHash(PeFile* pe)
{
    pe->imphash[0] = 0;
    if (!pe || pe->imports.empty())
        return;
    std::string blob;
    blob.reserve(2048);
    for (const PeImportDll& d : pe->imports)
    {
        char stem[96];
        DllStem(d.name.c_str(), stem, (int)sizeof(stem));
        if (!stem[0])
            continue;
        for (const PeImportFn& fn : d.fns)
        {
            if (!blob.empty())
                blob.push_back(',');
            blob.append(stem);
            blob.push_back('.');
            if (fn.name[0] && fn.ordinal == 0)
            {
                for (char c : fn.name)
                    blob.push_back((char)tolower((unsigned char)c));
            }
            else
            {
                char ord[24];
                snprintf(ord, sizeof(ord), "ord%u", fn.ordinal ? fn.ordinal : 0);
                blob.append(ord);
            }
            if (blob.size() > 256u * 1024u)
                break;
        }
        if (blob.size() > 256u * 1024u)
            break;
    }
    if (blob.empty())
        return;
    HashHex(BCRYPT_MD5_ALGORITHM, (const uint8_t*)blob.data(), blob.size(),
        pe->imphash, (int)sizeof(pe->imphash), nullptr, 0.f, 0.f);
}

static void ParseRich(const uint8_t* b, size_t n, uint32_t e_lfanew, PeFile* out)
{
    // DanS xor + "Rich" key. not copied verbatim, layout from public writeups.
    // credit: https://bytepointer.com/articles/the_microsoft_rich_header.htm
    // credit: https://github.com/dishather/richprint
    if (e_lfanew < 0x80)
        return;
    uint32_t rich_off = 0;
    for (uint32_t i = 0x80; i + 8 < e_lfanew; i += 4)
    {
        if (b[i] == 'R' && b[i + 1] == 'i' && b[i + 2] == 'c' && b[i + 3] == 'h')
        {
            rich_off = i;
            break;
        }
    }
    if (!rich_off)
        return;
    uint32_t key = *(const uint32_t*)(b + rich_off + 4);
    uint32_t dans = 0;
    for (uint32_t i = 0x80; i + 4 < rich_off; i += 4)
    {
        uint32_t v = *(const uint32_t*)(b + i) ^ key;
        if (v == 0x536E6144) // DanS
        {
            dans = i;
            break;
        }
    }
    if (!dans)
        return;
    for (uint32_t i = dans + 16; i + 8 <= rich_off; i += 8)
    {
        uint32_t idv = *(const uint32_t*)(b + i) ^ key;
        uint32_t cnt = *(const uint32_t*)(b + i + 4) ^ key;
        PeRichEntry e{};
        e.prod = (uint16_t)(idv >> 16);
        e.build = (uint16_t)(idv & 0xffff);
        e.count = cnt;
        out->rich.push_back(e);
        if (out->rich.size() > 64)
            break;
    }
}

static void ParseOneThunkTable(const uint8_t* b, size_t n, PeFile* pe, uint32_t thunk_rva, PeImportDll* dll)
{
    uint32_t toff = RvaToOff(pe, thunk_rva);
    const int step = pe->pe32plus ? 8 : 4;
    for (int k = 0; k < 4096; k++)
    {
        if (!toff || toff + (size_t)k * step + step > n)
            break;
        uint64_t thunk = 0;
        if (pe->pe32plus)
            thunk = *(const uint64_t*)(b + toff + k * 8);
        else
            thunk = *(const uint32_t*)(b + toff + k * 4);
        if (!thunk)
            break;
        PeImportFn fn{};
        uint64_t ord_flag = pe->pe32plus ? 0x8000000000000000ull : 0x80000000ull;
        if (thunk & ord_flag)
        {
            fn.ordinal = (uint32_t)(thunk & 0xffff);
            char tmp[32];
            snprintf(tmp, 32, "ord_%u", fn.ordinal);
            fn.name = tmp;
        }
        else
        {
            uint32_t ib = RvaToOff(pe, (uint32_t)(thunk & 0x7fffffff));
            const IMAGE_IMPORT_BY_NAME* ibn = At<IMAGE_IMPORT_BY_NAME>(b, n, ib);
            if (ibn)
            {
                fn.hint = ibn->Hint;
                char fnn[128];
                if (ReadAscii(b, n, ib + 2, fnn, 128))
                    fn.name = fnn;
                else
                    fn.name = "?";
            }
        }
        dll->fns.push_back(fn);
    }
}

static void ParseImports(const uint8_t* b, size_t n, PeFile* pe)
{
    if (pe->dd_n > IMAGE_DIRECTORY_ENTRY_IMPORT && pe->dd_rva[IMAGE_DIRECTORY_ENTRY_IMPORT])
    {
        uint32_t rva = pe->dd_rva[IMAGE_DIRECTORY_ENTRY_IMPORT];
        uint32_t off = RvaToOff(pe, rva);
        if (off)
        {
            pe->has_import = true;
            for (int d = 0; d < 512; d++)
            {
                const IMAGE_IMPORT_DESCRIPTOR* desc = At<IMAGE_IMPORT_DESCRIPTOR>(b, n, off + d * sizeof(IMAGE_IMPORT_DESCRIPTOR));
                if (!desc || !desc->Name)
                    break;
                PeImportDll dll;
                char name[128];
                uint32_t noff = RvaToOff(pe, desc->Name);
                if (!ReadAscii(b, n, noff, name, 128))
                    snprintf(name, 128, "dll_%u", desc->Name);
                dll.name = name;
                dll.delay = false;
                dll.bound = desc->TimeDateStamp != 0 && desc->TimeDateStamp != 0xFFFFFFFFu;
                uint32_t thunk_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
                ParseOneThunkTable(b, n, pe, thunk_rva, &dll);
                pe->imports.push_back(std::move(dll));
            }
        }
    }

    if (pe->dd_n <= IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT || !pe->dd_rva[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT])
        return;
    uint32_t doff = RvaToOff(pe, pe->dd_rva[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]);
    if (!doff)
        return;
    pe->has_import = true;
    for (uint32_t d = 0; d < kMaxImportDescriptors; d++)
    {
        const IMAGE_DELAYLOAD_DESCRIPTOR* desc = At<IMAGE_DELAYLOAD_DESCRIPTOR>(b, n, doff + d * sizeof(IMAGE_DELAYLOAD_DESCRIPTOR));
        if (!desc || !desc->DllNameRVA)
            break;
        PeImportDll dll;
        dll.delay = true;
        dll.bound = desc->TimeDateStamp != 0;
        char name[128];
        uint32_t noff = RvaToOff(pe, desc->DllNameRVA);
        if (!ReadAscii(b, n, noff, name, 128))
            snprintf(name, 128, "delay_%u", desc->DllNameRVA);
        dll.name = name;
        uint32_t thunk_rva = desc->ImportNameTableRVA ? desc->ImportNameTableRVA : desc->ImportAddressTableRVA;
        ParseOneThunkTable(b, n, pe, thunk_rva, &dll);
        pe->imports.push_back(std::move(dll));
    }
}

static void ParseExports(const uint8_t* b, size_t n, PeFile* pe)
{
    if (pe->dd_n <= IMAGE_DIRECTORY_ENTRY_EXPORT)
        return;
    uint32_t rva = pe->dd_rva[IMAGE_DIRECTORY_ENTRY_EXPORT];
    uint32_t off = RvaToOff(pe, rva);
    const IMAGE_EXPORT_DIRECTORY* exp = At<IMAGE_EXPORT_DIRECTORY>(b, n, off);
    if (!exp || !exp->NumberOfFunctions)
        return;
    pe->has_export = true;
    uint32_t funcs = RvaToOff(pe, exp->AddressOfFunctions);
    uint32_t names = RvaToOff(pe, exp->AddressOfNames);
    uint32_t ords = RvaToOff(pe, exp->AddressOfNameOrdinals);
    uint32_t nfunc = exp->NumberOfFunctions;
    uint32_t nname = exp->NumberOfNames;
    if (nfunc > 8192)
        nfunc = 8192;
    if (nname > nfunc)
        nname = nfunc;
    std::vector<uint32_t> rvas(nfunc);
    for (uint32_t i = 0; i < nfunc; i++)
    {
        const uint32_t* p = At<uint32_t>(b, n, funcs + i * 4);
        rvas[i] = p ? *p : 0;
    }
    for (uint32_t i = 0; i < nname; i++)
    {
        const uint32_t* nr = At<uint32_t>(b, n, names + i * 4);
        const uint16_t* od = At<uint16_t>(b, n, ords + i * 2);
        if (!nr || !od)
            continue;
        PeExportFn e{};
        e.ordinal = exp->Base + *od;
        if (*od < nfunc)
            e.rva = rvas[*od];
        char fn[128];
        uint32_t no = RvaToOff(pe, *nr);
        if (ReadAscii(b, n, no, fn, 128))
            e.name = fn;
        if (e.rva >= rva && e.rva < rva + pe->dd_size[IMAGE_DIRECTORY_ENTRY_EXPORT])
        {
            e.forwarded = true;
            uint32_t fo = RvaToOff(pe, e.rva);
            if (!ReadAscii(b, n, fo, e.forwarder, (int)sizeof(e.forwarder)))
                e.forwarder[0] = 0;
        }
        pe->exports.push_back(std::move(e));
    }
}

static const char* RsrcTypeName(uint32_t id)
{
    switch (id)
    {
    case 1: return "CURSOR";
    case 2: return "BITMAP";
    case 3: return "ICON";
    case 4: return "MENU";
    case 5: return "DIALOG";
    case 6: return "STRING";
    case 7: return "FONTDIR";
    case 8: return "FONT";
    case 9: return "ACCELERATOR";
    case 10: return "RCDATA";
    case 11: return "MESSAGETABLE";
    case 12: return "GROUP_CURSOR";
    case 14: return "GROUP_ICON";
    case 16: return "VERSION";
    case 24: return "MANIFEST";
    default: return nullptr;
    }
}

static void ParseResources(const uint8_t* b, size_t n, PeFile* pe)
{
    if (pe->dd_n <= IMAGE_DIRECTORY_ENTRY_RESOURCE)
        return;
    uint32_t rva = pe->dd_rva[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    uint32_t root = RvaToOff(pe, rva);
    const IMAGE_RESOURCE_DIRECTORY* dir = At<IMAGE_RESOURCE_DIRECTORY>(b, n, root);
    if (!dir)
        return;
    pe->has_resource = true;
    int total = dir->NumberOfNamedEntries + dir->NumberOfIdEntries;
    if (total > 64)
        total = 64;
    size_t ent0 = root + sizeof(IMAGE_RESOURCE_DIRECTORY);
    for (int i = 0; i < total; i++)
    {
        const IMAGE_RESOURCE_DIRECTORY_ENTRY* e = At<IMAGE_RESOURCE_DIRECTORY_ENTRY>(b, n, ent0 + i * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
        if (!e)
            break;
        PeRsrcType t{};
        t.id = e->Id;
        const char* known = (!(e->NameIsString)) ? RsrcTypeName(e->Id) : nullptr;
        if (known)
            snprintf(t.name, sizeof(t.name), "%s", known);
        else if (e->NameIsString)
            snprintf(t.name, sizeof(t.name), "named");
        else
            snprintf(t.name, sizeof(t.name), "type_%u", e->Id);
        t.entries = 0;
        if (e->DataIsDirectory)
        {
            uint32_t suboff = root + e->OffsetToDirectory;
            const IMAGE_RESOURCE_DIRECTORY* sub = At<IMAGE_RESOURCE_DIRECTORY>(b, n, suboff);
            if (sub)
                t.entries = sub->NumberOfNamedEntries + sub->NumberOfIdEntries;
        }
        pe->rsrc_types.push_back(t);
    }
}

static void ReadRsrcStr(const uint8_t* b, size_t n, uint32_t root, uint32_t name_off, char* out, int cap)
{
    out[0] = 0;
    const IMAGE_RESOURCE_DIR_STRING_U* s = At<IMAGE_RESOURCE_DIR_STRING_U>(b, n, root + name_off);
    if (!s || !s->Length)
        return;
    int nch = s->Length;
    if (nch > cap - 1)
        nch = cap - 1;
    for (int i = 0; i < nch; i++)
    {
        wchar_t w = s->NameString[i];
        out[i] = (w >= 32 && w < 127) ? (char)w : '?';
    }
    out[nch] = 0;
}

static uint32_t Align4(uint32_t v) { return (v + 3u) & ~3u; }

static void WalkRsrc(const uint8_t* b, size_t n, PeFile* pe, uint32_t root, uint32_t dir_rel, int depth,
    const char* type_name, uint32_t type_id, const char* res_name, uint32_t res_id)
{
    // type / name / lang tree. same three-level walk as the spec.
    // credit: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section
    const IMAGE_RESOURCE_DIRECTORY* dir = At<IMAGE_RESOURCE_DIRECTORY>(b, n, root + dir_rel);
    if (!dir)
        return;
    int total = dir->NumberOfNamedEntries + dir->NumberOfIdEntries;
    if (total > 256)
        total = 256;
    size_t ent0 = root + dir_rel + sizeof(IMAGE_RESOURCE_DIRECTORY);
    for (int i = 0; i < total; i++)
    {
        const IMAGE_RESOURCE_DIRECTORY_ENTRY* e = At<IMAGE_RESOURCE_DIRECTORY_ENTRY>(b, n, ent0 + i * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
        if (!e)
            break;
        char label[64];
        uint32_t nid = 0;
        if (e->NameIsString)
            ReadRsrcStr(b, n, root, e->NameOffset, label, 64);
        else
        {
            nid = e->Id;
            snprintf(label, 64, "%u", e->Id);
        }

        char tname[48];
        uint32_t tid = type_id;
        char nname[64];
        uint32_t rid = res_id;
        snprintf(tname, sizeof(tname), "%s", type_name);
        snprintf(nname, sizeof(nname), "%s", res_name);
        if (depth == 0)
        {
            tid = e->NameIsString ? 0 : e->Id;
            const char* kn = (!e->NameIsString) ? RsrcTypeName(e->Id) : nullptr;
            snprintf(tname, sizeof(tname), "%s", kn ? kn : label);
        }
        else if (depth == 1)
        {
            rid = nid;
            snprintf(nname, sizeof(nname), "%s", label);
        }

        if (e->DataIsDirectory && depth < 2)
        {
            WalkRsrc(b, n, pe, root, e->OffsetToDirectory, depth + 1, tname, tid, nname, rid);
            continue;
        }
        if (e->DataIsDirectory)
            continue;
        const IMAGE_RESOURCE_DATA_ENTRY* de = At<IMAGE_RESOURCE_DATA_ENTRY>(b, n, root + e->OffsetToData);
        if (!de)
            continue;

        PeRsrcLeaf leaf{};
        leaf.type_id = tid;
        snprintf(leaf.type_name, sizeof(leaf.type_name), "%s", tname);
        leaf.name_id = rid;
        snprintf(leaf.name, sizeof(leaf.name), "%s", nname[0] ? nname : label);
        leaf.lang = (uint16_t)(e->NameIsString ? 0 : e->Id);
        leaf.rva = de->OffsetToData;
        leaf.size = de->Size;
        leaf.file_off = RvaToOff(pe, de->OffsetToData);
        if (pe->rsrc.size() < 1024)
            pe->rsrc.push_back(leaf);

        if (_stricmp(tname, "TYPELIB") == 0 && pe->typelibs.size() < 16)
        {
            PeTypelib t{};
            snprintf(t.name, sizeof(t.name), "%s", leaf.name);
            t.size = leaf.size;
            t.file_off = leaf.file_off;
            t.msft = false;
            t.version = 0;
            if (t.file_off && t.file_off + 8 <= n)
            {
                uint32_t mag = *(const uint32_t*)(b + t.file_off);
                t.msft = (mag == 0x5446534D); // "MSFT"
                // credit: https://gitlab.winehq.org/wine/wine/-/blob/master/dlls/oleaut32/typelib.h
                if (t.msft)
                    t.version = *(const uint32_t*)(b + t.file_off + 4);
            }
            pe->typelibs.push_back(t);
        }
    }
}

static bool VerReadKey(const uint8_t* b, size_t n, uint32_t off, char* out, int cap, uint32_t* after)
{
    out[0] = 0;
    if (off + 2 > n)
        return false;
    int nch = 0;
    while (off + (uint32_t)(nch + 1) * 2u <= n && nch < 260)
    {
        wchar_t c = *(const wchar_t*)(b + off + nch * 2);
        nch++;
        if (!c)
            break;
    }
    WideCharToMultiByte(CP_UTF8, 0, (const wchar_t*)(b + off), nch, out, cap, nullptr, nullptr);
    if (cap > 0)
        out[cap - 1] = 0;
    if (after)
        *after = Align4(off + (uint32_t)nch * 2u);
    return true;
}

static void ParseVerStrings(const uint8_t* b, size_t n, uint32_t pos, uint32_t end, PeVerInfo* vi)
{
    // VS_VERSIONINFO / StringFileInfo tree
    // credit: https://learn.microsoft.com/en-us/windows/win32/menurc/vs-versioninfo
    while (pos + 6 <= end && vi->strings.size() < 48)
    {
        uint16_t len = *(const uint16_t*)(b + pos);
        uint16_t vlen = *(const uint16_t*)(b + pos + 2);
        uint16_t type = *(const uint16_t*)(b + pos + 4);
        if (len < 6)
            break;
        uint32_t node_end = pos + len;
        if (node_end > end)
            break;
        char key[64];
        uint32_t after = 0;
        if (!VerReadKey(b, n, pos + 6, key, 64, &after))
            break;
        uint32_t val_off = after;
        if (type == 1 && vlen > 0 && val_off + 2 <= node_end)
        {
            PeVerString s{};
            snprintf(s.key, sizeof(s.key), "%s", key);
            uint32_t nbytes = (uint32_t)vlen * 2u;
            if (val_off + nbytes > node_end)
                nbytes = node_end - val_off;
            WideCharToMultiByte(CP_UTF8, 0, (const wchar_t*)(b + val_off), (int)(nbytes / 2), s.value, (int)sizeof(s.value), nullptr, nullptr);
            s.value[sizeof(s.value) - 1] = 0;
            s.node_off = pos;
            s.value_off = val_off;
            s.value_cap = node_end - val_off;
            vi->strings.push_back(s);
        }
        else
            ParseVerStrings(b, n, val_off, node_end, vi);
        uint32_t next = Align4(node_end);
        if (next <= pos)
            break;
        pos = next;
    }
}

static void ParseVersionLeaf(const uint8_t* b, size_t n, const PeRsrcLeaf& leaf, PeFile* pe)
{
    if (!leaf.file_off || leaf.file_off + 6 > n || !leaf.size)
        return;
    uint32_t pos = leaf.file_off;
    uint32_t end = leaf.file_off + leaf.size;
    if (end > n)
        end = (uint32_t)n;
    uint16_t len = *(const uint16_t*)(b + pos);
    uint16_t vlen = *(const uint16_t*)(b + pos + 2);
    if (len < 6)
        return;
    uint32_t node_end = pos + len;
    if (node_end > end)
        node_end = end;
    char key[64];
    uint32_t after = 0;
    if (!VerReadKey(b, n, pos + 6, key, 64, &after))
        return;
    PeVerInfo vi{};
    vi.ok = true;
    vi.file_off = leaf.file_off;
    vi.size = leaf.size;
    snprintf(vi.name, sizeof(vi.name), "%s", leaf.name);
    if (vlen >= 52 && after + 52 <= node_end)
    {
        const uint8_t* ffi = b + after;
        if (*(const uint32_t*)ffi == 0xFEEF04BD)
        {
            vi.ffi_off = after;
            uint32_t fms = *(const uint32_t*)(ffi + 8);
            uint32_t fls = *(const uint32_t*)(ffi + 12);
            uint32_t pms = *(const uint32_t*)(ffi + 16);
            uint32_t pls = *(const uint32_t*)(ffi + 20);
            vi.file[0] = (uint16_t)(fms >> 16);
            vi.file[1] = (uint16_t)(fms & 0xffff);
            vi.file[2] = (uint16_t)(fls >> 16);
            vi.file[3] = (uint16_t)(fls & 0xffff);
            vi.prod[0] = (uint16_t)(pms >> 16);
            vi.prod[1] = (uint16_t)(pms & 0xffff);
            vi.prod[2] = (uint16_t)(pls >> 16);
            vi.prod[3] = (uint16_t)(pls & 0xffff);
        }
    }
    uint32_t kids = Align4(after + vlen);
    ParseVerStrings(b, n, kids, node_end, &vi);
    if (pe->versions.size() < 8)
        pe->versions.push_back(std::move(vi));
}

static void IconGeom(const uint8_t* p, uint32_t n, PeIconImg* ic)
{
    ic->w = 0;
    ic->h = 0;
    ic->bpp = 0;
    ic->png = false;
    if (n >= 8 && p[0] == 0x89 && p[1] == 'P' && p[2] == 'N' && p[3] == 'G')
    {
        ic->png = true;
        if (n >= 24)
        {
            ic->w = (int)((p[16] << 24) | (p[17] << 16) | (p[18] << 8) | p[19]);
            ic->h = (int)((p[20] << 24) | (p[21] << 16) | (p[22] << 8) | p[23]);
            ic->bpp = 32;
        }
        return;
    }
    if (n < 16)
        return;
    const BITMAPINFOHEADER* bi = (const BITMAPINFOHEADER*)p;
    if (bi->biSize < 12)
        return;
    ic->w = (int)bi->biWidth;
    int h = (int)bi->biHeight;
    if (h < 0)
        h = -h;
    ic->h = h / 2;
    if (ic->h <= 0)
        ic->h = h;
    ic->bpp = (int)bi->biBitCount;
}

static const PeRsrcLeaf* FindIconLeaf(const PeFile* pe, uint16_t id, uint16_t lang)
{
    const PeRsrcLeaf* fallback = nullptr;
    for (const PeRsrcLeaf& L : pe->rsrc)
    {
        if (L.type_id != 3)
            continue;
        if (L.name_id != id)
            continue;
        if (L.lang == lang)
            return &L;
        if (!fallback)
            fallback = &L;
    }
    return fallback;
}

static void ParseIcons(const uint8_t* b, size_t n, PeFile* pe)
{
#pragma pack(push, 1)
    struct GrpEntry
    {
        uint8_t  w, h, colors, reserved;
        uint16_t planes, bpp;
        uint32_t bytes;
        uint16_t id;
    };
#pragma pack(pop)

    for (const PeRsrcLeaf& L : pe->rsrc)
    {
        bool grp = (L.type_id == 14) || (_stricmp(L.type_name, "GROUP_ICON") == 0);
        if (!grp || L.file_off + 6 > n)
            continue;
        uint16_t count = *(const uint16_t*)(b + L.file_off + 4);
        if (count > 64)
            count = 64;
        uint32_t off = L.file_off + 6;
        for (uint16_t i = 0; i < count; i++)
        {
            if (off + sizeof(GrpEntry) > n)
                break;
            const GrpEntry* e = (const GrpEntry*)(b + off);
            off += sizeof(GrpEntry);
            const PeRsrcLeaf* raw = FindIconLeaf(pe, e->id, L.lang);
            if (!raw || !raw->file_off)
                continue;
            PeIconImg ic{};
            ic.id = e->id;
            ic.lang = L.lang;
            ic.file_off = raw->file_off;
            ic.size = raw->size;
            if (raw->file_off + raw->size <= n)
                IconGeom(b + raw->file_off, raw->size, &ic);
            if (!ic.w)
                ic.w = e->w ? e->w : 256;
            if (!ic.h)
                ic.h = e->h ? e->h : 256;
            if (!ic.bpp)
                ic.bpp = e->bpp;
            if (pe->icons.size() < 128)
                pe->icons.push_back(ic);
        }
    }
    if (!pe->icons.empty())
        return;
    for (const PeRsrcLeaf& L : pe->rsrc)
    {
        if (L.type_id != 3 || !L.file_off)
            continue;
        PeIconImg ic{};
        ic.id = (uint16_t)L.name_id;
        ic.lang = L.lang;
        ic.file_off = L.file_off;
        ic.size = L.size;
        if (L.file_off + L.size <= n)
            IconGeom(b + L.file_off, L.size, &ic);
        if (pe->icons.size() < 128)
            pe->icons.push_back(ic);
    }
}

static void ParseClr(const uint8_t* b, size_t n, PeFile* pe)
{
    // IMAGE_COR20_HEADER / COMIMAGE_FLAGS
    // credit: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-cor20-header-image-only
    if (!pe->has_com)
        return;
    uint32_t off = RvaToOff(pe, pe->dd_rva[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR]);
    const IMAGE_COR20_HEADER* h = At<IMAGE_COR20_HEADER>(b, n, off);
    if (!h || h->cb < 16)
        return;
    pe->clr_off = off;
    pe->clr_major = h->MajorRuntimeVersion;
    pe->clr_minor = h->MinorRuntimeVersion;
    pe->clr_flags = h->Flags;
    pe->clr_entry = h->EntryPointToken;
}

bool PeAddrFromRva(const PeFile* pe, uint32_t rva, PeAddr* out)
{
    if (!pe || !out)
        return false;
    *out = PeAddr{};
    out->rva = rva;
    out->va = pe->image_base + rva;
    out->section_index = -1;
    for (int i = 0; i < pe->section_n; i++)
    {
        uint32_t va = pe->sections[i].vaddr;
        uint32_t span = pe->sections[i].vsize;
        if (pe->sections[i].rawsize > span)
            span = pe->sections[i].rawsize;
        if (span == 0)
            continue;
        if (rva >= va && rva < va + span)
        {
            out->section_index = i;
            memcpy(out->section_name, pe->sections[i].name, 9);
            uint32_t delta = rva - va;
            if (pe->sections[i].rawptr && delta < pe->sections[i].rawsize)
            {
                out->file_off = (uint64_t)pe->sections[i].rawptr + delta;
                out->valid = true;
            }
            return true;
        }
    }
    if (rva < pe->size_of_headers)
    {
        out->file_off = rva;
        out->valid = true;
        return true;
    }
    return false;
}

static uint32_t ComputePeChecksum(const uint8_t* b, size_t n, uint64_t checksum_field_offset)
{
    uint32_t sum = 0;
    uint64_t offset = 0;
    while (offset + 1 < n)
    {
        if (offset >= checksum_field_offset && offset < checksum_field_offset + 4)
        {
            offset += 2;
            continue;
        }
        uint16_t word = (uint16_t)b[offset] | ((uint16_t)b[offset + 1] << 8);
        sum += word;
        sum = (sum & 0xFFFFu) + (sum >> 16);
        offset += 2;
    }
    if (offset < n && !(offset >= checksum_field_offset && offset < checksum_field_offset + 4))
    {
        sum += b[offset];
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    sum = (sum & 0xFFFFu) + (sum >> 16);
    sum = (sum & 0xFFFFu) + (sum >> 16);
    return sum + (uint32_t)n;
}

static double ShannonEntropy(const uint8_t* data, uint64_t size)
{
    if (!data || size == 0)
        return 0.0;
    uint64_t counts[256] = {};
    for (uint64_t i = 0; i < size; i++)
        counts[data[i]]++;
    double entropy = 0.0;
    double nn = (double)size;
    for (int i = 0; i < 256; i++)
    {
        if (!counts[i])
            continue;
        double p = (double)counts[i] / nn;
        entropy -= p * log2(p);
    }
    return entropy;
}

static void PushEntropy(PeFile* pe, const char* label, uint64_t off, uint64_t size, const uint8_t* b, size_t n)
{
    PeEntropyRange r{};
    snprintf(r.label, sizeof(r.label), "%s", label);
    r.offset = off;
    r.size = size;
    if (off < n && size && off + size <= n)
        r.entropy = ShannonEntropy(b + (size_t)off, size);
    pe->entropy.push_back(r);
}

static void ParseRelocs(const uint8_t* b, size_t n, PeFile* pe)
{
    if (pe->dd_n <= IMAGE_DIRECTORY_ENTRY_BASERELOC || !pe->dd_rva[IMAGE_DIRECTORY_ENTRY_BASERELOC])
        return;
    uint32_t rva = pe->dd_rva[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    uint32_t dir_size = pe->dd_size[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    uint32_t consumed = 0;
    uint32_t blocks = 0;
    while (consumed + sizeof(IMAGE_BASE_RELOCATION) <= dir_size && blocks < kMaxRelocBlocks)
    {
        uint32_t off = RvaToOff(pe, rva + consumed);
        const IMAGE_BASE_RELOCATION* block = At<IMAGE_BASE_RELOCATION>(b, n, off);
        if (!block || block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION))
            break;
        if (consumed + block->SizeOfBlock > dir_size)
            break;
        PeRelocBlock parsed{};
        parsed.page_rva = block->VirtualAddress;
        parsed.block_size = block->SizeOfBlock;
        uint32_t entry_count = (block->SizeOfBlock - (uint32_t)sizeof(IMAGE_BASE_RELOCATION)) / 2u;
        uint32_t store = entry_count < kMaxRelocEntriesPerBlock ? entry_count : kMaxRelocEntriesPerBlock;
        for (uint32_t i = 0; i < entry_count; i++)
        {
            const uint16_t* ep = At<uint16_t>(b, n, off + sizeof(IMAGE_BASE_RELOCATION) + i * 2);
            if (!ep)
                break;
            uint8_t type = (uint8_t)(*ep >> 12);
            uint16_t rel_off = (uint16_t)(*ep & 0x0FFF);
            if (type == IMAGE_REL_BASED_ABSOLUTE)
                parsed.type_absolute++;
            else if (type == IMAGE_REL_BASED_HIGHLOW)
                parsed.type_highlow++;
            else if (type == IMAGE_REL_BASED_DIR64)
                parsed.type_dir64++;
            else
                parsed.type_other++;
            if (i < store)
            {
                PeRelocEntry re{};
                re.type = type;
                re.offset = rel_off;
                re.rva = block->VirtualAddress + rel_off;
                PeAddr a;
                if (PeAddrFromRva(pe, re.rva, &a) && a.valid)
                    re.file_off = (uint32_t)a.file_off;
                parsed.entries.push_back(re);
            }
        }
        pe->relocs.push_back(std::move(parsed));
        consumed += block->SizeOfBlock;
        blocks++;
    }
}

static void ParseTls(const uint8_t* b, size_t n, PeFile* pe)
{
    if (pe->dd_n <= IMAGE_DIRECTORY_ENTRY_TLS || !pe->dd_rva[IMAGE_DIRECTORY_ENTRY_TLS])
        return;
    uint32_t off = RvaToOff(pe, pe->dd_rva[IMAGE_DIRECTORY_ENTRY_TLS]);
    uint64_t callbacks_va = 0;
    if (pe->pe32plus)
    {
        const IMAGE_TLS_DIRECTORY64* raw = At<IMAGE_TLS_DIRECTORY64>(b, n, off);
        if (!raw)
            return;
        pe->tls.start_raw = raw->StartAddressOfRawData;
        pe->tls.end_raw = raw->EndAddressOfRawData;
        pe->tls.index_va = raw->AddressOfIndex;
        pe->tls.callbacks_va = raw->AddressOfCallBacks;
        pe->tls.zero_fill = raw->SizeOfZeroFill;
        pe->tls.chars = raw->Characteristics;
        callbacks_va = raw->AddressOfCallBacks;
    }
    else
    {
        const IMAGE_TLS_DIRECTORY32* raw = At<IMAGE_TLS_DIRECTORY32>(b, n, off);
        if (!raw)
            return;
        pe->tls.start_raw = raw->StartAddressOfRawData;
        pe->tls.end_raw = raw->EndAddressOfRawData;
        pe->tls.index_va = raw->AddressOfIndex;
        pe->tls.callbacks_va = raw->AddressOfCallBacks;
        pe->tls.zero_fill = raw->SizeOfZeroFill;
        pe->tls.chars = raw->Characteristics;
        callbacks_va = raw->AddressOfCallBacks;
    }
    pe->tls.present = true;
    pe->has_tls = true;
    if (callbacks_va < pe->image_base)
        return;
    uint32_t cb_rva = (uint32_t)(callbacks_va - pe->image_base);
    uint32_t ptr_size = pe->pe32plus ? 8u : 4u;
    for (uint32_t i = 0; i < kMaxTlsCallbacks; i++)
    {
        uint32_t slot = RvaToOff(pe, cb_rva + i * ptr_size);
        if (!slot)
            break;
        uint64_t value = 0;
        if (pe->pe32plus)
        {
            const uint64_t* v = At<uint64_t>(b, n, slot);
            if (!v || *v == 0)
                break;
            value = *v;
        }
        else
        {
            const uint32_t* v = At<uint32_t>(b, n, slot);
            if (!v || *v == 0)
                break;
            value = *v;
        }
        if (value >= pe->image_base)
            pe->tls.callback_rvas.push_back((uint32_t)(value - pe->image_base));
    }
}

static const char* DebugTypeName(uint32_t type)
{
    switch (type)
    {
    case IMAGE_DEBUG_TYPE_COFF: return "COFF";
    case IMAGE_DEBUG_TYPE_CODEVIEW: return "CODEVIEW";
    case IMAGE_DEBUG_TYPE_FPO: return "FPO";
    case IMAGE_DEBUG_TYPE_MISC: return "MISC";
    case IMAGE_DEBUG_TYPE_EXCEPTION: return "EXCEPTION";
    case IMAGE_DEBUG_TYPE_FIXUP: return "FIXUP";
    case IMAGE_DEBUG_TYPE_OMAP_TO_SRC: return "OMAP_TO_SRC";
    case IMAGE_DEBUG_TYPE_OMAP_FROM_SRC: return "OMAP_FROM_SRC";
    case IMAGE_DEBUG_TYPE_BORLAND: return "BORLAND";
    case IMAGE_DEBUG_TYPE_CLSID: return "CLSID";
    case IMAGE_DEBUG_TYPE_VC_FEATURE: return "VC_FEATURE";
    case IMAGE_DEBUG_TYPE_POGO: return "POGO";
    case IMAGE_DEBUG_TYPE_ILTCG: return "ILTCG";
    case IMAGE_DEBUG_TYPE_REPRO: return "REPRO";
    default: return "OTHER";
    }
}

static void ParseDebug(const uint8_t* b, size_t n, PeFile* pe)
{
    if (pe->dd_n <= IMAGE_DIRECTORY_ENTRY_DEBUG || !pe->dd_rva[IMAGE_DIRECTORY_ENTRY_DEBUG])
        return;
    uint32_t off = RvaToOff(pe, pe->dd_rva[IMAGE_DIRECTORY_ENTRY_DEBUG]);
    uint32_t count = pe->dd_size[IMAGE_DIRECTORY_ENTRY_DEBUG] / (uint32_t)sizeof(IMAGE_DEBUG_DIRECTORY);
    if (count > kMaxDebugEntries)
        count = kMaxDebugEntries;
    pe->pdb_path[0] = 0;
    for (uint32_t i = 0; i < count; i++)
    {
        const IMAGE_DEBUG_DIRECTORY* raw = At<IMAGE_DEBUG_DIRECTORY>(b, n, off + i * sizeof(IMAGE_DEBUG_DIRECTORY));
        if (!raw)
            break;
        PeDebugEntry e{};
        e.type = raw->Type;
        snprintf(e.type_name, sizeof(e.type_name), "%s", DebugTypeName(raw->Type));
        e.timestamp = raw->TimeDateStamp;
        e.size = raw->SizeOfData;
        e.rva = raw->AddressOfRawData;
        e.file_off = raw->PointerToRawData;
        if (raw->Type == IMAGE_DEBUG_TYPE_CODEVIEW && raw->PointerToRawData && raw->SizeOfData >= 24)
        {
            const uint32_t* sig = At<uint32_t>(b, n, raw->PointerToRawData);
            if (sig && *sig == 0x53445352)
                ReadAscii(b, n, raw->PointerToRawData + 24, pe->pdb_path, (int)sizeof(pe->pdb_path));
            else if (sig && *sig == 0x3031424E)
                ReadAscii(b, n, raw->PointerToRawData + 16, pe->pdb_path, (int)sizeof(pe->pdb_path));
            snprintf(e.extra, sizeof(e.extra), "%s", pe->pdb_path);
        }
        pe->debug.push_back(e);
    }
}

static bool AsciiPrintable(uint8_t c)
{
    return c == '\t' || (c >= 0x20 && c <= 0x7E);
}

static void ExtractStrings(const uint8_t* b, size_t n, PeFile* pe)
{
    std::string ascii;
    uint64_t ascii_start = 0;
    auto flush_ascii = [&]() {
        if (ascii.size() >= kMinExtractedStringLength && pe->strings.size() < kMaxExtractedStrings)
        {
            if (ascii.size() > kMaxExtractedStringChars)
                ascii.resize(kMaxExtractedStringChars);
            PeStringEntry s;
            s.file_off = ascii_start;
            s.utf16 = false;
            s.text = std::move(ascii);
            pe->strings.push_back(std::move(s));
        }
        ascii.clear();
    };
    for (size_t i = 0; i < n; i++)
    {
        if (AsciiPrintable(b[i]))
        {
            if (ascii.empty())
                ascii_start = i;
            ascii.push_back((char)b[i]);
        }
        else
            flush_ascii();
        if (pe->strings.size() >= kMaxExtractedStrings)
            return;
    }
    flush_ascii();

    std::string utf16;
    uint64_t utf_start = 0;
    auto flush_utf = [&]() {
        if (utf16.size() >= kMinExtractedStringLength && pe->strings.size() < kMaxExtractedStrings)
        {
            if (utf16.size() > kMaxExtractedStringChars)
                utf16.resize(kMaxExtractedStringChars);
            PeStringEntry s;
            s.file_off = utf_start;
            s.utf16 = true;
            s.text = std::move(utf16);
            pe->strings.push_back(std::move(s));
        }
        utf16.clear();
    };
    for (size_t i = 0; i + 1 < n; i++)
    {
        if (b[i + 1] == 0 && AsciiPrintable(b[i]))
        {
            if (utf16.empty())
                utf_start = i;
            utf16.push_back((char)b[i]);
            i++;
        }
        else
            flush_utf();
        if (pe->strings.size() >= kMaxExtractedStrings)
            return;
    }
    flush_utf();
}

bool PeParse(const uint8_t* data, size_t n, PeFile* out, std::atomic<float>* progress)
{
    *out = PeFile{};
    out->ok = false;
    out->size = n;
    if (!data || n < sizeof(IMAGE_DOS_HEADER))
    {
        snprintf(out->error, sizeof(out->error), "too small for a DOS header");
        return false;
    }
    if (progress)
        progress->store(0.05f);

    const IMAGE_DOS_HEADER* dos = At<IMAGE_DOS_HEADER>(data, n, 0);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        snprintf(out->error, sizeof(out->error), "not MZ");
        return false;
    }
    out->e_lfanew = (uint32_t)dos->e_lfanew;
    if (out->e_lfanew < sizeof(IMAGE_DOS_HEADER) || out->e_lfanew + 4 >= n)
    {
        snprintf(out->error, sizeof(out->error), "e_lfanew is junk");
        return false;
    }

    HashFile(data, n, out, progress);
    if (progress)
        progress->store(0.28f);

    ParseRich(data, n, out->e_lfanew, out);

    const uint32_t* sig = At<uint32_t>(data, n, out->e_lfanew);
    if (!sig || *sig != IMAGE_NT_SIGNATURE)
    {
        snprintf(out->error, sizeof(out->error), "no PE signature");
        return false;
    }

    const IMAGE_FILE_HEADER* fh = At<IMAGE_FILE_HEADER>(data, n, out->e_lfanew + 4);
    if (!fh)
    {
        snprintf(out->error, sizeof(out->error), "truncated file header");
        return false;
    }
    out->machine = fh->Machine;
    out->sections_n = fh->NumberOfSections;
    out->timestamp = fh->TimeDateStamp;
    out->opt_size = fh->SizeOfOptionalHeader;
    out->chars = fh->Characteristics;
    MachineName(out->machine, out->machine_s, 32);

    size_t opt_off = out->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER);
    const uint16_t* magic = At<uint16_t>(data, n, opt_off);
    if (!magic)
    {
        snprintf(out->error, sizeof(out->error), "truncated optional header");
        return false;
    }
    out->magic = *magic;
    out->pe32plus = (*magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    auto take_dd = [&](const IMAGE_DATA_DIRECTORY* dd, int count)
    {
        out->dd_n = count > 16 ? 16 : count;
        for (int i = 0; i < out->dd_n; i++)
        {
            out->dd_rva[i] = dd[i].VirtualAddress;
            out->dd_size[i] = dd[i].Size;
        }
    };

    if (out->pe32plus)
    {
        const IMAGE_OPTIONAL_HEADER64* oh = At<IMAGE_OPTIONAL_HEADER64>(data, n, opt_off);
        if (!oh)
        {
            snprintf(out->error, sizeof(out->error), "truncated PE32+ optional");
            return false;
        }
        out->entry_rva = oh->AddressOfEntryPoint;
        out->image_base = oh->ImageBase;
        out->linker_major = oh->MajorLinkerVersion;
        out->linker_minor = oh->MinorLinkerVersion;
        out->section_align = oh->SectionAlignment;
        out->file_align = oh->FileAlignment;
        out->size_of_image = oh->SizeOfImage;
        out->size_of_headers = oh->SizeOfHeaders;
        out->checksum = oh->CheckSum;
        out->subsystem = oh->Subsystem;
        out->dllchars = oh->DllCharacteristics;
        out->size_of_stack_res = (uint32_t)oh->SizeOfStackReserve;
        out->size_of_heap_res = (uint32_t)oh->SizeOfHeapReserve;
        take_dd(oh->DataDirectory, oh->NumberOfRvaAndSizes);
    }
    else if (*magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        const IMAGE_OPTIONAL_HEADER32* oh = At<IMAGE_OPTIONAL_HEADER32>(data, n, opt_off);
        if (!oh)
        {
            snprintf(out->error, sizeof(out->error), "truncated PE32 optional");
            return false;
        }
        out->entry_rva = oh->AddressOfEntryPoint;
        out->image_base = oh->ImageBase;
        out->linker_major = oh->MajorLinkerVersion;
        out->linker_minor = oh->MinorLinkerVersion;
        out->section_align = oh->SectionAlignment;
        out->file_align = oh->FileAlignment;
        out->size_of_image = oh->SizeOfImage;
        out->size_of_headers = oh->SizeOfHeaders;
        out->checksum = oh->CheckSum;
        out->subsystem = oh->Subsystem;
        out->dllchars = oh->DllCharacteristics;
        out->size_of_stack_res = oh->SizeOfStackReserve;
        out->size_of_heap_res = oh->SizeOfHeapReserve;
        take_dd(oh->DataDirectory, oh->NumberOfRvaAndSizes);
    }
    else
    {
        snprintf(out->error, sizeof(out->error), "optional magic 0x%04x not PE", out->magic);
        return false;
    }
    SubsystemName(out->subsystem, out->subsystem_s, 32);
    {
        uint64_t csum_off = (uint64_t)opt_off + 64;
        out->checksum_computed = ComputePeChecksum(data, n, csum_off);
        out->checksum_ok = (out->checksum == 0) || (out->checksum == out->checksum_computed);
    }
    if (progress)
        progress->store(0.45f);

    size_t sec_off = opt_off + out->opt_size;
    int ns = out->sections_n;
    if (ns > 96)
        ns = 96;
    out->section_n = 0;
    uint32_t max_raw = 0;
    for (int i = 0; i < ns; i++)
    {
        const IMAGE_SECTION_HEADER* sh = At<IMAGE_SECTION_HEADER>(data, n, sec_off + i * sizeof(IMAGE_SECTION_HEADER));
        if (!sh)
            break;
        PeSection& s = out->sections[out->section_n++];
        memset(s.name, 0, sizeof(s.name));
        memcpy(s.name, sh->Name, 8);
        for (int c = 0; c < 8; c++)
            if (s.name[c] < 32)
                s.name[c] = 0;
        s.vsize = sh->Misc.VirtualSize;
        s.vaddr = sh->VirtualAddress;
        s.rawsize = sh->SizeOfRawData;
        s.rawptr = sh->PointerToRawData;
        s.chars = sh->Characteristics;
        uint32_t end = s.rawptr + s.rawsize;
        if (end > max_raw)
            max_raw = end;
    }
    if ((uint64_t)max_raw < n)
    {
        out->overlay_off = max_raw;
        out->overlay_size = n - max_raw;
    }

    if (out->dd_n > IMAGE_DIRECTORY_ENTRY_BASERELOC && out->dd_rva[IMAGE_DIRECTORY_ENTRY_BASERELOC])
        out->has_reloc = true;
    if (out->dd_n > IMAGE_DIRECTORY_ENTRY_TLS && out->dd_rva[IMAGE_DIRECTORY_ENTRY_TLS])
        out->has_tls = true;
    if (out->dd_n > IMAGE_DIRECTORY_ENTRY_DEBUG && out->dd_rva[IMAGE_DIRECTORY_ENTRY_DEBUG])
        out->has_debug = true;
    if (out->dd_n > IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG && out->dd_rva[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG])
        out->has_loadcfg = true;
    if (out->dd_n > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR && out->dd_rva[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR])
        out->has_com = true;

    if (progress)
        progress->store(0.62f);
    ParseImports(data, n, out);
    ImpHash(out);
    if (progress)
        progress->store(0.78f);
    ParseExports(data, n, out);
    if (progress)
        progress->store(0.88f);
    ParseResources(data, n, out);
    uint32_t rroot = 0;
    if (out->dd_n > IMAGE_DIRECTORY_ENTRY_RESOURCE)
        rroot = RvaToOff(out, out->dd_rva[IMAGE_DIRECTORY_ENTRY_RESOURCE]);
    if (rroot)
        WalkRsrc(data, n, out, rroot, 0, 0, "", 0, "", 0);
    for (const PeRsrcLeaf& L : out->rsrc)
    {
        if (L.type_id == 16 || _stricmp(L.type_name, "VERSION") == 0)
            ParseVersionLeaf(data, n, L, out);
    }
    ParseIcons(data, n, out);
    ParseClr(data, n, out);
    if (progress)
        progress->store(0.90f);
    ParseRelocs(data, n, out);
    ParseTls(data, n, out);
    ParseDebug(data, n, out);
    PushEntropy(out, "Entire file", 0, n, data, n);
    for (int i = 0; i < out->section_n; i++)
        PushEntropy(out, out->sections[i].name[0] ? out->sections[i].name : "(unnamed)",
            out->sections[i].rawptr, out->sections[i].rawsize, data, n);
    if (out->overlay_size)
        PushEntropy(out, "Overlay", out->overlay_off, out->overlay_size, data, n);
    if (progress)
        progress->store(0.95f);
    ExtractStrings(data, n, out);
    out->ok = true;
    DetectApplyToPe(out, data, n);
    AnalyzeRun(out, data, n);
    PeCollectFindings(out);
    if (progress)
        progress->store(1.f);
    return true;
}

enum
{
    JobIdle = 0,
    JobRun,
    JobDone,
    JobFail
};

static std::mutex          g_mu;
static std::thread         g_th;
static std::atomic<int>    g_state{ JobIdle };
static std::atomic<float>  g_prog{ 0.f };
static PeFile              g_file;
static char                g_path[MAX_PATH];
static char                g_err[256];
static std::vector<uint8_t> g_bytes;
static bool                g_dirty;

static void JobThread(std::string path)
{
    LogInfo(LogBuiltinAnalyzer, "Analysis started");
    g_prog.store(0.02f);
    wchar_t wpath[MAX_PATH];
    if (!MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, wpath, MAX_PATH))
    {
        snprintf(g_err, sizeof(g_err), "path utf-8 failed");
        LogError(LogBuiltinPeAnalyzer, "Path UTF-8 conversion failed");
        g_state.store(JobFail);
        return;
    }
    HANDLE h = CreateFileW(wpath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        snprintf(g_err, sizeof(g_err), "open failed (%lu)", GetLastError());
        LogError(LogBuiltinPeAnalyzer, "Open failed (%lu)", GetLastError());
        g_state.store(JobFail);
        return;
    }
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || (uint64_t)sz.QuadPart > kMaxFile)
    {
        CloseHandle(h);
        snprintf(g_err, sizeof(g_err), "bad size");
        LogError(LogBuiltinPeAnalyzer, "Invalid file size");
        g_state.store(JobFail);
        return;
    }
    std::vector<uint8_t> buf((size_t)sz.QuadPart);
    DWORD got = 0;
    size_t off = 0;
    while (off < buf.size())
    {
        DWORD chunk = (DWORD)((buf.size() - off > 1024 * 1024) ? 1024 * 1024 : (buf.size() - off));
        if (!ReadFile(h, buf.data() + off, chunk, &got, nullptr) || !got)
            break;
        off += got;
        g_prog.store(0.02f + 0.06f * (float)off / (float)buf.size());
    }
    CloseHandle(h);
    if (off != buf.size())
    {
        snprintf(g_err, sizeof(g_err), "short read");
        LogError(LogBuiltinPeAnalyzer, "Short read (%zu / %zu)", off, buf.size());
        g_state.store(JobFail);
        return;
    }
    LogDebug(LogBuiltinPeAnalyzer, "Read %zu bytes", buf.size());

    LogInfo(LogBuiltinPeAnalyzer, "Parsing PE");
    PeFile local;
    if (!PeParse(buf.data(), buf.size(), &local, &g_prog))
    {
        std::lock_guard<std::mutex> lock(g_mu);
        g_file = local;
        snprintf(g_err, sizeof(g_err), "%s", local.error);
        LogError(LogBuiltinPeAnalyzer, "Parse failed: %s", local.error[0] ? local.error : "unknown");
        g_state.store(JobFail);
        return;
    }
    uint32_t sec_n = 0;
    size_t imp_n = 0;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        g_file = std::move(local);
        snprintf(g_file.path, sizeof(g_file.path), "%s", path.c_str());
        g_bytes = std::move(buf);
        g_dirty = false;
        g_err[0] = 0;
        sec_n = g_file.section_n;
        imp_n = g_file.imports.size();
        PatchJournalLoad(g_bytes.data(), g_bytes.size());
    }
    LogSuccess(LogBuiltinAnalyzer, "Analysis completed (%u sections, %zu imports)", sec_n, imp_n);
    g_state.store(JobDone);
}

void PeJobStart(const char* path)
{
    PeJobShutdown();
    PatchJournalReset();
    if (!path || !path[0])
        return;
    snprintf(g_path, MAX_PATH, "%s", path);
    g_err[0] = 0;
    g_prog.store(0.f);
    g_state.store(JobRun);
    g_th = std::thread(JobThread, std::string(path));
}

void PeJobShutdown()
{
    if (g_th.joinable())
        g_th.join();
    g_state.store(JobIdle);
}

bool        PeJobBusy() { return g_state.load() == JobRun; }
bool        PeJobDone() { return g_state.load() == JobDone; }
bool        PeJobFailed() { return g_state.load() == JobFail; }
float       PeJobProgress() { return g_prog.load(); }
const char* PeJobPath() { return g_path; }
const char* PeJobError() { return g_err; }

const PeFile* PeJobResult()
{
    if (g_state.load() != JobDone)
        return nullptr;
    return &g_file;
}

PeFile* PeJobResultMut()
{
    if (g_state.load() != JobDone)
        return nullptr;
    return &g_file;
}

uint8_t* PeJobBytes(size_t* n)
{
    if (n)
        *n = g_bytes.size();
    if (g_state.load() != JobDone || g_bytes.empty())
        return nullptr;
    return g_bytes.data();
}

bool PeJobDirty() { return g_dirty; }
void PeJobTouch() { g_dirty = true; }
void PeJobClearDirty() { g_dirty = false; }

void PePatchClr()
{
    if (g_state.load() != JobDone || !g_file.clr_off)
        return;
    if (g_file.clr_off + 24 > g_bytes.size())
        return;
    uint8_t after[24];
    memcpy(after, g_bytes.data() + g_file.clr_off, 24);
    *(uint16_t*)(after + 4) = g_file.clr_major;
    *(uint16_t*)(after + 6) = g_file.clr_minor;
    *(uint32_t*)(after + 16) = g_file.clr_flags;
    *(uint32_t*)(after + 20) = g_file.clr_entry;
    PatchApply(g_file.clr_off, after, 24, PatchSrcClr);
}

void PePatchTypelib(int index)
{
    if (g_state.load() != JobDone || index < 0 || index >= (int)g_file.typelibs.size())
        return;
    const PeTypelib& t = g_file.typelibs[index];
    if (!t.msft || t.file_off + 8 > g_bytes.size())
        return;
    uint8_t after[4];
    memcpy(after, &t.version, 4);
    PatchApply(t.file_off + 4, after, 4, PatchSrcOther);
}

bool PePatchBytes(uint32_t off, const uint8_t* src, uint32_t n)
{
    return PatchApply(off, src, n, PatchSrcOther);
}

uint32_t PeImageRvaToOff(const PeFile* pe, uint32_t rva)
{
    if (!pe)
        return 0;
    return RvaToOff(pe, rva);
}

uint32_t PeRvaToFileOff(uint32_t rva)
{
    if (g_state.load() != JobDone)
        return 0;
    return RvaToOff(&g_file, rva);
}

uint32_t PeFileOffToRva(const PeFile* pe, uint32_t off)
{
    if (!pe || !pe->ok)
        return 0;
    if (pe->size_of_headers && off < pe->size_of_headers)
        return off;
    for (int i = 0; i < pe->section_n; i++)
    {
        const PeSection& s = pe->sections[i];
        if (!s.rawptr || !s.rawsize)
            continue;
        if (off >= s.rawptr && off < s.rawptr + s.rawsize)
            return s.vaddr + (off - s.rawptr);
    }
    return 0;
}

static bool WriteVerStr(PeVerString& s, const char* utf8)
{
    if (!utf8 || s.value_off + 2 > g_bytes.size())
        return false;
    wchar_t wbuf[260];
    int nch = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, wbuf, 260);
    if (nch < 1)
        return false;
    uint32_t need = (uint32_t)nch * 2u;
    if (need > s.value_cap)
        return false;
    std::vector<uint8_t> after(s.value_cap, 0);
    memcpy(after.data(), wbuf, need);
    if (!PatchApply(s.value_off, after.data(), s.value_cap, PatchSrcVersion))
        return false;
    if (s.node_off + 4 <= g_bytes.size())
    {
        uint8_t lenb[2];
        uint16_t nch16 = (uint16_t)nch;
        memcpy(lenb, &nch16, 2);
        PatchApply(s.node_off + 2, lenb, 2, PatchSrcVersion);
    }
    snprintf(s.value, sizeof(s.value), "%s", utf8);
    return true;
}

bool PePatchVerFixed(int index)
{
    if (g_state.load() != JobDone || index < 0 || index >= (int)g_file.versions.size())
        return false;
    PeVerInfo& v = g_file.versions[index];
    if (!v.ffi_off || v.ffi_off + 24 > g_bytes.size())
        return false;
    uint32_t fms = ((uint32_t)v.file[0] << 16) | v.file[1];
    uint32_t fls = ((uint32_t)v.file[2] << 16) | v.file[3];
    uint32_t pms = ((uint32_t)v.prod[0] << 16) | v.prod[1];
    uint32_t pls = ((uint32_t)v.prod[2] << 16) | v.prod[3];
    uint8_t after[16];
    memcpy(after + 0, &fms, 4);
    memcpy(after + 4, &fls, 4);
    memcpy(after + 8, &pms, 4);
    memcpy(after + 12, &pls, 4);
    PatchApply(v.ffi_off + 8, after, 16, PatchSrcVersion);
    char fv[48], pv[48];
    snprintf(fv, sizeof(fv), "%u.%u.%u.%u", v.file[0], v.file[1], v.file[2], v.file[3]);
    snprintf(pv, sizeof(pv), "%u.%u.%u.%u", v.prod[0], v.prod[1], v.prod[2], v.prod[3]);
    for (PeVerString& s : v.strings)
    {
        if (_stricmp(s.key, "FileVersion") == 0)
            WriteVerStr(s, fv);
        if (_stricmp(s.key, "ProductVersion") == 0)
            WriteVerStr(s, pv);
    }
    g_dirty = true;
    return true;
}

bool PePatchVerString(int ver_index, int str_index, const char* utf8)
{
    if (g_state.load() != JobDone || ver_index < 0 || ver_index >= (int)g_file.versions.size())
        return false;
    PeVerInfo& v = g_file.versions[ver_index];
    if (str_index < 0 || str_index >= (int)v.strings.size())
        return false;
    if (!WriteVerStr(v.strings[str_index], utf8))
        return false;
    g_dirty = true;
    return true;
}

static bool WriteFileBytes(const char* path, const void* data, DWORD n)
{
    wchar_t wpath[MAX_PATH];
    if (!MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, MAX_PATH))
        return false;
    HANDLE h = CreateFileW(wpath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    DWORD wr = 0;
    BOOL ok = WriteFile(h, data, n, &wr, nullptr);
    CloseHandle(h);
    return ok && wr == n;
}

bool PeExportIco(int icon_index, const char* path)
{
    if (g_state.load() != JobDone || icon_index < 0 || icon_index >= (int)g_file.icons.size() || !path)
        return false;
    const PeIconImg& ic = g_file.icons[icon_index];
    if (!ic.file_off || ic.file_off + ic.size > g_bytes.size())
        return false;
#pragma pack(push, 1)
    struct IcoDir
    {
        uint16_t reserved, type, count;
    };
    struct IcoEnt
    {
        uint8_t w, h, colors, reserved;
        uint16_t planes, bpp;
        uint32_t bytes, off;
    };
#pragma pack(pop)
    uint32_t blob = ic.size;
    std::vector<uint8_t> out(sizeof(IcoDir) + sizeof(IcoEnt) + blob);
    IcoDir* d = (IcoDir*)out.data();
    d->reserved = 0;
    d->type = 1;
    d->count = 1;
    IcoEnt* e = (IcoEnt*)(out.data() + sizeof(IcoDir));
    e->w = (uint8_t)(ic.w >= 256 ? 0 : ic.w);
    e->h = (uint8_t)(ic.h >= 256 ? 0 : ic.h);
    e->colors = 0;
    e->reserved = 0;
    e->planes = 1;
    e->bpp = (uint16_t)(ic.bpp ? ic.bpp : 32);
    e->bytes = blob;
    e->off = sizeof(IcoDir) + sizeof(IcoEnt);
    memcpy(out.data() + e->off, g_bytes.data() + ic.file_off, blob);
    return WriteFileBytes(path, out.data(), (DWORD)out.size());
}

bool PeReplaceIco(int icon_index, const char* path)
{
    if (g_state.load() != JobDone || icon_index < 0 || icon_index >= (int)g_file.icons.size() || !path)
        return false;
    const PeIconImg& ic = g_file.icons[icon_index];
    wchar_t wpath[MAX_PATH];
    if (!MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, MAX_PATH))
        return false;
    HANDLE h = CreateFileW(wpath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart < 22 || sz.QuadPart > 16 * 1024 * 1024)
    {
        CloseHandle(h);
        return false;
    }
    std::vector<uint8_t> ico((size_t)sz.QuadPart);
    DWORD rd = 0;
    BOOL ok = ReadFile(h, ico.data(), (DWORD)ico.size(), &rd, nullptr);
    CloseHandle(h);
    if (!ok || rd != ico.size())
        return false;
    const uint8_t* img = nullptr;
    uint32_t img_n = 0;
    if (ico.size() >= 6 && ico[2] == 1 && ico[3] == 0)
    {
        uint16_t count = *(const uint16_t*)(ico.data() + 4);
        if (!count)
            return false;
        uint32_t bytes = *(const uint32_t*)(ico.data() + 6 + 8);
        uint32_t off = *(const uint32_t*)(ico.data() + 6 + 12);
        if (off + bytes > ico.size())
            return false;
        img = ico.data() + off;
        img_n = bytes;
    }
    else
    {
        img = ico.data();
        img_n = (uint32_t)ico.size();
    }
    if (img_n != ic.size)
        return false;
    return PatchApply(ic.file_off, img, img_n, PatchSrcIcon);
}

static char g_save_err_key[64];
static char g_backup_utf8[MAX_PATH];

const char* PeJobSaveErrorKey() { return g_save_err_key; }
const char* PeJobBackupPath() { return g_backup_utf8; }

static bool Utf8ToWide(const char* u, wchar_t* w, int cap)
{
    return u && w && MultiByteToWideChar(CP_UTF8, 0, u, -1, w, cap) > 0;
}

static bool WideToUtf8(const wchar_t* w, char* u, int cap)
{
    return w && u && WideCharToMultiByte(CP_UTF8, 0, w, -1, u, cap, nullptr, nullptr) > 0;
}

static bool PathExistsW(const wchar_t* p)
{
    DWORD a = GetFileAttributesW(p);
    return a != INVALID_FILE_ATTRIBUTES;
}

static void SplitDirName(const wchar_t* path, wchar_t* dir, int dir_cap, wchar_t* name, int name_cap)
{
    dir[0] = 0;
    name[0] = 0;
    const wchar_t* slash = wcsrchr(path, L'\\');
    if (!slash)
        slash = wcsrchr(path, L'/');
    if (!slash)
    {
        wcsncpy_s(dir, dir_cap, L".", _TRUNCATE);
        wcsncpy_s(name, name_cap, path, _TRUNCATE);
        return;
    }
    size_t dlen = (size_t)(slash - path);
    if (dlen >= (size_t)dir_cap)
        dlen = (size_t)dir_cap - 1;
    wcsncpy_s(dir, dir_cap, path, dlen);
    dir[dlen] = 0;
    wcsncpy_s(name, name_cap, slash + 1, _TRUNCATE);
}

static void StemOf(const wchar_t* name, wchar_t* stem, int cap)
{
    wcsncpy_s(stem, cap, name, _TRUNCATE);
    wchar_t* dot = wcsrchr(stem, L'.');
    if (dot && dot != stem)
        *dot = 0;
}

static bool UniqueBackupPath(const wchar_t* dir, const wchar_t* name, wchar_t* out, int cap)
{
    wchar_t first[MAX_PATH];
    _snwprintf_s(first, _TRUNCATE, L"%s\\%s.bak", dir, name);
    if (!PathExistsW(first))
    {
        wcsncpy_s(out, cap, first, _TRUNCATE);
        return true;
    }
    SYSTEMTIME st{};
    GetLocalTime(&st);
    wchar_t stem[MAX_PATH];
    StemOf(name, stem, MAX_PATH);
    for (int n = 0; n < 100; n++)
    {
        if (n == 0)
            _snwprintf_s(out, cap, _TRUNCATE,
                L"%s\\%s_%04u-%02u-%02u_%02u-%02u-%02u_original.bak",
                dir, stem, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        else
            _snwprintf_s(out, cap, _TRUNCATE,
                L"%s\\%s_%04u-%02u-%02u_%02u-%02u-%02u_original_%d.bak",
                dir, stem, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, n + 1);
        if (!PathExistsW(out))
            return true;
    }
    return false;
}

static bool CopyBackup(const wchar_t* src, const wchar_t* dst)
{
    return CopyFileW(src, dst, TRUE) != 0;
}

static bool WriteTempReplace(const wchar_t* dest, const void* data, DWORD n)
{
    wchar_t tmp[MAX_PATH];
    _snwprintf_s(tmp, _TRUNCATE, L"%s.%u.tmp", dest, GetCurrentProcessId());
    HANDLE h = CreateFileW(tmp, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    DWORD wr = 0;
    BOOL ok = WriteFile(h, data, n, &wr, nullptr);
    if (ok)
        FlushFileBuffers(h);
    CloseHandle(h);
    if (!ok || wr != n)
    {
        DeleteFileW(tmp);
        return false;
    }
    if (MoveFileExW(tmp, dest, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        return true;
    if (ReplaceFileW(dest, tmp, nullptr, REPLACEFILE_WRITE_THROUGH, nullptr, nullptr))
        return true;
    DeleteFileW(tmp);
    return false;
}

PeSaveStatus PeJobSaveEx(const char* path, bool skip_backup)
{
    auto log = LogFor(LogBuiltinPeAnalyzer).Module("Patch");
    g_save_err_key[0] = 0;
    g_backup_utf8[0] = 0;
    if (!path || !path[0] || g_bytes.empty())
    {
        snprintf(g_save_err_key, sizeof(g_save_err_key), "pe.save_fail");
        return PeSaveBadArgs;
    }
    wchar_t wpath[MAX_PATH];
    if (!Utf8ToWide(path, wpath, MAX_PATH))
    {
        snprintf(g_save_err_key, sizeof(g_save_err_key), "pe.save_fail");
        return PeSaveBadArgs;
    }

    if (PathExistsW(wpath) && !skip_backup)
    {
        wchar_t dir[MAX_PATH], name[MAX_PATH], bak[MAX_PATH];
        SplitDirName(wpath, dir, MAX_PATH, name, MAX_PATH);
        if (!UniqueBackupPath(dir, name, bak, MAX_PATH) || !CopyBackup(wpath, bak))
        {
            snprintf(g_save_err_key, sizeof(g_save_err_key), "pe.backup_fail");
            log.Error("Backup failed before save (win32 %lu)", GetLastError());
            return PeSaveBackupFailed;
        }
        WideToUtf8(bak, g_backup_utf8, MAX_PATH);
        log.Info("Backup written: %s", g_backup_utf8);
    }

    if (!WriteTempReplace(wpath, g_bytes.data(), (DWORD)g_bytes.size()))
    {
        snprintf(g_save_err_key, sizeof(g_save_err_key), "pe.save_fail");
        log.Error("Atomic save failed (win32 %lu)", GetLastError());
        return PeSaveWriteFailed;
    }
    PatchLogPersisted();
    PatchOnSaved();
    snprintf(g_path, MAX_PATH, "%s", path);
    snprintf(g_file.path, sizeof(g_file.path), "%s", path);
    log.Success("Saved %s", path);
    return PeSaveOk;
}

bool PeJobSave(const char* path)
{
    return PeJobSaveEx(path, false) == PeSaveOk;
}
