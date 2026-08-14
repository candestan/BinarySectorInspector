#include "pe/pe_directories.h"
#include "pe/pe_address.h"
#include "platform/utf8.h"

#include <delayimp.h>
#include <algorithm>
#include <cstring>
#include <unordered_set>

#ifndef IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS
#define IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS 20
#endif
#ifndef IMAGE_DEBUG_TYPE_REPRO
#define IMAGE_DEBUG_TYPE_REPRO 16
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_GUARD_CF
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF 0x4000
#endif

namespace {

const DataDirectoryEntry* dir(const PeHeaders& headers, uint32_t index)
{
    if (index >= headers.directories.size())
        return nullptr;
    return &headers.directories[index];
}

bool thunk_is_ordinal32(uint32_t value)
{
    return (value & IMAGE_ORDINAL_FLAG32) != 0;
}

bool thunk_is_ordinal64(uint64_t value)
{
    return (value & IMAGE_ORDINAL_FLAG64) != 0;
}

void parse_thunks(
    const PeFile& file,
    const PeHeaders& headers,
    uint32_t lookup_rva,
    uint32_t iat_rva,
    std::vector<ImportedSymbol>& symbols)
{
    for (uint32_t i = 0; i < kMaxThunksPerDll; ++i)
    {
        ImportedSymbol sym;
        if (headers.pe32_plus)
        {
            IMAGE_THUNK_DATA64 lookup{};
            IMAGE_THUNK_DATA64 iat{};
            const uint32_t look_rva = lookup_rva + i * static_cast<uint32_t>(sizeof(IMAGE_THUNK_DATA64));
            const uint32_t iat_slot = iat_rva + i * static_cast<uint32_t>(sizeof(IMAGE_THUNK_DATA64));
            const FileAddress look_addr = address_from_rva(headers, look_rva);
            if (!look_addr.has_file || !file.read_struct(look_addr.file_offset, lookup))
                break;
            if (lookup.u1.AddressOfData == 0)
                break;
            sym.ilt = look_addr;
            sym.iat = address_from_rva(headers, iat_slot);
            if (sym.iat.has_file)
                file.read_struct(sym.iat.file_offset, iat);

            if (thunk_is_ordinal64(lookup.u1.Ordinal))
            {
                sym.by_ordinal = true;
                sym.ordinal = static_cast<uint16_t>(lookup.u1.Ordinal & 0xFFFFu);
            }
            else
            {
                const FileAddress name_addr = address_from_rva(headers, static_cast<uint32_t>(lookup.u1.AddressOfData));
                if (name_addr.has_file)
                {
                    file.read(name_addr.file_offset, &sym.hint, sizeof(sym.hint));
                    sym.name = file.read_cstring(name_addr.file_offset + 2, kMaxStringRead);
                }
            }
        }
        else
        {
            IMAGE_THUNK_DATA32 lookup{};
            IMAGE_THUNK_DATA32 iat{};
            const uint32_t look_rva = lookup_rva + i * static_cast<uint32_t>(sizeof(IMAGE_THUNK_DATA32));
            const uint32_t iat_slot = iat_rva + i * static_cast<uint32_t>(sizeof(IMAGE_THUNK_DATA32));
            const FileAddress look_addr = address_from_rva(headers, look_rva);
            if (!look_addr.has_file || !file.read_struct(look_addr.file_offset, lookup))
                break;
            if (lookup.u1.AddressOfData == 0)
                break;
            sym.ilt = look_addr;
            sym.iat = address_from_rva(headers, iat_slot);
            if (sym.iat.has_file)
                file.read_struct(sym.iat.file_offset, iat);

            if (thunk_is_ordinal32(lookup.u1.Ordinal))
            {
                sym.by_ordinal = true;
                sym.ordinal = static_cast<uint16_t>(lookup.u1.Ordinal & 0xFFFFu);
            }
            else
            {
                const FileAddress name_addr = address_from_rva(headers, lookup.u1.AddressOfData);
                if (name_addr.has_file)
                {
                    file.read(name_addr.file_offset, &sym.hint, sizeof(sym.hint));
                    sym.name = file.read_cstring(name_addr.file_offset + 2, kMaxStringRead);
                }
            }
        }
        symbols.push_back(std::move(sym));
    }
}

std::string debug_type_name(uint32_t type)
{
    switch (type)
    {
    case IMAGE_DEBUG_TYPE_UNKNOWN: return "UNKNOWN";
    case IMAGE_DEBUG_TYPE_COFF: return "COFF";
    case IMAGE_DEBUG_TYPE_CODEVIEW: return "CODEVIEW";
    case IMAGE_DEBUG_TYPE_FPO: return "FPO";
    case IMAGE_DEBUG_TYPE_MISC: return "MISC";
    case IMAGE_DEBUG_TYPE_EXCEPTION: return "EXCEPTION";
    case IMAGE_DEBUG_TYPE_FIXUP: return "FIXUP";
    case IMAGE_DEBUG_TYPE_OMAP_TO_SRC: return "OMAP_TO_SRC";
    case IMAGE_DEBUG_TYPE_OMAP_FROM_SRC: return "OMAP_FROM_SRC";
    case IMAGE_DEBUG_TYPE_BORLAND: return "BORLAND";
    case IMAGE_DEBUG_TYPE_RESERVED10: return "RESERVED10";
    case IMAGE_DEBUG_TYPE_CLSID: return "CLSID";
    case IMAGE_DEBUG_TYPE_VC_FEATURE: return "VC_FEATURE";
    case IMAGE_DEBUG_TYPE_POGO: return "POGO";
    case IMAGE_DEBUG_TYPE_ILTCG: return "ILTCG";
    case IMAGE_DEBUG_TYPE_MPX: return "MPX";
    case IMAGE_DEBUG_TYPE_REPRO: return "REPRO";
    case IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS: return "EX_DLLCHARACTERISTICS";
    default: return "OTHER";
    }
}

bool parse_resource_directory(
    const PeFile& file,
    const PeHeaders& headers,
    uint32_t root_rva,
    uint32_t dir_offset_from_root,
    int depth,
    uint32_t& entry_budget,
    std::unordered_set<uint32_t>& visited,
    ResourceNode& node)
{
    if (depth > kMaxResourceDepth || entry_budget == 0)
        return false;
    if (!visited.insert(dir_offset_from_root).second)
        return false;

    const uint32_t dir_rva = root_rva + dir_offset_from_root;
    const FileAddress dir_addr = address_from_rva(headers, dir_rva);
    IMAGE_RESOURCE_DIRECTORY directory{};
    if (!dir_addr.has_file || !file.read_struct(dir_addr.file_offset, directory))
        return false;

    const uint32_t total = static_cast<uint32_t>(directory.NumberOfNamedEntries) + directory.NumberOfIdEntries;
    const uint64_t entries_off = dir_addr.file_offset + sizeof(IMAGE_RESOURCE_DIRECTORY);
    for (uint32_t i = 0; i < total && entry_budget > 0; ++i)
    {
        IMAGE_RESOURCE_DIRECTORY_ENTRY entry{};
        if (!file.read_struct(entries_off + i * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), entry))
            break;
        --entry_budget;

        ResourceNode child;
        child.name_is_string = entry.NameIsString != 0;
        if (child.name_is_string)
        {
            const FileAddress name_addr = address_from_rva(headers, root_rva + entry.NameOffset);
            if (name_addr.has_file)
            {
                uint16_t length = 0;
                if (file.read(name_addr.file_offset, &length, sizeof(length)))
                {
                    const std::wstring wide = file.read_wstring(name_addr.file_offset + 2, length);
                    child.name = wide_to_utf8(wide);
                }
            }
        }
        else
        {
            child.id = entry.Id;
        }

        if (entry.DataIsDirectory)
        {
            child.is_directory = true;
            parse_resource_directory(
                file, headers, root_rva, entry.OffsetToDirectory, depth + 1,
                entry_budget, visited, child);
        }
        else
        {
            const FileAddress data_entry_addr = address_from_rva(headers, root_rva + entry.OffsetToData);
            IMAGE_RESOURCE_DATA_ENTRY data{};
            if (data_entry_addr.has_file && file.read_struct(data_entry_addr.file_offset, data))
            {
                child.data_rva = data.OffsetToData;
                child.data_size = data.Size;
                child.code_page = data.CodePage;
                child.data = address_from_rva(headers, data.OffsetToData);
            }
        }
        node.children.push_back(std::move(child));
    }
    node.is_directory = true;
    return true;
}

void find_version(const ResourceNode& node, int type_level, uint32_t type_id, VersionInfo& version, const PeFile& file)
{
    if (type_level == 0 && !node.is_directory)
        return;
    for (const ResourceNode& child : node.children)
    {
        uint32_t next_type = type_id;
        if (type_level == 0 && !child.name_is_string)
            next_type = child.id;
        if (type_level == 2 && type_id == 16 && child.data.has_file && child.data_size >= 40)
        {
            // VS_VERSIONINFO: skip length/value length/type + L"VS_VERSION_INFO" then align, then VS_FIXEDFILEINFO
            const uint64_t start = child.data.file_offset;
            uint16_t length = 0;
            if (!file.read(start, &length, 2))
                continue;
            uint32_t cursor = 6;
            std::wstring key = file.read_wstring(start + cursor, 32);
            cursor += static_cast<uint32_t>((key.size() + 1) * 2);
            cursor = (cursor + 3u) & ~3u;
            uint32_t sig = 0;
            if (file.contains(start + cursor, sizeof(VS_FIXEDFILEINFO)))
            {
                VS_FIXEDFILEINFO ffi{};
                if (file.read_struct(start + cursor, ffi) && ffi.dwSignature == 0xFEEF04BD)
                {
                    version.present = true;
                    version.file_major = static_cast<uint16_t>(ffi.dwFileVersionMS >> 16);
                    version.file_minor = static_cast<uint16_t>(ffi.dwFileVersionMS & 0xFFFF);
                    version.file_build = static_cast<uint16_t>(ffi.dwFileVersionLS >> 16);
                    version.file_revision = static_cast<uint16_t>(ffi.dwFileVersionLS & 0xFFFF);
                    version.product_major = static_cast<uint16_t>(ffi.dwProductVersionMS >> 16);
                    version.product_minor = static_cast<uint16_t>(ffi.dwProductVersionMS & 0xFFFF);
                    version.product_build = static_cast<uint16_t>(ffi.dwProductVersionLS >> 16);
                    version.product_revision = static_cast<uint16_t>(ffi.dwProductVersionLS & 0xFFFF);
                    version.file_flags = ffi.dwFileFlags;
                }
            }
        }
        find_version(child, type_level + 1, next_type, version, file);
    }
}

} // namespace

ImportTable parse_imports(const PeFile& file, const PeHeaders& headers)
{
    ImportTable table;
    const DataDirectoryEntry* import_dir = dir(headers, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (import_dir && import_dir->present)
    {
        for (uint32_t i = 0; i < kMaxImportDescriptors; ++i)
        {
            const uint32_t desc_rva = import_dir->rva + i * static_cast<uint32_t>(sizeof(IMAGE_IMPORT_DESCRIPTOR));
            const FileAddress desc_addr = address_from_rva(headers, desc_rva);
            IMAGE_IMPORT_DESCRIPTOR desc{};
            if (!desc_addr.has_file || !file.read_struct(desc_addr.file_offset, desc))
            {
                table.error = "Import descriptor table is truncated.";
                break;
            }
            if (desc.Name == 0 && desc.FirstThunk == 0 && desc.OriginalFirstThunk == 0)
                break;

            ImportedModule mod;
            mod.descriptor = desc_addr;
            mod.dll_name = read_rva_cstring(file, headers, desc.Name, kMaxStringRead);
            mod.time_date_stamp = desc.TimeDateStamp;
            mod.bound = desc.TimeDateStamp != 0 && desc.TimeDateStamp != 0xFFFFFFFF;
            const uint32_t lookup = desc.OriginalFirstThunk != 0 ? desc.OriginalFirstThunk : desc.FirstThunk;
            mod.iat = address_from_rva(headers, desc.FirstThunk);
            parse_thunks(file, headers, lookup, desc.FirstThunk, mod.symbols);
            table.modules.push_back(std::move(mod));
        }
    }

    const DataDirectoryEntry* delay_dir = dir(headers, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
    if (delay_dir && delay_dir->present)
    {
        for (uint32_t i = 0; i < kMaxImportDescriptors; ++i)
        {
            const uint32_t desc_rva = delay_dir->rva + i * static_cast<uint32_t>(sizeof(IMAGE_DELAYLOAD_DESCRIPTOR));
            const FileAddress desc_addr = address_from_rva(headers, desc_rva);
            IMAGE_DELAYLOAD_DESCRIPTOR desc{};
            if (!desc_addr.has_file || !file.read_struct(desc_addr.file_offset, desc))
                break;
            if (desc.DllNameRVA == 0)
                break;

            ImportedModule mod;
            mod.delay_load = true;
            mod.descriptor = desc_addr;
            mod.dll_name = read_rva_cstring(file, headers, desc.DllNameRVA, kMaxStringRead);
            mod.time_date_stamp = desc.TimeDateStamp;
            mod.bound = desc.TimeDateStamp != 0;
            const uint32_t lookup = desc.ImportNameTableRVA != 0 ? desc.ImportNameTableRVA : desc.ImportAddressTableRVA;
            mod.iat = address_from_rva(headers, desc.ImportAddressTableRVA);
            parse_thunks(file, headers, lookup, desc.ImportAddressTableRVA, mod.symbols);
            table.modules.push_back(std::move(mod));
        }
    }

    return table;
}

ExportTable parse_exports(const PeFile& file, const PeHeaders& headers)
{
    ExportTable table;
    const DataDirectoryEntry* export_dir = dir(headers, IMAGE_DIRECTORY_ENTRY_EXPORT);
    if (!export_dir || !export_dir->present)
        return table;

    const FileAddress dir_addr = address_from_rva(headers, export_dir->rva);
    IMAGE_EXPORT_DIRECTORY exp{};
    if (!dir_addr.has_file || !file.read_struct(dir_addr.file_offset, exp))
    {
        table.error = "Export directory is truncated.";
        return table;
    }

    table.dll_name = read_rva_cstring(file, headers, exp.Name, kMaxStringRead);
    table.ordinal_base = exp.Base;
    table.timestamp = exp.TimeDateStamp;

    const uint32_t nfunc = (std::min)(static_cast<uint32_t>(exp.NumberOfFunctions), kMaxExportEntries);
    const uint32_t nnames = (std::min)(static_cast<uint32_t>(exp.NumberOfNames), kMaxExportEntries);

    std::vector<uint32_t> functions(nfunc);
    std::vector<uint32_t> names(nnames);
    std::vector<uint16_t> ordinals(nnames);

    const FileAddress func_addr = address_from_rva(headers, exp.AddressOfFunctions);
    const FileAddress name_addr = address_from_rva(headers, exp.AddressOfNames);
    const FileAddress ord_addr = address_from_rva(headers, exp.AddressOfNameOrdinals);
    if (func_addr.has_file)
        file.read(func_addr.file_offset, functions.data(), nfunc * sizeof(uint32_t));
    if (name_addr.has_file)
        file.read(name_addr.file_offset, names.data(), nnames * sizeof(uint32_t));
    if (ord_addr.has_file)
        file.read(ord_addr.file_offset, ordinals.data(), nnames * sizeof(uint16_t));

    std::vector<std::string> name_by_index(nfunc);
    for (uint32_t i = 0; i < nnames; ++i)
    {
        if (ordinals[i] < nfunc)
            name_by_index[ordinals[i]] = read_rva_cstring(file, headers, names[i], kMaxStringRead);
    }

    const uint32_t export_begin = export_dir->rva;
    const uint32_t export_end = export_dir->rva + export_dir->size;
    table.symbols.reserve(nfunc);
    for (uint32_t i = 0; i < nfunc; ++i)
    {
        if (functions[i] == 0)
            continue;
        ExportedSymbol sym;
        sym.ordinal = exp.Base + i;
        sym.name = name_by_index[i];
        if (functions[i] >= export_begin && functions[i] < export_end)
        {
            sym.forwarded = true;
            sym.forwarder = read_rva_cstring(file, headers, functions[i], kMaxStringRead);
        }
        else
        {
            sym.address = address_from_rva(headers, functions[i]);
        }
        table.symbols.push_back(std::move(sym));
    }
    return table;
}

RelocTable parse_relocs(const PeFile& file, const PeHeaders& headers)
{
    RelocTable table;
    const DataDirectoryEntry* reloc_dir = dir(headers, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (!reloc_dir || !reloc_dir->present)
        return table;

    uint32_t consumed = 0;
    uint32_t blocks = 0;
    while (consumed + sizeof(IMAGE_BASE_RELOCATION) <= reloc_dir->size && blocks < kMaxRelocBlocks)
    {
        const uint32_t block_rva = reloc_dir->rva + consumed;
        const FileAddress block_addr = address_from_rva(headers, block_rva);
        IMAGE_BASE_RELOCATION block{};
        if (!block_addr.has_file || !file.read_struct(block_addr.file_offset, block))
        {
            table.error = "Relocation table is truncated.";
            break;
        }
        if (block.SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION))
        {
            table.error = "Relocation block size is smaller than 8 bytes.";
            break;
        }
        if (consumed + block.SizeOfBlock > reloc_dir->size)
        {
            table.error = "Relocation block overruns the directory.";
            break;
        }

        RelocBlock parsed;
        parsed.page_rva = block.VirtualAddress;
        parsed.block_size = block.SizeOfBlock;
        const uint32_t entry_count = (block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
        const uint32_t store = (std::min)(entry_count, kMaxRelocEntriesPerBlock);
        parsed.entries.reserve(store);
        for (uint32_t i = 0; i < entry_count; ++i)
        {
            uint16_t entry = 0;
            const uint64_t entry_off = block_addr.file_offset + sizeof(IMAGE_BASE_RELOCATION) + i * sizeof(uint16_t);
            if (!file.read(entry_off, &entry, sizeof(entry)))
                break;
            const uint8_t type = static_cast<uint8_t>(entry >> 12);
            const uint16_t off = static_cast<uint16_t>(entry & 0x0FFF);
            if (type == IMAGE_REL_BASED_ABSOLUTE)
                ++table.type_absolute;
            else if (type == IMAGE_REL_BASED_HIGHLOW)
                ++table.type_highlow;
            else if (type == IMAGE_REL_BASED_DIR64)
                ++table.type_dir64;
            else
                ++table.type_other;

            if (i < store)
            {
                RelocEntry re;
                re.type = type;
                re.offset = off;
                re.address = address_from_rva(headers, block.VirtualAddress + off);
                parsed.entries.push_back(re);
            }
        }
        table.blocks.push_back(std::move(parsed));
        consumed += block.SizeOfBlock;
        ++blocks;
    }
    table.block_count = blocks;
    return table;
}

TlsInfo parse_tls(const PeFile& file, const PeHeaders& headers)
{
    TlsInfo tls;
    const DataDirectoryEntry* tls_dir = dir(headers, IMAGE_DIRECTORY_ENTRY_TLS);
    if (!tls_dir || !tls_dir->present)
        return tls;

    const FileAddress addr = address_from_rva(headers, tls_dir->rva);
    if (!addr.has_file)
    {
        tls.error = "TLS directory RVA does not map to a file offset.";
        return tls;
    }

    uint64_t callbacks_va = 0;
    if (headers.pe32_plus)
    {
        IMAGE_TLS_DIRECTORY64 raw{};
        if (!file.read_struct(addr.file_offset, raw))
        {
            tls.error = "TLS directory is truncated.";
            return tls;
        }
        tls.start_address_of_raw_data = raw.StartAddressOfRawData;
        tls.end_address_of_raw_data = raw.EndAddressOfRawData;
        tls.address_of_index = raw.AddressOfIndex;
        tls.address_of_callbacks = raw.AddressOfCallBacks;
        tls.size_of_zero_fill = raw.SizeOfZeroFill;
        tls.characteristics = raw.Characteristics;
        callbacks_va = raw.AddressOfCallBacks;
    }
    else
    {
        IMAGE_TLS_DIRECTORY32 raw{};
        if (!file.read_struct(addr.file_offset, raw))
        {
            tls.error = "TLS directory is truncated.";
            return tls;
        }
        tls.start_address_of_raw_data = raw.StartAddressOfRawData;
        tls.end_address_of_raw_data = raw.EndAddressOfRawData;
        tls.address_of_index = raw.AddressOfIndex;
        tls.address_of_callbacks = raw.AddressOfCallBacks;
        tls.size_of_zero_fill = raw.SizeOfZeroFill;
        tls.characteristics = raw.Characteristics;
        callbacks_va = raw.AddressOfCallBacks;
    }
    tls.present = true;

    if (callbacks_va >= headers.image_base)
    {
        const uint32_t cb_rva = static_cast<uint32_t>(callbacks_va - headers.image_base);
        const uint32_t ptr_size = headers.pe32_plus ? 8u : 4u;
        for (uint32_t i = 0; i < kMaxTlsCallbacks; ++i)
        {
            const FileAddress slot = address_from_rva(headers, cb_rva + i * ptr_size);
            if (!slot.has_file)
                break;
            uint64_t value = 0;
            if (headers.pe32_plus)
            {
                uint64_t v = 0;
                if (!file.read(slot.file_offset, &v, 8) || v == 0)
                    break;
                value = v;
            }
            else
            {
                uint32_t v = 0;
                if (!file.read(slot.file_offset, &v, 4) || v == 0)
                    break;
                value = v;
            }
            if (value >= headers.image_base)
                tls.callbacks.push_back(address_from_rva(headers, static_cast<uint32_t>(value - headers.image_base)));
        }
    }
    return tls;
}

ResourceTree parse_resources(const PeFile& file, const PeHeaders& headers)
{
    ResourceTree tree;
    const DataDirectoryEntry* res_dir = dir(headers, IMAGE_DIRECTORY_ENTRY_RESOURCE);
    if (!res_dir || !res_dir->present)
        return tree;

    uint32_t budget = kMaxResourceEntries;
    std::unordered_set<uint32_t> visited;
    if (!parse_resource_directory(file, headers, res_dir->rva, 0, 0, budget, visited, tree.root))
        tree.error = "Resource directory could not be parsed fully.";
    find_version(tree.root, 0, 0, tree.version, file);
    return tree;
}

DebugInfo parse_debug(const PeFile& file, const PeHeaders& headers)
{
    DebugInfo info;
    const DataDirectoryEntry* debug_dir = dir(headers, IMAGE_DIRECTORY_ENTRY_DEBUG);
    if (!debug_dir || !debug_dir->present)
        return info;

    const uint32_t count = (std::min)(
        debug_dir->size / static_cast<uint32_t>(sizeof(IMAGE_DEBUG_DIRECTORY)),
        kMaxDebugEntries);
    const FileAddress first = address_from_rva(headers, debug_dir->rva);
    if (!first.has_file)
    {
        info.error = "Debug directory RVA does not map to a file offset.";
        return info;
    }

    for (uint32_t i = 0; i < count; ++i)
    {
        IMAGE_DEBUG_DIRECTORY raw{};
        const uint64_t off = first.file_offset + i * sizeof(IMAGE_DEBUG_DIRECTORY);
        if (!file.read_struct(off, raw))
        {
            info.error = "Debug directory is truncated.";
            break;
        }
        DebugEntry entry;
        entry.type = raw.Type;
        entry.type_name = debug_type_name(raw.Type);
        entry.timestamp = raw.TimeDateStamp;
        entry.size = raw.SizeOfData;
        if (raw.PointerToRawData != 0 && file.contains(raw.PointerToRawData, raw.SizeOfData))
        {
            entry.address.has_file = true;
            entry.address.file_offset = raw.PointerToRawData;
            entry.address.valid = true;
        }
        if (raw.AddressOfRawData != 0)
        {
            const FileAddress mapped = address_from_rva(headers, raw.AddressOfRawData);
            entry.address.has_rva = true;
            entry.address.rva = raw.AddressOfRawData;
            entry.address.has_va = mapped.has_va;
            entry.address.va = mapped.va;
            if (!entry.address.has_file && mapped.has_file)
                entry.address = mapped;
        }

        if (raw.Type == IMAGE_DEBUG_TYPE_CODEVIEW && entry.address.has_file && raw.SizeOfData >= 24)
        {
            uint32_t sig = 0;
            file.read(entry.address.file_offset, &sig, 4);
            if (sig == 0x53445352) // RSDS
            {
                info.pdb_path = file.read_cstring(entry.address.file_offset + 24, kMaxStringRead);
                entry.extra = info.pdb_path;
            }
            else if (sig == 0x3031424E) // NB10
            {
                info.pdb_path = file.read_cstring(entry.address.file_offset + 16, kMaxStringRead);
                entry.extra = info.pdb_path;
            }
        }
        info.entries.push_back(std::move(entry));
    }
    return info;
}
