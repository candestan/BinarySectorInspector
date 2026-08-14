#pragma once

#include "pe/pe_file.h"
#include "pe/pe_headers.h"
#include "pe/pe_types.h"

#include <cstdint>
#include <string>
#include <vector>

struct ImportedSymbol
{
    bool by_ordinal = false;
    uint16_t hint = 0;
    uint16_t ordinal = 0;
    std::string name;
    FileAddress ilt;
    FileAddress iat;
};

struct ImportedModule
{
    std::string dll_name;
    uint32_t time_date_stamp = 0;
    bool bound = false;
    bool delay_load = false;
    FileAddress descriptor;
    FileAddress iat;
    std::vector<ImportedSymbol> symbols;
};

struct ImportTable
{
    std::string error;
    std::vector<ImportedModule> modules;
};

struct ExportedSymbol
{
    uint32_t ordinal = 0;
    std::string name;
    bool forwarded = false;
    std::string forwarder;
    FileAddress address;
};

struct ExportTable
{
    std::string error;
    std::string dll_name;
    uint32_t ordinal_base = 0;
    uint32_t timestamp = 0;
    std::vector<ExportedSymbol> symbols;
};

struct RelocEntry
{
    uint8_t type = 0;
    uint16_t offset = 0;
    FileAddress address;
};

struct RelocBlock
{
    uint32_t page_rva = 0;
    uint32_t block_size = 0;
    std::vector<RelocEntry> entries;
};

struct RelocTable
{
    std::string error;
    uint32_t block_count = 0;
    uint32_t type_absolute = 0;
    uint32_t type_highlow = 0;
    uint32_t type_dir64 = 0;
    uint32_t type_other = 0;
    std::vector<RelocBlock> blocks;
};

struct TlsInfo
{
    std::string error;
    bool present = false;
    uint64_t start_address_of_raw_data = 0;
    uint64_t end_address_of_raw_data = 0;
    uint64_t address_of_index = 0;
    uint64_t address_of_callbacks = 0;
    uint32_t size_of_zero_fill = 0;
    uint32_t characteristics = 0;
    std::vector<FileAddress> callbacks;
};

struct ResourceNode
{
    bool is_directory = false;
    bool name_is_string = false;
    uint32_t id = 0;
    std::string name;
    uint32_t data_rva = 0;
    uint32_t data_size = 0;
    uint32_t code_page = 0;
    FileAddress data;
    std::vector<ResourceNode> children;
};

struct VersionInfo
{
    bool present = false;
    uint16_t file_major = 0;
    uint16_t file_minor = 0;
    uint16_t file_build = 0;
    uint16_t file_revision = 0;
    uint16_t product_major = 0;
    uint16_t product_minor = 0;
    uint16_t product_build = 0;
    uint16_t product_revision = 0;
    uint32_t file_flags = 0;
};

struct ResourceTree
{
    std::string error;
    ResourceNode root;
    VersionInfo version;
};

struct DebugEntry
{
    uint32_t type = 0;
    std::string type_name;
    uint32_t timestamp = 0;
    uint32_t size = 0;
    FileAddress address;
    std::string extra;
};

struct DebugInfo
{
    std::string error;
    std::vector<DebugEntry> entries;
    std::string pdb_path;
};

ImportTable parse_imports(const PeFile& file, const PeHeaders& headers);
ExportTable parse_exports(const PeFile& file, const PeHeaders& headers);
RelocTable parse_relocs(const PeFile& file, const PeHeaders& headers);
TlsInfo parse_tls(const PeFile& file, const PeHeaders& headers);
ResourceTree parse_resources(const PeFile& file, const PeHeaders& headers);
DebugInfo parse_debug(const PeFile& file, const PeHeaders& headers);
