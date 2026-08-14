#pragma once

#include "pe/pe_file.h"
#include "pe/pe_types.h"

#include <cstdint>
#include <string>
#include <vector>
#include <windows.h>

struct DataDirectoryEntry
{
    uint32_t rva = 0;
    uint32_t size = 0;
    bool present = false;
};

struct SectionInfo
{
    std::string name;
    uint32_t virtual_address = 0;
    uint32_t virtual_size = 0;
    uint32_t pointer_to_raw_data = 0;
    uint32_t size_of_raw_data = 0;
    uint32_t characteristics = 0;
    uint32_t pointer_to_relocations = 0;
    uint32_t pointer_to_linenumbers = 0;
    uint16_t number_of_relocations = 0;
    uint16_t number_of_linenumbers = 0;
};

struct PeHeaders
{
    bool ok = false;
    std::string error;

    uint64_t dos_offset = 0;
    uint32_t e_lfanew = 0;
    IMAGE_DOS_HEADER dos{};

    uint64_t nt_offset = 0;
    uint32_t pe_signature = 0;
    IMAGE_FILE_HEADER file{};

    bool pe32_plus = false;
    uint16_t optional_magic = 0;
    uint64_t optional_offset = 0;
    uint32_t size_of_optional_header = 0;

    uint64_t image_base = 0;
    uint32_t address_of_entry_point = 0;
    uint32_t size_of_image = 0;
    uint32_t size_of_headers = 0;
    uint32_t section_alignment = 0;
    uint32_t file_alignment = 0;
    uint16_t subsystem = 0;
    uint16_t dll_characteristics = 0;
    uint32_t checksum_field = 0;
    uint32_t checksum_computed = 0;
    bool checksum_ok = false;
    uint32_t number_of_rva_and_sizes = 0;
    uint32_t loader_flags = 0;
    uint32_t win32_version = 0;
    uint16_t major_os = 0;
    uint16_t minor_os = 0;
    uint16_t major_image = 0;
    uint16_t minor_image = 0;
    uint16_t major_subsystem = 0;
    uint16_t minor_subsystem = 0;
    uint64_t size_of_stack_reserve = 0;
    uint64_t size_of_stack_commit = 0;
    uint64_t size_of_heap_reserve = 0;
    uint64_t size_of_heap_commit = 0;
    uint32_t base_of_code = 0;
    uint32_t base_of_data = 0;
    uint32_t size_of_code = 0;
    uint32_t size_of_initialized_data = 0;
    uint32_t size_of_uninitialized_data = 0;

    std::vector<DataDirectoryEntry> directories;
    uint64_t section_table_offset = 0;
    std::vector<SectionInfo> sections;
};

PeHeaders parse_headers(const PeFile& file);
uint32_t compute_pe_checksum(const PeFile& file, uint64_t checksum_field_offset);
