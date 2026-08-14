#include "pe/pe_headers.h"

#include <algorithm>
#include <cstring>

namespace {

std::string section_name_from_bytes(const BYTE name[IMAGE_SIZEOF_SHORT_NAME])
{
    char raw[IMAGE_SIZEOF_SHORT_NAME + 1] = {};
    memcpy(raw, name, IMAGE_SIZEOF_SHORT_NAME);
    return std::string(raw);
}

} // namespace

uint32_t compute_pe_checksum(const PeFile& file, uint64_t checksum_field_offset)
{
    uint32_t sum = 0;
    const uint64_t size = file.size();
    uint64_t offset = 0;
    while (offset + 1 < size)
    {
        if (offset == checksum_field_offset || offset + 1 == checksum_field_offset)
        {
            offset += 2;
            continue;
        }
        if (offset >= checksum_field_offset && offset < checksum_field_offset + 4)
        {
            offset += 2;
            continue;
        }

        uint16_t word = 0;
        file.read(offset, &word, sizeof(word));
        sum += word;
        sum = (sum & 0xFFFFu) + (sum >> 16);
        offset += 2;
    }
    if (offset < size && !(offset >= checksum_field_offset && offset < checksum_field_offset + 4))
    {
        uint8_t last = 0;
        file.read(offset, &last, 1);
        sum += last;
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }

    sum = (sum & 0xFFFFu) + (sum >> 16);
    sum = (sum & 0xFFFFu) + (sum >> 16);
    return sum + static_cast<uint32_t>(size);
}

PeHeaders parse_headers(const PeFile& file)
{
    PeHeaders h;
    if (file.size() < sizeof(IMAGE_DOS_HEADER))
    {
        h.error = "File is smaller than an IMAGE_DOS_HEADER.";
        return h;
    }

    if (!file.read_struct(0, h.dos))
    {
        h.error = "Could not read DOS header.";
        return h;
    }
    if (h.dos.e_magic != IMAGE_DOS_SIGNATURE)
    {
        h.error = "DOS signature is not MZ.";
        return h;
    }

    h.e_lfanew = static_cast<uint32_t>(h.dos.e_lfanew);
    if (h.e_lfanew < sizeof(IMAGE_DOS_HEADER))
    {
        h.error = "e_lfanew points inside the DOS header.";
        return h;
    }
    h.nt_offset = h.e_lfanew;
    if (!file.contains(h.nt_offset, sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)))
    {
        h.error = "e_lfanew is outside the file; NT headers do not fit.";
        return h;
    }

    if (!file.read_struct(h.nt_offset, h.pe_signature))
    {
        h.error = "Could not read PE signature.";
        return h;
    }
    if (h.pe_signature != IMAGE_NT_SIGNATURE)
    {
        h.error = "NT signature is not PE\\0\\0.";
        return h;
    }

    const uint64_t file_header_offset = h.nt_offset + sizeof(DWORD);
    if (!file.read_struct(file_header_offset, h.file))
    {
        h.error = "Could not read IMAGE_FILE_HEADER.";
        return h;
    }

    h.size_of_optional_header = h.file.SizeOfOptionalHeader;
    h.optional_offset = file_header_offset + sizeof(IMAGE_FILE_HEADER);
    if (h.file.NumberOfSections > kMaxSectionCount)
    {
        h.error = "NumberOfSections exceeds the parser limit.";
        return h;
    }
    if (h.size_of_optional_header < sizeof(uint16_t))
    {
        h.error = "SizeOfOptionalHeader is too small.";
        return h;
    }
    if (!file.contains(h.optional_offset, h.size_of_optional_header))
    {
        h.error = "Optional header does not fit in the file.";
        return h;
    }

    if (!file.read_struct(h.optional_offset, h.optional_magic))
    {
        h.error = "Could not read optional header magic.";
        return h;
    }

    const uint64_t checksum_field_offset = h.optional_offset + kChecksumFieldOffsetInOptional32;

    if (h.optional_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        IMAGE_OPTIONAL_HEADER32 opt{};
        const size_t copy = (std::min)(static_cast<size_t>(h.size_of_optional_header), sizeof(opt));
        if (!file.read(h.optional_offset, &opt, copy))
        {
            h.error = "Could not read PE32 optional header.";
            return h;
        }
        h.pe32_plus = false;
        h.image_base = opt.ImageBase;
        h.address_of_entry_point = opt.AddressOfEntryPoint;
        h.size_of_image = opt.SizeOfImage;
        h.size_of_headers = opt.SizeOfHeaders;
        h.section_alignment = opt.SectionAlignment;
        h.file_alignment = opt.FileAlignment;
        h.subsystem = opt.Subsystem;
        h.dll_characteristics = opt.DllCharacteristics;
        h.checksum_field = opt.CheckSum;
        h.number_of_rva_and_sizes = opt.NumberOfRvaAndSizes;
        h.loader_flags = opt.LoaderFlags;
        h.win32_version = opt.Win32VersionValue;
        h.major_os = opt.MajorOperatingSystemVersion;
        h.minor_os = opt.MinorOperatingSystemVersion;
        h.major_image = opt.MajorImageVersion;
        h.minor_image = opt.MinorImageVersion;
        h.major_subsystem = opt.MajorSubsystemVersion;
        h.minor_subsystem = opt.MinorSubsystemVersion;
        h.size_of_stack_reserve = opt.SizeOfStackReserve;
        h.size_of_stack_commit = opt.SizeOfStackCommit;
        h.size_of_heap_reserve = opt.SizeOfHeapReserve;
        h.size_of_heap_commit = opt.SizeOfHeapCommit;
        h.base_of_code = opt.BaseOfCode;
        h.base_of_data = opt.BaseOfData;
        h.size_of_code = opt.SizeOfCode;
        h.size_of_initialized_data = opt.SizeOfInitializedData;
        h.size_of_uninitialized_data = opt.SizeOfUninitializedData;

        const uint32_t dir_count = (std::min)(h.number_of_rva_and_sizes, static_cast<uint32_t>(IMAGE_NUMBEROF_DIRECTORY_ENTRIES));
        h.directories.resize(IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
        for (uint32_t i = 0; i < dir_count; ++i)
        {
            h.directories[i].rva = opt.DataDirectory[i].VirtualAddress;
            h.directories[i].size = opt.DataDirectory[i].Size;
            h.directories[i].present = opt.DataDirectory[i].Size != 0 && opt.DataDirectory[i].VirtualAddress != 0;
        }
    }
    else if (h.optional_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        IMAGE_OPTIONAL_HEADER64 opt{};
        const size_t copy = (std::min)(static_cast<size_t>(h.size_of_optional_header), sizeof(opt));
        if (!file.read(h.optional_offset, &opt, copy))
        {
            h.error = "Could not read PE32+ optional header.";
            return h;
        }
        h.pe32_plus = true;
        h.image_base = opt.ImageBase;
        h.address_of_entry_point = opt.AddressOfEntryPoint;
        h.size_of_image = opt.SizeOfImage;
        h.size_of_headers = opt.SizeOfHeaders;
        h.section_alignment = opt.SectionAlignment;
        h.file_alignment = opt.FileAlignment;
        h.subsystem = opt.Subsystem;
        h.dll_characteristics = opt.DllCharacteristics;
        h.checksum_field = opt.CheckSum;
        h.number_of_rva_and_sizes = opt.NumberOfRvaAndSizes;
        h.loader_flags = opt.LoaderFlags;
        h.win32_version = opt.Win32VersionValue;
        h.major_os = opt.MajorOperatingSystemVersion;
        h.minor_os = opt.MinorOperatingSystemVersion;
        h.major_image = opt.MajorImageVersion;
        h.minor_image = opt.MinorImageVersion;
        h.major_subsystem = opt.MajorSubsystemVersion;
        h.minor_subsystem = opt.MinorSubsystemVersion;
        h.size_of_stack_reserve = opt.SizeOfStackReserve;
        h.size_of_stack_commit = opt.SizeOfStackCommit;
        h.size_of_heap_reserve = opt.SizeOfHeapReserve;
        h.size_of_heap_commit = opt.SizeOfHeapCommit;
        h.base_of_code = opt.BaseOfCode;
        h.base_of_data = 0;
        h.size_of_code = opt.SizeOfCode;
        h.size_of_initialized_data = opt.SizeOfInitializedData;
        h.size_of_uninitialized_data = opt.SizeOfUninitializedData;

        const uint32_t dir_count = (std::min)(h.number_of_rva_and_sizes, static_cast<uint32_t>(IMAGE_NUMBEROF_DIRECTORY_ENTRIES));
        h.directories.resize(IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
        for (uint32_t i = 0; i < dir_count; ++i)
        {
            h.directories[i].rva = opt.DataDirectory[i].VirtualAddress;
            h.directories[i].size = opt.DataDirectory[i].Size;
            h.directories[i].present = opt.DataDirectory[i].Size != 0 && opt.DataDirectory[i].VirtualAddress != 0;
        }
    }
    else
    {
        h.error = "Optional header magic is neither PE32 nor PE32+.";
        return h;
    }

    if (h.directories.size() < IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
        h.directories.resize(IMAGE_NUMBEROF_DIRECTORY_ENTRIES);

    h.section_table_offset = h.optional_offset + h.size_of_optional_header;
    const uint64_t section_bytes = static_cast<uint64_t>(h.file.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
    if (!file.contains(h.section_table_offset, section_bytes))
    {
        h.error = "Section table does not fit in the file.";
        return h;
    }

    h.sections.reserve(h.file.NumberOfSections);
    for (uint16_t i = 0; i < h.file.NumberOfSections; ++i)
    {
        IMAGE_SECTION_HEADER raw{};
        const uint64_t off = h.section_table_offset + static_cast<uint64_t>(i) * sizeof(IMAGE_SECTION_HEADER);
        if (!file.read_struct(off, raw))
        {
            h.error = "Could not read a section header.";
            return h;
        }
        SectionInfo s;
        s.name = section_name_from_bytes(raw.Name);
        s.virtual_address = raw.VirtualAddress;
        s.virtual_size = raw.Misc.VirtualSize;
        s.pointer_to_raw_data = raw.PointerToRawData;
        s.size_of_raw_data = raw.SizeOfRawData;
        s.characteristics = raw.Characteristics;
        s.pointer_to_relocations = raw.PointerToRelocations;
        s.pointer_to_linenumbers = raw.PointerToLinenumbers;
        s.number_of_relocations = raw.NumberOfRelocations;
        s.number_of_linenumbers = raw.NumberOfLinenumbers;
        h.sections.push_back(std::move(s));
    }

    h.checksum_computed = compute_pe_checksum(file, checksum_field_offset);
    h.checksum_ok = (h.checksum_field == 0) || (h.checksum_field == h.checksum_computed);
    h.ok = true;
    return h;
}
