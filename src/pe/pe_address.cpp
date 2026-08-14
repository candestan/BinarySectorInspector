#include "pe/pe_address.h"

namespace {

uint32_t virtual_span(const SectionInfo& section)
{
    return section.virtual_size != 0 ? section.virtual_size : section.size_of_raw_data;
}

} // namespace

std::string section_name_at(const PeHeaders& headers, int index)
{
    if (index < 0 || static_cast<size_t>(index) >= headers.sections.size())
        return {};
    return headers.sections[static_cast<size_t>(index)].name;
}

std::optional<int> section_index_for_rva(const PeHeaders& headers, uint32_t rva)
{
    for (int i = 0; i < static_cast<int>(headers.sections.size()); ++i)
    {
        const SectionInfo& s = headers.sections[static_cast<size_t>(i)];
        const uint32_t span = virtual_span(s);
        if (span == 0)
            continue;
        if (rva >= s.virtual_address && rva < s.virtual_address + span)
            return i;
    }
    return std::nullopt;
}

std::optional<int> section_index_for_offset(const PeHeaders& headers, uint64_t offset)
{
    for (int i = 0; i < static_cast<int>(headers.sections.size()); ++i)
    {
        const SectionInfo& s = headers.sections[static_cast<size_t>(i)];
        if (s.pointer_to_raw_data == 0 || s.size_of_raw_data == 0)
            continue;
        if (offset >= s.pointer_to_raw_data &&
            offset < static_cast<uint64_t>(s.pointer_to_raw_data) + s.size_of_raw_data)
            return i;
    }
    return std::nullopt;
}

FileAddress address_from_rva(const PeHeaders& headers, uint32_t rva)
{
    FileAddress a;
    a.has_rva = true;
    a.rva = rva;
    a.va = headers.image_base + rva;
    a.has_va = true;

    const auto index = section_index_for_rva(headers, rva);
    if (!index)
        return a;

    const SectionInfo& s = headers.sections[static_cast<size_t>(*index)];
    a.section_index = *index;
    a.section_name = s.name;
    const uint32_t delta = rva - s.virtual_address;
    if (s.pointer_to_raw_data != 0 && delta < s.size_of_raw_data)
    {
        a.has_file = true;
        a.file_offset = static_cast<uint64_t>(s.pointer_to_raw_data) + delta;
        a.valid = true;
    }
    return a;
}

FileAddress address_from_offset(const PeHeaders& headers, uint64_t offset)
{
    FileAddress a;
    a.has_file = true;
    a.file_offset = offset;

    const auto index = section_index_for_offset(headers, offset);
    if (!index)
        return a;

    const SectionInfo& s = headers.sections[static_cast<size_t>(*index)];
    a.section_index = *index;
    a.section_name = s.name;
    const uint32_t delta = static_cast<uint32_t>(offset - s.pointer_to_raw_data);
    a.has_rva = true;
    a.rva = s.virtual_address + delta;
    a.has_va = true;
    a.va = headers.image_base + a.rva;
    a.valid = true;
    return a;
}

std::string read_rva_cstring(const PeFile& file, const PeHeaders& headers, uint32_t rva, uint32_t max_chars)
{
    const FileAddress a = address_from_rva(headers, rva);
    if (!a.has_file)
        return {};
    return file.read_cstring(a.file_offset, max_chars);
}
