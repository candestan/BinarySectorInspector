#pragma once

#include "pe/pe_file.h"
#include "pe/pe_headers.h"
#include "pe/pe_types.h"

#include <optional>
#include <string>

std::optional<int> section_index_for_rva(const PeHeaders& headers, uint32_t rva);
std::optional<int> section_index_for_offset(const PeHeaders& headers, uint64_t offset);
FileAddress address_from_rva(const PeHeaders& headers, uint32_t rva);
FileAddress address_from_offset(const PeHeaders& headers, uint64_t offset);
std::string section_name_at(const PeHeaders& headers, int index);
std::string read_rva_cstring(const PeFile& file, const PeHeaders& headers, uint32_t rva, uint32_t max_chars);
