#pragma once

#include "pe/pe_file.h"
#include "pe/pe_headers.h"
#include "pe/pe_directories.h"
#include "pe/pe_types.h"

#include <string>
#include <vector>

struct EntropyRange
{
    std::string label;
    uint64_t offset = 0;
    uint64_t size = 0;
    double entropy = 0.0;
};

struct EntropyReport
{
    std::vector<EntropyRange> ranges;
};

struct ExtractedString
{
    uint64_t file_offset = 0;
    bool utf16 = false;
    std::string text;
};

struct StringTable
{
    std::vector<ExtractedString> items;
};

EntropyReport compute_entropy(const PeFile& file, const PeHeaders& headers);
StringTable extract_strings(const PeFile& file);
std::vector<Finding> collect_findings(
    const PeFile& file,
    const PeHeaders& headers,
    const ImportTable& imports,
    const TlsInfo& tls,
    const DebugInfo& debug,
    const EntropyReport& entropy);
