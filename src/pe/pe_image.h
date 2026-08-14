#pragma once

#include "pe/pe_file.h"
#include "pe/pe_headers.h"
#include "pe/pe_directories.h"
#include "pe/pe_analysis.h"

#include <string>

struct PeImage
{
    std::wstring path;
    std::string error;
    bool headers_ok = false;
    PeFile file;
    PeHeaders headers;
    ImportTable imports;
    ExportTable exports;
    RelocTable relocs;
    TlsInfo tls;
    ResourceTree resources;
    DebugInfo debug;
    EntropyReport entropy;
    StringTable strings;
    std::vector<Finding> findings;

    static PeImage load(const std::wstring& path);
};
