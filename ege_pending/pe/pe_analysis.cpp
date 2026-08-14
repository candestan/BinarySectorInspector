#include "pe/pe_analysis.h"
#include "pe/pe_address.h"

#include <cmath>
#include <cctype>

namespace {

double shannon_entropy(const uint8_t* data, uint64_t size)
{
    if (data == nullptr || size == 0)
        return 0.0;

    uint64_t counts[256] = {};
    for (uint64_t i = 0; i < size; ++i)
        ++counts[data[i]];

    double entropy = 0.0;
    const double n = static_cast<double>(size);
    for (uint32_t i = 0; i < 256; ++i)
    {
        if (counts[i] == 0)
            continue;
        const double p = static_cast<double>(counts[i]) / n;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

bool is_ascii_printable(uint8_t b)
{
    return b == '\t' || (b >= 0x20 && b <= 0x7E);
}

const char* machine_is_unusual_ep_section(const std::string& name)
{
    if (name.empty())
        return "Entry point section name is empty.";
    if (name.rfind("UPX", 0) == 0)
        return "Entry point is in a UPX-named section; packing is worth checking.";
    if (name == ".themida" || name == ".aspack" || name == ".nsp0" || name == "PEPACK")
        return "Entry point section name is associated with packers/protectors.";
    return nullptr;
}

} // namespace

EntropyReport compute_entropy(const PeFile& file, const PeHeaders& headers)
{
    EntropyReport report;
    EntropyRange whole;
    whole.label = "Entire file";
    whole.offset = 0;
    whole.size = file.size();
    whole.entropy = shannon_entropy(file.data(), file.size());
    report.ranges.push_back(whole);

    uint64_t max_raw_end = 0;
    for (const SectionInfo& s : headers.sections)
    {
        EntropyRange r;
        r.label = s.name.empty() ? "(unnamed section)" : s.name;
        r.offset = s.pointer_to_raw_data;
        r.size = s.size_of_raw_data;
        if (s.pointer_to_raw_data != 0 && file.contains(s.pointer_to_raw_data, s.size_of_raw_data))
        {
            r.entropy = shannon_entropy(file.data() + s.pointer_to_raw_data, s.size_of_raw_data);
            const uint64_t end = static_cast<uint64_t>(s.pointer_to_raw_data) + s.size_of_raw_data;
            if (end > max_raw_end)
                max_raw_end = end;
        }
        report.ranges.push_back(r);
    }

    if (max_raw_end < file.size())
    {
        EntropyRange overlay;
        overlay.label = "Overlay";
        overlay.offset = max_raw_end;
        overlay.size = file.size() - max_raw_end;
        overlay.entropy = shannon_entropy(file.data() + static_cast<size_t>(max_raw_end), overlay.size);
        report.ranges.push_back(overlay);
    }
    return report;
}

StringTable extract_strings(const PeFile& file)
{
    StringTable table;
    const uint8_t* data = file.data();
    const uint64_t n = file.size();

    std::string ascii;
    uint64_t ascii_start = 0;
    auto flush_ascii = [&](uint64_t end) {
        if (ascii.size() >= kMinExtractedStringLength && table.items.size() < kMaxExtractedStrings)
        {
            if (ascii.size() > kMaxExtractedStringChars)
                ascii.resize(kMaxExtractedStringChars);
            ExtractedString s;
            s.file_offset = ascii_start;
            s.utf16 = false;
            s.text = std::move(ascii);
            table.items.push_back(std::move(s));
        }
        ascii.clear();
        (void)end;
    };

    for (uint64_t i = 0; i < n; ++i)
    {
        if (is_ascii_printable(data[i]))
        {
            if (ascii.empty())
                ascii_start = i;
            ascii.push_back(static_cast<char>(data[i]));
        }
        else
        {
            flush_ascii(i);
        }
        if (table.items.size() >= kMaxExtractedStrings)
            return table;
    }
    flush_ascii(n);

    std::string utf16;
    uint64_t utf_start = 0;
    auto flush_utf = [&]() {
        if (utf16.size() >= kMinExtractedStringLength && table.items.size() < kMaxExtractedStrings)
        {
            if (utf16.size() > kMaxExtractedStringChars)
                utf16.resize(kMaxExtractedStringChars);
            ExtractedString s;
            s.file_offset = utf_start;
            s.utf16 = true;
            s.text = std::move(utf16);
            table.items.push_back(std::move(s));
        }
        utf16.clear();
    };

    for (uint64_t i = 0; i + 1 < n; ++i)
    {
        const uint8_t lo = data[i];
        const uint8_t hi = data[i + 1];
        if (hi == 0 && is_ascii_printable(lo))
        {
            if (utf16.empty())
                utf_start = i;
            utf16.push_back(static_cast<char>(lo));
            ++i;
        }
        else
        {
            flush_utf();
        }
        if (table.items.size() >= kMaxExtractedStrings)
            return table;
    }
    flush_utf();
    return table;
}

std::vector<Finding> collect_findings(
    const PeFile& file,
    const PeHeaders& headers,
    const ImportTable& imports,
    const TlsInfo& tls,
    const DebugInfo& debug,
    const EntropyReport& entropy)
{
    std::vector<Finding> findings;

    if (headers.e_lfanew > kUnusualDosStubThreshold)
    {
        findings.push_back({
            FindingSeverity::Notice,
            "Large DOS stub / e_lfanew",
            "e_lfanew is unusually far from the DOS header. The stub may hide extra data worth inspecting."
        });
    }

    if (headers.file.NumberOfSections == 0)
    {
        findings.push_back({
            FindingSeverity::Warning,
            "No sections",
            "NumberOfSections is 0. The image may be malformed or constructed unusually."
        });
    }

    if (headers.file.TimeDateStamp == 0 || headers.file.TimeDateStamp == 0xFFFFFFFFu)
    {
        findings.push_back({
            FindingSeverity::Notice,
            "Unusual timestamp",
            "TimeDateStamp is 0 or 0xFFFFFFFF. Authenticode-stripped or reproducible builds also do this; still worth noting."
        });
    }

    if ((headers.dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) == 0)
    {
        findings.push_back({
            FindingSeverity::Notice,
            "NX (DEP) not advertised",
            "IMAGE_DLLCHARACTERISTICS_NX_COMPAT is clear. The binary does not request data execution prevention."
        });
    }
    if ((headers.dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) == 0)
    {
        findings.push_back({
            FindingSeverity::Notice,
            "ASLR not advertised",
            "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE is clear. The image does not request relocation-based ASLR."
        });
    }
    if ((headers.dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) == 0)
    {
        findings.push_back({
            FindingSeverity::Info,
            "CFG not advertised",
            "IMAGE_DLLCHARACTERISTICS_GUARD_CF is clear. Control Flow Guard is not requested."
        });
    }
    if (headers.pe32_plus && (headers.dll_characteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) == 0)
    {
        findings.push_back({
            FindingSeverity::Info,
            "High-entropy VA not advertised",
            "PE32+ without IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA; 64-bit ASLR entropy may be reduced."
        });
    }

    if (headers.checksum_field != 0 && !headers.checksum_ok)
    {
        findings.push_back({
            FindingSeverity::Notice,
            "PE checksum mismatch",
            "Optional header CheckSum does not match the computed image checksum. Drivers care; user-mode binaries often ignore this."
        });
    }

    uint64_t max_raw_end = 0;
    for (const SectionInfo& s : headers.sections)
    {
        const bool exec = (s.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        const bool write = (s.characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        if (exec && write)
        {
            findings.push_back({
                FindingSeverity::Warning,
                "Writable and executable section",
                "Section \"" + s.name + "\" has MEM_EXECUTE and MEM_WRITE. That is valid but worth investigating (self-modifying code or packer stub)."
            });
        }
        bool name_odd = s.name.empty();
        for (char c : s.name)
        {
            if (c == '/' || static_cast<unsigned char>(c) < 0x20)
                name_odd = true;
        }
        if (name_odd)
        {
            findings.push_back({
                FindingSeverity::Notice,
                "Unusual section name",
                "A section name is empty, contains a slash, or non-printable bytes."
            });
        }
        const uint64_t vend = static_cast<uint64_t>(s.virtual_address) + (s.virtual_size != 0 ? s.virtual_size : s.size_of_raw_data);
        if (headers.size_of_image != 0 && vend > headers.size_of_image)
        {
            findings.push_back({
                FindingSeverity::Warning,
                "Section exceeds SizeOfImage",
                "Section \"" + s.name + "\" virtual range extends past SizeOfImage."
            });
        }
        const uint64_t rend = static_cast<uint64_t>(s.pointer_to_raw_data) + s.size_of_raw_data;
        if (rend > max_raw_end)
            max_raw_end = rend;
    }

    if (max_raw_end > 0 && max_raw_end < file.size())
    {
        findings.push_back({
            FindingSeverity::Notice,
            "Overlay data",
            "Bytes exist after the last section raw range. Installers, appended payloads, and signatures often live here."
        });
    }

    const FileAddress ep = address_from_rva(headers, headers.address_of_entry_point);
    if (headers.address_of_entry_point != 0 && ep.section_index < 0)
    {
        findings.push_back({
            FindingSeverity::Warning,
            "Entry point outside sections",
            "AddressOfEntryPoint does not fall in any section virtual range (headers or unmapped)."
        });
    }
    else if (ep.section_index >= 0)
    {
        if (const char* why = machine_is_unusual_ep_section(ep.section_name))
        {
            findings.push_back({ FindingSeverity::Notice, "Unusual entry point section", why });
        }
    }

    if (imports.modules.empty() && (headers.file.Characteristics & IMAGE_FILE_DLL) == 0)
    {
        findings.push_back({
            FindingSeverity::Notice,
            "No imports",
            "No import or delay-load descriptors were parsed. Native images, packed stubs, or truncated tables can look like this."
        });
    }

    if (tls.present && !tls.callbacks.empty())
    {
        findings.push_back({
            FindingSeverity::Notice,
            "TLS callbacks present",
            "The loader runs TLS callbacks before the entry point. Check callback RVAs when reconstructing startup."
        });
    }

    if (!debug.pdb_path.empty())
    {
        findings.push_back({
            FindingSeverity::Info,
            "PDB path present",
            "CodeView debug info contains a PDB path. That can leak build-machine layout; useful for matching symbols, not a verdict."
        });
    }

    for (const EntropyRange& r : entropy.ranges)
    {
        if (r.size >= 256 && r.entropy >= kHighEntropyThreshold)
        {
            findings.push_back({
                FindingSeverity::Notice,
                "High entropy: " + r.label,
                "Shannon entropy is high (possible compression or packing). Confirm with section names and imports; entropy alone is not a malware label."
            });
        }
    }

    if (headers.section_alignment == 0 || headers.file_alignment == 0)
    {
        findings.push_back({
            FindingSeverity::Warning,
            "Zero alignment",
            "SectionAlignment or FileAlignment is 0. Address conversion and mapping assumptions may fail."
        });
    }

    (void)file;
    return findings;
}
