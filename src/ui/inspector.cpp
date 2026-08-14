#include "ui/inspector.h"
#include "platform/utf8.h"
#include "pe/pe_address.h"
#include "imgui.h"

#include <cstdio>
#include <string>
#include <vector>

namespace {

std::string hex_u32(uint32_t v)
{
    char buf[16];
    snprintf(buf, sizeof(buf), "0x%08X", v);
    return buf;
}

std::string hex_u64(uint64_t v)
{
    char buf[24];
    snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(v));
    return buf;
}

std::string format_address(const FileAddress& a)
{
    std::string s;
    s += a.has_rva ? ("RVA " + hex_u32(a.rva)) : "RVA n/a";
    s += " | ";
    s += a.has_va ? ("VA " + hex_u64(a.va)) : "VA n/a";
    s += " | ";
    s += a.has_file ? ("File " + hex_u64(a.file_offset)) : "File n/a";
    if (!a.section_name.empty())
        s += " | " + a.section_name;
    return s;
}

const char* machine_name(uint16_t machine)
{
    switch (machine)
    {
    case IMAGE_FILE_MACHINE_I386: return "I386";
    case IMAGE_FILE_MACHINE_AMD64: return "AMD64";
    case IMAGE_FILE_MACHINE_ARM: return "ARM";
    case IMAGE_FILE_MACHINE_ARM64: return "ARM64";
    case IMAGE_FILE_MACHINE_IA64: return "IA64";
    default: return "UNKNOWN";
    }
}

const char* subsystem_name(uint16_t subsystem)
{
    switch (subsystem)
    {
    case IMAGE_SUBSYSTEM_NATIVE: return "NATIVE";
    case IMAGE_SUBSYSTEM_WINDOWS_GUI: return "WINDOWS_GUI";
    case IMAGE_SUBSYSTEM_WINDOWS_CUI: return "WINDOWS_CUI";
    case IMAGE_SUBSYSTEM_OS2_CUI: return "OS2_CUI";
    case IMAGE_SUBSYSTEM_POSIX_CUI: return "POSIX_CUI";
    case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI: return "WINDOWS_CE_GUI";
    case IMAGE_SUBSYSTEM_EFI_APPLICATION: return "EFI_APPLICATION";
    case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: return "EFI_BOOT_SERVICE_DRIVER";
    case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER: return "EFI_RUNTIME_DRIVER";
    case IMAGE_SUBSYSTEM_EFI_ROM: return "EFI_ROM";
    case IMAGE_SUBSYSTEM_XBOX: return "XBOX";
    case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION: return "WINDOWS_BOOT_APPLICATION";
    default: return "UNKNOWN";
    }
}

const char* reloc_type_name(uint8_t type)
{
    switch (type)
    {
    case IMAGE_REL_BASED_ABSOLUTE: return "ABSOLUTE";
    case IMAGE_REL_BASED_HIGH: return "HIGH";
    case IMAGE_REL_BASED_LOW: return "LOW";
    case IMAGE_REL_BASED_HIGHLOW: return "HIGHLOW";
    case IMAGE_REL_BASED_DIR64: return "DIR64";
    default: return "OTHER";
    }
}

const char* finding_severity(FindingSeverity s)
{
    switch (s)
    {
    case FindingSeverity::Warning: return "warning";
    case FindingSeverity::Notice: return "notice";
    default: return "info";
    }
}

std::string directory_name(uint32_t index)
{
    static const char* names[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = {
        "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC",
        "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG",
        "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED"
    };
    if (index < IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
        return names[index];
    return "DIR";
}

void kv(const char* key, const char* value)
{
    ImGui::TableNextRow();
    ImGui::TableNextColumn();
    ImGui::TextUnformatted(key);
    ImGui::TableNextColumn();
    ImGui::TextUnformatted(value);
}

void kv_u32(const char* key, uint32_t v)
{
    kv(key, (hex_u32(v) + " (" + std::to_string(v) + ")").c_str());
}

void kv_u64(const char* key, uint64_t v)
{
    kv(key, hex_u64(v).c_str());
}

bool begin_kv_table(const char* id)
{
    const ImGuiTableFlags flags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp;
    if (!ImGui::BeginTable(id, 2, flags))
        return false;
    ImGui::TableSetupColumn("Field", ImGuiTableColumnFlags_WidthFixed, 260.f);
    ImGui::TableSetupColumn("Value");
    return true;
}

void draw_flag_line(const char* name, bool on)
{
    ImGui::Text("%s: %s", name, on ? "yes" : "no");
}

void draw_overview(const PeImage& image)
{
    const PeHeaders& h = image.headers;
    ImGui::Text("Path: %s", wide_to_utf8(image.path).c_str());
    ImGui::Text("Format: %s  Machine: %s  Subsystem: %s",
        h.pe32_plus ? "PE32+" : "PE32",
        machine_name(h.file.Machine),
        subsystem_name(h.subsystem));
    ImGui::Text("ImageBase: %s", hex_u64(h.image_base).c_str());
    ImGui::Text("SizeOfImage: %s", hex_u32(h.size_of_image).c_str());
    ImGui::Text("Sections: %u  File size: %s",
        static_cast<unsigned>(h.sections.size()),
        hex_u64(image.file.size()).c_str());

    const FileAddress ep = address_from_rva(h, h.address_of_entry_point);
    ImGui::Text("Entry point: %s", format_address(ep).c_str());

    ImGui::Separator();
    ImGui::TextUnformatted("DllCharacteristics");
    draw_flag_line("DYNAMIC_BASE (ASLR)", (h.dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0);
    draw_flag_line("NX_COMPAT (DEP)", (h.dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0);
    draw_flag_line("HIGH_ENTROPY_VA", (h.dll_characteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) != 0);
    draw_flag_line("GUARD_CF", (h.dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0);
    draw_flag_line("NO_SEH", (h.dll_characteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) != 0);
    draw_flag_line("FORCE_INTEGRITY", (h.dll_characteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) != 0);
    draw_flag_line("TERMINAL_SERVER_AWARE", (h.dll_characteristics & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE) != 0);

    ImGui::Separator();
    ImGui::Text("Checksum field %s  computed %s  %s",
        hex_u32(h.checksum_field).c_str(),
        hex_u32(h.checksum_computed).c_str(),
        h.checksum_field == 0 ? "(not set)" : (h.checksum_ok ? "match" : "mismatch"));
    ImGui::Text("Findings: %zu", image.findings.size());
    if (image.resources.version.present)
    {
        ImGui::Text("File version: %u.%u.%u.%u",
            image.resources.version.file_major, image.resources.version.file_minor,
            image.resources.version.file_build, image.resources.version.file_revision);
    }
}

void draw_headers(const PeImage& image)
{
    const PeHeaders& h = image.headers;
    if (ImGui::CollapsingHeader("DOS header", ImGuiTreeNodeFlags_DefaultOpen) && begin_kv_table("dos"))
    {
        kv("e_magic", hex_u32(h.dos.e_magic).c_str());
        kv_u32("e_lfanew", h.e_lfanew);
        kv_u32("e_cblp", h.dos.e_cblp);
        kv_u32("e_cp", h.dos.e_cp);
        kv_u32("e_cparhdr", h.dos.e_cparhdr);
        kv_u32("e_sp", h.dos.e_sp);
        kv_u32("e_ip", h.dos.e_ip);
        ImGui::EndTable();
    }
    if (ImGui::CollapsingHeader("File header", ImGuiTreeNodeFlags_DefaultOpen) && begin_kv_table("file"))
    {
        kv("Machine", machine_name(h.file.Machine));
        kv_u32("NumberOfSections", h.file.NumberOfSections);
        kv_u32("TimeDateStamp", h.file.TimeDateStamp);
        kv_u32("PointerToSymbolTable", h.file.PointerToSymbolTable);
        kv_u32("NumberOfSymbols", h.file.NumberOfSymbols);
        kv_u32("SizeOfOptionalHeader", h.file.SizeOfOptionalHeader);
        kv_u32("Characteristics", h.file.Characteristics);
        ImGui::EndTable();
    }
    if (ImGui::CollapsingHeader("Optional header", ImGuiTreeNodeFlags_DefaultOpen) && begin_kv_table("opt"))
    {
        kv("Magic", h.pe32_plus ? "PE32+" : "PE32");
        kv_u64("ImageBase", h.image_base);
        kv_u32("AddressOfEntryPoint", h.address_of_entry_point);
        kv_u32("BaseOfCode", h.base_of_code);
        if (!h.pe32_plus)
            kv_u32("BaseOfData", h.base_of_data);
        kv_u32("SizeOfImage", h.size_of_image);
        kv_u32("SizeOfHeaders", h.size_of_headers);
        kv_u32("SectionAlignment", h.section_alignment);
        kv_u32("FileAlignment", h.file_alignment);
        kv("Subsystem", subsystem_name(h.subsystem));
        kv_u32("DllCharacteristics", h.dll_characteristics);
        kv_u32("CheckSum", h.checksum_field);
        kv_u32("NumberOfRvaAndSizes", h.number_of_rva_and_sizes);
        kv_u64("SizeOfStackReserve", h.size_of_stack_reserve);
        kv_u64("SizeOfStackCommit", h.size_of_stack_commit);
        kv_u64("SizeOfHeapReserve", h.size_of_heap_reserve);
        kv_u64("SizeOfHeapCommit", h.size_of_heap_commit);
        ImGui::EndTable();
    }
    if (ImGui::CollapsingHeader("Data directories", ImGuiTreeNodeFlags_DefaultOpen))
    {
        if (ImGui::BeginTable("dirs", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, 220)))
        {
            ImGui::TableSetupColumn("Index");
            ImGui::TableSetupColumn("Name");
            ImGui::TableSetupColumn("RVA");
            ImGui::TableSetupColumn("Size");
            ImGui::TableHeadersRow();
            for (uint32_t i = 0; i < image.headers.directories.size(); ++i)
            {
                const DataDirectoryEntry& d = image.headers.directories[i];
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::Text("%u", i);
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(directory_name(i).c_str());
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(d.present ? hex_u32(d.rva).c_str() : "-");
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(d.present ? hex_u32(d.size).c_str() : "-");
            }
            ImGui::EndTable();
        }
    }
}

void draw_sections(PeImage& image, InspectorState& state)
{
    if (!ImGui::BeginTable("sections", 7, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable, ImVec2(0, -120)))
        return;
    ImGui::TableSetupColumn("Name");
    ImGui::TableSetupColumn("VA");
    ImGui::TableSetupColumn("VSize");
    ImGui::TableSetupColumn("RawPtr");
    ImGui::TableSetupColumn("RawSize");
    ImGui::TableSetupColumn("Chars");
    ImGui::TableSetupColumn("Flags");
    ImGui::TableHeadersRow();
    for (int i = 0; i < static_cast<int>(image.headers.sections.size()); ++i)
    {
        const SectionInfo& s = image.headers.sections[static_cast<size_t>(i)];
        ImGui::PushID(i);
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        if (ImGui::Selectable(s.name.empty() ? "(unnamed)" : s.name.c_str(), state.selected_section == i, ImGuiSelectableFlags_SpanAllColumns))
        {
            state.selected_section = i;
            state.hex_scroll_offset = s.pointer_to_raw_data;
            state.hex_scroll_pending = true;
            state.hex_highlight_start = s.pointer_to_raw_data;
            state.hex_highlight_size = s.size_of_raw_data;
        }
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(hex_u32(s.virtual_address).c_str());
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(hex_u32(s.virtual_size).c_str());
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(hex_u32(s.pointer_to_raw_data).c_str());
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(hex_u32(s.size_of_raw_data).c_str());
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(hex_u32(s.characteristics).c_str());
        ImGui::TableNextColumn();
        std::string flags;
        if (s.characteristics & IMAGE_SCN_CNT_CODE) flags += "CODE ";
        if (s.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) flags += "IDATA ";
        if (s.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) flags += "UDATA ";
        if (s.characteristics & IMAGE_SCN_MEM_EXECUTE) flags += "X ";
        if (s.characteristics & IMAGE_SCN_MEM_READ) flags += "R ";
        if (s.characteristics & IMAGE_SCN_MEM_WRITE) flags += "W ";
        if (s.characteristics & IMAGE_SCN_MEM_DISCARDABLE) flags += "DISC ";
        if (s.characteristics & IMAGE_SCN_MEM_SHARED) flags += "SHARE ";
        ImGui::TextUnformatted(flags.c_str());
        ImGui::PopID();
    }
    ImGui::EndTable();

    if (state.selected_section >= 0 && static_cast<size_t>(state.selected_section) < image.headers.sections.size())
    {
        const SectionInfo& s = image.headers.sections[static_cast<size_t>(state.selected_section)];
        FileAddress start = address_from_rva(image.headers, s.virtual_address);
        ImGui::Text("Selected: %s", format_address(start).c_str());
        ImGui::TextUnformatted("Switch to Hex to view the selected raw range.");
    }
}

bool pass_filter(const char* filter, const std::string& text)
{
    if (filter == nullptr || filter[0] == '\0')
        return true;
    return text.find(filter) != std::string::npos;
}

void draw_imports(const PeImage& image, InspectorState& state)
{
    if (!image.imports.error.empty())
        ImGui::TextWrapped("Import parse: %s", image.imports.error.c_str());
    ImGui::InputTextWithHint("##impfilter", "Filter DLL / symbol", state.filter, sizeof(state.filter));
    if (!ImGui::BeginTable("imports", 6, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable, ImVec2(0, 0)))
        return;
    ImGui::TableSetupColumn("DLL");
    ImGui::TableSetupColumn("Kind");
    ImGui::TableSetupColumn("Symbol");
    ImGui::TableSetupColumn("Hint/Ord");
    ImGui::TableSetupColumn("IAT");
    ImGui::TableSetupColumn("Bound");
    ImGui::TableHeadersRow();
    int id = 0;
    for (const ImportedModule& mod : image.imports.modules)
    {
        for (const ImportedSymbol& sym : mod.symbols)
        {
            const std::string label = sym.by_ordinal ? ("#" + std::to_string(sym.ordinal)) : sym.name;
            if (!pass_filter(state.filter, mod.dll_name) && !pass_filter(state.filter, label))
                continue;
            ImGui::PushID(id++);
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(mod.dll_name.c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(mod.delay_load ? "delay" : "import");
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(label.c_str());
            ImGui::TableNextColumn();
            if (sym.by_ordinal)
                ImGui::Text("ord %u", sym.ordinal);
            else
                ImGui::Text("hint %u", sym.hint);
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(format_address(sym.iat).c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(mod.bound ? "yes" : "no");
            ImGui::PopID();
        }
    }
    ImGui::EndTable();
}

void draw_exports(const PeImage& image, InspectorState& state)
{
    if (!image.exports.error.empty())
        ImGui::TextWrapped("Export parse: %s", image.exports.error.c_str());
    ImGui::Text("DLL name: %s  Base: %u", image.exports.dll_name.c_str(), image.exports.ordinal_base);
    ImGui::InputTextWithHint("##expfilter", "Filter export", state.filter, sizeof(state.filter));
    if (!ImGui::BeginTable("exports", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable))
        return;
    ImGui::TableSetupColumn("Ordinal");
    ImGui::TableSetupColumn("Name");
    ImGui::TableSetupColumn("Address / forwarder");
    ImGui::TableSetupColumn("Location");
    ImGui::TableHeadersRow();
    int id = 0;
    for (const ExportedSymbol& sym : image.exports.symbols)
    {
        if (!pass_filter(state.filter, sym.name) && !pass_filter(state.filter, std::to_string(sym.ordinal)))
            continue;
        ImGui::PushID(id++);
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::Text("%u", sym.ordinal);
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(sym.name.empty() ? "(ordinal only)" : sym.name.c_str());
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(sym.forwarded ? sym.forwarder.c_str() : format_address(sym.address).c_str());
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(sym.forwarded ? "forwarded" : "rva");
        ImGui::PopID();
    }
    ImGui::EndTable();
}

void draw_relocs(const PeImage& image, InspectorState& state)
{
    if (!image.relocs.error.empty())
        ImGui::TextWrapped("%s", image.relocs.error.c_str());
    ImGui::Text("Blocks: %u  ABSOLUTE: %u  HIGHLOW: %u  DIR64: %u  other: %u",
        image.relocs.block_count, image.relocs.type_absolute, image.relocs.type_highlow,
        image.relocs.type_dir64, image.relocs.type_other);
    ImGui::TextUnformatted("Select a block to inspect entries (large tables stay collapsed).");
    if (ImGui::BeginTable("relocblocks", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, 180)))
    {
        ImGui::TableSetupColumn("Page RVA");
        ImGui::TableSetupColumn("Block size");
        ImGui::TableSetupColumn("Stored entries");
        ImGui::TableHeadersRow();
        for (int i = 0; i < static_cast<int>(image.relocs.blocks.size()); ++i)
        {
            const RelocBlock& b = image.relocs.blocks[static_cast<size_t>(i)];
            ImGui::PushID(i);
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            if (ImGui::Selectable(hex_u32(b.page_rva).c_str(), state.reloc_block == i, ImGuiSelectableFlags_SpanAllColumns))
                state.reloc_block = i;
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(hex_u32(b.block_size).c_str());
            ImGui::TableNextColumn();
            ImGui::Text("%zu", b.entries.size());
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    if (state.reloc_block >= 0 && static_cast<size_t>(state.reloc_block) < image.relocs.blocks.size())
    {
        const RelocBlock& b = image.relocs.blocks[static_cast<size_t>(state.reloc_block)];
        if (ImGui::BeginTable("relocents", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY))
        {
            ImGui::TableSetupColumn("Type");
            ImGui::TableSetupColumn("Off");
            ImGui::TableSetupColumn("Address");
            ImGui::TableHeadersRow();
            for (const RelocEntry& e : b.entries)
            {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(reloc_type_name(e.type));
                ImGui::TableNextColumn();
                ImGui::Text("0x%03X", e.offset);
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(format_address(e.address).c_str());
            }
            ImGui::EndTable();
        }
    }
}

void draw_tls(const PeImage& image)
{
    if (!image.tls.error.empty())
        ImGui::TextWrapped("%s", image.tls.error.c_str());
    if (!image.tls.present)
    {
        ImGui::TextUnformatted("No TLS directory.");
        return;
    }
    if (begin_kv_table("tls"))
    {
        kv_u64("StartAddressOfRawData", image.tls.start_address_of_raw_data);
        kv_u64("EndAddressOfRawData", image.tls.end_address_of_raw_data);
        kv_u64("AddressOfIndex", image.tls.address_of_index);
        kv_u64("AddressOfCallBacks", image.tls.address_of_callbacks);
        kv_u32("SizeOfZeroFill", image.tls.size_of_zero_fill);
        kv_u32("Characteristics", image.tls.characteristics);
        ImGui::EndTable();
    }
    ImGui::Text("Callbacks: %zu", image.tls.callbacks.size());
    for (size_t i = 0; i < image.tls.callbacks.size(); ++i)
        ImGui::Text("[%zu] %s", i, format_address(image.tls.callbacks[i]).c_str());
}

void draw_resource_node(const ResourceNode& node, int depth)
{
    std::string label;
    if (node.name_is_string)
        label = node.name;
    else
        label = "#" + std::to_string(node.id);
    if (!node.is_directory)
        label += "  size " + hex_u32(node.data_size);

    ImGui::PushID(static_cast<int>(reinterpret_cast<uintptr_t>(&node)));
    if (node.is_directory)
    {
        if (ImGui::TreeNode(label.c_str()))
        {
            for (const ResourceNode& child : node.children)
                draw_resource_node(child, depth + 1);
            ImGui::TreePop();
        }
    }
    else
    {
        ImGui::BulletText("%s  %s", label.c_str(), format_address(node.data).c_str());
    }
    ImGui::PopID();
    (void)depth;
}

void draw_resources(const PeImage& image)
{
    if (!image.resources.error.empty())
        ImGui::TextWrapped("%s", image.resources.error.c_str());
    if (image.resources.version.present)
    {
        ImGui::Text("Version: file %u.%u.%u.%u  product %u.%u.%u.%u  flags %s",
            image.resources.version.file_major, image.resources.version.file_minor,
            image.resources.version.file_build, image.resources.version.file_revision,
            image.resources.version.product_major, image.resources.version.product_minor,
            image.resources.version.product_build, image.resources.version.product_revision,
            hex_u32(image.resources.version.file_flags).c_str());
    }
    if (image.resources.root.children.empty())
        ImGui::TextUnformatted("No resources.");
    for (const ResourceNode& child : image.resources.root.children)
        draw_resource_node(child, 0);
}

void draw_debug(const PeImage& image)
{
    if (!image.debug.error.empty())
        ImGui::TextWrapped("%s", image.debug.error.c_str());
    if (!image.debug.pdb_path.empty())
        ImGui::Text("PDB: %s", image.debug.pdb_path.c_str());
    if (!ImGui::BeginTable("debug", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY))
        return;
    ImGui::TableSetupColumn("Type");
    ImGui::TableSetupColumn("Timestamp");
    ImGui::TableSetupColumn("Size");
    ImGui::TableSetupColumn("Location");
    ImGui::TableSetupColumn("Extra");
    ImGui::TableHeadersRow();
    for (const DebugEntry& e : image.debug.entries)
    {
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(e.type_name.c_str());
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(hex_u32(e.timestamp).c_str());
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(hex_u32(e.size).c_str());
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(format_address(e.address).c_str());
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(e.extra.c_str());
    }
    ImGui::EndTable();
}

void draw_strings(const PeImage& image, InspectorState& state)
{
    ImGui::InputTextWithHint("##strfilter", "Filter strings", state.filter, sizeof(state.filter));
    ImGui::Text("Showing up to %zu extracted strings", image.strings.items.size());
    if (!ImGui::BeginTable("strings", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable))
        return;
    ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 110.f);
    ImGui::TableSetupColumn("Enc", ImGuiTableColumnFlags_WidthFixed, 50.f);
    ImGui::TableSetupColumn("Text");
    ImGui::TableHeadersRow();
    int id = 0;
    for (const ExtractedString& s : image.strings.items)
    {
        if (!pass_filter(state.filter, s.text))
            continue;
        ImGui::PushID(id++);
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(hex_u64(s.file_offset).c_str());
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(s.utf16 ? "u16" : "asc");
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(s.text.c_str());
        ImGui::PopID();
        if (id > 4000)
            break;
    }
    ImGui::EndTable();
}

void draw_findings(const PeImage& image)
{
    if (!ImGui::BeginTable("findings", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable))
        return;
    ImGui::TableSetupColumn("Severity", ImGuiTableColumnFlags_WidthFixed, 90.f);
    ImGui::TableSetupColumn("Title", ImGuiTableColumnFlags_WidthFixed, 240.f);
    ImGui::TableSetupColumn("Why");
    ImGui::TableHeadersRow();
    for (const Finding& f : image.findings)
    {
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(finding_severity(f.severity));
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(f.title.c_str());
        ImGui::TableNextColumn();
        ImGui::TextWrapped("%s", f.why.c_str());
    }
    ImGui::EndTable();
}

void draw_hex(const PeImage& image, InspectorState& state)
{
    constexpr int kBytesPerRow = 16;
    const uint64_t size = image.file.size();
    if (size == 0)
    {
        ImGui::TextUnformatted("No file bytes.");
        return;
    }

    ImGui::Text("File size %s  highlight %s + %s",
        hex_u64(size).c_str(),
        hex_u64(state.hex_highlight_start).c_str(),
        hex_u64(state.hex_highlight_size).c_str());

    const int row_count = static_cast<int>((size + kBytesPerRow - 1) / kBytesPerRow);
    const float row_h = ImGui::GetTextLineHeightWithSpacing();
    ImGuiListClipper clipper;
    clipper.Begin(row_count, row_h);
    const uint8_t* data = image.file.data();
    while (clipper.Step())
    {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row)
        {
            const uint64_t off = static_cast<uint64_t>(row) * kBytesPerRow;
            ImGui::Text("%08llX ", static_cast<unsigned long long>(off));
            ImGui::SameLine(0, 0);
            char hex[3 * kBytesPerRow + 8];
            char ascii[kBytesPerRow + 1];
            int hex_n = 0;
            for (int c = 0; c < kBytesPerRow; ++c)
            {
                const uint64_t p = off + static_cast<uint64_t>(c);
                if (p < size)
                {
                    const uint8_t b = data[static_cast<size_t>(p)];
                    hex_n += snprintf(hex + hex_n, sizeof(hex) - hex_n, "%02X ", b);
                    ascii[c] = (b >= 0x20 && b <= 0x7E) ? static_cast<char>(b) : '.';
                }
                else
                {
                    hex_n += snprintf(hex + hex_n, sizeof(hex) - hex_n, "   ");
                    ascii[c] = ' ';
                }
            }
            ascii[kBytesPerRow] = 0;
            const bool hl = state.hex_highlight_size > 0 &&
                off < state.hex_highlight_start + state.hex_highlight_size &&
                off + kBytesPerRow > state.hex_highlight_start;
            if (hl)
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.95f, 0.85f, 0.35f, 1.f));
            ImGui::TextUnformatted(hex);
            ImGui::SameLine();
            ImGui::TextUnformatted(ascii);
            if (hl)
                ImGui::PopStyleColor();
        }
    }

    if (state.hex_scroll_pending)
    {
        const int focus_row = static_cast<int>(state.hex_scroll_offset / kBytesPerRow);
        ImGui::SetScrollY(static_cast<float>(focus_row) * row_h);
        state.hex_scroll_pending = false;
    }
}

void draw_entropy(const PeImage& image)
{
    if (!ImGui::BeginTable("entropy", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg))
        return;
    ImGui::TableSetupColumn("Range");
    ImGui::TableSetupColumn("Offset");
    ImGui::TableSetupColumn("Size");
    ImGui::TableSetupColumn("Entropy");
    ImGui::TableHeadersRow();
    for (const EntropyRange& r : image.entropy.ranges)
    {
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(r.label.c_str());
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(hex_u64(r.offset).c_str());
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(hex_u64(r.size).c_str());
        ImGui::TableNextColumn();
        ImGui::Text("%.3f", r.entropy);
    }
    ImGui::EndTable();
}

} // namespace

bool draw_inspector(PeImage& image, InspectorState& state, bool& request_open_another)
{
    request_open_another = false;
    ImGui::SetNextWindowPos(ImVec2(40.f, 24.f), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(1180.f, 620.f), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("PE inspector"))
    {
        ImGui::End();
        return false;
    }

    if (ImGui::Button("Open another..."))
        request_open_another = true;
    ImGui::SameLine();
    ImGui::TextUnformatted(wide_to_utf8(image.path).c_str());

    if (!image.headers_ok)
    {
        ImGui::Separator();
        ImGui::TextWrapped("Could not parse PE headers: %s", image.error.c_str());
        ImGui::End();
        return true;
    }

    if (ImGui::BeginTabBar("pe_tabs"))
    {
        if (ImGui::BeginTabItem("Overview"))
        {
            draw_overview(image);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Headers"))
        {
            draw_headers(image);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Sections"))
        {
            draw_sections(image, state);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Imports"))
        {
            draw_imports(image, state);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Exports"))
        {
            draw_exports(image, state);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Relocs"))
        {
            draw_relocs(image, state);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("TLS"))
        {
            draw_tls(image);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Resources"))
        {
            draw_resources(image);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Debug"))
        {
            draw_debug(image);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Entropy"))
        {
            draw_entropy(image);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Strings"))
        {
            draw_strings(image, state);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Findings"))
        {
            draw_findings(image);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Hex"))
        {
            draw_hex(image, state);
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }

    ImGui::End();
    return true;
}
