#include "detect/detect_p.h"

#include <nlohmann/json.hpp>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <algorithm>

static bool IsHexDigit(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static int HexVal(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

bool DetectParseBytePattern(const char* text, BytePat* out, std::string* err)
{
    if (out)
        *out = BytePat{};
    if (!text || !text[0])
    {
        if (err)
            *err = "empty byte pattern";
        return false;
    }
    BytePat pat;
    const char* p = text;
    int tokens = 0;
    while (*p)
    {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
            p++;
        if (!*p)
            break;
        if (tokens >= 256)
        {
            if (err)
                *err = "byte pattern longer than 256 bytes";
            return false;
        }
        if (p[0] == '?' && p[1] == '?')
        {
            pat.bytes.push_back(0);
            pat.mask.push_back(0);
            p += 2;
            tokens++;
            continue;
        }
        if (p[0] == '?')
        {
            if (err)
                *err = "use ?? for a wildcard byte";
            return false;
        }
        if (!IsHexDigit(p[0]) || !IsHexDigit(p[1]))
        {
            if (err)
                *err = "invalid byte pattern token";
            return false;
        }
        int v = (HexVal(p[0]) << 4) | HexVal(p[1]);
        pat.bytes.push_back((uint8_t)v);
        pat.mask.push_back(0xFF);
        p += 2;
        tokens++;
        if (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n')
        {
            if (err)
                *err = "byte pattern tokens must be separated by whitespace";
            return false;
        }
    }
    if (pat.bytes.empty())
    {
        if (err)
            *err = "byte pattern has no tokens";
        return false;
    }
    bool any_fixed = false;
    for (uint8_t m : pat.mask)
    {
        if (m)
        {
            any_fixed = true;
            break;
        }
    }
    if (!any_fixed)
    {
        if (err)
            *err = "byte pattern cannot be all wildcards";
        return false;
    }
    if (out)
        *out = std::move(pat);
    return true;
}

static bool ValidId(const std::string& id)
{
    if (id.size() < 3 || id.size() > 80)
        return false;
    for (char c : id)
    {
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')
            continue;
        return false;
    }
    if (id.front() == '.' || id.back() == '.')
        return false;
    return true;
}

static bool ParseCategory(const std::string& s, DetectCategory* out)
{
    if (s == "packer")
        *out = DetectCatPacker;
    else if (s == "protector")
        *out = DetectCatProtector;
    else if (s == "compiler")
        *out = DetectCatCompiler;
    else if (s == "toolchain")
        *out = DetectCatToolchain;
    else if (s == "dotnet_obfuscator" || s == "dotnet")
        *out = DetectCatDotNetObfuscator;
    else
        return false;
    return true;
}

static bool ParseConfidence(const std::string& s, DetectConfidence* out)
{
    if (s == "low")
        *out = DetectConfLow;
    else if (s == "medium")
        *out = DetectConfMedium;
    else if (s == "high")
        *out = DetectConfHigh;
    else if (s == "exact")
        *out = DetectConfExact;
    else
        return false;
    return true;
}

static int ClampWeight(int w, int def)
{
    if (w <= 0)
        return def;
    if (w > 100)
        return 100;
    return w;
}

static MatchMode ParseMatchMode(const nlohmann::json& j)
{
    if (!j.contains("match") || !j["match"].is_string())
        return MatchExact;
    std::string m = j["match"].get<std::string>();
    if (m == "contains")
        return MatchContains;
    if (m == "prefix")
        return MatchPrefix;
    return MatchExact;
}

static ScanWhere ParseWhere(const nlohmann::json& j)
{
    if (!j.contains("where") || !j["where"].is_string())
        return ScanEntry;
    std::string w = j["where"].get<std::string>();
    if (w == "file")
        return ScanFile;
    if (w == "overlay")
        return ScanOverlay;
    return ScanEntry;
}

static bool JsNum(const nlohmann::json& j, const char* k, double* out)
{
    if (!j.contains(k))
        return false;
    if (j[k].is_number())
    {
        *out = j[k].get<double>();
        return true;
    }
    return false;
}

static bool JsInt(const nlohmann::json& j, const char* k, int* out)
{
    if (!j.contains(k))
        return false;
    if (j[k].is_number_integer())
    {
        *out = j[k].get<int>();
        return true;
    }
    if (j[k].is_number())
    {
        *out = (int)j[k].get<double>();
        return true;
    }
    return false;
}

static bool ParseCond(const nlohmann::json& j, Cond* out, int depth, std::string* err);

static bool ParseKids(const nlohmann::json& arr, Cond* parent, int depth, std::string* err)
{
    if (!arr.is_array() || arr.empty())
    {
        *err = "logical group must be a non-empty array";
        return false;
    }
    if (arr.size() > 64)
    {
        *err = "too many conditions in one group";
        return false;
    }
    for (const auto& k : arr)
    {
        Cond c;
        if (!ParseCond(k, &c, depth + 1, err))
            return false;
        parent->kids.push_back(std::move(c));
    }
    return true;
}

static bool ParseCond(const nlohmann::json& j, Cond* out, int depth, std::string* err)
{
    if (depth > 8)
    {
        *err = "condition tree deeper than 8";
        return false;
    }
    if (!j.is_object())
    {
        *err = "condition must be an object";
        return false;
    }
    *out = Cond{};
    int w = 0;
    JsInt(j, "weight", &w);

    if (j.contains("all"))
    {
        out->kind = CondAll;
        return ParseKids(j["all"], out, depth, err);
    }
    if (j.contains("any"))
    {
        out->kind = CondAny;
        return ParseKids(j["any"], out, depth, err);
    }
    if (j.contains("not"))
    {
        out->kind = CondNot;
        Cond inner;
        if (!ParseCond(j["not"], &inner, depth + 1, err))
            return false;
        out->kids.push_back(std::move(inner));
        return true;
    }

    auto take_str = [&](const char* key) -> bool {
        return j.contains(key) && j[key].is_string();
    };

    if (take_str("section_name"))
    {
        out->kind = CondSectionName;
        out->a = j["section_name"].get<std::string>();
        out->mode = ParseMatchMode(j);
        out->weight = ClampWeight(w, out->mode == MatchExact ? 25 : 15);
        if (out->a.empty() || out->a.size() > 16)
        {
            *err = "section_name is empty or too long";
            return false;
        }
        return true;
    }
    if (j.contains("section_count"))
    {
        out->kind = CondSectionCount;
        out->weight = ClampWeight(w, 8);
        const auto& v = j["section_count"];
        if (v.is_number())
        {
            out->i0 = v.get<int>();
            out->i1 = v.get<int>();
        }
        else if (v.is_object())
        {
            out->i0 = 0;
            out->i1 = 96;
            JsInt(v, "min", &out->i0);
            JsInt(v, "eq", &out->i0);
            if (v.contains("eq"))
                out->i1 = out->i0;
            JsInt(v, "max", &out->i1);
        }
        else
        {
            *err = "section_count must be a number or {min,max,eq}";
            return false;
        }
        return true;
    }
    if (j.contains("section_chars"))
    {
        out->kind = CondSectionChars;
        out->weight = ClampWeight(w, 12);
        const auto& v = j["section_chars"];
        if (v.is_number())
            out->i0 = (int)v.get<uint32_t>();
        else if (v.is_object() && v["mask"].is_number())
        {
            out->i0 = (int)v["mask"].get<uint32_t>();
            if (v.contains("name") && v["name"].is_string())
                out->a = v["name"].get<std::string>();
        }
        else
        {
            *err = "section_chars must be a mask or {mask,name}";
            return false;
        }
        return true;
    }
    if (j.contains("section_entropy"))
    {
        out->kind = CondSectionEntropy;
        out->weight = ClampWeight(w, 10);
        const auto& v = j["section_entropy"];
        if (!v.is_object())
        {
            *err = "section_entropy must be an object";
            return false;
        }
        out->f0 = 0.0;
        if (!JsNum(v, "min", &out->f0))
        {
            *err = "section_entropy requires min";
            return false;
        }
        if (out->f0 < 0.0 || out->f0 > 8.0)
        {
            *err = "section_entropy min must be 0..8";
            return false;
        }
        if (v.contains("name") && v["name"].is_string())
            out->a = v["name"].get<std::string>();
        return true;
    }
    if (take_str("entry_point_bytes"))
    {
        out->kind = CondEntryBytes;
        out->where = ScanEntry;
        out->weight = ClampWeight(w, 40);
        if (!DetectParseBytePattern(j["entry_point_bytes"].get<std::string>().c_str(), &out->pat, err))
            return false;
        return true;
    }
    if (take_str("byte_pattern"))
    {
        out->kind = CondBytePattern;
        out->where = ParseWhere(j);
        out->weight = ClampWeight(w, out->where == ScanEntry ? 40 : 35);
        if (!DetectParseBytePattern(j["byte_pattern"].get<std::string>().c_str(), &out->pat, err))
            return false;
        return true;
    }
    if (take_str("imported_dll"))
    {
        out->kind = CondImportedDll;
        out->a = j["imported_dll"].get<std::string>();
        out->mode = ParseMatchMode(j);
        out->weight = ClampWeight(w, 20);
        if (out->a.empty())
        {
            *err = "imported_dll is empty";
            return false;
        }
        return true;
    }
    if (take_str("imported_function"))
    {
        out->kind = CondImportedFn;
        out->a = j["imported_function"].get<std::string>();
        if (j.contains("dll") && j["dll"].is_string())
            out->b = j["dll"].get<std::string>();
        out->weight = ClampWeight(w, 18);
        if (out->a.empty())
        {
            *err = "imported_function is empty";
            return false;
        }
        return true;
    }
    if (take_str("exported_symbol"))
    {
        out->kind = CondExported;
        out->a = j["exported_symbol"].get<std::string>();
        out->mode = ParseMatchMode(j);
        out->weight = ClampWeight(w, 15);
        return true;
    }
    if (j.contains("pe_chars") && j["pe_chars"].is_number())
    {
        out->kind = CondPeChars;
        out->i0 = (int)j["pe_chars"].get<uint32_t>();
        out->weight = ClampWeight(w, 8);
        return true;
    }
    if (j.contains("dll_chars") && j["dll_chars"].is_number())
    {
        out->kind = CondDllChars;
        out->i0 = (int)j["dll_chars"].get<uint32_t>();
        out->weight = ClampWeight(w, 8);
        return true;
    }
    if (j.contains("rich_present"))
    {
        out->kind = CondRichPresent;
        out->b0 = j["rich_present"].is_boolean() ? j["rich_present"].get<bool>() : true;
        out->weight = ClampWeight(w, 12);
        return true;
    }
    if (j.contains("rich_prod") && j["rich_prod"].is_number())
    {
        out->kind = CondRichProd;
        out->i0 = j["rich_prod"].get<int>();
        out->weight = ClampWeight(w, 16);
        return true;
    }
    if (j.contains("rich_build") && j["rich_build"].is_number())
    {
        out->kind = CondRichBuild;
        out->i0 = j["rich_build"].get<int>();
        out->weight = ClampWeight(w, 16);
        return true;
    }
    if (j.contains("overlay"))
    {
        out->kind = CondOverlay;
        out->weight = ClampWeight(w, 8);
        out->b0 = true;
        if (j["overlay"].is_boolean())
            out->b0 = j["overlay"].get<bool>();
        else if (j["overlay"].is_object())
            JsInt(j["overlay"], "min_size", &out->i0);
        else
        {
            *err = "overlay must be a boolean or {min_size}";
            return false;
        }
        return true;
    }
    if (j.contains("tls") && j["tls"].is_boolean())
    {
        out->kind = CondTls;
        out->b0 = j["tls"].get<bool>();
        out->weight = ClampWeight(w, 8);
        return true;
    }
    if (j.contains("tls_callbacks") && j["tls_callbacks"].is_boolean())
    {
        out->kind = CondTlsCallbacks;
        out->b0 = j["tls_callbacks"].get<bool>();
        out->weight = ClampWeight(w, 10);
        return true;
    }
    if (take_str("debug_type"))
    {
        out->kind = CondDebugType;
        out->a = j["debug_type"].get<std::string>();
        out->weight = ClampWeight(w, 10);
        return true;
    }
    if (j.contains("version_string"))
    {
        out->kind = CondVersionString;
        out->weight = ClampWeight(w, 20);
        const auto& v = j["version_string"];
        if (v.is_string())
            out->a = v.get<std::string>();
        else if (v.is_object())
        {
            if (v.contains("key") && v["key"].is_string())
                out->a = v["key"].get<std::string>();
            if (v.contains("contains") && v["contains"].is_string())
                out->b = v["contains"].get<std::string>();
            else if (v.contains("value") && v["value"].is_string())
                out->b = v["value"].get<std::string>();
        }
        else
        {
            *err = "version_string must be a string or {key,contains}";
            return false;
        }
        if (out->a.empty() && out->b.empty())
        {
            *err = "version_string needs key or contains";
            return false;
        }
        return true;
    }
    if (take_str("resource_type"))
    {
        out->kind = CondResourceType;
        out->a = j["resource_type"].get<std::string>();
        out->mode = ParseMatchMode(j);
        out->weight = ClampWeight(w, 12);
        return true;
    }
    if (take_str("resource_name"))
    {
        out->kind = CondResourceName;
        out->a = j["resource_name"].get<std::string>();
        out->mode = ParseMatchMode(j);
        out->weight = ClampWeight(w, 18);
        return true;
    }
    if (take_str("string_contains"))
    {
        out->kind = CondStringContains;
        out->a = j["string_contains"].get<std::string>();
        out->weight = ClampWeight(w, 22);
        if (out->a.size() < 4)
        {
            *err = "string_contains must be at least 4 characters";
            return false;
        }
        return true;
    }
    if (j.contains("has_com") && j["has_com"].is_boolean())
    {
        out->kind = CondHasCom;
        out->b0 = j["has_com"].get<bool>();
        out->weight = ClampWeight(w, 15);
        return true;
    }
    if (take_str("clr_stream"))
    {
        out->kind = CondClrStream;
        out->a = j["clr_stream"].get<std::string>();
        out->weight = ClampWeight(w, 12);
        return true;
    }
    if (take_str("assembly_ref"))
    {
        out->kind = CondAsmRef;
        out->a = j["assembly_ref"].get<std::string>();
        out->mode = ParseMatchMode(j);
        out->weight = ClampWeight(w, 25);
        return true;
    }
    if (take_str("type_name"))
    {
        out->kind = CondTypeName;
        out->a = j["type_name"].get<std::string>();
        out->mode = ParseMatchMode(j);
        out->weight = ClampWeight(w, 28);
        return true;
    }
    if (take_str("namespace"))
    {
        out->kind = CondNamespace;
        out->a = j["namespace"].get<std::string>();
        out->mode = ParseMatchMode(j);
        out->weight = ClampWeight(w, 20);
        return true;
    }
    if (j.contains("linker_major") && j["linker_major"].is_number())
    {
        out->kind = CondLinkerMajor;
        out->i0 = j["linker_major"].get<int>();
        out->weight = ClampWeight(w, 15);
        return true;
    }
    if (j.contains("linker_minor") && j["linker_minor"].is_number())
    {
        out->kind = CondLinkerMinor;
        out->i0 = j["linker_minor"].get<int>();
        out->weight = ClampWeight(w, 10);
        return true;
    }
    if (j.contains("import_dll_count"))
    {
        out->kind = CondImportDllCount;
        out->weight = ClampWeight(w, 8);
        const auto& v = j["import_dll_count"];
        out->i0 = 0;
        out->i1 = 100000;
        if (v.is_number())
        {
            out->i0 = v.get<int>();
            out->i1 = v.get<int>();
        }
        else if (v.is_object())
        {
            JsInt(v, "min", &out->i0);
            JsInt(v, "max", &out->i1);
            if (v.contains("eq"))
            {
                JsInt(v, "eq", &out->i0);
                out->i1 = out->i0;
            }
        }
        else
        {
            *err = "import_dll_count must be a number or {min,max,eq}";
            return false;
        }
        return true;
    }
    if (j.contains("writable_executable_section") && j["writable_executable_section"].is_boolean())
    {
        out->kind = CondWxSection;
        out->b0 = j["writable_executable_section"].get<bool>();
        out->weight = ClampWeight(w, 10);
        return true;
    }
    if (j.contains("section_raw_size"))
    {
        out->kind = CondSectionRawSize;
        out->weight = ClampWeight(w, 20);
        const auto& v = j["section_raw_size"];
        if (!v.is_object())
        {
            *err = "section_raw_size must be {name?,min,max,eq}";
            return false;
        }
        out->i0 = 0;
        out->i1 = 0x7fffffff;
        JsInt(v, "min", &out->i0);
        if (v.contains("eq"))
        {
            JsInt(v, "eq", &out->i0);
            out->i1 = out->i0;
        }
        JsInt(v, "max", &out->i1);
        if (v.contains("name") && v["name"].is_string())
            out->a = v["name"].get<std::string>();
        return true;
    }
    if (j.contains("odd_section_names"))
    {
        out->kind = CondOddSectionNames;
        out->weight = ClampWeight(w, 35);
        const auto& v = j["odd_section_names"];
        out->i0 = 2;
        if (v.is_boolean())
        {
            if (!v.get<bool>())
            {
                *err = "odd_section_names false is not useful; omit the leaf";
                return false;
            }
        }
        else if (v.is_number())
            out->i0 = v.get<int>();
        else if (v.is_object())
            JsInt(v, "min", &out->i0);
        else
        {
            *err = "odd_section_names must be true, a count, or {min}";
            return false;
        }
        if (out->i0 < 1)
            out->i0 = 1;
        return true;
    }
    if (j.contains("virtual_only_before_entry"))
    {
        out->kind = CondVirtualOnlyBeforeEntry;
        out->weight = ClampWeight(w, 35);
        out->i0 = 1;
        const auto& v = j["virtual_only_before_entry"];
        if (v.is_number())
            out->i0 = v.get<int>();
        else if (v.is_object())
            JsInt(v, "min", &out->i0);
        else
        {
            *err = "virtual_only_before_entry must be a count or {min}";
            return false;
        }
        if (out->i0 < 1)
            out->i0 = 1;
        return true;
    }
    if (j.contains("entry_section_chars"))
    {
        out->kind = CondEntrySectionChars;
        out->weight = ClampWeight(w, 12);
        const auto& v = j["entry_section_chars"];
        if (v.is_number())
            out->i0 = (int)v.get<uint32_t>();
        else if (v.is_object() && v.contains("mask") && v["mask"].is_number())
            out->i0 = (int)v["mask"].get<uint32_t>();
        else
        {
            *err = "entry_section_chars must be a mask or {mask}";
            return false;
        }
        return true;
    }
    if (j.contains("entry_section_raw_size"))
    {
        out->kind = CondEntrySectionRawSize;
        out->weight = ClampWeight(w, 20);
        const auto& v = j["entry_section_raw_size"];
        if (!v.is_object())
        {
            *err = "entry_section_raw_size must be {min,max,eq}";
            return false;
        }
        out->i0 = 0;
        out->i1 = 0x7fffffff;
        JsInt(v, "min", &out->i0);
        if (v.contains("eq"))
        {
            JsInt(v, "eq", &out->i0);
            out->i1 = out->i0;
        }
        JsInt(v, "max", &out->i1);
        return true;
    }
    if (j.contains("entry_section_entropy"))
    {
        out->kind = CondEntrySectionEntropy;
        out->weight = ClampWeight(w, 20);
        const auto& v = j["entry_section_entropy"];
        if (!v.is_object())
        {
            *err = "entry_section_entropy must be {min}";
            return false;
        }
        out->f0 = 0.0;
        if (!JsNum(v, "min", &out->f0))
        {
            *err = "entry_section_entropy requires min";
            return false;
        }
        if (out->f0 < 0.0 || out->f0 > 8.0)
        {
            *err = "entry_section_entropy min must be 0..8";
            return false;
        }
        return true;
    }

    *err = "unsupported condition type";
    return false;
}

static uint32_t ParseArch(const nlohmann::json& j, std::string* err)
{
    uint32_t mask = 0;
    if (!j.contains("architecture"))
        return ArchAny;
    auto add = [&](const std::string& s) -> bool {
        if (s == "any")
            mask |= ArchAny;
        else if (s == "x86" || s == "i386" || s == "pe32")
            mask |= ArchX86;
        else if (s == "x64" || s == "amd64" || s == "pe32+")
            mask |= ArchX64;
        else if (s == "arm64" || s == "aarch64")
            mask |= ArchArm64;
        else
        {
            *err = "unsupported architecture '" + s + "'";
            return false;
        }
        return true;
    };
    if (j["architecture"].is_string())
    {
        if (!add(j["architecture"].get<std::string>()))
            return 0;
    }
    else if (j["architecture"].is_array())
    {
        if (j["architecture"].size() > 8)
        {
            *err = "too many architecture values";
            return 0;
        }
        for (const auto& a : j["architecture"])
        {
            if (!a.is_string() || !add(a.get<std::string>()))
            {
                if (err->empty())
                    *err = "architecture entries must be strings";
                return 0;
            }
        }
    }
    else
    {
        *err = "architecture must be a string or array";
        return 0;
    }
    return mask ? mask : ArchAny;
}

bool DetectParseSignatureJson(const char* json, const char* origin, DetectSource src, CompiledSig* out, std::string* err)
{
    if (err)
        err->clear();
    if (!json || !out)
    {
        if (err)
            *err = "null signature buffer";
        return false;
    }
    std::string local_err;
    if (!err)
        err = &local_err;
    nlohmann::json j;
    try
    {
        j = nlohmann::json::parse(json, nullptr, true, true);
    }
    catch (const std::exception& e)
    {
        if (err)
            *err = e.what();
        return false;
    }
    if (!j.is_object())
    {
        if (err)
            *err = "signature root must be an object";
        return false;
    }

    int schema = 1;
    if (j.contains("schema_version"))
    {
        if (!j["schema_version"].is_number_integer())
        {
            *err = "schema_version must be an integer";
            return false;
        }
        schema = j["schema_version"].get<int>();
    }
    if (schema != 1)
    {
        *err = "unsupported schema_version (want 1)";
        return false;
    }

    CompiledSig s;
    s.schema_version = schema;
    s.source = src;
    s.origin = origin ? origin : "";

    if (!j.contains("id") || !j["id"].is_string())
    {
        *err = "missing id";
        return false;
    }
    s.id = j["id"].get<std::string>();
    std::transform(s.id.begin(), s.id.end(), s.id.begin(), [](unsigned char c) { return (char)tolower(c); });
    if (!ValidId(s.id))
    {
        *err = "id must be 3-80 chars of [a-z0-9._-]";
        return false;
    }
    if (!j.contains("name") || !j["name"].is_string() || j["name"].get<std::string>().empty())
    {
        *err = "missing name";
        return false;
    }
    s.name = j["name"].get<std::string>();
    if (s.name.size() > 80)
    {
        *err = "name longer than 80 characters";
        return false;
    }
    if (!j.contains("category") || !j["category"].is_string() || !ParseCategory(j["category"].get<std::string>(), &s.category))
    {
        *err = "missing or unsupported category";
        return false;
    }
    if (j.contains("confidence"))
    {
        if (!j["confidence"].is_string() || !ParseConfidence(j["confidence"].get<std::string>(), &s.cap))
        {
            *err = "confidence must be low|medium|high|exact";
            return false;
        }
    }
    if (j.contains("vendor") && j["vendor"].is_string())
        s.vendor = j["vendor"].get<std::string>();
    if (j.contains("version") && j["version"].is_string())
        s.version = j["version"].get<std::string>();
    if (j.contains("description") && j["description"].is_string())
        s.description = j["description"].get<std::string>();
    if (j.contains("author") && j["author"].is_string())
        s.author = j["author"].get<std::string>();
    if (j.contains("reference") && j["reference"].is_string())
        s.reference = j["reference"].get<std::string>();
    if (j.contains("product_key") && j["product_key"].is_string())
        s.product_key = j["product_key"].get<std::string>();
    else
        s.product_key = s.id;
    if (j.contains("heuristic") && j["heuristic"].is_boolean())
        s.heuristic = j["heuristic"].get<bool>();
    if (j.contains("requires_clr") && j["requires_clr"].is_boolean())
        s.requires_clr = j["requires_clr"].get<bool>();
    if (j.contains("native_only") && j["native_only"].is_boolean())
        s.native_only = j["native_only"].get<bool>();

    if (j.contains("format"))
    {
        auto ok_fmt = [](const std::string& f) { return f == "pe" || f == "any"; };
        if (j["format"].is_string())
        {
            if (!ok_fmt(j["format"].get<std::string>()))
            {
                *err = "unsupported format";
                return false;
            }
        }
        else if (j["format"].is_array())
        {
            for (const auto& f : j["format"])
            {
                if (!f.is_string() || !ok_fmt(f.get<std::string>()))
                {
                    *err = "unsupported format";
                    return false;
                }
            }
        }
        else
        {
            *err = "format must be a string or array";
            return false;
        }
    }

    s.arch = ParseArch(j, err);
    if (s.arch == 0)
        return false;

    if (!j.contains("conditions"))
    {
        *err = "missing conditions";
        return false;
    }
    if (!ParseCond(j["conditions"], &s.root, 0, err))
        return false;

    if (s.category == DetectCatDotNetObfuscator)
        s.requires_clr = true;

    *out = std::move(s);
    return true;
}
