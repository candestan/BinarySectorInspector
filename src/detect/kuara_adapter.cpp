#include "detect/kuara_adapter.h"

#include "kuara_internal.h"

#include <algorithm>
#include <mutex>

namespace
{
std::mutex g_kuara_mu;
kuara::CompiledRuleSet g_kuara_compiled;
bool g_kuara_ready = false;

kuara::ScanFacts ToKuaraFacts(const DetectFacts& in)
{
    kuara::ScanFacts out{};
    out.is_pe = in.is_pe;
    out.pe32plus = in.pe32plus;
    out.has_com = in.has_com;
    out.overlay = in.overlay;
    out.tls = in.tls;
    out.tls_callbacks = in.tls_callbacks;
    out.linker_major = in.linker_major;
    out.linker_minor = in.linker_minor;
    out.machine = in.machine;
    out.chars = in.chars;
    out.dllchars = in.dllchars;
    out.entry_rva = in.entry_rva;
    out.entry_off = in.entry_off;
    out.overlay_off = in.overlay_off;
    out.overlay_size = in.overlay_size;
    out.import_dll_n = in.import_dll_n;

    out.sections.reserve(in.sections.size());
    for (const DetectSectionFact& s : in.sections)
    {
        kuara::SectionFact ks{};
        ks.name = s.name;
        ks.chars = s.chars;
        ks.vsize = s.vsize;
        ks.vaddr = s.vaddr;
        ks.rawsize = s.rawsize;
        ks.rawptr = s.rawptr;
        ks.entropy = s.entropy;
        out.sections.push_back(std::move(ks));
    }

    out.import_dlls = in.import_dlls;
    out.rich_prod = in.rich_prod;
    out.rich_build = in.rich_build;
    out.import_fns = in.import_fns;
    out.exports = in.exports;
    out.resource_types = in.resource_types;
    out.resource_names = in.resource_names;
    out.version_kv = in.version_kv;
    out.strings = in.strings;
    out.clr_streams = in.clr_streams;
    out.clr_asm_refs = in.clr_asm_refs;
    out.clr_types = in.clr_types;
    out.clr_namespaces = in.clr_namespaces;
    out.bytes = in.bytes;
    out.byte_n = in.byte_n;
    return out;
}

DetectCategory ToDetectCategory(kuara::Category c)
{
    switch (c)
    {
    case kuara::Category::Packer: return DetectCatPacker;
    case kuara::Category::Protector: return DetectCatProtector;
    case kuara::Category::Compiler: return DetectCatCompiler;
    case kuara::Category::Toolchain: return DetectCatToolchain;
    case kuara::Category::DotNetObfuscator: return DetectCatDotNetObfuscator;
    default: return DetectCatPacker;
    }
}

DetectConfidence ToDetectConfidence(int c)
{
    if (c <= 0) return DetectConfLow;
    if (c == 1) return DetectConfMedium;
    if (c == 2) return DetectConfHigh;
    return DetectConfExact;
}
} // namespace

bool KuaraReloadRules(const std::vector<std::string>& rule_files, std::string* err)
{
    if (err)
        err->clear();

    kuara::RuleSet merged{};
    std::vector<kuara::Diagnostic> diags;
    for (const std::string& file : rule_files)
    {
        kuara::RuleSet one{};
        std::vector<kuara::Diagnostic> one_diags;
        if (!kuara::LoadRuleSetFromFile(file, &one, &one_diags))
        {
            diags.insert(diags.end(), one_diags.begin(), one_diags.end());
            continue;
        }
        merged.rules.insert(merged.rules.end(), one.rules.begin(), one.rules.end());
    }

    if (merged.rules.empty())
    {
        if (err)
            *err = "no valid KUARA rules loaded";
        std::lock_guard<std::mutex> lock(g_kuara_mu);
        g_kuara_compiled.rules.clear();
        g_kuara_ready = false;
        return false;
    }

    kuara::CompiledRuleSet compiled{};
    if (!kuara::CompileRuleSet(merged, &compiled, &diags))
    {
        if (err && !diags.empty())
            *err = diags[0].source + ": " + diags[0].message;
        std::lock_guard<std::mutex> lock(g_kuara_mu);
        g_kuara_compiled.rules.clear();
        g_kuara_ready = false;
        return false;
    }

    std::lock_guard<std::mutex> lock(g_kuara_mu);
    g_kuara_compiled = std::move(compiled);
    g_kuara_ready = true;
    return true;
}

bool KuaraRunDetect(const DetectFacts& facts, std::vector<DetectionResult>* out)
{
    if (!out)
        return false;
    out->clear();

    kuara::CompiledRuleSet compiled{};
    {
        std::lock_guard<std::mutex> lock(g_kuara_mu);
        if (!g_kuara_ready)
            return false;
        compiled = g_kuara_compiled;
    }

    std::vector<kuara::Match> matches;
    if (!kuara::Scan(compiled, ToKuaraFacts(facts), &matches))
        return false;

    out->reserve(matches.size());
    for (const kuara::Match& m : matches)
    {
        DetectionResult r{};
        r.category = ToDetectCategory(m.category);
        r.confidence = ToDetectConfidence(m.confidence);
        r.score = m.score > 100 ? 100 : m.score;
        r.heuristic = m.heuristic;
        r.source = DetectSrcBuiltin;
        r.product_key = m.product_key.empty() ? m.rule_id : m.product_key;
        r.product = m.product;
        r.vendor = m.vendor;
        r.version = m.version;
        r.description = m.description;
        r.reference = m.reference;

        DetectMatch sig{};
        sig.signature_id = m.rule_id;
        sig.source = DetectSrcBuiltin;
        r.signatures.push_back(std::move(sig));

        r.evidence.reserve(m.evidence.size());
        for (const kuara::Evidence& e : m.evidence)
        {
            DetectEvidence de{};
            de.condition = e.condition;
            de.detail = e.detail;
            de.weight = e.weight;
            r.evidence.push_back(std::move(de));
            r.signatures[0].evidence.push_back(r.evidence.back());
        }
        out->push_back(std::move(r));
    }

    std::sort(out->begin(), out->end(), [](const DetectionResult& a, const DetectionResult& b) {
        if (a.category != b.category)
            return a.category < b.category;
        if (a.heuristic != b.heuristic)
            return !a.heuristic && b.heuristic;
        if (a.confidence != b.confidence)
            return a.confidence > b.confidence;
        return a.product < b.product;
    });
    return true;
}

bool KuaraIsReady()
{
    std::lock_guard<std::mutex> lock(g_kuara_mu);
    return g_kuara_ready;
}
