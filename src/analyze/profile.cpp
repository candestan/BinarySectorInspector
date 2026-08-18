#include "analyze/profile.h"
#include "persist/paths.h"
#include "log/log.h"

#include <windows.h>
#include <nlohmann/json.hpp>
#include <stdio.h>
#include <string.h>

static AnalysisProfile g_profile{};
static bool g_loaded;

static void SetDefaults(AnalysisProfile* p)
{
    *p = AnalysisProfile{};
    p->schema_version = 1;
    snprintf(p->id, sizeof(p->id), "default");
    snprintf(p->display_name, sizeof(p->display_name), "Standard");
    snprintf(p->analysis_depth, sizeof(p->analysis_depth), "standard");
    for (int i = 0; i < StageCount; i++)
        p->stage_enabled[i] = true;
    p->caps = AnalysisCapabilities{
        true, true, true, true, true, true, true, true, true
    };
    p->budgets = AnalysisBudgets{
        64, 120, 256, 2, 1, 2, 64ull * 1024 * 1024
    };
}

static bool StageFromName(const char* s, AnalysisStage* out)
{
    if (!s || !out)
        return false;
    if (_stricmp(s, "signatures") == 0) { *out = StageSignatures; return true; }
    if (_stricmp(s, "specialized_analysis") == 0) { *out = StageSpecialized; return true; }
    if (_stricmp(s, "atomic_findings") == 0) { *out = StageAtomicFindings; return true; }
    if (_stricmp(s, "correlation") == 0) { *out = StageCorrelation; return true; }
    if (_stricmp(s, "summary") == 0) { *out = StageSummary; return true; }
    return false;
}

static bool ParseProfileJson(const nlohmann::json& j, AnalysisProfile* p, char* err, int err_cap)
{
    if (!p)
        return false;
    SetDefaults(p);
    if (!j.is_object())
    {
        snprintf(err, err_cap, "profile root must be an object");
        return false;
    }
    int schema = j.value("schema_version", 1);
    if (schema != 1)
    {
        snprintf(err, err_cap, "unsupported schema_version %d", schema);
        return false;
    }
    p->schema_version = schema;
    if (j.contains("id") && j["id"].is_string())
        snprintf(p->id, sizeof(p->id), "%s", j["id"].get<std::string>().c_str());
    if (j.contains("display_name") && j["display_name"].is_string())
        snprintf(p->display_name, sizeof(p->display_name), "%s", j["display_name"].get<std::string>().c_str());
    if (j.contains("analysis_depth") && j["analysis_depth"].is_string())
        snprintf(p->analysis_depth, sizeof(p->analysis_depth), "%s", j["analysis_depth"].get<std::string>().c_str());
    if (j.contains("stages") && j["stages"].is_array())
    {
        for (int i = 0; i < StageCount; i++)
            p->stage_enabled[i] = false;
        for (const auto& st : j["stages"])
        {
            if (!st.is_string())
                continue;
            AnalysisStage s = StageCount;
            if (StageFromName(st.get<std::string>().c_str(), &s) && s < StageCount)
                p->stage_enabled[s] = true;
        }
    }
    if (j.contains("capabilities") && j["capabilities"].is_object())
    {
        const auto& c = j["capabilities"];
        p->caps.signature_detection = c.value("signature_detection", p->caps.signature_detection);
        p->caps.resource_analysis = c.value("resource_analysis", p->caps.resource_analysis);
        p->caps.embedded_payload_analysis = c.value("embedded_payload_analysis", p->caps.embedded_payload_analysis);
        p->caps.compiler_metadata = c.value("compiler_metadata", p->caps.compiler_metadata);
        p->caps.script_artifact_analysis = c.value("script_artifact_analysis", p->caps.script_artifact_analysis);
        p->caps.structural_heuristics = c.value("structural_heuristics", p->caps.structural_heuristics);
        p->caps.import_behavior = c.value("import_behavior", p->caps.import_behavior);
        p->caps.string_indicators = c.value("string_indicators", p->caps.string_indicators);
        p->caps.correlation = c.value("correlation", p->caps.correlation);
    }
    if (j.contains("budgets") && j["budgets"].is_object())
    {
        const auto& b = j["budgets"];
        p->budgets.max_artifacts = b.value("max_artifacts", (int)p->budgets.max_artifacts);
        p->budgets.max_findings = b.value("max_findings", (int)p->budgets.max_findings);
        p->budgets.max_evidence = b.value("max_evidence", (int)p->budgets.max_evidence);
        p->budgets.max_correlation_passes = b.value("max_correlation_passes", (int)p->budgets.max_correlation_passes);
        p->budgets.max_analyzer_passes = b.value("max_analyzer_passes", (int)p->budgets.max_analyzer_passes);
        p->budgets.max_nested_depth = b.value("max_nested_depth", (int)p->budgets.max_nested_depth);
        p->budgets.max_scan_bytes = b.value("max_scan_bytes", (uint64_t)p->budgets.max_scan_bytes);
    }
    return true;
}

void AnalyzeProfileInit()
{
    char err[256] = {};
    if (!AnalyzeProfileReload(err, (int)sizeof(err)))
    {
        SetDefaults(&g_profile);
        g_loaded = true;
        LogFor(LogBuiltinPeAnalyzer).Warning("Analysis profile load failed: %s (using built-in defaults)", err[0] ? err : "unknown");
    }
}

bool AnalyzeProfileReload(char* err, int err_cap)
{
    char path[MAX_PATH];
    PathsBesideExe(path, MAX_PATH, "analysis\\profiles\\default.json");
    char* text = nullptr;
    int len = 0;
    if (!PathsReadFile(path, &text, &len) || !text)
    {
        snprintf(err, err_cap, "could not read %s", path);
        return false;
    }
    try
    {
        nlohmann::json j = nlohmann::json::parse(text, text + len);
        AnalysisProfile tmp{};
        if (!ParseProfileJson(j, &tmp, err, err_cap))
        {
            free(text);
            return false;
        }
        g_profile = tmp;
        g_loaded = true;
        free(text);
        LogFor(LogBuiltinPeAnalyzer).Info("Loaded analysis profile '%s'", g_profile.id);
        return true;
    }
    catch (const std::exception& ex)
    {
        snprintf(err, err_cap, "profile JSON: %s", ex.what());
        free(text);
        return false;
    }
}

const AnalysisProfile* AnalyzeProfileActive()
{
    if (!g_loaded)
        AnalyzeProfileInit();
    return &g_profile;
}
