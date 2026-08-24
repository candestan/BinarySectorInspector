#pragma once

#include <stdint.h>

enum AnalysisStage : uint8_t
{
    StageSignatures = 0,
    StageSpecialized,
    StageAtomicFindings,
    StageCorrelation,
    StageSummary,
    StageCount
};

struct AnalysisBudgets
{
    uint32_t max_artifacts;
    uint32_t max_findings;
    uint32_t max_evidence;
    uint32_t max_correlation_passes;
    uint32_t max_analyzer_passes;
    uint32_t max_nested_depth;
    uint64_t max_scan_bytes;
    uint64_t max_decompress_bytes;
    uint64_t max_artifact_bytes;
    uint32_t max_inflate_ratio;
};

struct AnalysisCapabilities
{
    bool signature_detection;
    bool resource_analysis;
    bool embedded_payload_analysis;
    bool compiler_metadata;
    bool script_artifact_analysis;
    bool structural_heuristics;
    bool import_behavior;
    bool string_indicators;
    bool correlation;
};

struct AnalysisProfile
{
    int                 schema_version;
    char                id[48];
    char                display_name[64];
    char                analysis_depth[24];
    bool                stage_enabled[StageCount];
    AnalysisCapabilities caps;
    AnalysisBudgets     budgets;
};

void AnalyzeProfileInit();
bool AnalyzeProfileReload(char* err, int err_cap);
const AnalysisProfile* AnalyzeProfileActive();
