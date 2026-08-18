#include "analyze/engine.h"
#include "analyze/profile.h"
#include "analyze/analyze.h"
#include "detect/detect.h"
#include "findings/findings.h"
#include "pe/pe.h"
#include "log/log.h"

#include <stddef.h>

void AnalyzeEngineInit()
{
    AnalyzeProfileInit();
}

void AnalyzeEngineRun(PeFile* pe, const uint8_t* data, size_t n)
{
    if (!pe || !pe->ok || !data)
        return;
    const AnalysisProfile* prof = AnalyzeProfileActive();
    if (!prof)
        return;
    auto log = LogFor(LogBuiltinPeAnalyzer).Module("Analyze Engine");

    if (prof->stage_enabled[StageSignatures] && prof->caps.signature_detection)
    {
        log.Info("Checking known packers, protectors, and compilers...");
        DetectApplyToPe(pe, data, n);
    }

    if (prof->stage_enabled[StageSpecialized])
    {
        log.Info("Inspecting embedded data and runtime metadata...");
        AnalyzeRun(pe, data, n);
    }

    if (prof->stage_enabled[StageAtomicFindings] || prof->stage_enabled[StageCorrelation] || prof->stage_enabled[StageSummary])
    {
        log.Info("Building evidence and findings...");
        FindingsEngineRun(pe);
    }
}
