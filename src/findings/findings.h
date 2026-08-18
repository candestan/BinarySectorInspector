#pragma once

#include <stdint.h>
#include <vector>

enum FindingSeverity : uint8_t
{
    FindSevInfo = 0,
    FindSevLow,
    FindSevMedium,
    FindSevHigh,
    FindSevCritical
};

enum FindingConfidence : uint8_t
{
    FindConfLow = 0,
    FindConfMedium,
    FindConfHigh,
    FindConfExact
};

enum FindingCategory : uint8_t
{
    FindCatStructure = 0,
    FindCatExecution,
    FindCatMemory,
    FindCatImports,
    FindCatResources,
    FindCatPacking,
    FindCatManaged,
    FindCatEmbedded,
    FindCatMetadata,
    FindCatIntegrity,
    FindCatNetwork,
    FindCatPersistence,
    FindCatInjection,
    FindCatIdentity,
    FindCatCrypto
};

enum EvidenceKind : uint8_t
{
    EvSection = 0,
    EvImport,
    EvString,
    EvEntropy,
    EvDetection,
    EvArtifact,
    EvHeader,
    EvOverlay,
    EvTls,
    EvEntry,
    EvGeneric
};

enum FindingActionKind : uint8_t
{
    FactActHex = 0,
    FactActSection,
    FactActEvidence,
    FactActDetection,
    FactActArtifact,
    FactActTechnical
};

enum
{
    FindingMaxEvidence = 8,
    FindingMaxRelated = 4,
    FindingMaxActions = 4,
    SummaryStartHereMax = 8
};

struct EvidenceItem
{
    char         id[40];
    EvidenceKind kind;
    char         source[32];
    char         summary[160];
    char         detail[128];
    uint32_t     file_off;
    uint32_t     rva;
    char         subject[64];
};

struct FindingAction
{
    char              label_key[48];
    FindingActionKind kind;
    uint32_t          target_off;
    char              target_id[48];
};

struct FindingItem
{
    char               id[56];
    char               title_key[56];
    char               explain_key[56];
    char               matter_key[56];
    char               next_key[56];
    char               tech_key[56];
    FindingSeverity    severity;
    FindingConfidence  confidence;
    FindingCategory    category;
    bool               derived;
    char               rule_id[40];
    char               provider_id[48];
    uint32_t           file_off;
    char               evidence_text[192];
    int                evidence_idx[FindingMaxEvidence];
    int                evidence_n;
    int                related_idx[FindingMaxRelated];
    int                related_n;
    FindingAction      actions[FindingMaxActions];
    int                action_n;
    int                priority;
};

struct AnalysisSummary
{
    char headline[256];
    char headline_key[56];
    int  start_here[SummaryStartHereMax];
    int  start_here_n;
    int  finding_count;
    int  detection_count;
    int  artifact_count;
    bool complete;
    char incomplete_reason[128];
};

struct AnalysisReport
{
    std::vector<EvidenceItem> evidence;
    std::vector<FindingItem>  findings;
    AnalysisSummary           summary;
};

struct PeFile;

void FindingsEngineRun(PeFile* pe);
const char* FindingCategoryKey(FindingCategory cat);
const char* FindingSeverityKey(FindingSeverity sev);
const char* FindingConfidenceKey(FindingConfidence conf);
