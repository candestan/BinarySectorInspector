#pragma once

// Shared surface between the inspector translation units. This is not a public API:
// only inspector*.cpp include it. Anything here is used by more than one of them.

#include "pe/pe.h"
#include "detect/detect.h"

#include <stdint.h>

// Panel selection that has to survive across views and be reset when a new file loads.
extern int g_an_root;
extern int g_an_child;
extern int g_an_grand; // -1 = no grandchild selected
extern int g_find_sel;
extern float g_split_an;
extern float g_split_find;
extern float g_split_start_here;

// Field rows and small chrome every panel draws with.
float FieldLabelCol();
void FieldLabel(const char* k, const char* help = nullptr);
void EmptyHint(const char* key = "pe.none");
void Field(const char* k, const char* v, const char* help = nullptr);
void FieldU(const char* k, uint64_t v, bool hex, const char* help = nullptr);
void ConfBadge(const char* id, DetectConfidence conf);

// Splitters persist their size through the layout store, so they stay with the shell.
float SplitListW(float* sz);
void SplitH(const char* id, float* sz, const char* key, float sign, float min_sz, float max_sz = 0.f);
void SplitListHandle(const char* id, float* sz, const char* key);

void GoHex(uint32_t off);

// Defined in inspector_analysis.cpp.
void DrawAnalysis(PeFile* pe);
void DrawDetection(const PeFile* pe);
void DrawFindings(const PeFile* pe);
void DrawArtifactBundle(PeFile* pe, const AnalysisArtifact* root, bool picker);
const char* FindingText(const char* s);
