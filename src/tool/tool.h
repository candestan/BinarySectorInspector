#pragma once

#include "analyze/analyze.h"

#include <stdint.h>
#include <stddef.h>
#include <vector>
#include <string>

struct ToolDescriptor
{
    const char* id;
    const char* name;
    const char* version;
    const char* author;
    const char* description;
    const char* in_media;
    const char* out_media;
    const char* action_i18n;
    bool (*available)();
    bool (*run)(const AnalysisArtifact* art, const uint8_t* data, size_t n,
        std::string* out, char* suggest, int sug_cap, char* err, int err_cap);
};

void ToolInit();
void ToolRegister(const ToolDescriptor* tool);
int  ToolCount();
const ToolDescriptor* ToolAt(int i);
const ToolDescriptor* ToolFind(const char* id);
int  ToolMatchMedia(const char* media, const ToolDescriptor** out, int cap);
