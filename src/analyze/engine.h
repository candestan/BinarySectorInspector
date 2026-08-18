#pragma once

#include <stdint.h>
#include <stddef.h>

struct PeFile;

void AnalyzeEngineInit();
void AnalyzeEngineRun(PeFile* pe, const uint8_t* data, size_t n);
