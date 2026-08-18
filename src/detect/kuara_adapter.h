#pragma once

#include "detect/detect.h"

#include <string>
#include <vector>

bool KuaraReloadRules(const std::vector<std::string>& rule_files, std::string* err);
bool KuaraRunDetect(const DetectFacts& facts, std::vector<DetectionResult>* out);
bool KuaraIsReady();
