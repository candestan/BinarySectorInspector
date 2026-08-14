#pragma once

void PathsExeDir(char* out, int cap);
void PathsJoin(char* out, int cap, const char* dir, const char* file);
bool PathsReadFile(const char* path, char** out_text, int* out_len);
