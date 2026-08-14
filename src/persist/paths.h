#pragma once

void PathsExeDir(char* out, int cap);
void PathsJoin(char* out, int cap, const char* dir, const char* file);
void PathsBesideExe(char* out, int cap, const char* relative);
void PathsThemesDir(char* out, int cap);
void PathsLanguagesDir(char* out, int cap);
void PathsSettingsFile(char* out, int cap);
void PathsAssetFile(char* out, int cap, const char* file);
bool PathsWindowsFont(char* out, int cap, const char* file);
bool PathsReadFile(const char* path, char** out_text, int* out_len);
