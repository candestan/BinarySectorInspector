#pragma once

struct ScriptPyInstall
{
    char path[260];
    int  major;
    int  minor;
    int  patch;
    char label[96];
};

void ScriptingInit();
void ScriptingScan();

int  ScriptingPyCount(int family);
bool ScriptingPyAt(int family, int index, ScriptPyInstall* out);
bool ScriptingPyGet(int family, char* out, int cap);
void ScriptingPySet(int family, const char* path);
bool ScriptingPyProbe(const char* path, ScriptPyInstall* out);

bool ScriptingLuaGet(char* out, int cap);
void ScriptingLuaSet(const char* path);
