#pragma once

#include <nlohmann/json.hpp>

struct WindowLayout
{
    int  x = 80;
    int  y = 80;
    int  w = 360;
    int  h = 240;
    bool maximized = false;
};

nlohmann::json& SettingsRoot();
bool            SettingsLoad();
bool            SettingsSave();
bool            SettingsGetWindow(const char* name, WindowLayout* out);
void            SettingsPutWindow(const char* name, const WindowLayout& w);

void SettingsRecentsAdd(const char* path);
int  SettingsRecentsCount();
bool SettingsRecentsGet(int index, char* out, int cap);

void SettingsSetString(const char* key, const char* val);
bool SettingsGetString(const char* key, char* out, int cap, const char* def);
void SettingsSetBool(const char* key, bool val);
bool SettingsGetBool(const char* key, bool def);
void SettingsSetInt(const char* key, int val);
int  SettingsGetInt(const char* key, int def);
void SettingsSetFloat(const char* key, float val);
float SettingsGetFloat(const char* key, float def);

void SettingsTick();
void SettingsFlush();
void SettingsMarkDirty();

int  SettingsLayoutEpoch();
void SettingsLayoutResetWorkspace();
bool SettingsLayoutHas(const char* key);
float SettingsLayoutGet(const char* key, float def);
void SettingsLayoutSet(const char* key, float val);
int  SettingsLayoutGetInt(const char* key, int def);
void SettingsLayoutSetInt(const char* key, int val);
bool SettingsLayoutGetBool(const char* key, bool def);
void SettingsLayoutSetBool(const char* key, bool val);
int  SettingsLayoutGetString(const char* key, char* out, int cap, const char* def);
void SettingsLayoutSetString(const char* key, const char* val);
bool SettingsLayoutHasCol(const char* table, const char* col);
float SettingsLayoutColW(const char* table, const char* col, float def);
void SettingsLayoutSetColW(const char* table, const char* col, float logical);
void SettingsLayoutClearTable(const char* table);
