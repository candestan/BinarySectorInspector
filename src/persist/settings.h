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
