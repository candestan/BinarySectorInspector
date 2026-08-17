#pragma once

void PluginInit();
void PluginShutdown();
void PluginRescan();
void PluginNotifyJob(int ready);

int  PluginCount();
const char* PluginId(int i);
const char* PluginName(int i);
const char* PluginVersion(int i);
const char* PluginAuthor(int i);
const char* PluginDescription(int i);
const char* PluginPath(int i);
const char* PluginError(int i);
bool PluginEnabled(int i);
void PluginSetEnabled(int i, bool on);
bool PluginInited(int i);

void PluginDrawToolsMenu(bool ready, bool locked);
bool PluginHasSettings(int i);
void PluginDrawSettings(int i);
int  PluginViewCount();
bool PluginViewSelId(int i, char* out, int cap);
const char* PluginViewLabel(int i);
bool PluginSelIsView(const char* sel);
void PluginDrawView(const char* sel);
