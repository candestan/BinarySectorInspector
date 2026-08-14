#pragma once

const char* I18nGet(const char* key);
const char* I18nName();
const char* I18nFile();
void        I18nInit();
void        I18nRescan();
void        I18nLoadFile(const char* file);
int         I18nCount();
const char* I18nEntryName(int index);
const char* I18nEntryFile(int index);
