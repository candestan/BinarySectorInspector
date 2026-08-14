#pragma once

// shell pages. inspector is the PE view; compiler/packer/hex still later.

enum AppPage
{
    AppPageWelcome = 0,
    AppPageSettings,
    AppPageInspector,
};

void    AppInit();
void    AppShutdown();
void    AppPrepareFrame();
void    AppOpenPath(const char* path);
void    AppOpenSettings();
bool    AppPickOpenPe(char* out, int cap);
bool    AppPickSavePe(char* out, int cap);
bool    AppPickOpenFilter(char* out, int cap, const wchar_t* filter, const wchar_t* title);
bool    AppPickSaveFilter(char* out, int cap, const wchar_t* filter, const wchar_t* title, const char* suggest);
void    AppOpenWindowPicker();

void    AppSetPage(AppPage page);
AppPage AppGetPage();
AppPage AppSettingsReturn();
void    AppDraw();
