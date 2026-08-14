#pragma once

// shell pages. inspector (compiler/packer/COM/rsrc/hex) not wired.

enum AppPage
{
    AppPageWelcome = 0,
    AppPageSettings,
};

void    AppInit();
void    AppPrepareFrame();
void    AppOpenPath(const char* path);

void    AppSetPage(AppPage page);
AppPage AppGetPage();
void    AppDraw();
