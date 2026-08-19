#include "engine/engine.h"
#include "app/app.h"

#include <windows.h>
#include <stdio.h>

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, PWSTR, int)
{
    // Drop the cwd and PATH from the module search order before anything is loaded.
    // We open untrusted files from arbitrary folders, so a stray dll next to a sample
    // must never win over the real one.
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);

    bool force_sw = false;
    char pending[8][MAX_PATH];
    int pending_n = 0;

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv)
    {
        for (int i = 1; i < argc; i++)
        {
            // -sw forces WARP. remaining argv are file paths.
            if (!lstrcmpiW(argv[i], L"-sw") || !lstrcmpiW(argv[i], L"--software"))
            {
                force_sw = true;
                continue;
            }
            if (pending_n >= 8)
                continue;
            WideCharToMultiByte(CP_UTF8, 0, argv[i], -1, pending[pending_n], MAX_PATH, nullptr, nullptr);
            if (pending[pending_n][0])
                pending_n++;
        }
        LocalFree(argv);
    }

    if (!EngineInit(inst, force_sw))
        return 1;
    AppInit();
    for (int i = 0; i < pending_n; i++)
        AppOpenPath(pending[i]);

    while (EngineProcessEvents())
    {
        if (!EngineShouldRender())
            continue;

        AppPrepareFrame();
        EngineApplyPending();
        if (BeginForm("Binary Sector Inspector", nullptr, ImVec2(780.f, 620.f), true))
            AppDraw();
        EndForm();

        EngineEndFrame();
    }

    AppShutdown();
    EngineShutdown();
    return 0;
}
