#pragma once

#include <windows.h>
#include <string>
#include "ui/open_target_dialog.h"
#include "ui/inspector.h"
#include "pe/pe_image.h"

class App
{
public:
    explicit App(HWND host_hwnd);
    void draw();

private:
    HWND host_hwnd_;
    bool inspecting_ = false;
    OpenTargetDialog open_dialog_;
    PeImage image_;
    InspectorState inspector_;
};
