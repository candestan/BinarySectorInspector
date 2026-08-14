#include "app.h"

App::App(HWND host_hwnd) : host_hwnd_(host_hwnd) {}

void App::draw()
{
    if (!inspecting_)
    {
        if (open_dialog_.draw(host_hwnd_))
        {
            image_ = PeImage::load(open_dialog_.selected_path());
            inspector_ = InspectorState{};
            inspecting_ = true;
        }
        return;
    }

    bool open_another = false;
    draw_inspector(image_, inspector_, open_another);
    if (open_another)
        inspecting_ = false;
}
