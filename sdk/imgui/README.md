# BSI ImGui runtime

Plugins that want Dear ImGui call the **same** `bsi_imgui.dll` the host uses. They do not compile `imgui.cpp`.

```
{BinarySectorInspector.exe}
  bsi_imgui.dll          # loaded with the host; plugins import this
```

## Plugin usage

1. Import `sdk/imgui/bsi_imgui.props` (or match its include/lib flags).
2. `#include "imgui.h"`.
3. In `BsiPluginViewDraw` / `BsiPluginDrawSettings`, draw as usual:

```cpp
if (BSI_UI_HAS(ui, imgui) && ui->imgui)
    ImGui::SetCurrentContext((ImGuiContext*)ui->imgui);
ImGui::TextUnformatted("hello");
```

`SetCurrentContext` is optional while the callback runs on the UI thread (the host already bound the form context), but it is cheap and keeps a plugin safe if it also compiled a private ImGui copy by mistake.

4. Do not call `CreateContext` / `DestroyContext` / `NewFrame` / `Render`. Do not compile Win32/DX backends. Do not call ImGui from a worker thread.

imnodes stays compiled into the host EXE. A plugin that wants `ImNodes::` still compiles `imnodes.cpp` at the host pin and binds `ui->imnodes`.

See `sdk/plugin/skeleton_imgui.cpp`.
