/* Level 2 plugin: native ImGui via bsi_imgui.dll.
 *
 * Import sdk/imgui/bsi_imgui.props (or match its include/lib flags).
 * Copy the DLL next to the host exe is already done by the host build.
 */

#include "bsi_plugin.h"
#include "imgui.h"

static const BsiHost* g_host;

BSI_PLUGIN_EXPORT const BsiPluginInfo* BsiPluginGetInfo(void)
{
    static const BsiPluginInfo info = {
        "com.example.skeleton_imgui",
        "Skeleton ImGui",
        "1.0.0",
        "example",
        "Draws with host ImGui (bsi_imgui.dll).",
        BSI_PLUGIN_ABI_VERSION,
        BsiKindView
    };
    return &info;
}

BSI_PLUGIN_EXPORT int BsiPluginInit(const BsiHost* host)
{
    if (!BsiHostCompatible(host))
        return 1;
    g_host = host;
    return 0;
}

BSI_PLUGIN_EXPORT void BsiPluginShutdown(void)
{
    g_host = nullptr;
}

BSI_PLUGIN_EXPORT int BsiPluginViewCount(void)
{
    return 1;
}

BSI_PLUGIN_EXPORT int BsiPluginViewInfo(int index, BsiViewInfo* out)
{
    if (index != 0 || !out)
        return 0;
    out->id = "skeleton_imgui";
    out->label = "Skeleton ImGui";
    return 1;
}

BSI_PLUGIN_EXPORT int BsiPluginViewDraw(int index, const BsiUi* ui)
{
    if (index != 0 || !ui)
        return 0;
    if (BSI_UI_HAS(ui, imgui) && ui->imgui)
        ImGui::SetCurrentContext((ImGuiContext*)ui->imgui);
    ImGui::TextUnformatted("Native ImGui from bsi_imgui.dll.");
    if (ImGui::Button("Ping"))
    {
        if (g_host && g_host->toast)
            g_host->toast(g_host->ctx, BsiToastSuccess, "Skeleton ImGui", "Button clicked");
    }
    return 1;
}
