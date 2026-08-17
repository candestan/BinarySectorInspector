/* Minimal drop-in plugin. Copy bsi_plugin.h next to this file.
 *
 * cl /LD /I. skeleton.c /Fe:example.dll
 * copy example.dll <BSI>\x64\Debug\plugins\
 */

#include "bsi_plugin.h"

static const BsiHost* g_host;

BSI_PLUGIN_EXPORT const struct BsiPluginInfo* BsiPluginGetInfo(void)
{
    static const struct BsiPluginInfo info = {
        "com.example.skeleton",
        "Skeleton",
        "1.0.0",
        "example",
        "Drop-in SDK skeleton.",
        BSI_PLUGIN_ABI_VERSION,
        BsiKindTool
    };
    return &info;
}

BSI_PLUGIN_EXPORT int BsiPluginInit(const struct BsiHost* host)
{
    if (!BsiHostCompatible(host))
        return 1;
    g_host = host;
    if (host->log)
        host->log(host->ctx, BsiSevInfo, "skeleton", "Ready");
    return 0;
}

BSI_PLUGIN_EXPORT void BsiPluginShutdown(void)
{
    g_host = 0;
}

BSI_PLUGIN_EXPORT int BsiPluginToolCount(void)
{
    return 1;
}

BSI_PLUGIN_EXPORT int BsiPluginToolInfo(int index, struct BsiToolInfo* out)
{
    if (index != 0 || !out)
        return 0;
    out->id = "hello";
    out->parent = "Skeleton";
    out->label = "Log hello";
    return 1;
}

BSI_PLUGIN_EXPORT int BsiPluginToolRun(int index)
{
    if (index != 0 || !g_host || !g_host->log)
        return 0;
    g_host->log(g_host->ctx, BsiSevInfo, "skeleton", "Hello from a drop-in plugin");
    return 1;
}

BSI_PLUGIN_EXPORT void BsiPluginOnJob(int ready)
{
    if (!g_host || !g_host->log)
        return;
    g_host->log(g_host->ctx, BsiSevDebug, "skeleton", ready ? "Job ready" : "Job closed");
}

/* Optional card art: return local paths relative to the DLL.
BSI_PLUGIN_EXPORT const struct BsiVisuals* BsiPluginVisuals(void)
{
    static const struct BsiVisuals v = {
        (uint32_t)sizeof(struct BsiVisuals),
        "icon.png",
        "cover.png"
    };
    return &v;
}
*/
