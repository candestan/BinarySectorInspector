#include "tool/tool.h"
#include "log/log.h"

#include <string.h>
#include <vector>

static std::vector<const ToolDescriptor*> g_tools;
static bool g_inited;

void ToolRegister(const ToolDescriptor* tool)
{
    if (!tool || !tool->id || !tool->run)
        return;
    for (const ToolDescriptor* t : g_tools)
    {
        if (t && _stricmp(t->id, tool->id) == 0)
            return;
    }
    g_tools.push_back(tool);
}

void ToolInit()
{
    if (g_inited)
        return;
    g_inited = true;
}

int ToolCount() { return (int)g_tools.size(); }

const ToolDescriptor* ToolAt(int i)
{
    if (i < 0 || i >= (int)g_tools.size())
        return nullptr;
    return g_tools[(size_t)i];
}

const ToolDescriptor* ToolFind(const char* id)
{
    if (!id)
        return nullptr;
    for (const ToolDescriptor* t : g_tools)
    {
        if (t && _stricmp(t->id, id) == 0)
            return t;
    }
    return nullptr;
}

int ToolMatchMedia(const char* media, const ToolDescriptor** out, int cap)
{
    if (!media || !media[0] || !out || cap <= 0)
        return 0;
    int n = 0;
    for (const ToolDescriptor* t : g_tools)
    {
        if (!t || !t->in_media)
            continue;
        if (_stricmp(t->in_media, media) != 0)
            continue;
        if (t->available && !t->available())
            continue;
        out[n++] = t;
        if (n >= cap)
            break;
    }
    return n;
}
