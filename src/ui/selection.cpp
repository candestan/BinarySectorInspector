#include "ui/selection.h"
#include "ui/workspace.h"
#include "ui/hex_view.h"
#include "app/inspector.h"

#include <string.h>
#include <stdio.h>

static Selection g_sel;

void SelectionClear()
{
    memset(&g_sel, 0, sizeof(g_sel));
}

void SelectionSet(const char* kind, const char* id, const char* title,
    const char* body, uint32_t off, uint32_t size)
{
    memset(&g_sel, 0, sizeof(g_sel));
    if (kind)
        snprintf(g_sel.kind, sizeof(g_sel.kind), "%s", kind);
    if (id)
        snprintf(g_sel.id, sizeof(g_sel.id), "%s", id);
    if (title)
        snprintf(g_sel.title, sizeof(g_sel.title), "%s", title);
    if (body)
        snprintf(g_sel.body, sizeof(g_sel.body), "%s", body);
    g_sel.off = off;
    g_sel.size = size;
}

const Selection& SelectionGet()
{
    return g_sel;
}

void NavOpenView(const char* view_id)
{
    WorkspaceSetVisible(view_id, true);
    if (view_id && strncmp(view_id, "view.", 5) == 0)
        WorkspaceDockToCenter(view_id);
    WorkspaceFocus(view_id);
}

void NavFocusView(const char* view_id)
{
    WorkspaceFocus(view_id);
}

void NavOpenInHex(uint32_t file_off)
{
    HexViewUseJobImage();
    InspectorSelect("hex");
    HexViewGoto(file_off);
}

void NavShowProperties()
{
    NavOpenView("panel.properties");
}

void NavShowEvidence()
{
    NavOpenView("panel.evidence");
}
