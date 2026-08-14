#pragma once

#include "pe/pe_image.h"

struct InspectorState
{
    int selected_section = -1;
    uint64_t hex_highlight_start = 0;
    uint64_t hex_highlight_size = 0;
    bool hex_scroll_pending = false;
    uint64_t hex_scroll_offset = 0;
    char filter[256] = {};
    int reloc_block = -1;
};

bool draw_inspector(PeImage& image, InspectorState& state, bool& request_open_another);
