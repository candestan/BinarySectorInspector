#pragma once

#include <stdint.h>

struct Selection
{
    char     kind[32];
    char     id[96];
    char     title[160];
    char     body[512];
    uint32_t off;
    uint32_t size;
};

void             SelectionClear();
void             SelectionSet(const char* kind, const char* id, const char* title,
                    const char* body, uint32_t off, uint32_t size);
const Selection& SelectionGet();
void             NavOpenView(const char* view_id);
void             NavFocusView(const char* view_id);
void             NavOpenInHex(uint32_t file_off);
void             NavShowProperties();
void             NavShowEvidence();
