#pragma once

#include <stddef.h>
#include <stdint.h>

void HexViewReset();
void HexViewOpen(const uint8_t* data, size_t n);
void HexViewOnSaved();
void HexViewGoto(size_t off);
void HexViewSelect(size_t off, size_t n);
bool HexViewCursor(size_t* off, size_t* size);
void HexViewDraw();
