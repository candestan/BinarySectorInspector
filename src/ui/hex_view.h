#pragma once

#include <stddef.h>
#include <stdint.h>

void HexViewReset();
void HexViewOpen(const uint8_t* data, size_t n);
void HexViewOnSaved();
void HexViewGoto(size_t off);
void HexViewDraw();
