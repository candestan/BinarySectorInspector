#pragma once

#include <d3d11.h>
#include <stddef.h>
#include <stdint.h>

bool TexLoadFile(const char* path, ID3D11ShaderResourceView** out_srv, int* out_w, int* out_h);
bool TexLoadMemory(const void* data, size_t n, ID3D11ShaderResourceView** out_srv, int* out_w, int* out_h);
bool TexLoadPeIcon(const uint8_t* blob, uint32_t n, ID3D11ShaderResourceView** out_srv, int* out_w, int* out_h);
ID3D11ShaderResourceView* TexPlaceholder();
void TexShutdown();
