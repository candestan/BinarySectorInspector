#pragma once

#include <d3d11.h>

bool TexLoadFile(const char* path, ID3D11ShaderResourceView** out_srv, int* out_w, int* out_h);
ID3D11ShaderResourceView* TexPlaceholder();
void TexShutdown();
