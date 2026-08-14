#pragma once

#include <windows.h>
#include <string>

bool pick_pe_file(HWND owner, std::wstring& out_path);
