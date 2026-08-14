#include "persist/paths.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void PathsExeDir(char* out, int cap)
{
    if (!out || cap < 4)
        return;
    out[0] = 0;
    GetModuleFileNameA(nullptr, out, cap);
    char* slash = strrchr(out, '\\');
    if (slash)
        slash[1] = 0;
}

void PathsJoin(char* out, int cap, const char* dir, const char* file)
{
    if (!out || cap < 4)
        return;
    snprintf(out, cap, "%s%s", dir ? dir : "", file ? file : "");
}

bool PathsReadFile(const char* path, char** out_text, int* out_len)
{
    if (out_text)
        *out_text = nullptr;
    if (out_len)
        *out_len = 0;
    if (!path || !out_text)
        return false;
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    DWORD sz = GetFileSize(h, nullptr);
    if (sz == INVALID_FILE_SIZE || sz > 4 * 1024 * 1024)
    {
        CloseHandle(h);
        return false;
    }
    char* buf = (char*)malloc(sz + 1);
    if (!buf)
    {
        CloseHandle(h);
        return false;
    }
    DWORD read = 0;
    BOOL ok = ReadFile(h, buf, sz, &read, nullptr);
    CloseHandle(h);
    if (!ok)
    {
        free(buf);
        return false;
    }
    buf[read] = 0;
    *out_text = buf;
    if (out_len)
        *out_len = (int)read;
    return true;
}
