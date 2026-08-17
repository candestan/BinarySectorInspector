#include "runtime/scripting.h"
#include "persist/settings.h"
#include "log/log.h"

#pragma comment(lib, "version.lib")

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <string>
#include <vector>
#include <algorithm>

static const int kMaxPy = 48;
static const int kPathCap = 260;

struct Slot
{
    char key[32];
    int  family;
};

static const Slot kPy2 = { "python2.path", 2 };
static const Slot kPy3 = { "python3.path", 3 };

static std::vector<ScriptPyInstall> g_py2;
static std::vector<ScriptPyInstall> g_py3;

static bool EqPath(const char* a, const char* b)
{
    return a && b && _stricmp(a, b) == 0;
}

static bool HasI(const char* s, const char* sub)
{
    if (!s || !sub || !sub[0])
        return false;
    size_t n = strlen(s);
    size_t m = strlen(sub);
    if (m > n)
        return false;
    for (size_t i = 0; i + m <= n; i++)
    {
        size_t j = 0;
        for (; j < m; j++)
        {
            unsigned char ca = (unsigned char)s[i + j];
            unsigned char cb = (unsigned char)sub[j];
            if (ca >= 'A' && ca <= 'Z')
                ca = (unsigned char)(ca + 32);
            if (cb >= 'A' && cb <= 'Z')
                cb = (unsigned char)(cb + 32);
            if (ca != cb)
                break;
        }
        if (j == m)
            return true;
    }
    return false;
}

static bool FileExistsUtf8(const char* path)
{
    if (!path || !path[0])
        return false;
    wchar_t w[MAX_PATH];
    if (!MultiByteToWideChar(CP_UTF8, 0, path, -1, w, MAX_PATH))
        return false;
    DWORD a = GetFileAttributesW(w);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static void ToUtf8(const wchar_t* w, char* out, int cap)
{
    if (!out || cap < 2)
        return;
    out[0] = 0;
    if (!w)
        return;
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out, cap, nullptr, nullptr);
}

static bool ParseVer(const char* s, int* maj, int* min, int* pat)
{
    *maj = 0;
    *min = 0;
    *pat = 0;
    if (!s || !s[0])
        return false;
    int a = 0, b = 0, c = 0;
    if (sscanf_s(s, "%d.%d.%d", &a, &b, &c) >= 2 && a >= 1 && a <= 3)
    {
        *maj = a;
        *min = b;
        *pat = c;
        return true;
    }
    return false;
}

static bool VerFromFolder(const char* path, int* maj, int* min, int* pat)
{
    *maj = 0;
    *min = 0;
    *pat = 0;
    const char* slash = strrchr(path, '\\');
    if (!slash)
        slash = strrchr(path, '/');
    char dir[MAX_PATH];
    if (slash && slash > path)
    {
        size_t n = (size_t)(slash - path);
        if (n >= sizeof(dir))
            n = sizeof(dir) - 1;
        memcpy(dir, path, n);
        dir[n] = 0;
        slash = strrchr(dir, '\\');
        if (!slash)
            slash = strrchr(dir, '/');
        const char* leaf = slash ? slash + 1 : dir;
        const char* p = leaf;
        if (_strnicmp(p, "python", 6) == 0)
            p += 6;
        if (p[0] == '2' && isdigit((unsigned char)p[1]) && !isdigit((unsigned char)p[2]))
        {
            *maj = 2;
            *min = p[1] - '0';
            return true;
        }
        if (p[0] == '3')
        {
            *maj = 3;
            if (p[1] == '.')
                *min = atoi(p + 2);
            else if (isdigit((unsigned char)p[1]))
                *min = atoi(p + 1);
            return *min > 0 || p[1] == 0;
        }
    }
    return false;
}

static bool VerFromResource(const wchar_t* wpath, int* maj, int* min, int* pat)
{
    *maj = 0;
    *min = 0;
    *pat = 0;
    DWORD dummy = 0;
    DWORD n = GetFileVersionInfoSizeW(wpath, &dummy);
    if (!n || n > 1u << 20)
        return false;
    std::vector<unsigned char> buf(n);
    if (!GetFileVersionInfoW(wpath, 0, n, buf.data()))
        return false;
    struct LANGANDCODEPAGE { WORD wLanguage; WORD wCodePage; };
    LANGANDCODEPAGE* lp = nullptr;
    UINT lp_n = 0;
    if (!VerQueryValueW(buf.data(), L"\\VarFileInfo\\Translation", (void**)&lp, &lp_n) || !lp || lp_n < sizeof(LANGANDCODEPAGE))
        return false;
    wchar_t q[64];
    swprintf(q, 64, L"\\StringFileInfo\\%04x%04x\\ProductVersion", lp[0].wLanguage, lp[0].wCodePage);
    wchar_t* val = nullptr;
    UINT val_n = 0;
    if (!VerQueryValueW(buf.data(), q, (void**)&val, &val_n) || !val)
    {
        swprintf(q, 64, L"\\StringFileInfo\\%04x%04x\\FileVersion", lp[0].wLanguage, lp[0].wCodePage);
        if (!VerQueryValueW(buf.data(), q, (void**)&val, &val_n) || !val)
            return false;
    }
    char u8[64];
    ToUtf8(val, u8, (int)sizeof(u8));
    return ParseVer(u8, maj, min, pat);
}

static bool VerFromSpawn(const wchar_t* wpath, int* maj, int* min, int* pat)
{
    *maj = 0;
    *min = 0;
    *pat = 0;
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0))
        return false;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    wchar_t cmd[MAX_PATH + 96];
    swprintf(cmd, MAX_PATH + 96,
        L"\"%s\" -c \"import sys;sys.stdout.write('%%d.%%d.%%d'%%sys.version_info[:3])\"",
        wpath);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = wr;
    si.hStdError = wr;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessW(nullptr, cmd, nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(wr);
    if (!ok)
    {
        CloseHandle(rd);
        return false;
    }
    WaitForSingleObject(pi.hProcess, 1500);
    char buf[64] = {};
    DWORD got = 0;
    PeekNamedPipe(rd, nullptr, 0, nullptr, &got, nullptr);
    if (got)
        ReadFile(rd, buf, sizeof(buf) - 1, &got, nullptr);
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(rd);
    return ParseVer(buf, maj, min, pat);
}

bool ScriptingPyProbe(const char* path, ScriptPyInstall* out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    if (!path || !path[0] || !FileExistsUtf8(path))
        return false;
    if (HasI(path, "\\WindowsApps\\") || HasI(path, "/WindowsApps/"))
        return false;
    snprintf(out->path, sizeof(out->path), "%s", path);
    wchar_t w[MAX_PATH];
    if (!MultiByteToWideChar(CP_UTF8, 0, path, -1, w, MAX_PATH))
        return false;
    if (!VerFromResource(w, &out->major, &out->minor, &out->patch))
        VerFromFolder(path, &out->major, &out->minor, &out->patch);
    if (out->major < 2 || out->major > 3)
        snprintf(out->label, sizeof(out->label), "python.exe");
    else if (out->patch)
        snprintf(out->label, sizeof(out->label), "Python %d.%d.%d", out->major, out->minor, out->patch);
    else
        snprintf(out->label, sizeof(out->label), "Python %d.%d", out->major, out->minor);
    return true;
}

static void AddInstall(const char* path)
{
    ScriptPyInstall inst{};
    if (!ScriptingPyProbe(path, &inst))
        return;
    if (inst.major < 2 || inst.major > 3)
    {
        wchar_t w[MAX_PATH];
        if (MultiByteToWideChar(CP_UTF8, 0, path, -1, w, MAX_PATH))
            VerFromSpawn(w, &inst.major, &inst.minor, &inst.patch);
        if (inst.major < 2 || inst.major > 3)
            return;
        if (inst.patch)
            snprintf(inst.label, sizeof(inst.label), "Python %d.%d.%d", inst.major, inst.minor, inst.patch);
        else
            snprintf(inst.label, sizeof(inst.label), "Python %d.%d", inst.major, inst.minor);
    }
    std::vector<ScriptPyInstall>* dst = inst.major == 2 ? &g_py2 : &g_py3;
    for (const ScriptPyInstall& h : *dst)
    {
        if (EqPath(h.path, inst.path))
            return;
    }
    if ((int)dst->size() >= kMaxPy)
        return;
    dst->push_back(inst);
}

static void EnumRegCompany(HKEY root, REGSAM wow)
{
    HKEY py = nullptr;
    if (RegOpenKeyExW(root, L"SOFTWARE\\Python", 0, KEY_READ | wow, &py) != ERROR_SUCCESS)
        return;
    wchar_t company[128];
    for (DWORD ci = 0;; ci++)
    {
        DWORD cn = 128;
        if (RegEnumKeyExW(py, ci, company, &cn, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;
        HKEY ck = nullptr;
        if (RegOpenKeyExW(py, company, 0, KEY_READ | wow, &ck) != ERROR_SUCCESS)
            continue;
        wchar_t tag[64];
        for (DWORD ti = 0;; ti++)
        {
            DWORD tn = 64;
            if (RegEnumKeyExW(ck, ti, tag, &tn, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                break;
            wchar_t ipath[160];
            swprintf(ipath, 160, L"%s\\InstallPath", tag);
            HKEY ik = nullptr;
            if (RegOpenKeyExW(ck, ipath, 0, KEY_READ | wow, &ik) != ERROR_SUCCESS)
                continue;
            wchar_t exe[MAX_PATH];
            DWORD exe_n = sizeof(exe);
            DWORD ty = 0;
            LONG st = RegQueryValueExW(ik, L"ExecutablePath", nullptr, &ty, (LPBYTE)exe, &exe_n);
            if (st != ERROR_SUCCESS || ty != REG_SZ)
            {
                exe_n = sizeof(exe);
                st = RegQueryValueExW(ik, nullptr, nullptr, &ty, (LPBYTE)exe, &exe_n);
                if (st == ERROR_SUCCESS && ty == REG_SZ)
                {
                    size_t n = wcslen(exe);
                    if (n && exe[n - 1] != L'\\' && n + 12 < MAX_PATH)
                        wcscat_s(exe, MAX_PATH, L"\\python.exe");
                    else if (n && n + 11 < MAX_PATH)
                        wcscat_s(exe, MAX_PATH, L"python.exe");
                }
            }
            if (st == ERROR_SUCCESS && ty == REG_SZ)
            {
                char u8[MAX_PATH];
                ToUtf8(exe, u8, MAX_PATH);
                AddInstall(u8);
            }
            RegCloseKey(ik);
        }
        RegCloseKey(ck);
    }
    RegCloseKey(py);
}

static void ScanWellKnown()
{
    AddInstall("C:\\Python27\\python.exe");
    AddInstall("C:\\Python26\\python.exe");
    AddInstall("C:\\Python25\\python.exe");
    AddInstall("C:\\Python24\\python.exe");
    AddInstall("C:\\Python23\\python.exe");
    AddInstall("C:\\Python22\\python.exe");
    AddInstall("C:\\Python21\\python.exe");
    AddInstall("C:\\Python20\\python.exe");

    wchar_t base[MAX_PATH];
    if (GetEnvironmentVariableW(L"LOCALAPPDATA", base, MAX_PATH))
    {
        wchar_t dir[MAX_PATH];
        swprintf(dir, MAX_PATH, L"%s\\Programs\\Python\\*", base);
        WIN32_FIND_DATAW fd{};
        HANDLE h = FindFirstFileW(dir, &fd);
        if (h != INVALID_HANDLE_VALUE)
        {
            do
            {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                    continue;
                if (fd.cFileName[0] == L'.')
                    continue;
                wchar_t exe[MAX_PATH];
                swprintf(exe, MAX_PATH, L"%s\\Programs\\Python\\%s\\python.exe", base, fd.cFileName);
                char u8[MAX_PATH];
                ToUtf8(exe, u8, MAX_PATH);
                AddInstall(u8);
            } while (FindNextFileW(h, &fd));
            FindClose(h);
        }
    }

    const wchar_t* env[] = { L"ProgramFiles", L"ProgramFiles(x86)", L"ProgramW6432" };
    for (const wchar_t* e : env)
    {
        if (!GetEnvironmentVariableW(e, base, MAX_PATH))
            continue;
        wchar_t dir[MAX_PATH];
        WIN32_FIND_DATAW fd{};
        HANDLE h = nullptr;
        swprintf(dir, MAX_PATH, L"%s\\Python*", base);
        h = FindFirstFileW(dir, &fd);
        if (h == INVALID_HANDLE_VALUE)
            continue;
        do
        {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                continue;
            wchar_t exe[MAX_PATH];
            swprintf(exe, MAX_PATH, L"%s\\%s\\python.exe", base, fd.cFileName);
            char u8[MAX_PATH];
            ToUtf8(exe, u8, MAX_PATH);
            AddInstall(u8);
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
}

static void ScanPathEnv()
{
    char path[4096];
    DWORD n = GetEnvironmentVariableA("PATH", path, (DWORD)sizeof(path));
    if (!n || n >= sizeof(path))
        return;
    char* ctx = nullptr;
    for (char* tok = strtok_s(path, ";", &ctx); tok; tok = strtok_s(nullptr, ";", &ctx))
    {
        while (*tok == ' ')
            tok++;
        char exe[MAX_PATH];
        snprintf(exe, sizeof(exe), "%s\\python.exe", tok);
        AddInstall(exe);
        snprintf(exe, sizeof(exe), "%s\\python2.exe", tok);
        AddInstall(exe);
        snprintf(exe, sizeof(exe), "%s\\python3.exe", tok);
        AddInstall(exe);
        snprintf(exe, sizeof(exe), "%s\\python27.exe", tok);
        AddInstall(exe);
    }
}

static void ScanPyLauncher()
{
    wchar_t py[MAX_PATH];
    if (!SearchPathW(nullptr, L"py.exe", nullptr, MAX_PATH, py, nullptr))
        return;
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0))
        return;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    wchar_t cmd[MAX_PATH + 8];
    swprintf(cmd, MAX_PATH + 8, L"\"%s\" -0p", py);
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = wr;
    si.hStdError = wr;
    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessW(nullptr, cmd, nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(wr);
    if (!ok)
    {
        CloseHandle(rd);
        return;
    }
    WaitForSingleObject(pi.hProcess, 2000);
    char buf[4096] = {};
    DWORD got = 0;
    ReadFile(rd, buf, sizeof(buf) - 1, &got, nullptr);
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(rd);
    for (char* line = buf; *line;)
    {
        char* nl = strchr(line, '\n');
        if (nl)
            *nl = 0;
        char* cr = strchr(line, '\r');
        if (cr)
            *cr = 0;
        char* exe = strstr(line, ":\\");
        if (!exe)
            exe = strstr(line, ":/");
        if (exe && exe > line)
            exe--;
        if (exe && HasI(exe, "python.exe"))
        {
            while (*exe == ' ' || *exe == '\t')
                exe++;
            size_t n = strlen(exe);
            while (n && (exe[n - 1] == ' ' || exe[n - 1] == '\t'))
                exe[--n] = 0;
            AddInstall(exe);
        }
        if (!nl)
            break;
        line = nl + 1;
    }
}

static void SortFamily(std::vector<ScriptPyInstall>* v, int family)
{
    std::sort(v->begin(), v->end(), [family](const ScriptPyInstall& a, const ScriptPyInstall& b)
    {
        if (family == 2)
        {
            if (a.minor != b.minor)
                return a.minor > b.minor;
            return a.patch > b.patch;
        }
        if (a.minor != b.minor)
            return a.minor > b.minor;
        return a.patch > b.patch;
    });
}

static const Slot& SlotFor(int family)
{
    return family == 2 ? kPy2 : kPy3;
}

static std::vector<ScriptPyInstall>& ListFor(int family)
{
    return family == 2 ? g_py2 : g_py3;
}

void ScriptingScan()
{
    g_py2.clear();
    g_py3.clear();
    EnumRegCompany(HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY);
    EnumRegCompany(HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY);
    EnumRegCompany(HKEY_CURRENT_USER, 0);
    ScanWellKnown();
    ScanPyLauncher();
    ScanPathEnv();
    SortFamily(&g_py2, 2);
    SortFamily(&g_py3, 3);

    auto log = LogFor(LogBuiltinCore).Module("python");
    log.Info("Found %d Python 2 and %d Python 3 install(s)", (int)g_py2.size(), (int)g_py3.size());
    for (const ScriptPyInstall& p : g_py2)
        log.Debug("%s  %s", p.label, p.path);
    for (const ScriptPyInstall& p : g_py3)
        log.Debug("%s  %s", p.label, p.path);
}

static void AutoFill(int family)
{
    const Slot& s = SlotFor(family);
    char cur[kPathCap];
    SettingsGetString(s.key, cur, kPathCap, "");
    if (cur[0] && FileExistsUtf8(cur))
        return;
    const std::vector<ScriptPyInstall>& list = ListFor(family);
    if (list.empty())
        return;
    ScriptingPySet(family, list[0].path);
}

void ScriptingInit()
{
    ScriptingScan();
    AutoFill(2);
    AutoFill(3);
}

int ScriptingPyCount(int family)
{
    return (int)ListFor(family).size();
}

bool ScriptingPyAt(int family, int index, ScriptPyInstall* out)
{
    if (!out)
        return false;
    const std::vector<ScriptPyInstall>& list = ListFor(family);
    if (index < 0 || index >= (int)list.size())
        return false;
    *out = list[index];
    return true;
}

bool ScriptingPyGet(int family, char* out, int cap)
{
    if (!out || cap < 2)
        return false;
    return SettingsGetString(SlotFor(family).key, out, cap, "");
}

void ScriptingPySet(int family, const char* path)
{
    SettingsSetString(SlotFor(family).key, path ? path : "");
}

bool ScriptingLuaGet(char* out, int cap)
{
    if (!out || cap < 2)
        return false;
    return SettingsGetString("lua.path", out, cap, "");
}

void ScriptingLuaSet(const char* path)
{
    SettingsSetString("lua.path", path ? path : "");
}
