#include "analyze/analyze.h"
#include "pe/pe.h"
#include "log/log.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <vector>
#include <string>

// AutoHotkey compiled-container inventory. Identity is JSON.
// Recovers overlay/RCDATA blobs and plaintext fragments. Not a decompiler.
// credit: https://www.autohotkey.com/docs/v1/Scripts.htm#ahk2exe

static const char* kAnalyzerId = "com.binarysectorinspector.analyzer.autohotkey";
static const uint32_t kMaxBlob = 16u * 1024u * 1024u;
static const int kMaxSnips = 80;
static const int kMaxSnipChars = 180;

static bool MemFind(const uint8_t* b, size_t n, const uint8_t* needle, size_t k, size_t* out)
{
    if (!b || !needle || k == 0 || n < k)
        return false;
    size_t lim = n - k;
    if (lim > 64u * 1024u * 1024u)
        lim = 64u * 1024u * 1024u;
    for (size_t i = 0; i <= lim; i++)
    {
        if (memcmp(b + i, needle, k) == 0)
        {
            *out = i;
            return true;
        }
    }
    return false;
}

static bool LooksAhkLine(const char* s)
{
    if (!s || !s[0])
        return false;
    if (s[0] == '#' || s[0] == ':' || s[0] == '^' || s[0] == '!' || s[0] == '+')
        return true;
    static const char* k[] = {
        "#NoEnv", "#SingleInstance", "#NoTrayIcon", "#IfWinActive",
        "MsgBox", "SendInput", "Send,", "WinActivate", "Gui,",
        "Hotkey", "SetTimer", "FileInstall", "IfWinExist", "CoordMode"
    };
    for (int i = 0; i < (int)(sizeof(k) / sizeof(k[0])); i++)
    {
        if (strstr(s, k[i]))
            return true;
    }
    return false;
}

static void PushSnip(AnalysisArtifact* art, const char* line, int* n)
{
    if (!art || !line || *n >= kMaxSnips)
        return;
    if (!LooksAhkLine(line))
        return;
    for (const std::string& have : art->strings)
    {
        if (have == line)
            return;
    }
    art->strings.push_back(line);
    (*n)++;
}

static void HarvestAscii(const uint8_t* p, uint32_t n, AnalysisArtifact* art, int* snips)
{
    uint32_t i = 0;
    while (i < n && *snips < kMaxSnips)
    {
        while (i < n && (p[i] < 32 || p[i] > 126))
            i++;
        if (i >= n)
            break;
        char line[kMaxSnipChars];
        int k = 0;
        while (i < n && k < kMaxSnipChars - 1 && p[i] >= 32 && p[i] < 127)
            line[k++] = (char)p[i++];
        line[k] = 0;
        if (k >= 4)
            PushSnip(art, line, snips);
    }
}

static void HarvestUtf16(const uint8_t* p, uint32_t n, AnalysisArtifact* art, int* snips)
{
    if (n < 8)
        return;
    uint32_t i = 0;
    if (n >= 2 && p[0] == 0xFF && p[1] == 0xFE)
        i = 2;
    while (i + 1 < n && *snips < kMaxSnips)
    {
        char line[kMaxSnipChars];
        int k = 0;
        while (i + 1 < n && k < kMaxSnipChars - 1)
        {
            uint16_t w = (uint16_t)(p[i] | (p[i + 1] << 8));
            i += 2;
            if (w == 0 || w == '\n' || w == '\r')
                break;
            if (w >= 32 && w < 127)
                line[k++] = (char)w;
            else if (w > 127)
                break;
        }
        line[k] = 0;
        if (k >= 4)
            PushSnip(art, line, snips);
    }
}

static bool AnalyzeAhk(PeFile* pe, const uint8_t* data, size_t n)
{
    auto log = LogFor(LogBuiltinPeAnalyzer).Module("autohotkey");
    if (!pe || !data || !n)
        return false;

    static const uint8_t kNameU16[] = {
        0x41, 0x00, 0x75, 0x00, 0x74, 0x00, 0x6F, 0x00,
        0x48, 0x00, 0x6F, 0x00, 0x74, 0x00, 0x6B, 0x00,
        0x65, 0x00, 0x79, 0x00
    };
    static const uint8_t kMarkAsc[] = {
        '>','A','U','T','O','H','O','T','K','E','Y',' ','S','C','R','I','P','T','<'
    };
    size_t name_off = (size_t)-1, mark_off = (size_t)-1;
    MemFind(data, n, kNameU16, sizeof(kNameU16), &name_off);
    MemFind(data, n, kMarkAsc, sizeof(kMarkAsc), &mark_off);

    const PeRsrcLeaf* rcdata = nullptr;
    for (const PeRsrcLeaf& L : pe->rsrc)
    {
        if (_stricmp(L.type_name, "RCDATA") != 0)
            continue;
        if (!rcdata || L.size > rcdata->size)
            rcdata = &L;
    }

    AnalysisArtifact root{};
    snprintf(root.id, sizeof(root.id), "ahk.container");
    root.kind = AnalysisKindPayload;
    snprintf(root.label, sizeof(root.label), "AutoHotkey");
    AnalyzeStamp(&root, kAnalyzerId, "AutoHotkey");
    snprintf(root.status_i18n, sizeof(root.status_i18n), "pe.analysis_not_source");

    if (name_off != (size_t)-1)
    {
        char offb[16];
        snprintf(offb, sizeof(offb), "0x%X", (unsigned)name_off);
        AnalyzeAddProp(&root, "name_off", offb);
        if (!root.file_off)
            root.file_off = (uint32_t)name_off;
    }
    if (mark_off != (size_t)-1)
    {
        char offb[16];
        snprintf(offb, sizeof(offb), "0x%X", (unsigned)mark_off);
        AnalyzeAddProp(&root, "script_mark", offb);
        root.file_off = (uint32_t)mark_off;
        AnalyzeAddProp(&root, "magic", ">AUTOHOTKEY SCRIPT<");
    }
    else
        AnalyzeAddProp(&root, "runtime", "AutoHotkey");

    int snips = 0;
    if (pe->overlay_size && pe->overlay_off < n)
    {
        uint32_t on = (uint32_t)pe->overlay_size;
        if ((uint64_t)pe->overlay_off + on > n)
            on = (uint32_t)(n - pe->overlay_off);
        if (on > kMaxBlob)
            on = kMaxBlob;
        AnalyzeAddRawExport(&root, "overlay", "pe.analysis_dump_raw", "ahk_overlay.bin",
            pe->overlay_off, on);
        char sz[16];
        snprintf(sz, sizeof(sz), "%u", on);
        AnalyzeAddProp(&root, "overlay", sz);
        if (!root.file_off)
        {
            root.file_off = pe->overlay_off;
            root.size = on;
        }
        HarvestAscii(data + pe->overlay_off, on, &root, &snips);
        HarvestUtf16(data + pe->overlay_off, on, &root, &snips);
        log.Info("Overlay %u bytes", on);
    }
    if (rcdata && rcdata->file_off && rcdata->size)
    {
        uint32_t szn = rcdata->size;
        if (szn > kMaxBlob)
            szn = kMaxBlob;
        AnalyzeAddRawExport(&root, "rcdata", "pe.analysis_dump_raw", "ahk_rcdata.bin",
            rcdata->file_off, szn);
        AnalyzeAddProp(&root, "rcdata", rcdata->name);
        if ((uint64_t)rcdata->file_off + szn <= n)
        {
            HarvestAscii(data + rcdata->file_off, szn, &root, &snips);
            HarvestUtf16(data + rcdata->file_off, szn, &root, &snips);
        }
        if (!root.file_off)
        {
            root.file_off = rcdata->file_off;
            root.size = szn;
        }
        log.Info("RCDATA %s %u bytes", rcdata->name, szn);
    }

    if (snips)
    {
        char nb[12];
        snprintf(nb, sizeof(nb), "%d", snips);
        AnalyzeAddProp(&root, "plaintext_fragments", nb);
        AnalyzeAddProviderExport(&root, "listing", "pe.analysis_dump_listing", "ahk_fragments.txt");
        log.Info("Harvested %d AutoHotkey-like plaintext fragments (not claimed source)", snips);
    }
    else
        log.Info("No plaintext script fragments (compiled/encrypted payload)");

    AnalyzeAddFinding(pe, PeFindingNotice,
        "AutoHotkey compiled script",
        "Ahk2Exe stub plus overlay/RCDATA. Not original .ahk source.");
    pe->analysis.push_back(std::move(root));
    return true;
}

static bool ExportAhk(const PeFile* pe, const uint8_t* data, size_t n,
    const AnalysisArtifact* art, const AnalysisExport* ex, const char* path)
{
    (void)pe;
    (void)data;
    (void)n;
    if (!art || !ex || !path || strcmp(ex->id, "listing") != 0)
        return false;
    std::string t;
    char line[512];
    snprintf(line, sizeof(line), "AutoHotkey analysis (fragments, not source)\n");
    t.append(line);
    for (const AnalysisProp& p : art->props)
    {
        snprintf(line, sizeof(line), "%s=%s\n", p.key, p.value);
        t.append(line);
    }
    t.push_back('\n');
    for (const std::string& s : art->strings)
    {
        t.append(s);
        t.push_back('\n');
    }
    wchar_t wpath[MAX_PATH];
    if (!MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, MAX_PATH))
        return false;
    HANDLE h = CreateFileW(wpath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    DWORD wr = 0;
    BOOL ok = WriteFile(h, t.data(), (DWORD)t.size(), &wr, nullptr);
    CloseHandle(h);
    return ok && wr == (DWORD)t.size();
}

static const AnalyzerProvider kAhkProvider = {
    kAnalyzerId,
    "autohotkey",
    { true, false, nullptr, "autohotkey", nullptr },
    AnalyzeAhk,
    ExportAhk
};

void AnalyzeRegisterAhk()
{
    AnalyzeRegister(&kAhkProvider);
}
