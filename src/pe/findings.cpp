#include "pe/pe.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <algorithm>
#include <vector>
#include <string>

#ifndef IMAGE_DLLCHARACTERISTICS_GUARD_CF
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF 0x4000
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
#define IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA 0x0020
#endif

static const uint32_t kMaxFindings = 80;
static const uint32_t kUnusualDosStub = 1024;
static const double kHighEntropy = 7.0;

static void Add(PeFile* pe, PeFindingSev sev, PeFindingKind kind,
    const char* title, const char* why, const char* evidence, uint32_t off)
{
    if (!pe || pe->findings.size() >= kMaxFindings)
        return;
    PeFinding f{};
    f.sev = sev;
    f.kind = kind;
    snprintf(f.title, sizeof(f.title), "%s", title ? title : "");
    snprintf(f.why, sizeof(f.why), "%s", why ? why : "");
    snprintf(f.evidence, sizeof(f.evidence), "%s", evidence ? evidence : "");
    f.file_off = off;
    pe->findings.push_back(f);
}

static bool HasFn(const PeFile* pe, const char* name)
{
    if (!pe || !name)
        return false;
    for (const PeImportDll& d : pe->imports)
    {
        for (const PeImportFn& fn : d.fns)
        {
            if (!fn.name.empty() && _stricmp(fn.name.c_str(), name) == 0)
                return true;
        }
    }
    return false;
}

static void JoinFns(char* out, int cap, const char* const* names, int n, const PeFile* pe)
{
    out[0] = 0;
    int p = 0;
    int got = 0;
    for (int i = 0; i < n && got < 8; i++)
    {
        if (!HasFn(pe, names[i]))
            continue;
        if (got)
            p += snprintf(out + p, cap - p, ", ");
        p += snprintf(out + p, cap - p, "%s", names[i]);
        got++;
        if (p >= cap - 8)
            break;
    }
}

static const char* IStr(const char* hay, const char* needle)
{
    if (!hay || !needle || !needle[0])
        return nullptr;
    size_t n = strlen(needle);
    for (const char* p = hay; *p; p++)
    {
        if (_strnicmp(p, needle, (int)n) == 0)
            return p;
    }
    return nullptr;
}

static bool LooksLikeIPv4(const char* s)
{
    if (!s)
        return false;
    unsigned oct[4] = {};
    const char* p = s;
    for (int i = 0; i < 4; i++)
    {
        if (*p < '0' || *p > '9')
            return false;
        if (p[0] == '0' && p[1] >= '0' && p[1] <= '9')
            return false;
        unsigned v = 0;
        while (*p >= '0' && *p <= '9')
        {
            v = v * 10u + (unsigned)(*p - '0');
            if (v > 255)
                return false;
            p++;
        }
        oct[i] = v;
        if (i < 3)
        {
            if (*p != '.')
                return false;
            p++;
        }
    }
    if (*p)
        return false;
    unsigned a = oct[0], b = oct[1], c = oct[2], d = oct[3];
    if (a == 0 || a == 127 || a >= 224)
        return false;
    if (a == 1 && b == 0)
        return false;
    if (a < 10 && b < 10 && c < 10 && d < 10)
        return false;
    return true;
}

static bool LooksLikeEmail(const char* s)
{
    if (!s || IStr(s, "://"))
        return false;
    size_t n = strlen(s);
    if (n < 6 || n > 80)
        return false;
    const char* at = strchr(s, '@');
    if (!at || at == s || at[1] == 0)
        return false;
    const char* dot = strchr(at + 1, '.');
    if (!dot || !dot[1] || dot[1] == '.')
        return false;
    for (const char* p = s; *p; p++)
    {
        unsigned char c = (unsigned char)*p;
        if (c <= 32 || c == '<' || c == '>' || c == '"' || c == '\'')
            return false;
    }
    return true;
}

static bool LooksLikeUnc(const char* s)
{
    if (!s || s[0] != '\\' || s[1] != '\\' || s[2] == 0 || s[2] == '\\')
        return false;
    return strchr(s + 2, '\\') != nullptr;
}

static void AppendEv(char* dst, int cap, const char* add, int* count, int maxn)
{
    if (!add || !add[0] || *count >= maxn)
        return;
    size_t used = strlen(dst);
    size_t need = strlen(add) + (*count ? 2 : 0);
    if (used + need + 1 >= (size_t)cap)
        return;
    if (*count)
        strcat_s(dst, cap, "; ");
    strcat_s(dst, cap, add);
    (*count)++;
}

static void ScanStrings(PeFile* pe)
{
    char urls[192] = {};
    char ips[192] = {};
    char persist[192] = {};
    char exec[192] = {};
    char mails[192] = {};
    char uncs[192] = {};
    char onions[192] = {};
    int nurl = 0, nip = 0, nper = 0, nexec = 0, nmail = 0, nunc = 0, nonion = 0;
    uint32_t url_off = 0, ip_off = 0, per_off = 0, exec_off = 0;
    uint32_t mail_off = 0, unc_off = 0, onion_off = 0;

    const int kScan = 8000;
    int n = (int)pe->strings.size();
    if (n > kScan)
        n = kScan;
    for (int i = 0; i < n; i++)
    {
        const PeStringEntry& s = pe->strings[i];
        const char* t = s.text.c_str();
        uint32_t off = (uint32_t)s.file_off;

        const char* u = IStr(t, "https://");
        if (!u)
            u = IStr(t, "http://");
        if (!u)
            u = IStr(t, "ftp://");
        if (u)
        {
            char one[96];
            int k = 0;
            while (u[k] && k < 90 && u[k] > 32 && u[k] != '"' && u[k] != '\'')
                k++;
            memcpy(one, u, (size_t)k);
            one[k] = 0;
            if (!url_off)
                url_off = off;
            AppendEv(urls, (int)sizeof(urls), one, &nurl, 6);
        }
        if (LooksLikeIPv4(t))
        {
            if (!ip_off)
                ip_off = off;
            AppendEv(ips, (int)sizeof(ips), t, &nip, 4);
        }
        if (IStr(t, "CurrentVersion\\Run") || IStr(t, "CurrentVersion/Run") ||
            IStr(t, "UserInit") || IStr(t, "Image File Execution Options"))
        {
            if (!per_off)
                per_off = off;
            char clip[80];
            snprintf(clip, sizeof(clip), "%.70s", t);
            AppendEv(persist, (int)sizeof(persist), clip, &nper, 3);
        }
        if (IStr(t, "powershell") || IStr(t, "cmd.exe") || IStr(t, "wscript") ||
            IStr(t, "cscript") || IStr(t, "mshta") || IStr(t, "rundll32") ||
            IStr(t, "regsvr32") || IStr(t, "schtasks") || IStr(t, "bitsadmin") ||
            IStr(t, "certutil"))
        {
            if (!exec_off)
                exec_off = off;
            char clip[80];
            snprintf(clip, sizeof(clip), "%.70s", t);
            AppendEv(exec, (int)sizeof(exec), clip, &nexec, 4);
        }
        if (LooksLikeEmail(t))
        {
            if (!mail_off)
                mail_off = off;
            AppendEv(mails, (int)sizeof(mails), t, &nmail, 4);
        }
        if (LooksLikeUnc(t))
        {
            if (!unc_off)
                unc_off = off;
            char clip[80];
            snprintf(clip, sizeof(clip), "%.70s", t);
            AppendEv(uncs, (int)sizeof(uncs), clip, &nunc, 3);
        }
        if (IStr(t, ".onion"))
        {
            if (!onion_off)
                onion_off = off;
            char clip[80];
            snprintf(clip, sizeof(clip), "%.70s", t);
            AppendEv(onions, (int)sizeof(onions), clip, &nonion, 3);
        }
    }

    if (nurl)
        Add(pe, PeFindingWarn, PeFindNetwork, "find.url.title", "find.url.why", urls, url_off);
    if (nip)
        Add(pe, PeFindingNotice, PeFindNetwork, "find.ip.title", "find.ip.why", ips, ip_off);
    if (nmail)
        Add(pe, PeFindingNotice, PeFindNetwork, "find.email.title", "find.email.why", mails, mail_off);
    if (nunc)
        Add(pe, PeFindingNotice, PeFindNetwork, "find.unc.title", "find.unc.why", uncs, unc_off);
    if (nonion)
        Add(pe, PeFindingWarn, PeFindNetwork, "find.onion.title", "find.onion.why", onions, onion_off);
    if (nper)
        Add(pe, PeFindingWarn, PeFindPersistence, "find.runkey.title", "find.runkey.why", persist, per_off);
    if (nexec)
        Add(pe, PeFindingWarn, PeFindExecution, "find.lolbin.title", "find.lolbin.why", exec, exec_off);
}

static void ScanImports(PeFile* pe)
{
    char buf[192];
    static const char* inj[] = {
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtMapViewOfSection", "NtUnmapViewOfSection", "QueueUserAPC",
        "SetWindowsHookExA", "SetWindowsHookExW", "RtlCreateUserThread"
    };
    JoinFns(buf, (int)sizeof(buf), inj, (int)(sizeof(inj) / sizeof(inj[0])), pe);
    if (buf[0])
        Add(pe, PeFindingWarn, PeFindInjection, "find.inject.title", "find.inject.why", buf, 0);

    static const char* net[] = {
        "URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenUrlA",
        "InternetOpenUrlW", "InternetConnectA", "InternetConnectW",
        "WinHttpOpen", "HttpSendRequestA", "HttpSendRequestW",
        "connect", "send", "recv"
    };
    JoinFns(buf, (int)sizeof(buf), net, (int)(sizeof(net) / sizeof(net[0])), pe);
    if (buf[0])
        Add(pe, PeFindingNotice, PeFindNetwork, "find.netapi.title", "find.netapi.why", buf, 0);

    static const char* run[] = {
        "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW",
        "WinExec", "CreateProcessA", "CreateProcessW"
    };
    JoinFns(buf, (int)sizeof(buf), run, (int)(sizeof(run) / sizeof(run[0])), pe);
    if (buf[0])
        Add(pe, PeFindingNotice, PeFindExecution, "find.spawn.title", "find.spawn.why", buf, 0);

    static const char* cry[] = {
        "CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "BCryptDecrypt",
        "CryptImportKey", "CryptAcquireContextA"
    };
    JoinFns(buf, (int)sizeof(buf), cry, (int)(sizeof(cry) / sizeof(cry[0])), pe);
    if (buf[0])
        Add(pe, PeFindingInfo, PeFindCrypto, "find.crypto.title", "find.crypto.why", buf, 0);

    static const char* dbg[] = {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"
    };
    JoinFns(buf, (int)sizeof(buf), dbg, (int)(sizeof(dbg) / sizeof(dbg[0])), pe);
    if (buf[0])
        Add(pe, PeFindingNotice, PeFindAnomaly, "find.antidebug.title", "find.antidebug.why", buf, 0);

    static const char* mtx[] = {
        "CreateMutexA", "CreateMutexW", "OpenMutexA", "OpenMutexW"
    };
    JoinFns(buf, (int)sizeof(buf), mtx, (int)(sizeof(mtx) / sizeof(mtx[0])), pe);
    if (buf[0])
        Add(pe, PeFindingInfo, PeFindPersistence, "find.mutex.title", "find.mutex.why", buf, 0);

    static const char* reg[] = {
        "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW"
    };
    JoinFns(buf, (int)sizeof(buf), reg, (int)(sizeof(reg) / sizeof(reg[0])), pe);
    if (buf[0])
        Add(pe, PeFindingNotice, PeFindPersistence, "find.regwrite.title", "find.regwrite.why", buf, 0);
}

void PeCollectFindings(PeFile* pe)
{
    if (!pe)
        return;

    if (pe->packer_detected && _stricmp(pe->packer, "none") != 0)
        Add(pe, PeFindingNotice, PeFindIdentity, "find.packer.title", "find.packer.why", pe->packer, 0);
    else if (pe->compiler_detected && _stricmp(pe->compiler, "unknown") != 0 &&
        _stricmp(pe->compiler, "MSVC") != 0)
        Add(pe, PeFindingInfo, PeFindIdentity, "find.compiler.title", "find.compiler.why", pe->compiler, 0);

    if (pe->e_lfanew > kUnusualDosStub)
        Add(pe, PeFindingNotice, PeFindAnomaly, "find.dos.title", "find.dos.why", nullptr, 0);
    if (pe->section_n == 0)
        Add(pe, PeFindingWarn, PeFindAnomaly, "find.nosec.title", "find.nosec.why", nullptr, 0);
    if (pe->timestamp == 0 || pe->timestamp == 0xFFFFFFFFu)
        Add(pe, PeFindingNotice, PeFindAnomaly, "find.ts.title", "find.ts.why", nullptr, 0);
    if ((pe->dllchars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) == 0)
        Add(pe, PeFindingInfo, PeFindHardening, "find.nx.title", "find.nx.why", nullptr, 0);
    if ((pe->dllchars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) == 0)
        Add(pe, PeFindingInfo, PeFindHardening, "find.aslr.title", "find.aslr.why", nullptr, 0);
    if (pe->checksum != 0 && !pe->checksum_ok)
        Add(pe, PeFindingNotice, PeFindAnomaly, "find.cksum.title", "find.cksum.why", nullptr, 0);

    for (int i = 0; i < pe->section_n; i++)
    {
        const PeSection& s = pe->sections[i];
        if ((s.chars & IMAGE_SCN_MEM_EXECUTE) && (s.chars & IMAGE_SCN_MEM_WRITE))
            Add(pe, PeFindingWarn, PeFindPacking, "find.wx.title", "find.wx.why", s.name, s.rawptr);
        uint64_t vend = (uint64_t)s.vaddr + (s.vsize ? s.vsize : s.rawsize);
        if (pe->size_of_image && vend > pe->size_of_image)
            Add(pe, PeFindingWarn, PeFindAnomaly, "find.vsize.title", "find.vsize.why", s.name, s.rawptr);
    }
    if (pe->overlay_size)
    {
        char ev[32];
        snprintf(ev, sizeof(ev), "%u", (unsigned)pe->overlay_size);
        Add(pe, PeFindingNotice, PeFindPacking, "find.overlay.title", "find.overlay.why", ev, pe->overlay_off);
    }

    PeAddr ep;
    PeAddrFromRva(pe, pe->entry_rva, &ep);
    if (pe->entry_rva && ep.section_index < 0)
        Add(pe, PeFindingWarn, PeFindAnomaly, "find.epout.title", "find.epout.why", nullptr, 0);
    else if (ep.section_index >= 0)
    {
        if (strncmp(ep.section_name, "UPX", 3) == 0 || strcmp(ep.section_name, ".themida") == 0 ||
            strcmp(ep.section_name, ".aspack") == 0)
            Add(pe, PeFindingNotice, PeFindPacking, "find.epsec.title", "find.epsec.why", ep.section_name, (uint32_t)ep.file_off);
    }
    if (pe->imports.empty() && (pe->chars & IMAGE_FILE_DLL) == 0)
        Add(pe, PeFindingNotice, PeFindPacking, "find.noimp.title", "find.noimp.why", nullptr, 0);
    if (pe->tls.present && !pe->tls.callback_rvas.empty())
        Add(pe, PeFindingNotice, PeFindExecution, "find.tls.title", "find.tls.why", nullptr, 0);
    if (pe->pdb_path[0])
        Add(pe, PeFindingInfo, PeFindAnomaly, "find.pdb.title", "find.pdb.why", pe->pdb_path, 0);
    for (const PeEntropyRange& r : pe->entropy)
    {
        if (r.size >= 256 && r.entropy >= kHighEntropy)
            Add(pe, PeFindingNotice, PeFindPacking, "find.entropy.title", "find.entropy.why", r.label, (uint32_t)r.offset);
    }
    if (pe->section_align == 0 || pe->file_align == 0)
        Add(pe, PeFindingWarn, PeFindAnomaly, "find.align.title", "find.align.why", nullptr, 0);

    ScanImports(pe);
    ScanStrings(pe);

    std::sort(pe->findings.begin(), pe->findings.end(), [](const PeFinding& a, const PeFinding& b) {
        if (a.sev != b.sev)
            return a.sev > b.sev;
        return (int)a.kind < (int)b.kind;
    });
}
