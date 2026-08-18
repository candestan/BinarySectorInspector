#include "findings/findings.h"
#include "analyze/profile.h"
#include "pe/pe.h"
#include "log/log.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <algorithm>

#ifndef IMAGE_DLLCHARACTERISTICS_GUARD_CF
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF 0x4000
#endif

static const uint32_t kUnusualDosStub = 1024;
static const double kHighEntropy = 7.0;

struct FindingsCtx
{
    PeFile*                 pe;
    AnalysisReport*         rep;
    const AnalysisProfile*  prof;
    int                     ev_serial;
};

const char* FindingCategoryKey(FindingCategory cat)
{
    switch (cat)
    {
    case FindCatStructure: return "finding.cat.structure";
    case FindCatExecution: return "finding.cat.execution";
    case FindCatMemory: return "finding.cat.memory";
    case FindCatImports: return "finding.cat.imports";
    case FindCatResources: return "finding.cat.resources";
    case FindCatPacking: return "finding.cat.packing";
    case FindCatManaged: return "finding.cat.managed";
    case FindCatEmbedded: return "finding.cat.embedded";
    case FindCatMetadata: return "finding.cat.metadata";
    case FindCatIntegrity: return "finding.cat.integrity";
    case FindCatNetwork: return "finding.cat.network";
    case FindCatPersistence: return "finding.cat.persistence";
    case FindCatInjection: return "finding.cat.injection";
    case FindCatIdentity: return "finding.cat.identity";
    case FindCatCrypto: return "finding.cat.crypto";
    default: return "finding.cat.structure";
    }
}

const char* FindingSeverityKey(FindingSeverity sev)
{
    switch (sev)
    {
    case FindSevCritical: return "finding.sev.critical";
    case FindSevHigh: return "finding.sev.high";
    case FindSevMedium: return "finding.sev.medium";
    case FindSevLow: return "finding.sev.low";
    default: return "finding.sev.info";
    }
}

const char* FindingConfidenceKey(FindingConfidence conf)
{
    switch (conf)
    {
    case FindConfExact: return "finding.conf.exact";
    case FindConfHigh: return "finding.conf.high";
    case FindConfMedium: return "finding.conf.medium";
    default: return "finding.conf.low";
    }
}

static PeFindingSev LegacySev(FindingSeverity s)
{
    if (s >= FindSevHigh)
        return PeFindingWarn;
    if (s >= FindSevMedium)
        return PeFindingNotice;
    return PeFindingInfo;
}

static PeFindingKind LegacyKind(FindingCategory c)
{
    switch (c)
    {
    case FindCatPacking: return PeFindPacking;
    case FindCatNetwork: return PeFindNetwork;
    case FindCatExecution: return PeFindExecution;
    case FindCatInjection: return PeFindInjection;
    case FindCatPersistence: return PeFindPersistence;
    case FindCatIdentity: return PeFindIdentity;
    case FindCatCrypto: return PeFindCrypto;
    case FindCatMemory: return PeFindPacking;
    default: return PeFindAnomaly;
    }
}

static int AddEvidence(FindingsCtx* ctx, EvidenceKind kind, const char* source,
    const char* summary, const char* detail, uint32_t off, uint32_t rva, const char* subject)
{
    if (!ctx || !ctx->rep || ctx->rep->evidence.size() >= ctx->prof->budgets.max_evidence)
        return -1;
    EvidenceItem ev{};
    snprintf(ev.id, sizeof(ev.id), "ev.%d", ctx->ev_serial++);
    ev.kind = kind;
    snprintf(ev.source, sizeof(ev.source), "%s", source ? source : "engine");
    snprintf(ev.summary, sizeof(ev.summary), "%s", summary ? summary : "");
    snprintf(ev.detail, sizeof(ev.detail), "%s", detail ? detail : "");
    ev.file_off = off;
    ev.rva = rva;
    snprintf(ev.subject, sizeof(ev.subject), "%s", subject ? subject : "");
    ctx->rep->evidence.push_back(ev);
    return (int)ctx->rep->evidence.size() - 1;
}

static bool HasFindingId(const FindingsCtx* ctx, const char* id)
{
    if (!ctx || !id || !id[0])
        return false;
    for (const FindingItem& f : ctx->rep->findings)
    {
        if (_stricmp(f.id, id) == 0)
            return true;
    }
    return false;
}

static void SyncLegacy(PeFile* pe, const FindingItem& f)
{
    if (!pe || pe->findings.size() >= 80)
        return;
    PeFinding lf{};
    lf.sev = LegacySev(f.severity);
    lf.kind = LegacyKind(f.category);
    snprintf(lf.title, sizeof(lf.title), "%s", f.title_key);
    snprintf(lf.why, sizeof(lf.why), "%s", f.matter_key[0] ? f.matter_key : f.explain_key);
    snprintf(lf.evidence, sizeof(lf.evidence), "%s", f.evidence_text);
    lf.file_off = f.file_off;
    pe->findings.push_back(lf);
}

static void AddFinding(FindingsCtx* ctx,
    const char* id, const char* title_key, const char* explain_key, const char* matter_key,
    const char* next_key, const char* tech_key,
    FindingSeverity sev, FindingConfidence conf, FindingCategory cat,
    const char* evidence_text, uint32_t file_off, int ev_idx)
{
    if (!ctx || !ctx->rep || !id || HasFindingId(ctx, id))
        return;
    if (ctx->rep->findings.size() >= ctx->prof->budgets.max_findings)
        return;
    FindingItem f{};
    snprintf(f.id, sizeof(f.id), "%s", id);
    snprintf(f.title_key, sizeof(f.title_key), "%s", title_key ? title_key : "");
    snprintf(f.explain_key, sizeof(f.explain_key), "%s", explain_key ? explain_key : "");
    snprintf(f.matter_key, sizeof(f.matter_key), "%s", matter_key ? matter_key : "");
    snprintf(f.next_key, sizeof(f.next_key), "%s", next_key ? next_key : "");
    snprintf(f.tech_key, sizeof(f.tech_key), "%s", tech_key ? tech_key : "");
    f.severity = sev;
    f.confidence = conf;
    f.category = cat;
    f.file_off = file_off;
    snprintf(f.evidence_text, sizeof(f.evidence_text), "%s", evidence_text ? evidence_text : "");
    if (ev_idx >= 0 && f.evidence_n < FindingMaxEvidence)
        f.evidence_idx[f.evidence_n++] = ev_idx;
    f.priority = (int)sev * 100 + (int)conf * 10;
    if (file_off)
    {
        f.actions[f.action_n++] = FindingAction{ "finding.action.open_hex", FactActHex, file_off, "" };
    }
    ctx->rep->findings.push_back(f);
    SyncLegacy(ctx->pe, f);
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
    size_t nlen = strlen(needle);
    for (const char* p = hay; *p; p++)
    {
        if (_strnicmp(p, needle, (int)nlen) == 0)
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

static void ScanStrings(FindingsCtx* ctx)
{
    PeFile* pe = ctx->pe;
    char urls[192] = {}, ips[192] = {}, persist[192] = {}, exec[192] = {};
    char mails[192] = {}, uncs[192] = {}, onions[192] = {};
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
        if (!u) u = IStr(t, "http://");
        if (!u) u = IStr(t, "ftp://");
        if (u)
        {
            char one[96];
            int k = 0;
            while (u[k] && k < 90 && u[k] > 32 && u[k] != '"' && u[k] != '\'')
                k++;
            memcpy(one, u, (size_t)k);
            one[k] = 0;
            if (!url_off) url_off = off;
            AppendEv(urls, (int)sizeof(urls), one, &nurl, 6);
        }
        if (LooksLikeIPv4(t))
        {
            if (!ip_off) ip_off = off;
            AppendEv(ips, (int)sizeof(ips), t, &nip, 4);
        }
        if (IStr(t, "CurrentVersion\\Run") || IStr(t, "CurrentVersion/Run") ||
            IStr(t, "UserInit") || IStr(t, "Image File Execution Options"))
        {
            if (!per_off) per_off = off;
            char clip[80];
            snprintf(clip, sizeof(clip), "%.70s", t);
            AppendEv(persist, (int)sizeof(persist), clip, &nper, 3);
        }
        if (IStr(t, "powershell") || IStr(t, "cmd.exe") || IStr(t, "wscript") ||
            IStr(t, "cscript") || IStr(t, "mshta") || IStr(t, "rundll32") ||
            IStr(t, "regsvr32") || IStr(t, "schtasks") || IStr(t, "bitsadmin") ||
            IStr(t, "certutil"))
        {
            if (!exec_off) exec_off = off;
            char clip[80];
            snprintf(clip, sizeof(clip), "%.70s", t);
            AppendEv(exec, (int)sizeof(exec), clip, &nexec, 4);
        }
        if (LooksLikeEmail(t))
        {
            if (!mail_off) mail_off = off;
            AppendEv(mails, (int)sizeof(mails), t, &nmail, 4);
        }
        if (LooksLikeUnc(t))
        {
            if (!unc_off) unc_off = off;
            char clip[80];
            snprintf(clip, sizeof(clip), "%.70s", t);
            AppendEv(uncs, (int)sizeof(uncs), clip, &nunc, 3);
        }
        if (IStr(t, ".onion"))
        {
            if (!onion_off) onion_off = off;
            char clip[80];
            snprintf(clip, sizeof(clip), "%.70s", t);
            AppendEv(onions, (int)sizeof(onions), clip, &nonion, 3);
        }
    }
    if (nurl)
    {
        int ev = AddEvidence(ctx, EvString, "strings", urls, nullptr, url_off, 0, nullptr);
        AddFinding(ctx, "pe.string.url", "finding.string.url.title", "finding.string.url.explain",
            "finding.string.url.matter", "finding.string.url.next", "finding.string.url.tech",
            FindSevHigh, FindConfMedium, FindCatNetwork, urls, url_off, ev);
    }
    if (nip)
    {
        int ev = AddEvidence(ctx, EvString, "strings", ips, nullptr, ip_off, 0, nullptr);
        AddFinding(ctx, "pe.string.ip", "finding.string.ip.title", "finding.string.ip.explain",
            "finding.string.ip.matter", "finding.string.ip.next", "finding.string.ip.tech",
            FindSevMedium, FindConfMedium, FindCatNetwork, ips, ip_off, ev);
    }
    if (nmail)
    {
        int ev = AddEvidence(ctx, EvString, "strings", mails, nullptr, mail_off, 0, nullptr);
        AddFinding(ctx, "pe.string.email", "finding.string.email.title", "finding.string.email.explain",
            "finding.string.email.matter", "finding.string.email.next", "finding.string.email.tech",
            FindSevLow, FindConfMedium, FindCatNetwork, mails, mail_off, ev);
    }
    if (nunc)
    {
        int ev = AddEvidence(ctx, EvString, "strings", uncs, nullptr, unc_off, 0, nullptr);
        AddFinding(ctx, "pe.string.unc", "finding.string.unc.title", "finding.string.unc.explain",
            "finding.string.unc.matter", "finding.string.unc.next", "finding.string.unc.tech",
            FindSevMedium, FindConfMedium, FindCatNetwork, uncs, unc_off, ev);
    }
    if (nonion)
    {
        int ev = AddEvidence(ctx, EvString, "strings", onions, nullptr, onion_off, 0, nullptr);
        AddFinding(ctx, "pe.string.onion", "finding.string.onion.title", "finding.string.onion.explain",
            "finding.string.onion.matter", "finding.string.onion.next", "finding.string.onion.tech",
            FindSevHigh, FindConfHigh, FindCatNetwork, onions, onion_off, ev);
    }
    if (nper)
    {
        int ev = AddEvidence(ctx, EvString, "strings", persist, nullptr, per_off, 0, nullptr);
        AddFinding(ctx, "pe.string.runkey", "finding.string.runkey.title", "finding.string.runkey.explain",
            "finding.string.runkey.matter", "finding.string.runkey.next", "finding.string.runkey.tech",
            FindSevHigh, FindConfMedium, FindCatPersistence, persist, per_off, ev);
    }
    if (nexec)
    {
        int ev = AddEvidence(ctx, EvString, "strings", exec, nullptr, exec_off, 0, nullptr);
        AddFinding(ctx, "pe.string.lolbin", "finding.string.lolbin.title", "finding.string.lolbin.explain",
            "finding.string.lolbin.matter", "finding.string.lolbin.next", "finding.string.lolbin.tech",
            FindSevHigh, FindConfMedium, FindCatExecution, exec, exec_off, ev);
    }
}

static void ScanImports(FindingsCtx* ctx)
{
    PeFile* pe = ctx->pe;
    char buf[192];
    static const char* inj[] = {
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtMapViewOfSection", "NtUnmapViewOfSection", "QueueUserAPC",
        "SetWindowsHookExA", "SetWindowsHookExW", "RtlCreateUserThread"
    };
    JoinFns(buf, (int)sizeof(buf), inj, (int)(sizeof(inj) / sizeof(inj[0])), pe);
    if (buf[0])
    {
        int ev = AddEvidence(ctx, EvImport, "imports", buf, nullptr, 0, 0, nullptr);
        AddFinding(ctx, "pe.import.injection", "finding.import.inject.title", "finding.import.inject.explain",
            "finding.import.inject.matter", "finding.import.inject.next", "finding.import.inject.tech",
            FindSevHigh, FindConfHigh, FindCatInjection, buf, 0, ev);
    }
    static const char* net[] = {
        "URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenUrlA",
        "InternetOpenUrlW", "InternetConnectA", "InternetConnectW",
        "WinHttpOpen", "HttpSendRequestA", "HttpSendRequestW",
        "connect", "send", "recv"
    };
    JoinFns(buf, (int)sizeof(buf), net, (int)(sizeof(net) / sizeof(net[0])), pe);
    if (buf[0])
    {
        int ev = AddEvidence(ctx, EvImport, "imports", buf, nullptr, 0, 0, nullptr);
        AddFinding(ctx, "pe.import.network", "finding.import.network.title", "finding.import.network.explain",
            "finding.import.network.matter", "finding.import.network.next", "finding.import.network.tech",
            FindSevMedium, FindConfHigh, FindCatNetwork, buf, 0, ev);
    }
    static const char* run[] = {
        "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW",
        "WinExec", "CreateProcessA", "CreateProcessW"
    };
    JoinFns(buf, (int)sizeof(buf), run, (int)(sizeof(run) / sizeof(run[0])), pe);
    if (buf[0])
    {
        int ev = AddEvidence(ctx, EvImport, "imports", buf, nullptr, 0, 0, nullptr);
        AddFinding(ctx, "pe.import.spawn", "finding.import.spawn.title", "finding.import.spawn.explain",
            "finding.import.spawn.matter", "finding.import.spawn.next", "finding.import.spawn.tech",
            FindSevMedium, FindConfHigh, FindCatExecution, buf, 0, ev);
    }
    static const char* cry[] = {
        "CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "BCryptDecrypt",
        "CryptImportKey", "CryptAcquireContextA"
    };
    JoinFns(buf, (int)sizeof(buf), cry, (int)(sizeof(cry) / sizeof(cry[0])), pe);
    if (buf[0])
    {
        int ev = AddEvidence(ctx, EvImport, "imports", buf, nullptr, 0, 0, nullptr);
        AddFinding(ctx, "pe.import.crypto", "finding.import.crypto.title", "finding.import.crypto.explain",
            "finding.import.crypto.matter", "finding.import.crypto.next", "finding.import.crypto.tech",
            FindSevLow, FindConfHigh, FindCatCrypto, buf, 0, ev);
    }
    static const char* dbg[] = {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"
    };
    JoinFns(buf, (int)sizeof(buf), dbg, (int)(sizeof(dbg) / sizeof(dbg[0])), pe);
    if (buf[0])
    {
        int ev = AddEvidence(ctx, EvImport, "imports", buf, nullptr, 0, 0, nullptr);
        AddFinding(ctx, "pe.import.antidebug", "finding.import.antidebug.title", "finding.import.antidebug.explain",
            "finding.import.antidebug.matter", "finding.import.antidebug.next", "finding.import.antidebug.tech",
            FindSevMedium, FindConfHigh, FindCatExecution, buf, 0, ev);
    }
    static const char* mtx[] = {
        "CreateMutexA", "CreateMutexW", "OpenMutexA", "OpenMutexW"
    };
    JoinFns(buf, (int)sizeof(buf), mtx, (int)(sizeof(mtx) / sizeof(mtx[0])), pe);
    if (buf[0])
    {
        int ev = AddEvidence(ctx, EvImport, "imports", buf, nullptr, 0, 0, nullptr);
        AddFinding(ctx, "pe.import.mutex", "finding.import.mutex.title", "finding.import.mutex.explain",
            "finding.import.mutex.matter", "finding.import.mutex.next", "finding.import.mutex.tech",
            FindSevLow, FindConfHigh, FindCatPersistence, buf, 0, ev);
    }
    static const char* reg[] = {
        "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW"
    };
    JoinFns(buf, (int)sizeof(buf), reg, (int)(sizeof(reg) / sizeof(reg[0])), pe);
    if (buf[0])
    {
        int ev = AddEvidence(ctx, EvImport, "imports", buf, nullptr, 0, 0, nullptr);
        AddFinding(ctx, "pe.import.regwrite", "finding.import.regwrite.title", "finding.import.regwrite.explain",
            "finding.import.regwrite.matter", "finding.import.regwrite.next", "finding.import.regwrite.tech",
            FindSevMedium, FindConfHigh, FindCatPersistence, buf, 0, ev);
    }
}

static void ScanStructure(FindingsCtx* ctx)
{
    PeFile* pe = ctx->pe;
    if (pe->packer_detected && _stricmp(pe->packer, "none") != 0)
    {
        int ev = AddEvidence(ctx, EvDetection, "detection", pe->packer, nullptr, 0, 0, pe->packer);
        AddFinding(ctx, "pe.detect.packer", "finding.detect.packer.title", "finding.detect.packer.explain",
            "finding.detect.packer.matter", "finding.detect.packer.next", "finding.detect.packer.tech",
            FindSevMedium, FindConfHigh, FindCatIdentity, pe->packer, 0, ev);
    }
    else if (pe->compiler_detected && _stricmp(pe->compiler, "unknown") != 0 &&
        _stricmp(pe->compiler, "MSVC") != 0)
    {
        int ev = AddEvidence(ctx, EvDetection, "detection", pe->compiler, nullptr, 0, 0, pe->compiler);
        AddFinding(ctx, "pe.detect.compiler", "finding.detect.compiler.title", "finding.detect.compiler.explain",
            "finding.detect.compiler.matter", "finding.detect.compiler.next", "finding.detect.compiler.tech",
            FindSevLow, FindConfHigh, FindCatIdentity, pe->compiler, 0, ev);
    }
    if (pe->protector_detected && _stricmp(pe->protector, "none") != 0)
    {
        int ev = AddEvidence(ctx, EvDetection, "detection", pe->protector, nullptr, 0, 0, pe->protector);
        char id[64];
        snprintf(id, sizeof(id), "pe.detect.protector");
        AddFinding(ctx, id, "finding.detect.protector.title", "finding.detect.protector.explain",
            "finding.detect.protector.matter", "finding.detect.protector.next", "finding.detect.protector.tech",
            FindSevMedium, FindConfHigh, FindCatPacking, pe->protector, 0, ev);
    }
    if (pe->e_lfanew > kUnusualDosStub)
        AddFinding(ctx, "pe.header.dos_stub", "finding.header.dos.title", "finding.header.dos.explain",
            "finding.header.dos.matter", "finding.header.dos.next", "finding.header.dos.tech",
            FindSevMedium, FindConfHigh, FindCatStructure, nullptr, 0, -1);
    if (pe->section_n == 0)
        AddFinding(ctx, "pe.header.no_sections", "finding.header.nosec.title", "finding.header.nosec.explain",
            "finding.header.nosec.matter", "finding.header.nosec.next", "finding.header.nosec.tech",
            FindSevCritical, FindConfExact, FindCatStructure, nullptr, 0, -1);
    if (pe->timestamp == 0 || pe->timestamp == 0xFFFFFFFFu)
        AddFinding(ctx, "pe.header.timestamp", "finding.header.ts.title", "finding.header.ts.explain",
            "finding.header.ts.matter", "finding.header.ts.next", "finding.header.ts.tech",
            FindSevLow, FindConfHigh, FindCatMetadata, nullptr, 0, -1);
    if ((pe->dllchars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) == 0)
        AddFinding(ctx, "pe.hardening.nx", "finding.hardening.nx.title", "finding.hardening.nx.explain",
            "finding.hardening.nx.matter", "finding.hardening.nx.next", "finding.hardening.nx.tech",
            FindSevLow, FindConfExact, FindCatIntegrity, nullptr, 0, -1);
    if ((pe->dllchars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) == 0)
        AddFinding(ctx, "pe.hardening.aslr", "finding.hardening.aslr.title", "finding.hardening.aslr.explain",
            "finding.hardening.aslr.matter", "finding.hardening.aslr.next", "finding.hardening.aslr.tech",
            FindSevLow, FindConfExact, FindCatIntegrity, nullptr, 0, -1);
    if (pe->checksum != 0 && !pe->checksum_ok)
        AddFinding(ctx, "pe.integrity.checksum", "finding.integrity.cksum.title", "finding.integrity.cksum.explain",
            "finding.integrity.cksum.matter", "finding.integrity.cksum.next", "finding.integrity.cksum.tech",
            FindSevMedium, FindConfExact, FindCatIntegrity, nullptr, 0, -1);

    for (int i = 0; i < pe->section_n; i++)
    {
        const PeSection& s = pe->sections[i];
        if ((s.chars & IMAGE_SCN_MEM_EXECUTE) && (s.chars & IMAGE_SCN_MEM_WRITE))
        {
            char id[64];
            snprintf(id, sizeof(id), "pe.section.rwx.%d", i);
            char tech[128];
            snprintf(tech, sizeof(tech), "Section: %s", s.name);
            int ev = AddEvidence(ctx, EvSection, "sections", tech, nullptr, s.rawptr, s.vaddr, s.name);
            AddFinding(ctx, id, "finding.section.rwx.title", "finding.section.rwx.explain",
                "finding.section.rwx.matter", "finding.section.rwx.next", "finding.section.rwx.tech",
                FindSevHigh, FindConfExact, FindCatMemory, s.name, s.rawptr, ev);
        }
        uint64_t vend = (uint64_t)s.vaddr + (s.vsize ? s.vsize : s.rawsize);
        if (pe->size_of_image && vend > pe->size_of_image)
        {
            char id[64];
            snprintf(id, sizeof(id), "pe.section.vsize.%d", i);
            int ev = AddEvidence(ctx, EvSection, "sections", s.name, nullptr, s.rawptr, s.vaddr, s.name);
            AddFinding(ctx, id, "finding.section.vsize.title", "finding.section.vsize.explain",
                "finding.section.vsize.matter", "finding.section.vsize.next", "finding.section.vsize.tech",
                FindSevHigh, FindConfExact, FindCatStructure, s.name, s.rawptr, ev);
        }
    }
    if (pe->overlay_size)
    {
        char evs[32];
        snprintf(evs, sizeof(evs), "%u", (unsigned)pe->overlay_size);
        int ev = AddEvidence(ctx, EvOverlay, "overlay", evs, nullptr, pe->overlay_off, 0, nullptr);
        AddFinding(ctx, "pe.overlay.present", "finding.overlay.title", "finding.overlay.explain",
            "finding.overlay.matter", "finding.overlay.next", "finding.overlay.tech",
            FindSevMedium, FindConfExact, FindCatEmbedded, evs, pe->overlay_off, ev);
    }
    PeAddr ep;
    PeAddrFromRva(pe, pe->entry_rva, &ep);
    if (pe->entry_rva && ep.section_index < 0)
        AddFinding(ctx, "pe.entry.outside", "finding.entry.out.title", "finding.entry.out.explain",
            "finding.entry.out.matter", "finding.entry.out.next", "finding.entry.out.tech",
            FindSevHigh, FindConfExact, FindCatStructure, nullptr, 0, -1);
    else if (ep.section_index >= 0)
    {
        int ev = AddEvidence(ctx, EvEntry, "entry", ep.section_name, nullptr, (uint32_t)ep.file_off, ep.rva, ep.section_name);
        AddFinding(ctx, "pe.entry.section", "finding.entry.sec.title", "finding.entry.sec.explain",
            "finding.entry.sec.matter", "finding.entry.sec.next", "finding.entry.sec.tech",
            FindSevMedium, FindConfHigh, FindCatExecution, ep.section_name, (uint32_t)ep.file_off, ev);
    }
    if (pe->imports.empty() && (pe->chars & IMAGE_FILE_DLL) == 0)
        AddFinding(ctx, "pe.import.none", "finding.import.none.title", "finding.import.none.explain",
            "finding.import.none.matter", "finding.import.none.next", "finding.import.none.tech",
            FindSevMedium, FindConfHigh, FindCatImports, nullptr, 0, -1);
    if (pe->tls.present && !pe->tls.callback_rvas.empty())
        AddFinding(ctx, "pe.tls.callbacks", "finding.tls.title", "finding.tls.explain",
            "finding.tls.matter", "finding.tls.next", "finding.tls.tech",
            FindSevMedium, FindConfExact, FindCatExecution, nullptr, 0, -1);
    if (pe->pdb_path[0])
    {
        int ev = AddEvidence(ctx, EvGeneric, "debug", pe->pdb_path, nullptr, 0, 0, pe->pdb_path);
        AddFinding(ctx, "pe.debug.pdb", "finding.pdb.title", "finding.pdb.explain",
            "finding.pdb.matter", "finding.pdb.next", "finding.pdb.tech",
            FindSevLow, FindConfExact, FindCatMetadata, pe->pdb_path, 0, ev);
    }
    for (const PeEntropyRange& r : pe->entropy)
    {
        if (r.size >= 256 && r.entropy >= kHighEntropy)
        {
            char id[80];
            snprintf(id, sizeof(id), "pe.entropy.%u", (unsigned)r.offset);
            char tech[96];
            snprintf(tech, sizeof(tech), "%.2f / 8.00", r.entropy);
            int ev = AddEvidence(ctx, EvEntropy, "entropy", r.label, tech, (uint32_t)r.offset, 0, r.label);
            AddFinding(ctx, id, "finding.entropy.title", "finding.entropy.explain",
                "finding.entropy.matter", "finding.entropy.next", "finding.entropy.tech",
                FindSevMedium, FindConfHigh, FindCatPacking, r.label, (uint32_t)r.offset, ev);
        }
    }
    if (pe->section_align == 0 || pe->file_align == 0)
        AddFinding(ctx, "pe.header.align", "finding.header.align.title", "finding.header.align.explain",
            "finding.header.align.matter", "finding.header.align.next", "finding.header.align.tech",
            FindSevHigh, FindConfExact, FindCatStructure, nullptr, 0, -1);
}

static void ScanArtifacts(FindingsCtx* ctx)
{
    PeFile* pe = ctx->pe;
    if (pe->analysis.empty())
        return;
    int ev = AddEvidence(ctx, EvArtifact, "analyze", "embedded content", nullptr, 0, 0, nullptr);
    char detail[32];
    snprintf(detail, sizeof(detail), "%zu", pe->analysis.size());
    AddFinding(ctx, "pe.embedded.content", "finding.embedded.title", "finding.embedded.explain",
        "finding.embedded.matter", "finding.embedded.next", "finding.embedded.tech",
        FindSevMedium, FindConfHigh, FindCatEmbedded, detail, 0, ev);
}

static int FindIdxById(const AnalysisReport* rep, const char* prefix)
{
    if (!rep || !prefix)
        return -1;
    for (int i = 0; i < (int)rep->findings.size(); i++)
    {
        if (strncmp(rep->findings[(size_t)i].id, prefix, strlen(prefix)) == 0)
            return i;
    }
    return -1;
}

static bool HasIdPrefix(const AnalysisReport* rep, const char* prefix)
{
    return FindIdxById(rep, prefix) >= 0;
}

static void Correlate(FindingsCtx* ctx)
{
    if (!ctx->prof->caps.correlation || !ctx->prof->stage_enabled[StageCorrelation])
        return;
    bool high_entropy = HasIdPrefix(ctx->rep, "pe.entropy.");
    bool few_imports = HasIdPrefix(ctx->rep, "pe.import.none");
    bool rwx = HasIdPrefix(ctx->rep, "pe.section.rwx.");
    bool named_packer = HasIdPrefix(ctx->rep, "pe.detect.packer");
    bool protector = HasIdPrefix(ctx->rep, "pe.detect.protector");
    if ((high_entropy && few_imports) || (high_entropy && rwx) || named_packer || protector)
    {
        if (!HasFindingId(ctx, "corr.likely_packed"))
        {
            AddFinding(ctx, "corr.likely_packed", "finding.corr.packed.title", "finding.corr.packed.explain",
                "finding.corr.packed.matter", "finding.corr.packed.next", "finding.corr.packed.tech",
                FindSevMedium, FindConfMedium, FindCatPacking, nullptr, 0, -1);
            if (!ctx->rep->findings.empty())
                ctx->rep->findings.back().derived = true;
        }
    }
    LogFor(LogBuiltinPeAnalyzer).Module("Analyze Engine").Info("Correlation pass complete");
}

static void BuildSummary(FindingsCtx* ctx)
{
    AnalysisSummary* s = &ctx->rep->summary;
    PeFile* pe = ctx->pe;
    s->finding_count = (int)ctx->rep->findings.size();
    s->detection_count = (int)pe->detections.size();
    s->artifact_count = (int)pe->analysis.size();
    s->complete = true;
    s->start_here_n = 0;

    std::vector<int> order;
    for (int i = 0; i < (int)ctx->rep->findings.size(); i++)
        order.push_back(i);
    std::sort(order.begin(), order.end(), [&](int a, int b) {
        return ctx->rep->findings[(size_t)a].priority > ctx->rep->findings[(size_t)b].priority;
    });

    for (int i = 0; i < (int)order.size() && s->start_here_n < SummaryStartHereMax; i++)
    {
        const FindingItem& f = ctx->rep->findings[(size_t)order[i]];
        if (f.severity >= FindSevMedium)
            s->start_here[s->start_here_n++] = order[i];
    }

    if (pe->packer_detected || pe->protector_detected)
        snprintf(s->headline_key, sizeof(s->headline_key), "finding.summary.packed");
    else if (!ctx->rep->findings.empty())
        snprintf(s->headline_key, sizeof(s->headline_key), "finding.summary.indicators");
    else
        snprintf(s->headline_key, sizeof(s->headline_key), "finding.summary.none");
    snprintf(s->headline, sizeof(s->headline), "%s", s->headline_key);
}

void FindingsEngineRun(PeFile* pe)
{
    if (!pe)
        return;
    const AnalysisProfile* prof = AnalyzeProfileActive();
    if (!prof)
        return;
    pe->report = AnalysisReport{};
    pe->findings.clear();
    FindingsCtx ctx{ pe, &pe->report, prof, 0 };
    auto log = LogFor(LogBuiltinPeAnalyzer).Module("Analyze Engine");

    if (prof->caps.structural_heuristics)
        ScanStructure(&ctx);
    if (prof->caps.import_behavior)
        ScanImports(&ctx);
    if (prof->caps.string_indicators)
        ScanStrings(&ctx);
    if (prof->caps.embedded_payload_analysis)
        ScanArtifacts(&ctx);

    log.Info("Generated %d atomic findings", (int)pe->report.findings.size());
    Correlate(&ctx);
    if (prof->stage_enabled[StageSummary])
        BuildSummary(&ctx);

    std::sort(pe->report.findings.begin(), pe->report.findings.end(),
        [](const FindingItem& a, const FindingItem& b) {
            if (a.priority != b.priority)
                return a.priority > b.priority;
            return a.severity > b.severity;
        });
    std::sort(pe->findings.begin(), pe->findings.end(), [](const PeFinding& a, const PeFinding& b) {
        if (a.sev != b.sev)
            return a.sev > b.sev;
        return (int)a.kind < (int)b.kind;
    });
}
