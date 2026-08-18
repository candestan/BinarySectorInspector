#include "detect/detect.h"
#include "detect/detect_p.h"
#include "detect/kuara_adapter.h"
#include "pe/pe.h"
#include "log/log.h"
#include "persist/paths.h"
#include "persist/settings.h"
#include "app/version.h"
#include "kuara/kuara.h"

#include <windows.h>
#include <shellapi.h>

#include <mutex>
#include <vector>
#include <string>
#include <unordered_map>
#include <algorithm>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

static std::mutex g_mu;
static std::vector<CompiledSig> g_sigs;
static std::vector<std::string> g_sig_files;
static std::vector<std::string> g_extra_packs;
static DetectLoadStats g_stats;
static char g_builtin_dir[MAX_PATH];
static char g_user_dir[MAX_PATH];
static char g_packs_dir[MAX_PATH];
static LogScope g_log_sig;
static LogScope g_log_pe;
static bool g_log_ready;
static char g_applied_path[MAX_PATH];
static int  g_applied_key = -1;

static void DetectClearApplied()
{
    g_applied_path[0] = 0;
    g_applied_key = -1;
}

static LogScope& SigLog()
{
    if (!g_log_ready)
    {
        g_log_sig = LogFor(LogBuiltinAnalyzer).Module("Signature Engine");
        g_log_pe = LogFor(LogBuiltinPeAnalyzer).Module("Detection");
        g_log_ready = true;
    }
    return g_log_sig;
}

void DetectLogSig(int sev, const char* fmt, ...)
{
    SigLog();
    char msg[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    LogOrigin o{};
    o.source_id = g_log_sig.source_id;
    o.module_id = g_log_sig.module_id;
    LogWrite((LogSeverity)sev, o, "%s", msg);
}

void DetectLogPe(int sev, const char* fmt, ...)
{
    SigLog();
    char msg[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    LogOrigin o{};
    o.source_id = g_log_pe.source_id;
    o.module_id = g_log_pe.module_id;
    LogWrite((LogSeverity)sev, o, "%s", msg);
}

static void MakeDir(const char* path)
{
    if (path && path[0])
        CreateDirectoryA(path, nullptr);
}

static void InitDirs()
{
    PathsBesideExe(g_builtin_dir, MAX_PATH, "signatures\\builtin\\");
    PathsBesideExe(g_user_dir, MAX_PATH, "signatures\\user\\");
    PathsBesideExe(g_packs_dir, MAX_PATH, "signatures\\packs\\");
}

static bool ReadFileCapped(const char* path, std::string* out, std::string* err)
{
    out->clear();
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        *err = "cannot open file";
        return false;
    }
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart < 2 || sz.QuadPart > 256 * 1024)
    {
        CloseHandle(h);
        *err = "signature file empty or larger than 256 KiB";
        return false;
    }
    DWORD n = (DWORD)sz.QuadPart;
    out->resize(n);
    DWORD got = 0;
    BOOL ok = ReadFile(h, out->empty() ? nullptr : &(*out)[0], n, &got, nullptr);
    CloseHandle(h);
    if (!ok || got != n)
    {
        out->clear();
        *err = "short read";
        return false;
    }
    return true;
}

static bool IdTaken(const std::vector<CompiledSig>& list, const std::string& id)
{
    for (const CompiledSig& s : list)
    {
        if (s.id == id)
            return true;
    }
    return false;
}

static void LoadFile(const char* path, DetectSource src, std::vector<CompiledSig>* list, DetectLoadStats* st,
    std::vector<std::string>* files)
{
    std::string body, err;
    if (!ReadFileCapped(path, &body, &err))
    {
        st->invalid++;
        DetectLogSig(LogSevWarning, "Invalid signature ignored: %s (%s)", path, err.c_str());
        return;
    }
    CompiledSig sig;
    if (!DetectParseSignatureJson(body.c_str(), path, src, &sig, &err))
    {
        st->invalid++;
        DetectLogSig(LogSevWarning, "Invalid signature ignored: %s (%s)", path, err.c_str());
        return;
    }
    if (IdTaken(*list, sig.id))
    {
        st->collisions++;
        DetectLogSig(LogSevWarning, "Duplicate signature id '%s' in %s — keeping the first load", sig.id.c_str(), path);
        return;
    }
    if ((int)list->size() >= 10000)
    {
        st->invalid++;
        DetectLogSig(LogSevError, "Signature cap (10000) reached, ignoring %s", path);
        return;
    }
    list->push_back(std::move(sig));
    if (files)
        files->push_back(path);
    if (src == DetectSrcBuiltin)
        st->builtin++;
    else if (src == DetectSrcPack)
        st->pack++;
    else
        st->user++;
}

static void WalkDir(const char* dir, DetectSource src, std::vector<CompiledSig>* list, DetectLoadStats* st, int depth,
    std::vector<std::string>* files)
{
    if (!dir || !dir[0] || depth > 6)
        return;
    char spec[MAX_PATH];
    snprintf(spec, MAX_PATH, "%s*", dir);
    WIN32_FIND_DATAA fd{};
    HANDLE h = FindFirstFileA(spec, &fd);
    if (h == INVALID_HANDLE_VALUE)
        return;
    do
    {
        if (fd.cFileName[0] == '.' && (fd.cFileName[1] == 0 || (fd.cFileName[1] == '.' && fd.cFileName[2] == 0)))
            continue;
        char path[MAX_PATH];
        snprintf(path, MAX_PATH, "%s%s", dir, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            char sub[MAX_PATH];
            snprintf(sub, MAX_PATH, "%s\\", path);
            WalkDir(sub, src, list, st, depth + 1, files);
            continue;
        }
        const char* ext = strrchr(fd.cFileName, '.');
        if (!ext || _stricmp(ext, ".json") != 0)
            continue;
        if (_stricmp(fd.cFileName, "pack.json") == 0)
            continue;
        LoadFile(path, src, list, st, files);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

static void LoadAllUnlocked(std::vector<CompiledSig>* list, DetectLoadStats* st, std::vector<std::string>* files)
{
    *list = {};
    *st = {};
    if (files)
        files->clear();
    InitDirs();
    MakeDir(g_user_dir);
    MakeDir(g_packs_dir);
    WalkDir(g_builtin_dir, DetectSrcBuiltin, list, st, 0, files);
    WalkDir(g_packs_dir, DetectSrcPack, list, st, 0, files);
    for (const std::string& extra : g_extra_packs)
    {
        char dir[MAX_PATH];
        snprintf(dir, MAX_PATH, "%s", extra.c_str());
        size_t n = strlen(dir);
        if (n && dir[n - 1] != '\\')
            snprintf(dir, MAX_PATH, "%s\\", extra.c_str());
        WalkDir(dir, DetectSrcPack, list, st, 0, files);
    }
    if (SettingsGetBool("detect.user_signatures", true))
        WalkDir(g_user_dir, DetectSrcUser, list, st, 0, files);
    st->total = (int)list->size();
}

static DetectEngineKind ParseEngineKind(const char* s)
{
    if (s && _stricmp(s, "internal") == 0)
        return DetectEngineInternal;
    return DetectEngineKuara;
}

DetectEngineKind DetectEngineActive()
{
    char mode[32];
    SettingsGetString("detect.engine", mode, (int)sizeof(mode), "kuara");
    return ParseEngineKind(mode);
}

void DetectSetEngine(DetectEngineKind kind)
{
    SettingsSetString("detect.engine", kind == DetectEngineInternal ? "internal" : "kuara");
    SettingsSave();
}

void DetectEngineFillInfo(DetectEngineKind kind, DetectEngineInfo* out)
{
    if (!out)
        return;
    *out = {};
    out->kind = kind;
    if (kind == DetectEngineInternal)
    {
        out->id = "com.candestan.bsi.internal";
        out->name_key = "settings.detection.engine.internal";
        out->desc_key = "settings.detection.engine.desc.internal";
        out->author = "candestan";
        out->version = VersionString();
        out->brand_url = "";
        out->ready = true;
        return;
    }
    out->id = kuara::EngineId();
    out->name_key = "settings.detection.engine.kuara";
    out->desc_key = "settings.detection.engine.desc.kuara";
    out->author = kuara::EngineAuthor();
    out->version = kuara::EngineVersion();
    out->brand_url = kuara::BrandImageUrl();
    out->ready = KuaraIsReady();
}

void DetectInit()
{
    InitDirs();
    MakeDir(g_user_dir);
    MakeDir(g_packs_dir);
    std::vector<CompiledSig> list;
    std::vector<std::string> files;
    DetectLoadStats st;
    LoadAllUnlocked(&list, &st, &files);
    {
        std::lock_guard<std::mutex> lock(g_mu);
        g_sigs.swap(list);
        g_sig_files.swap(files);
        g_stats = st;
    }
    SigLog();
    DetectLogSig(LogSevInfo, "Loaded %d signatures (%d built-in, %d pack, %d user, %d invalid, %d collisions)",
        st.total, st.builtin, st.pack, st.user, st.invalid, st.collisions);
    std::string kuara_err;
    if (KuaraReloadRules(g_sig_files, &kuara_err))
        DetectLogSig(LogSevInfo, "KUARA rules compiled from %d signature files", (int)g_sig_files.size());
    else if (DetectEngineActive() == DetectEngineKuara)
        DetectLogSig(LogSevWarning, "KUARA compile failed, falling back to legacy matcher (%s)", kuara_err.c_str());
}

void DetectShutdown()
{
    std::lock_guard<std::mutex> lock(g_mu);
    g_sigs.clear();
    g_sig_files.clear();
    g_extra_packs.clear();
    g_stats = {};
}

bool DetectReload()
{
    std::vector<CompiledSig> list;
    std::vector<std::string> files;
    DetectLoadStats st;
    LoadAllUnlocked(&list, &st, &files);
    {
        std::lock_guard<std::mutex> lock(g_mu);
        g_sigs.swap(list);
        g_sig_files.swap(files);
        g_stats = st;
    }
    DetectLogSig(LogSevInfo, "Reloaded %d signatures (%d built-in, %d pack, %d user, %d invalid, %d collisions)",
        st.total, st.builtin, st.pack, st.user, st.invalid, st.collisions);
    std::string kuara_err;
    if (KuaraReloadRules(g_sig_files, &kuara_err))
        DetectLogSig(LogSevInfo, "KUARA rules recompiled from %d signature files", (int)g_sig_files.size());
    else if (DetectEngineActive() == DetectEngineKuara)
        DetectLogSig(LogSevWarning, "KUARA recompile failed, falling back to legacy matcher (%s)", kuara_err.c_str());
    DetectClearApplied();
    return true;
}

void DetectAddPackDirectory(const char* path)
{
    if (!path || !path[0])
        return;
    std::lock_guard<std::mutex> lock(g_mu);
    for (const std::string& s : g_extra_packs)
    {
        if (_stricmp(s.c_str(), path) == 0)
            return;
    }
    g_extra_packs.push_back(path);
}

DetectLoadStats DetectStats()
{
    std::lock_guard<std::mutex> lock(g_mu);
    return g_stats;
}

const char* DetectBuiltinDir()
{
    InitDirs();
    return g_builtin_dir;
}

const char* DetectUserDir()
{
    InitDirs();
    return g_user_dir;
}

const char* DetectPacksDir()
{
    InitDirs();
    return g_packs_dir;
}

void DetectEnsureUserDir()
{
    InitDirs();
    MakeDir(g_user_dir);
}

bool DetectOpenUserDir()
{
    DetectEnsureUserDir();
    HINSTANCE h = ShellExecuteA(nullptr, "open", g_user_dir, nullptr, nullptr, SW_SHOWNORMAL);
    return (INT_PTR)h > 32;
}

static bool CatEnabled(DetectCategory cat)
{
    if (cat == DetectCatPacker || cat == DetectCatProtector)
        return SettingsGetBool("detect.packers", true);
    if (cat == DetectCatCompiler || cat == DetectCatToolchain)
        return SettingsGetBool("detect.compilers", true);
    if (cat == DetectCatDotNetObfuscator)
        return SettingsGetBool("detect.dotnet", true);
    return true;
}

static DetectSource WorseSource(DetectSource a, DetectSource b)
{
    return a > b ? a : b;
}

void DetectRun(const DetectFacts& facts, std::vector<DetectionResult>* out)
{
    if (out)
        out->clear();
    if (!out || !facts.is_pe)
        return;
    if (DetectEngineActive() == DetectEngineKuara && KuaraRunDetect(facts, out))
    {
        out->erase(std::remove_if(out->begin(), out->end(), [](const DetectionResult& r) {
            return !CatEnabled(r.category);
        }), out->end());
        for (const DetectionResult& r : *out)
        {
            DetectLogPe(LogSevInfo, "Detected %s (%s) with %s confidence",
                r.product.c_str(), DetectCategoryId(r.category), DetectConfidenceId(r.confidence));
        }
        return;
    }

    std::vector<CompiledSig> snap;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        snap = g_sigs;
    }

    int applicable[DetectCatCount]{};
    struct Hit
    {
        const CompiledSig* sig;
        int score;
        DetectConfidence conf;
        std::vector<DetectEvidence> ev;
    };
    std::vector<Hit> hits;

    for (const CompiledSig& sig : snap)
    {
        if (!CatEnabled(sig.category))
            continue;
        if (!DetectSigApplies(facts, sig))
            continue;
        applicable[sig.category]++;
        std::vector<DetectEvidence> ev;
        if (!DetectEvalCond(facts, sig.root, &ev))
            continue;
        int score = 0;
        for (const DetectEvidence& e : ev)
            score += e.weight;
        if (score > 100)
            score = 100;
        DetectConfidence conf = DetectScoreToConfidence(score, sig.cap);
        Hit h;
        h.sig = &sig;
        h.score = score;
        h.conf = conf;
        h.ev = std::move(ev);
        hits.push_back(std::move(h));
    }

    DetectLogPe(LogSevDebug, "Running %d applicable packer rules, %d protector, %d compiler, %d toolchain, %d .NET obfuscator",
        applicable[DetectCatPacker], applicable[DetectCatProtector], applicable[DetectCatCompiler],
        applicable[DetectCatToolchain], applicable[DetectCatDotNetObfuscator]);

    std::unordered_map<std::string, DetectionResult> grouped;
    std::vector<std::string> order;
    for (Hit& h : hits)
    {
        const CompiledSig& sig = *h.sig;
        auto it = grouped.find(sig.product_key);
        if (it == grouped.end())
        {
            DetectionResult r;
            r.category = sig.category;
            r.confidence = h.conf;
            r.score = h.score;
            r.heuristic = sig.heuristic;
            r.source = sig.source;
            r.product_key = sig.product_key;
            r.product = sig.name;
            r.vendor = sig.vendor;
            r.version = sig.version;
            r.description = sig.description;
            r.reference = sig.reference;
            r.evidence = h.ev;
            DetectMatch m;
            m.signature_id = sig.id;
            m.source = sig.source;
            m.evidence = h.ev;
            r.signatures.push_back(std::move(m));
            order.push_back(sig.product_key);
            grouped.emplace(sig.product_key, std::move(r));
        }
        else
        {
            DetectionResult& r = it->second;
            if (h.score > r.score)
            {
                r.score = h.score;
                r.confidence = h.conf;
                if (!sig.heuristic)
                    r.heuristic = false;
                if (!sig.name.empty())
                    r.product = sig.name;
                if (!sig.vendor.empty())
                    r.vendor = sig.vendor;
                if (!sig.version.empty())
                    r.version = sig.version;
                if (!sig.description.empty())
                    r.description = sig.description;
                if (!sig.reference.empty())
                    r.reference = sig.reference;
            }
            r.source = WorseSource(r.source, sig.source);
            DetectMatch m;
            m.signature_id = sig.id;
            m.source = sig.source;
            m.evidence = h.ev;
            r.signatures.push_back(std::move(m));
            for (const DetectEvidence& e : h.ev)
            {
                bool dup = false;
                for (const DetectEvidence& have : r.evidence)
                {
                    if (have.condition == e.condition && have.detail == e.detail)
                    {
                        dup = true;
                        break;
                    }
                }
                if (!dup)
                    r.evidence.push_back(e);
            }
        }
    }

    for (const std::string& key : order)
    {
        DetectionResult& r = grouped[key];
        out->push_back(std::move(r));
    }

    std::sort(out->begin(), out->end(), [](const DetectionResult& a, const DetectionResult& b) {
        if (a.category != b.category)
            return a.category < b.category;
        if (a.heuristic != b.heuristic)
            return !a.heuristic && b.heuristic;
        if (a.confidence != b.confidence)
            return a.confidence > b.confidence;
        return a.product < b.product;
    });

    for (const DetectionResult& r : *out)
    {
        DetectLogPe(LogSevInfo, "Detected %s (%s) with %s confidence",
            r.product.c_str(), DetectCategoryId(r.category), DetectConfidenceId(r.confidence));
    }
}

static bool BetterHit(const DetectionResult* cur, const DetectionResult& cand)
{
    if (!cur)
        return true;
    if (cur->heuristic != cand.heuristic)
        return cur->heuristic && !cand.heuristic;
    if (cand.confidence != cur->confidence)
        return cand.confidence > cur->confidence;
    if (cand.score != cur->score)
        return cand.score > cur->score;
    return cand.category < cur->category;
}

static bool InCats(DetectCategory cat, const DetectCategory* cats, int n)
{
    for (int i = 0; i < n; i++)
    {
        if (cats[i] == cat)
            return true;
    }
    return false;
}

static void FillSummary(char* dst, int cap, bool* detected, DetectConfidence* conf,
    const std::vector<DetectionResult>& hits, const DetectCategory* cats, int ncat, const char* none)
{
    dst[0] = 0;
    if (detected)
        *detected = false;
    if (conf)
        *conf = DetectConfLow;

    const DetectionResult* best = nullptr;
    for (const DetectionResult& r : hits)
    {
        if (!InCats(r.category, cats, ncat) || r.heuristic)
            continue;
        if (BetterHit(best, r))
            best = &r;
    }
    if (!best)
    {
        for (const DetectionResult& r : hits)
        {
            if (!InCats(r.category, cats, ncat))
                continue;
            if (BetterHit(best, r))
                best = &r;
        }
    }
    if (!best)
    {
        snprintf(dst, cap, "%s", none);
        return;
    }
    if (detected)
        *detected = true;
    if (conf)
        *conf = best->confidence;
    if (best->version.empty())
        snprintf(dst, cap, "%s", best->product.c_str());
    else
        snprintf(dst, cap, "%s %s", best->product.c_str(), best->version.c_str());
}

static int DetectSettingsFingerprint()
{
    int key = (int)DetectEngineActive();
    if (DetectSettingPackers())
        key |= 1 << 4;
    if (DetectSettingCompilers())
        key |= 1 << 5;
    if (DetectSettingDotNet())
        key |= 1 << 6;
    if (DetectSettingUserSigs())
        key |= 1 << 7;
    key |= (DetectStats().total & 0xFFFF) << 8;
    return key;
}

void DetectApplyToPe(PeFile* pe, const uint8_t* bytes, size_t n)
{
    if (!pe)
        return;
    int key = DetectSettingsFingerprint();
    if (pe->path[0] && g_applied_key == key && strcmp(g_applied_path, pe->path) == 0)
        return;
    pe->detections.clear();
    pe->compiler_detected = false;
    pe->packer_detected = false;
    pe->protector_detected = false;
    pe->obfuscator_detected = false;
    DetectFacts facts;
    DetectFillFacts(pe, bytes, n, &facts);
    DetectRun(facts, &pe->detections);
    const DetectCategory built[] = { DetectCatCompiler, DetectCatToolchain };
    const DetectCategory pack[] = { DetectCatPacker };
    const DetectCategory prot[] = { DetectCatProtector };
    const DetectCategory net[] = { DetectCatDotNetObfuscator };
    FillSummary(pe->compiler, (int)sizeof(pe->compiler), &pe->compiler_detected, &pe->compiler_conf,
        pe->detections, built, 2, "unknown");
    FillSummary(pe->packer, (int)sizeof(pe->packer), &pe->packer_detected, &pe->packer_conf,
        pe->detections, pack, 1, "none");
    FillSummary(pe->protector, (int)sizeof(pe->protector), &pe->protector_detected, &pe->protector_conf,
        pe->detections, prot, 1, "none");
    FillSummary(pe->obfuscator, (int)sizeof(pe->obfuscator), &pe->obfuscator_detected, &pe->obfuscator_conf,
        pe->detections, net, 1, "none");
    if (pe->path[0])
        snprintf(g_applied_path, sizeof(g_applied_path), "%s", pe->path);
    else
        g_applied_path[0] = 0;
    g_applied_key = key;
}

bool DetectSettingPackers() { return SettingsGetBool("detect.packers", true); }
bool DetectSettingCompilers() { return SettingsGetBool("detect.compilers", true); }
bool DetectSettingDotNet() { return SettingsGetBool("detect.dotnet", true); }
bool DetectSettingUserSigs() { return SettingsGetBool("detect.user_signatures", true); }
void DetectSetPackers(bool on) { SettingsSetBool("detect.packers", on); SettingsSave(); }
void DetectSetCompilers(bool on) { SettingsSetBool("detect.compilers", on); SettingsSave(); }
void DetectSetDotNet(bool on) { SettingsSetBool("detect.dotnet", on); SettingsSave(); }
void DetectSetUserSigs(bool on) { SettingsSetBool("detect.user_signatures", on); SettingsSave(); }

const char* DetectCategoryId(DetectCategory cat)
{
    switch (cat)
    {
    case DetectCatPacker: return "packer";
    case DetectCatProtector: return "protector";
    case DetectCatCompiler: return "compiler";
    case DetectCatToolchain: return "toolchain";
    case DetectCatDotNetObfuscator: return "dotnet_obfuscator";
    default: return "unknown";
    }
}

const char* DetectConfidenceId(DetectConfidence conf)
{
    switch (conf)
    {
    case DetectConfLow: return "low";
    case DetectConfMedium: return "medium";
    case DetectConfHigh: return "high";
    case DetectConfExact: return "exact";
    default: return "low";
    }
}

void DetectResetForTest()
{
    std::lock_guard<std::mutex> lock(g_mu);
    g_sigs.clear();
    g_stats = {};
    DetectClearApplied();
}

bool DetectLoadJsonForTest(const char* json, DetectSource src, const char* origin, char* err, int err_cap)
{
    CompiledSig sig;
    std::string e;
    if (!DetectParseSignatureJson(json, origin ? origin : "test", src, &sig, &e))
    {
        if (err && err_cap > 0)
            snprintf(err, err_cap, "%s", e.c_str());
        return false;
    }
    std::lock_guard<std::mutex> lock(g_mu);
    if (IdTaken(g_sigs, sig.id))
    {
        g_stats.collisions++;
        if (err && err_cap > 0)
            snprintf(err, err_cap, "duplicate id");
        DetectLogSig(LogSevWarning, "Duplicate signature id '%s' — keeping the first load", sig.id.c_str());
        return false;
    }
    g_sigs.push_back(std::move(sig));
    g_stats.total = (int)g_sigs.size();
    if (src == DetectSrcBuiltin)
        g_stats.builtin++;
    else if (src == DetectSrcUser)
        g_stats.user++;
    else
        g_stats.pack++;
    if (err && err_cap > 0)
        err[0] = 0;
    return true;
}

int DetectSignatureCount()
{
    std::lock_guard<std::mutex> lock(g_mu);
    return (int)g_sigs.size();
}

bool DetectParseBytePatternForTest(const char* text, int* byte_n, int* wild_n, char* err, int err_cap)
{
    BytePat pat;
    std::string e;
    if (!DetectParseBytePattern(text, &pat, &e))
    {
        if (err && err_cap > 0)
            snprintf(err, err_cap, "%s", e.c_str());
        return false;
    }
    int wild = 0;
    for (uint8_t m : pat.mask)
    {
        if (!m)
            wild++;
    }
    if (byte_n)
        *byte_n = (int)pat.bytes.size();
    if (wild_n)
        *wild_n = wild;
    if (err && err_cap > 0)
        err[0] = 0;
    return true;
}
