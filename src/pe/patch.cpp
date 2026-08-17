#include "pe/patch.h"
#include "pe/pe.h"
#include "log/log.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <algorithm>

static const int kMaxOps = 4096;
static const uint32_t kMaxOpBytes = 1024 * 1024;

static std::vector<uint8_t> g_orig;
static std::vector<uint8_t> g_saved;
static std::vector<PatchOp> g_hist;
static std::vector<PatchOp> g_undo;
static std::vector<PatchOp> g_redo;
static uint64_t g_seq;
static uint32_t g_diff_saved;

static uint64_t NowMs()
{
    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return u.QuadPart / 10000ull;
}

static uint32_t RvaOf(uint32_t off)
{
    return PeFileOffToRva(PeJobResult(), off);
}

static void AccountRange(uint32_t off, uint32_t n, const uint8_t* oldb, const uint8_t* newb)
{
    for (uint32_t i = 0; i < n; i++)
    {
        uint32_t o = off + i;
        if (o >= g_saved.size())
            break;
        uint8_t sv = g_saved[o];
        bool was = oldb[i] != sv;
        bool now = newb[i] != sv;
        if (was && !now && g_diff_saved)
            g_diff_saved--;
        if (!was && now)
            g_diff_saved++;
    }
    if (g_diff_saved)
        PeJobTouch();
    else
        PeJobClearDirty();
}

static void PushHist(PatchOp op)
{
    if ((int)g_hist.size() >= kMaxOps)
        g_hist.erase(g_hist.begin());
    g_hist.push_back(std::move(op));
}

const char* PatchSourceId(PatchSource s)
{
    switch (s)
    {
    case PatchSrcHex: return "hex";
    case PatchSrcVersion: return "version";
    case PatchSrcClr: return "clr";
    case PatchSrcIcon: return "icon";
    default: return "other";
    }
}

const char* PatchSourceI18n(PatchSource s)
{
    switch (s)
    {
    case PatchSrcHex: return "patch.src.hex";
    case PatchSrcVersion: return "patch.src.version";
    case PatchSrcClr: return "patch.src.clr";
    case PatchSrcIcon: return "patch.src.icon";
    default: return "patch.src.other";
    }
}

void PatchFmtBytes(const std::vector<uint8_t>& b, char* out, int cap)
{
    if (!out || cap < 2)
        return;
    out[0] = 0;
    int p = 0;
    int n = (int)b.size();
    int show = n > 16 ? 16 : n;
    for (int i = 0; i < show && p < cap - 8; i++)
        p += snprintf(out + p, cap - p, "%s%02X", i ? " " : "", b[i]);
    if (n > show && p < cap - 8)
        snprintf(out + p, cap - p, " … +%d", n - show);
}

void PatchJournalReset()
{
    g_orig.clear();
    g_saved.clear();
    g_hist.clear();
    g_undo.clear();
    g_redo.clear();
    g_seq = 0;
    g_diff_saved = 0;
}

void PatchJournalLoad(const uint8_t* data, size_t n)
{
    PatchJournalReset();
    if (!data || !n)
        return;
    g_orig.assign(data, data + n);
    g_saved = g_orig;
}

bool PatchApply(uint32_t off, const uint8_t* after, uint32_t n, PatchSource src)
{
    size_t sz = 0;
    uint8_t* cur = PeJobBytes(&sz);
    if (!cur || !after || !n || n > kMaxOpBytes)
        return false;
    if ((uint64_t)off + n > sz)
        return false;
    if (memcmp(cur + off, after, n) == 0)
        return true;

    if (src == PatchSrcHex && n == 1 && !g_undo.empty())
    {
        PatchOp& last = g_undo.back();
        uint64_t now = NowMs();
        if (last.kind == PatchKindBytes && last.source == PatchSrcHex &&
            now >= last.time_ms && now - last.time_ms < 1600)
        {
            if (last.offset + (uint32_t)last.after.size() == off && last.after.size() < 256)
            {
                last.after.push_back(after[0]);
                last.before.push_back(cur[off]);
                last.time_ms = now;
                AccountRange(off, 1, cur + off, after);
                cur[off] = after[0];
                if (!g_hist.empty() && g_hist.back().seq == last.seq)
                    g_hist.back() = last;
                g_redo.clear();
                return true;
            }
            if (last.offset == off && last.after.size() == 1)
            {
                uint8_t old = cur[off];
                AccountRange(off, 1, &old, after);
                last.after[0] = after[0];
                last.time_ms = now;
                cur[off] = after[0];
                if (!g_hist.empty() && g_hist.back().seq == last.seq)
                    g_hist.back() = last;
                g_redo.clear();
                return true;
            }
        }
    }

    PatchOp op{};
    op.seq = ++g_seq;
    op.kind = PatchKindBytes;
    op.source = src;
    op.offset = off;
    op.rva = RvaOf(off);
    op.before.assign(cur + off, cur + off + n);
    op.after.assign(after, after + n);
    op.time_ms = NowMs();
    AccountRange(off, n, cur + off, after);
    memcpy(cur + off, after, n);
    g_undo.push_back(op);
    if ((int)g_undo.size() > kMaxOps)
        g_undo.erase(g_undo.begin());
    g_redo.clear();
    PushHist(op);
    return true;
}

bool PatchCanUndo() { return !g_undo.empty(); }
bool PatchCanRedo() { return !g_redo.empty(); }

bool PatchUndo()
{
    if (g_undo.empty())
        return false;
    PatchOp op = std::move(g_undo.back());
    g_undo.pop_back();
    size_t sz = 0;
    uint8_t* cur = PeJobBytes(&sz);
    if (!cur || op.before.empty() || (uint64_t)op.offset + op.before.size() > sz)
        return false;
    AccountRange(op.offset, (uint32_t)op.before.size(), cur + op.offset, op.before.data());
    memcpy(cur + op.offset, op.before.data(), op.before.size());
    g_redo.push_back(std::move(op));
    auto log = LogFor(LogBuiltinPeAnalyzer).Module("Patch");
    log.Debug("Undo 0x%X (%zu bytes)", g_redo.back().offset, g_redo.back().before.size());
    return true;
}

bool PatchRedo()
{
    if (g_redo.empty())
        return false;
    PatchOp op = std::move(g_redo.back());
    g_redo.pop_back();
    size_t sz = 0;
    uint8_t* cur = PeJobBytes(&sz);
    if (!cur || op.after.empty() || (uint64_t)op.offset + op.after.size() > sz)
        return false;
    AccountRange(op.offset, (uint32_t)op.after.size(), cur + op.offset, op.after.data());
    memcpy(cur + op.offset, op.after.data(), op.after.size());
    g_undo.push_back(op);
    PushHist(op);
    auto log = LogFor(LogBuiltinPeAnalyzer).Module("Patch");
    log.Debug("Redo 0x%X (%zu bytes)", op.offset, op.after.size());
    return true;
}

bool PatchUndoSeq(uint64_t seq)
{
    if (g_undo.empty() || g_undo.back().seq != seq)
        return false;
    return PatchUndo();
}

void PatchOnSaved()
{
    size_t sz = 0;
    const uint8_t* cur = PeJobBytes(&sz);
    if (cur && sz)
        g_saved.assign(cur, cur + sz);
    g_diff_saved = 0;
    PeJobClearDirty();
    PatchOp mark{};
    mark.seq = ++g_seq;
    mark.kind = PatchKindSaveMarker;
    mark.time_ms = NowMs();
    PushHist(mark);
}

PatchByteState PatchColor(uint32_t off, uint8_t current)
{
    if (off >= g_saved.size())
        return PatchByteOriginal;
    if (current != g_saved[off])
        return PatchByteUnsaved;
    if (off < g_orig.size() && current != g_orig[off])
        return PatchByteSaved;
    return PatchByteOriginal;
}

const std::vector<PatchOp>& PatchHistory() { return g_hist; }
int PatchUndoDepth() { return (int)g_undo.size(); }

void PatchLogPersisted()
{
    auto log = LogFor(LogBuiltinPeAnalyzer).Module("Patch");
    size_t sz = 0;
    const uint8_t* cur = PeJobBytes(&sz);
    if (!cur || !sz || g_saved.size() != sz)
    {
        log.Info("Save wrote the working image");
        return;
    }

    struct Range { uint32_t off, rva, n; };
    std::vector<Range> rs;
    uint32_t i = 0;
    while (i < (uint32_t)sz)
    {
        if (cur[i] == g_saved[i])
        {
            i++;
            continue;
        }
        uint32_t start = i;
        while (i < (uint32_t)sz && cur[i] != g_saved[i])
            i++;
        Range r;
        r.off = start;
        r.rva = RvaOf(start);
        r.n = i - start;
        rs.push_back(r);
        if ((int)rs.size() > 4096)
            break;
    }
    if (rs.empty())
    {
        log.Info("Save wrote the working image (no byte differences vs last save)");
        return;
    }

    int logged = 0;
    const int kMaxLines = 48;
    uint32_t total_bytes = 0;
    for (const Range& r : rs)
        total_bytes += r.n;

    if ((int)rs.size() > kMaxLines || total_bytes > 4096)
    {
        log.Info("Persisted %d patch range(s), %u byte(s) (details in Changes)",
            (int)rs.size(), total_bytes);
        return;
    }

    for (const Range& r : rs)
    {
        std::vector<uint8_t> a(g_saved.begin() + r.off, g_saved.begin() + r.off + r.n);
        std::vector<uint8_t> b(cur + r.off, cur + r.off + r.n);
        char ba[96], aa[96];
        PatchFmtBytes(a, ba, (int)sizeof(ba));
        PatchFmtBytes(b, aa, (int)sizeof(aa));
        if (r.rva)
            log.Info("File 0x%X / RVA 0x%X: %s -> %s", r.off, r.rva, ba, aa);
        else
            log.Info("File 0x%X: %s -> %s", r.off, ba, aa);
        logged++;
    }
    (void)logged;
}
