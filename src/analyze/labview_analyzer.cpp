#include "analyze/analyze.h"
#include "pe/pe.h"
#include "log/log.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <vector>
#include <string>

// LabVIEW Application Builder / NI Resource Container inventory.
// Identity is JSON (product_key labview). Not a G decompiler — built EXEs
// usually strip block diagrams. credit: pylabview / labviewwiki RSRC notes.

static const char* kAnalyzerId = "com.binarysectorinspector.analyzer.labview";
static const uint32_t kMaxContainer = 32u * 1024u * 1024u;
static const int kMaxContainers = 48;
static const int kMaxSnips = 64;
static const int kMaxSnipChars = 160;

struct LvBlock
{
    char id[5];
    uint32_t count;
    uint32_t data_off;
    uint32_t data_size;
};

struct LvContainer
{
    uint32_t off;
    uint32_t size;
    uint16_t format;
    char file_type[5];
    char creator[5];
    std::vector<LvBlock> blocks;
    char note[80];
};

static uint16_t Be16(const uint8_t* p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t Be32(const uint8_t* p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
        ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void CopyFour(char out[5], const uint8_t* p)
{
    out[0] = (char)p[0];
    out[1] = (char)p[1];
    out[2] = (char)p[2];
    out[3] = (char)p[3];
    out[4] = 0;
    for (int i = 0; i < 4; i++)
    {
        if (out[i] < 32 || out[i] > 126)
            out[i] = '?';
    }
}

static bool LooksFourCc(const uint8_t* p)
{
    int ok = 0;
    for (int i = 0; i < 4; i++)
    {
        unsigned char c = p[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == ' ' || c == '_')
            ok++;
    }
    return ok >= 3;
}

static const char* BlockRole(const char* id4)
{
    struct Row { const char* id; const char* title; };
    static const Row k[] = {
        { "LVSR", "Save record" },
        { "LVIN", "Instrument header" },
        { "vers", "Version" },
        { "ICON", "VI icon" },
        { "FPHP", "Front panel heap" },
        { "FPHb", "Front panel" },
        { "FPHx", "Front panel ext" },
        { "CONP", "Connector pane" },
        { "BDPW", "Block diagram" },
        { "BDHb", "Block diagram heap" },
        { "BDHx", "Block diagram ext" },
        { "VICD", "Compiled code" },
        { "VCTP", "Type library" },
        { "LIvi", "Library link" },
        { "RTXT", "Rich text" },
        { "STR ", "String table" },
        { "CPRF", "Compressed file" },
        { "ZCRF", "Zlib file" },
        { "UCRF", "Uncompressed file" },
        { nullptr, nullptr }
    };
    if (!id4)
        return "Unknown";
    for (int i = 0; k[i].id; i++)
    {
        if (strncmp(id4, k[i].id, 4) == 0)
            return k[i].title;
    }
    return "Unknown";
}

static int BlockGroup(const char* id4)
{
    // 1 UI, 2 diagram, 3 code, 0 other
    if (!id4)
        return 0;
    if (strncmp(id4, "FPH", 3) == 0 || strncmp(id4, "ICON", 4) == 0 || strncmp(id4, "CONP", 4) == 0)
        return 1;
    if (strncmp(id4, "BD", 2) == 0)
        return 2;
    if (strncmp(id4, "VICD", 4) == 0 || strncmp(id4, "VCTP", 4) == 0)
        return 3;
    return 0;
}

static bool ParseContainer(const uint8_t* pe, size_t n, uint32_t off, LvContainer* c)
{
    if (!pe || !c || (size_t)off + 32 > n)
        return false;
    const uint8_t* h = pe + off;
    if (memcmp(h, "RSRC\r\n", 6) != 0)
        return false;

    memset(c, 0, sizeof(*c));
    c->off = off;
    c->format = Be16(h + 6);
    CopyFour(c->file_type, h + 8);
    CopyFour(c->creator, h + 12);
    uint32_t info_off = Be32(h + 16);
    uint32_t info_size = Be32(h + 20);
    uint32_t data_off = Be32(h + 24);
    uint32_t data_size = Be32(h + 28);

    uint64_t abs_info = (uint64_t)off + info_off;
    uint64_t abs_data = (uint64_t)off + data_off;
    if (abs_info > n || abs_data > n)
    {
        snprintf(c->note, sizeof(c->note), "header offsets out of range");
        c->size = 32;
        return true;
    }

    uint64_t end = abs_info + info_size;
    if (abs_data + data_size > end)
        end = abs_data + data_size;
    if (end < abs_info + 32)
        end = abs_info + 32;
    if (end > n)
        end = n;
    c->size = (uint32_t)(end - off);
    if (c->size < 32)
        c->size = 32;
    if (c->size > kMaxContainer)
        c->size = kMaxContainer;

    const uint8_t* info = pe + abs_info;
    const uint8_t* table = nullptr;
    uint32_t nblocks = 0;

    if ((size_t)abs_info + 0x2C <= n)
    {
        int32_t cntm1 = (int32_t)Be32(info + 0x28);
        if (cntm1 >= 0 && cntm1 < 4096)
        {
            nblocks = (uint32_t)cntm1 + 1;
            table = info + 0x2C;
        }
    }
    if (!table && (size_t)abs_info + 0x18 <= n)
    {
        uint32_t block_info_rel = Be32(info + 0x14);
        if (block_info_rel >= 4 && (uint64_t)abs_info + block_info_rel + 4 <= n)
        {
            int32_t cntm1 = (int32_t)Be32(pe + abs_info + block_info_rel);
            if (cntm1 >= 0 && cntm1 < 4096)
            {
                nblocks = (uint32_t)cntm1 + 1;
                table = pe + abs_info + block_info_rel + 4;
            }
        }
    }

    if (!table || nblocks == 0)
    {
        snprintf(c->note, sizeof(c->note), "block table not recognized");
        return true;
    }

    size_t table_end = (size_t)(table - pe);
    for (uint32_t i = 0; i < nblocks; i++)
    {
        size_t bo = table_end + (size_t)i * 20;
        if (bo + 20 > n)
            break;
        const uint8_t* bh = pe + bo;
        if (!LooksFourCc(bh))
            break;
        LvBlock b{};
        CopyFour(b.id, bh);
        int32_t sc_m1 = (int32_t)Be32(bh + 4);
        uint32_t sec_off = Be32(bh + 8);
        if (sc_m1 < 0 || sc_m1 > 4095)
            break;
        b.count = (uint32_t)sc_m1 + 1;
        uint64_t sec_abs = (uint64_t)abs_info + sec_off;
        if (sec_abs + 16 <= n)
        {
            uint32_t data_rel = Be32(pe + sec_abs + 8);
            uint64_t payload = (uint64_t)off + data_off + data_rel;
            if (payload + 4 <= n)
            {
                b.data_off = (uint32_t)payload;
                uint32_t psz = Be32(pe + payload);
                if (psz > 0 && psz < 64u * 1024u * 1024u && payload + 4 + psz <= n)
                    b.data_size = psz + 4;
                else if (data_size && data_rel < data_size)
                    b.data_size = data_size - data_rel;
            }
        }
        c->blocks.push_back(b);
    }

    snprintf(c->note, sizeof(c->note), "%u block type(s)", (unsigned)c->blocks.size());
    return true;
}

static bool LooksLvString(const char* s)
{
    if (!s || !s[0])
        return false;
    static const char* k[] = {
        "LabVIEW", "LVRT", "National Instruments", "ni.com",
        "Run-Time Engine", "LabVIEW Runtime", "LVIN", "LBVW"
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
    if (!LooksLvString(line))
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
        if (k >= 6)
            PushSnip(art, line, snips);
    }
}

static bool AnalyzeLabview(PeFile* pe, const uint8_t* data, size_t n)
{
    auto log = LogFor(LogBuiltinPeAnalyzer).Module("labview");
    if (!pe || !data || !n)
        return false;

    static const uint8_t kMagic[] = { 'R', 'S', 'R', 'C', '\r', '\n' };
    std::vector<LvContainer> containers;
    size_t lim = n > 6 ? n - 6 : 0;
    if (lim > 96u * 1024u * 1024u)
        lim = 96u * 1024u * 1024u;
    for (size_t i = 0; i <= lim && (int)containers.size() < kMaxContainers; i++)
    {
        if (memcmp(data + i, kMagic, 6) != 0)
            continue;
        LvContainer c{};
        if (!ParseContainer(data, n, (uint32_t)i, &c))
            continue;
        // Prefer NI-looking containers; still accept if block table parsed.
        bool niish =
            strcmp(c.creator, "LBVW") == 0 ||
            strcmp(c.file_type, "LVIN") == 0 ||
            strcmp(c.file_type, "LVSR") == 0 ||
            !c.blocks.empty();
        if (!niish && c.size <= 32)
            continue;
        containers.push_back(std::move(c));
        if (c.size > 6)
            i += (size_t)c.size - 1;
    }

    AnalysisArtifact root{};
    snprintf(root.id, sizeof(root.id), "labview.rsrc");
    root.kind = AnalysisKindRuntime;
    snprintf(root.label, sizeof(root.label), "LabVIEW");
    AnalyzeStamp(&root, kAnalyzerId, "LabVIEW");
    snprintf(root.status_i18n, sizeof(root.status_i18n), "pe.analysis_not_source");
    AnalyzeAddProp(&root, "runtime", "LabVIEW / LVRT");

    int has_fp = 0, has_bd = 0, has_code = 0, has_icon = 0;
    int snips = 0;

    if (containers.empty())
    {
        AnalyzeAddProp(&root, "rsrc_containers", "0");
        AnalyzeAddProp(&root, "note", "No NI RSRC container found; runtime strings/imports only");
        HarvestAscii(data, n > 8u * 1024u * 1024u ? 8u * 1024u * 1024u : (uint32_t)n, &root, &snips);
        log.Info("LabVIEW product match without RSRC container");
    }
    else
    {
        char nb[16];
        snprintf(nb, sizeof(nb), "%d", (int)containers.size());
        AnalyzeAddProp(&root, "rsrc_containers", nb);
        root.file_off = containers[0].off;
        root.size = containers[0].size;
        AnalyzeSetMedia(&root, "bytes.raw");

        AnalysisTable blocks_tbl{};
        AnalyzeTableInit(&blocks_tbl, "lv.blocks", "pe.analysis_col.blocks");
        AnalyzeTableAddCol(&blocks_tbl, "pe.analysis_col.name");
        AnalyzeTableAddCol(&blocks_tbl, "pe.analysis_col.kind");
        AnalyzeTableAddCol(&blocks_tbl, "pe.analysis_col.count");
        AnalyzeTableAddCol(&blocks_tbl, "pe.analysis_col.size");

        for (int ci = 0; ci < (int)containers.size(); ci++)
        {
            const LvContainer& c = containers[(size_t)ci];
            AnalysisArtifact child{};
            snprintf(child.id, sizeof(child.id), "labview.rsrc.%d", ci);
            child.kind = AnalysisKindPayload;
            snprintf(child.label, sizeof(child.label), "RSRC %s/%s @0x%X",
                c.file_type, c.creator, c.off);
            AnalyzeStamp(&child, kAnalyzerId, "LabVIEW");
            child.file_off = c.off;
            child.size = c.size;
            AnalyzeSetMedia(&child, "bytes.raw");

            char buf[48];
            snprintf(buf, sizeof(buf), "0x%X", c.off);
            AnalyzeAddProp(&child, "offset", buf);
            snprintf(buf, sizeof(buf), "%u", c.size);
            AnalyzeAddProp(&child, "size", buf);
            snprintf(buf, sizeof(buf), "%u", (unsigned)c.format);
            AnalyzeAddProp(&child, "format", buf);
            AnalyzeAddProp(&child, "file_type", c.file_type);
            AnalyzeAddProp(&child, "creator", c.creator);
            AnalyzeAddProp(&child, "blocks", c.note);

            char suggest[64];
            snprintf(suggest, sizeof(suggest), "labview_rsrc_%d.bin", ci);
            AnalyzeAddRawExport(&child, "rsrc", "pe.analysis_dump_raw", suggest, c.off, c.size);

            for (const LvBlock& b : c.blocks)
            {
                int g = BlockGroup(b.id);
                if (g == 1)
                    has_fp++;
                if (g == 2)
                    has_bd++;
                if (g == 3)
                    has_code++;
                if (strncmp(b.id, "ICON", 4) == 0)
                    has_icon++;

                char sz[24];
                snprintf(sz, sizeof(sz), "%u", b.data_size);
                char cnt[16];
                snprintf(cnt, sizeof(cnt), "%u", b.count);
                AnalyzeTableAddRow(&blocks_tbl, 0, b.data_off ? b.data_off : c.off,
                    b.id, BlockRole(b.id), cnt, sz);

                if (b.data_off && b.data_size && (uint64_t)b.data_off + b.data_size <= n)
                    HarvestAscii(data + b.data_off, b.data_size > 65536 ? 65536 : b.data_size, &root, &snips);
            }

            if ((uint64_t)c.off + c.size <= n)
                HarvestAscii(data + c.off, c.size > 256u * 1024u ? 256u * 1024u : c.size, &root, &snips);

            root.children.push_back(std::move(child));
            log.Info("RSRC @0x%X size=%u blocks=%u type=%s creator=%s",
                c.off, c.size, (unsigned)c.blocks.size(), c.file_type, c.creator);
        }

        if (!blocks_tbl.rows.empty())
            root.tables.push_back(std::move(blocks_tbl));
    }

    char cap[32];
    snprintf(cap, sizeof(cap), "%d", has_fp);
    AnalyzeAddProp(&root, "ui_blocks", cap);
    snprintf(cap, sizeof(cap), "%d", has_bd);
    AnalyzeAddProp(&root, "diagram_blocks", cap);
    snprintf(cap, sizeof(cap), "%d", has_code);
    AnalyzeAddProp(&root, "code_blocks", cap);
    snprintf(cap, sizeof(cap), "%d", has_icon);
    AnalyzeAddProp(&root, "icon_blocks", cap);

    if (has_bd == 0)
        AnalyzeAddProp(&root, "diagram", "stripped or absent (typical Application Builder)");
    else
        AnalyzeAddProp(&root, "diagram", "block-diagram resource present");

    if (snips)
    {
        char nb[12];
        snprintf(nb, sizeof(nb), "%d", snips);
        AnalyzeAddProp(&root, "string_hits", nb);
        AnalyzeAddProviderExport(&root, "listing", "pe.analysis_dump_listing", "labview_inventory.txt");
    }

    if (has_bd == 0)
    {
        AnalyzeAddFinding(pe, PeFindingNotice,
            "LabVIEW Application Builder (diagram stripped)",
            "NI RSRC / LVRT evidence found. G block diagram is typically removed at build; VICD is compiled runtime code, not source.");
    }
    else
    {
        AnalyzeAddFinding(pe, PeFindingNotice,
            "LabVIEW RSRC with diagram blocks",
            "Block-diagram resource ids present. Inventory only — not a full G decompiler.");
    }

    pe->analysis.push_back(std::move(root));
    return true;
}

static bool ExportLabview(const PeFile* pe, const uint8_t* data, size_t n,
    const AnalysisArtifact* art, const AnalysisExport* ex, const char* path)
{
    (void)pe;
    (void)data;
    (void)n;
    if (!art || !ex || !path || strcmp(ex->id, "listing") != 0)
        return false;
    std::string t;
    char line[512];
    snprintf(line, sizeof(line), "LabVIEW RSRC inventory (not G source)\n");
    t.append(line);
    for (const AnalysisProp& p : art->props)
    {
        snprintf(line, sizeof(line), "%s=%s\n", p.key, p.value);
        t.append(line);
    }
    t.push_back('\n');
    for (const AnalysisArtifact& c : art->children)
    {
        snprintf(line, sizeof(line), "[%s] off=0x%X size=%u\n", c.label, c.file_off, c.size);
        t.append(line);
    }
    t.push_back('\n');
    for (const AnalysisTable& tbl : art->tables)
    {
        for (const AnalysisTableRow& row : tbl.rows)
        {
            snprintf(line, sizeof(line), "%s\t%s\t%s\t%s\n",
                row.cells[0], row.cells[1], row.cells[2], row.cells[3]);
            t.append(line);
        }
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

static const AnalyzerProvider kLabviewProvider = {
    kAnalyzerId,
    "labview",
    { true, false, nullptr, "labview", nullptr },
    AnalyzeLabview,
    ExportLabview
};

static AnalyzerSelfRegister g_labview_reg(&kLabviewProvider);
