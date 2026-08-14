#pragma once

#include <stdint.h>
#include <vector>
#include <string>
#include <atomic>

struct PeSection
{
    char     name[9];
    uint32_t vsize;
    uint32_t vaddr;
    uint32_t rawsize;
    uint32_t rawptr;
    uint32_t chars;
};

struct PeRichEntry
{
    uint16_t prod;
    uint16_t build;
    uint32_t count;
};

struct PeImportFn
{
    std::string name;
    uint16_t    hint;
    uint32_t    ordinal; // 0 = by name
};

struct PeImportDll
{
    std::string            name;
    std::vector<PeImportFn> fns;
};

struct PeExportFn
{
    std::string name;
    uint32_t    ordinal;
    uint32_t    rva;
};

struct PeRsrcType
{
    char     name[48];
    uint32_t id;
    int      entries;
};

struct PeRsrcLeaf
{
    uint32_t type_id;
    char     type_name[48];
    uint32_t name_id;
    char     name[64];
    uint16_t lang;
    uint32_t rva;
    uint32_t file_off;
    uint32_t size;
};

struct PeVerString
{
    char     key[48];
    char     value[256];
    uint32_t node_off;
    uint32_t value_off;
    uint32_t value_cap;
};

struct PeVerInfo
{
    bool     ok;
    uint32_t file_off;
    uint32_t size;
    uint32_t ffi_off;
    uint16_t file[4];
    uint16_t prod[4];
    char     name[64];
    std::vector<PeVerString> strings;
};

struct PeIconImg
{
    uint16_t id;
    uint16_t lang;
    uint32_t file_off;
    uint32_t size;
    int      w;
    int      h;
    int      bpp;
    bool     png;
};

struct PeTypelib
{
    char     name[64];
    uint32_t file_off;
    uint32_t size;
    uint32_t version; // MSFT header +4
    bool     msft;
};

struct PeFile
{
    bool     ok;
    char     error[256];
    char     path[260];
    uint64_t size;
    char     sha256[65];
    char     compiler[96];
    char     packer[96];

    bool     pe32plus;
    uint32_t e_lfanew;
    uint16_t machine;
    uint16_t sections_n;
    uint16_t opt_size;
    uint16_t chars;
    uint32_t timestamp;
    uint16_t magic;
    uint16_t subsystem;
    uint16_t dllchars;
    uint64_t image_base;
    uint32_t entry_rva;
    uint32_t section_align;
    uint32_t file_align;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t checksum;
    uint32_t size_of_stack_res;
    uint32_t size_of_heap_res;

    char machine_s[32];
    char subsystem_s[32];

    PeSection sections[96];
    int       section_n;

    uint32_t dd_rva[16];
    uint32_t dd_size[16];
    int      dd_n;

    bool has_import;
    bool has_export;
    bool has_resource;
    bool has_reloc;
    bool has_tls;
    bool has_debug;
    bool has_loadcfg;
    bool has_com;

    std::vector<PeRichEntry> rich;
    std::vector<PeImportDll> imports;
    std::vector<PeExportFn>  exports;
    std::vector<PeRsrcType>  rsrc_types;
    std::vector<PeRsrcLeaf>  rsrc;
    std::vector<PeVerInfo>   versions;
    std::vector<PeIconImg>   icons;
    std::vector<PeTypelib>   typelibs;
    uint32_t overlay_off;
    uint64_t overlay_size;

    uint32_t clr_off;
    uint16_t clr_major;
    uint16_t clr_minor;
    uint32_t clr_flags;
    uint32_t clr_entry;
};

bool PeParse(const uint8_t* data, size_t n, PeFile* out, std::atomic<float>* progress);

void        PeJobStart(const char* path);
void        PeJobShutdown();
bool        PeJobBusy();
bool        PeJobDone();
bool        PeJobFailed();
float       PeJobProgress();
const PeFile* PeJobResult();
PeFile*     PeJobResultMut();
const char* PeJobError();
const char* PeJobPath();
uint8_t*    PeJobBytes(size_t* n);
bool        PeJobDirty();
void        PeJobTouch();
bool        PeJobSave(const char* path);
void        PePatchClr();
void        PePatchTypelib(int index);
bool        PePatchBytes(uint32_t off, const uint8_t* src, uint32_t n);
bool        PePatchVerFixed(int index);
bool        PePatchVerString(int ver_index, int str_index, const char* utf8);
uint32_t    PeRvaToFileOff(uint32_t rva);
bool        PeExportIco(int icon_index, const char* path);
bool        PeReplaceIco(int icon_index, const char* path);
