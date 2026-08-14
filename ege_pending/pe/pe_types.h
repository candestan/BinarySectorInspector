#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <windows.h>

#ifndef IMAGE_DLLCHARACTERISTICS_GUARD_CF
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF 0x4000
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
#define IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA 0x0020
#endif

constexpr uint64_t kMaxPeFileSize = 256ull * 1024ull * 1024ull;
constexpr uint16_t kMaxSectionCount = 96;
constexpr uint32_t kMaxStringRead = 4096;
constexpr uint32_t kMaxImportDescriptors = 4096;
constexpr uint32_t kMaxThunksPerDll = 16384;
constexpr uint32_t kMaxExportEntries = 65536;
constexpr uint32_t kMaxRelocBlocks = 65536;
constexpr uint32_t kMaxRelocEntriesPerBlock = 16384;
constexpr uint32_t kMaxTlsCallbacks = 1024;
constexpr uint32_t kMaxResourceEntries = 8192;
constexpr int kMaxResourceDepth = 16;
constexpr uint32_t kMaxDebugEntries = 256;
constexpr uint32_t kMinExtractedStringLength = 4;
constexpr uint32_t kMaxExtractedStrings = 20000;
constexpr uint32_t kMaxExtractedStringChars = 512;
constexpr uint32_t kUnusualDosStubThreshold = 1024;
constexpr double kHighEntropyThreshold = 7.0;
constexpr uint32_t kChecksumFieldOffsetInOptional32 = 64;
constexpr uint32_t kChecksumFieldOffsetInOptional64 = 64;

struct FileAddress
{
    bool valid = false;
    uint32_t rva = 0;
    uint64_t va = 0;
    uint64_t file_offset = 0;
    bool has_rva = false;
    bool has_va = false;
    bool has_file = false;
    int section_index = -1;
    std::string section_name;
};

enum class FindingSeverity
{
    Info,
    Notice,
    Warning,
};

struct Finding
{
    FindingSeverity severity = FindingSeverity::Info;
    std::string title;
    std::string why;
};
