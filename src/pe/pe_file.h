#pragma once

#include "pe/pe_types.h"

#include <cstdint>
#include <string>
#include <vector>
#include <optional>

class PeFile
{
public:
    static std::optional<PeFile> load(const std::wstring& path, std::string& error);

    uint64_t size() const { return bytes_.size(); }
    const uint8_t* data() const { return bytes_.data(); }
    const std::wstring& path() const { return path_; }

    bool contains(uint64_t offset, uint64_t length) const;
    bool read(uint64_t offset, void* dest, size_t length) const;
    template <typename T>
    bool read_struct(uint64_t offset, T& out) const
    {
        return read(offset, &out, sizeof(T));
    }

    std::string read_cstring(uint64_t offset, uint32_t max_chars) const;
    std::wstring read_wstring(uint64_t offset, uint32_t max_chars) const;

private:
    std::wstring path_;
    std::vector<uint8_t> bytes_;
};
