#include "pe/pe_file.h"
#include "platform/unique_handle.h"

#include <cstring>
#include <windows.h>

bool PeFile::contains(uint64_t offset, uint64_t length) const
{
    if (length == 0)
        return offset <= bytes_.size();
    if (offset >= bytes_.size())
        return false;
    return length <= bytes_.size() - offset;
}

bool PeFile::read(uint64_t offset, void* dest, size_t length) const
{
    if (dest == nullptr || !contains(offset, length))
        return false;
    memcpy(dest, bytes_.data() + static_cast<size_t>(offset), length);
    return true;
}

std::string PeFile::read_cstring(uint64_t offset, uint32_t max_chars) const
{
    if (offset >= bytes_.size() || max_chars == 0)
        return {};

    const uint64_t remaining = bytes_.size() - offset;
    const uint32_t limit = static_cast<uint32_t>(remaining < max_chars ? remaining : max_chars);
    std::string out;
    out.reserve(limit);
    for (uint32_t i = 0; i < limit; ++i)
    {
        const char ch = static_cast<char>(bytes_[static_cast<size_t>(offset) + i]);
        if (ch == '\0')
            break;
        out.push_back(ch);
    }
    return out;
}

std::wstring PeFile::read_wstring(uint64_t offset, uint32_t max_chars) const
{
    if (offset >= bytes_.size() || max_chars == 0)
        return {};

    const uint64_t remaining = bytes_.size() - offset;
    const uint32_t max_bytes = max_chars * 2u;
    const uint32_t limit_bytes = static_cast<uint32_t>(remaining < max_bytes ? remaining : max_bytes);
    std::wstring out;
    out.reserve(limit_bytes / 2);
    for (uint32_t i = 0; i + 1 < limit_bytes; i += 2)
    {
        wchar_t ch = 0;
        memcpy(&ch, bytes_.data() + static_cast<size_t>(offset) + i, 2);
        if (ch == 0)
            break;
        out.push_back(ch);
    }
    return out;
}

std::optional<PeFile> PeFile::load(const std::wstring& path, std::string& error)
{
    UniqueHandle file(CreateFileW(
        path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file)
    {
        error = "Could not open file (access denied or missing).";
        return std::nullopt;
    }

    LARGE_INTEGER file_size{};
    if (!GetFileSizeEx(file.get(), &file_size) || file_size.QuadPart <= 0)
    {
        error = "Could not read file size.";
        return std::nullopt;
    }
    if (static_cast<uint64_t>(file_size.QuadPart) > kMaxPeFileSize)
    {
        error = "File exceeds the 256 MiB analysis limit.";
        return std::nullopt;
    }

    PeFile pe;
    pe.path_ = path;
    pe.bytes_.resize(static_cast<size_t>(file_size.QuadPart));

    DWORD total_read = 0;
    while (total_read < pe.bytes_.size())
    {
        DWORD chunk = 0;
        const DWORD want = static_cast<DWORD>(
            (pe.bytes_.size() - total_read) > 0x40000000u
                ? 0x40000000u
                : (pe.bytes_.size() - total_read));
        if (!ReadFile(file.get(), pe.bytes_.data() + total_read, want, &chunk, nullptr) || chunk == 0)
        {
            error = "Truncated read while loading the file.";
            return std::nullopt;
        }
        total_read += chunk;
    }

    return pe;
}
