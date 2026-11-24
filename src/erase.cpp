#include "cypherarx/erase.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <system_error>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

namespace cypherarx {

namespace {

constexpr std::size_t kChunkBytes = 64 * 1024;

struct Close {
    void operator()(std::FILE* f) const { std::fclose(f); }
};

using File = std::unique_ptr<std::FILE, Close>;

File open_for_update(const std::filesystem::path& path) {
#ifdef _WIN32
    std::FILE* f = nullptr;
    if (_wfopen_s(&f, path.c_str(), L"r+b") != 0) {
        return {};
    }
    return File(f);
#else
    return File(std::fopen(path.c_str(), "r+b"));
#endif
}

bool flush_to_disk(std::FILE* f) {
    if (std::fflush(f) != 0) {
        return false;
    }
#ifdef _WIN32
    return _commit(_fileno(f)) == 0;
#else
    return fsync(fileno(f)) == 0;
#endif
}

}

std::expected<void, EraseError> overwrite_file(const std::filesystem::path& path) {
    std::error_code ec;
    const std::filesystem::file_status status = std::filesystem::symlink_status(path, ec);
    if (ec || !std::filesystem::is_regular_file(status)) {
        return std::unexpected(EraseError::NotAFile);
    }
    std::uintmax_t left = std::filesystem::file_size(path, ec);
    if (ec) {
        return std::unexpected(EraseError::NotAFile);
    }
    const File file = open_for_update(path);
    if (!file) {
        return std::unexpected(EraseError::WriteFailed);
    }
    static const std::array<char, kChunkBytes> zeros{};
    while (left > 0) {
        const std::size_t n = static_cast<std::size_t>(std::min<std::uintmax_t>(left, zeros.size()));
        if (std::fwrite(zeros.data(), 1, n, file.get()) != n) {
            return std::unexpected(EraseError::WriteFailed);
        }
        left -= n;
    }
    if (!flush_to_disk(file.get())) {
        return std::unexpected(EraseError::WriteFailed);
    }
    return {};
}

std::expected<void, EraseError> erase_file(const std::filesystem::path& path) {
    if (const auto written = overwrite_file(path); !written) {
        return written;
    }
    std::error_code ec;
    if (!std::filesystem::remove(path, ec) || ec) {
        return std::unexpected(EraseError::RemoveFailed);
    }
    return {};
}

}
