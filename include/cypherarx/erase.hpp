#pragma once

#include <expected>
#include <filesystem>

namespace cypherarx {

enum class EraseError { NotAFile, WriteFailed, RemoveFailed };

std::expected<void, EraseError> overwrite_file(const std::filesystem::path& path);
std::expected<void, EraseError> erase_file(const std::filesystem::path& path);

}
